"""Hub Mgmt: AINVR classification-model training (Frigate), for trainers and admins.

Every command re-checks `_is_trainer` (admin, or a user ID in `trainers`). Frigate is
reached on localhost:5000 (internal, unauthenticated); its URL/credentials never reach
the browser. Model names are validated against Frigate's own config, category and file
names against strict patterns, so no path component can be injected.
"""
from __future__ import annotations

import asyncio
import base64
import re
import time
from urllib.parse import quote

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.helpers.aiohttp_client import async_get_clientsession

DOMAIN = "hub_mgmt"
FRIGATE = "http://localhost:5000"
_CAT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,39}$")
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,200}\.(webp|png|jpg|jpeg)$")
TRAIN_TIMEOUT_S = 20 * 60


def _is_trainer(hass, user) -> bool:
    return bool(user.is_admin or user.id in set(hass.data[DOMAIN].get("trainers", [])))


def _trainer_only(fn):
    async def wrapper(hass, connection, msg):
        if not _is_trainer(hass, connection.user):
            connection.send_error(msg["id"], "unauthorized", "Not a trainer user")
            return
        try:
            await fn(hass, connection, msg)
        except _Bad as err:
            connection.send_error(msg["id"], "invalid", str(err))
        except Exception as err:  # noqa: BLE001
            connection.send_error(msg["id"], "training_failed", str(err) or type(err).__name__)

    wrapper.__name__ = fn.__name__
    return wrapper


class _Bad(Exception):
    pass


async def _req(hass, method, path, **kw):
    s = async_get_clientsession(hass)
    async with s.request(method, FRIGATE + "/api" + path, timeout=30, **kw) as r:
        body = await r.read()
        if r.status >= 400:
            raise _Bad(f"Frigate {r.status}: {body[:200].decode(errors='replace')}")
        return r.headers.get("content-type", ""), body


async def _json(hass, method, path, **kw):
    import json

    _, body = await _req(hass, method, path, **kw)
    return json.loads(body) if body else None


async def _model_cfg(hass) -> dict:
    cfg = await _json(hass, "GET", "/config")
    return cfg.get("classification", {}).get("custom") or {}


def _kind(c: dict) -> str:
    return "object" if c.get("object_config") else "state"


async def _models(hass) -> list[str]:
    return sorted((await _model_cfg(hass)).keys())


async def _model(hass, name) -> str:
    if name not in await _models(hass):
        raise _Bad("Unknown model")
    return name


def _cat(v) -> str:
    if not isinstance(v, str) or not _CAT.match(v):
        raise _Bad("Invalid category name (letters, digits, space . _ -; max 40)")
    return v


def _files(v) -> list[str]:
    if not isinstance(v, list) or not v or len(v) > 200 or not all(isinstance(x, str) and _FILE.match(x) for x in v):
        raise _Bad("Invalid file list")
    return v


def _q(s) -> str:
    return quote(s, safe="")


def _log(hass, connection, what):
    import logging

    logging.getLogger(__name__).info("Trainer %s: %s", connection.user.name, what)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/train_models"})
@websocket_api.async_response
@_trainer_only
async def ws_train_models(hass, connection, msg):
    out = []
    cfgs = await _model_cfg(hass)
    for m in sorted(cfgs):
        c = cfgs[m]
        d = await _json(hass, "GET", f"/classification/{_q(m)}/dataset")
        t = await _json(hass, "GET", f"/classification/{_q(m)}/train")
        out.append({
            "name": m,
            "type": _kind(c),
            "cameras": sorted(((c.get("state_config") or {}).get("cameras") or {}).keys()),
            "objects": (c.get("object_config") or {}).get("objects") or [],
            "threshold": c.get("threshold"),
            "categories": {k: len(v) for k, v in (d.get("categories") or {}).items()},
            "unlabelled": len(t or []),
            "meta": d.get("training_metadata"),
            "busy": _busy(hass, m),
        })
    connection.send_result(msg["id"], out)


def _busy(hass, model) -> bool:
    b = hass.data[DOMAIN].get("train_busy")
    return bool(b and time.time() - b["t"] < TRAIN_TIMEOUT_S and b.get("model") == model)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/train_data", vol.Required("model"): str})
@websocket_api.async_response
@_trainer_only
async def ws_train_data(hass, connection, msg):
    m = await _model(hass, msg["model"])
    d = await _json(hass, "GET", f"/classification/{_q(m)}/dataset")
    t = await _json(hass, "GET", f"/classification/{_q(m)}/train")
    busy = hass.data[DOMAIN].get("train_busy")
    meta = d.get("training_metadata") or {}
    if busy and busy.get("model") == m and meta.get("last_training_date") != busy.get("prev"):
        hass.data[DOMAIN]["train_busy"] = busy = None
    connection.send_result(msg["id"], {
        "categories": d.get("categories") or {},
        "train": sorted(t or [], reverse=True),
        "meta": meta,
        "busy": _busy(hass, m),
    })


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_images",
    vol.Required("model"): str,
    vol.Required("items"): [{vol.Required("kind"): vol.In(["train", "dataset"]),
                             vol.Optional("category"): str, vol.Required("file"): str}],
})
@websocket_api.async_response
@_trainer_only
async def ws_train_images(hass, connection, msg):
    m = await _model(hass, msg["model"])
    if len(msg["items"]) > 40:
        raise _Bad("Too many images per call")

    async def one(it):
        _files([it["file"]])
        path = f"/clips/{_q(m)}/train/{_q(it['file'])}" if it["kind"] == "train" else f"/clips/{_q(m)}/dataset/{_q(_cat(it.get('category', '')))}/{_q(it['file'])}"
        s = async_get_clientsession(hass)
        async with s.get(FRIGATE + path, timeout=20) as r:
            if r.status != 200:
                return None
            ext = it["file"].rsplit(".", 1)[-1].lower()
            mime = {"webp": "image/webp", "png": "image/png"}.get(ext, "image/jpeg")
            return f"data:{mime};base64," + base64.b64encode(await r.read()).decode()

    res = await asyncio.gather(*(one(i) for i in msg["items"]))
    connection.send_result(msg["id"], res)


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_categorize", vol.Required("model"): str,
    vol.Required("file"): str, vol.Required("category"): str,
})
@websocket_api.async_response
@_trainer_only
async def ws_train_categorize(hass, connection, msg):
    m = await _model(hass, msg["model"])
    f, c = _files([msg["file"]])[0], _cat(msg["category"])
    await _json(hass, "POST", f"/classification/{_q(m)}/dataset/categorize", json={"training_file": f, "category": c})
    _log(hass, connection, f"{m}: {f} -> {c}")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_discard", vol.Required("model"): str, vol.Required("files"): [str],
})
@websocket_api.async_response
@_trainer_only
async def ws_train_discard(hass, connection, msg):
    m = await _model(hass, msg["model"])
    await _json(hass, "POST", f"/classification/{_q(m)}/train/delete", json={"ids": _files(msg["files"])})
    _log(hass, connection, f"{m}: discarded {len(msg['files'])} unlabelled")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_dataset_delete", vol.Required("model"): str,
    vol.Required("category"): str, vol.Required("files"): [str],
})
@websocket_api.async_response
@_trainer_only
async def ws_train_dataset_delete(hass, connection, msg):
    m = await _model(hass, msg["model"])
    c = _cat(msg["category"])
    await _json(hass, "POST", f"/classification/{_q(m)}/dataset/{_q(c)}/delete", json={"ids": _files(msg["files"])})
    _log(hass, connection, f"{m}: deleted {len(msg['files'])} from {c}")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_category", vol.Required("model"): str,
    vol.Required("action"): vol.In(["create", "rename"]),
    vol.Required("category"): str, vol.Optional("new_category"): str,
})
@websocket_api.async_response
@_trainer_only
async def ws_train_category(hass, connection, msg):
    m = await _model(hass, msg["model"])
    c = _cat(msg["category"])
    if msg["action"] == "create":
        await _json(hass, "POST", f"/classification/{_q(m)}/dataset/{_q(c)}/create")
    else:
        await _json(hass, "PUT", f"/classification/{_q(m)}/dataset/{_q(c)}/rename", json={"new_category": _cat(msg.get("new_category"))})
    _log(hass, connection, f"{m}: category {msg['action']} {c}")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/train_start", vol.Required("model"): str})
@websocket_api.async_response
@_trainer_only
async def ws_train_start(hass, connection, msg):
    m = await _model(hass, msg["model"])
    st = hass.data[DOMAIN]
    b = st.get("train_busy")
    if b and time.time() - b["t"] < TRAIN_TIMEOUT_S:
        raise _Bad(f"A training run for {b['model']} is already in progress")
    d = await _json(hass, "GET", f"/classification/{_q(m)}/dataset")
    prev = (d.get("training_metadata") or {}).get("last_training_date")
    await _json(hass, "POST", f"/classification/{_q(m)}/train")
    st["train_busy"] = {"model": m, "t": time.time(), "prev": prev}
    _log(hass, connection, f"{m}: training started")
    connection.send_result(msg["id"], {"ok": True})


MAX_UP_BYTES = 10 * 1024 * 1024
MAX_UP_FILES = 20
MAX_SIDE = 1024
CLIPS = "/frigate_clips"


def _save_images(model: str, category: str, blobs: list[bytes]) -> int:
    """Validate, strip and store images in the model's dataset category (runs in executor)."""
    import io
    import os
    import random
    import string

    from PIL import Image, ImageOps

    root = os.path.realpath(os.path.join(CLIPS, model, "dataset"))
    dest = os.path.realpath(os.path.join(root, category))
    if not os.path.isdir(CLIPS):
        raise _Bad("Upload storage is not mounted on this hub")
    if os.path.dirname(dest) != root or not os.path.isdir(dest):
        raise _Bad("Category does not exist for this model")
    prepared = []
    for i, raw in enumerate(blobs, 1):
        try:
            im = Image.open(io.BytesIO(raw))
            im.load()
            im = ImageOps.exif_transpose(im).convert("RGB")
        except Exception:  # noqa: BLE001
            raise _Bad(f"File {i} is not a valid image")
        im.thumbnail((MAX_SIDE, MAX_SIDE))
        buf = io.BytesIO()
        im.save(buf, "PNG")
        prepared.append(buf.getvalue())
    n = 0
    for data in prepared:
        rid = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        name = f"{category}-{time.time()}-{rid}.png"
        with open(os.path.join(dest, name), "xb") as fh:
            fh.write(data)
        n += 1
    return n


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/train_upload", vol.Required("model"): str,
    vol.Required("category"): str, vol.Required("images"): [str],
})
@websocket_api.async_response
@_trainer_only
async def ws_train_upload(hass, connection, msg):
    m = await _model(hass, msg["model"])
    if _kind((await _model_cfg(hass))[m]) != "object":
        raise _Bad("Uploads are only available for object classification models")
    c = _cat(msg["category"])
    imgs = msg["images"]
    if not imgs or len(imgs) > MAX_UP_FILES:
        raise _Bad(f"Upload 1 to {MAX_UP_FILES} images at a time")
    blobs = []
    for s in imgs:
        try:
            b = base64.b64decode(s.split(",", 1)[-1], validate=True)
        except Exception:  # noqa: BLE001
            raise _Bad("Bad image encoding")
        if len(b) > MAX_UP_BYTES:
            raise _Bad("An image is larger than 10 MB")
        blobs.append(b)
    n = await hass.async_add_executor_job(_save_images, m, c, blobs)
    _log(hass, connection, f"{m}: uploaded {n} image(s) to {c}")
    connection.send_result(msg["id"], {"ok": True, "saved": n})


COMMANDS = (ws_train_upload, ws_train_models, ws_train_data, ws_train_images, ws_train_categorize,
            ws_train_discard, ws_train_dataset_delete, ws_train_category, ws_train_start)
