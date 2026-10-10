"""Hub Mgmt phase 5: scenes and simple rules for the node portal.

Capability `scenes` (admin, installer, homeowner). Scenes live in the hub's scenes.yaml and rules in automations.yaml, but
the portal only ever edits entries it created itself (id prefix `portal_`); everything else is listed read-only. Rules are
generated from a fixed catalog (scene_util.build_automation), never from client-supplied YAML. A rejected rule is rolled back.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.helpers import area_registry as ar, entity_registry as er

from . import scene_util as su
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_scenes = _cap("scenes", "Not allowed to manage scenes and rules")
_LOCK = asyncio.Lock()


def _paths(hass) -> tuple[str, str]:
    return hass.config.path("scenes.yaml"), hass.config.path("automations.yaml")


def _read(path: str) -> list[dict[str, Any]]:
    from homeassistant.util.yaml import load_yaml
    if not os.path.exists(path):
        return []
    data = load_yaml(path)
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _write(path: str, items: list[dict[str, Any]]) -> None:
    from homeassistant.util.file import write_utf8_file_atomic
    from homeassistant.util.yaml import dump
    if os.path.exists(path):
        with open(path, encoding="utf-8") as src, open(path + ".portal-bak", "w", encoding="utf-8") as dst:
            dst.write(src.read())
    write_utf8_file_atomic(path, dump(items))


def _scene_eid(hass, sid: str) -> str | None:
    return er.async_get(hass).async_get_entity_id("scene", "homeassistant", sid)


def _auto_eid(hass, rid: str) -> str | None:
    return er.async_get(hass).async_get_entity_id("automation", "automation", rid)


def _exists(hass, eid: str) -> bool:
    return hass.states.get(eid) is not None or er.async_get(hass).async_get(eid) is not None


async def _reload(hass, domain: str) -> None:
    await hass.services.async_call(domain, "reload", blocking=True)


def _scene_names(hass, items) -> dict[str, str]:
    out = {}
    for c in items:
        e = _scene_eid(hass, str(c.get("id")))
        if e:
            out[e] = str(c.get("name", e))
    return out


def _dup(items, name: str, keep_id: str | None, key: str) -> bool:
    return any(str(c.get(key, "")).casefold() == name.casefold() and c.get("id") != keep_id for c in items)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/scene_list"})
@websocket_api.async_response
@_scenes
async def ws_scene_list(hass, connection, msg):
    sp, ap = _paths(hass)
    scenes = await hass.async_add_executor_job(_read, sp)
    autos = await hass.async_add_executor_job(_read, ap)
    names = _scene_names(hass, scenes)
    sc = []
    for c in scenes:
        v = su.scene_view(c)
        v["entity_id"] = _scene_eid(hass, v["id"])
        sc.append(v)
    rules = []
    for c in autos:
        rid = str(c.get("id", ""))
        eid = _auto_eid(hass, rid) if rid else None
        st = hass.states.get(eid) if eid else None
        spec = su.rule_spec_from(c)
        rules.append({
            "id": rid, "name": str(c.get("alias", rid))[:su.NAME_MAX * 2], "entity_id": eid, "editable": spec is not None,
            "spec": spec, "summary": su.describe(spec, names) if spec else None,
            "enabled": (st.state != "off") if st else None, "last_triggered": (st.attributes.get("last_triggered") if st else None),
        })
    sc.sort(key=lambda x: (not x["editable"], x["name"].casefold()))
    rules.sort(key=lambda x: (not x["editable"], x["name"].casefold()))
    connection.send_result(msg["id"], {"scenes": sc, "rules": rules, "limits": {"scenes": su.MAX_SCENES, "rules": su.MAX_RULES}})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/scene_candidates"})
@websocket_api.async_response
@_scenes
async def ws_scene_candidates(hass, connection, msg):
    ereg, areg = er.async_get(hass), ar.async_get(hass)
    from homeassistant.helpers import device_registry as dr
    dreg = dr.async_get(hass)
    out = []
    for st in hass.states.async_all():
        dom = st.entity_id.split(".", 1)[0]
        if dom not in su.SCENE_DOMAINS and dom not in ("binary_sensor", "person", "scene"):
            continue
        ent = ereg.async_get(st.entity_id)
        if ent and (ent.hidden_by or ent.disabled_by):
            continue
        aid = (ent.area_id if ent else None) or ((dreg.async_get(ent.device_id).area_id) if ent and ent.device_id and dreg.async_get(ent.device_id) else None)
        a = areg.async_get_area(aid) if aid else None
        out.append({"entity_id": st.entity_id, "name": str(st.attributes.get("friendly_name") or st.entity_id)[:80], "domain": dom,
                    "state": st.state, "area": a.name if a else None})
    out.sort(key=lambda x: (x["domain"], x["name"].casefold()))
    connection.send_result(msg["id"], {"entities": out[:1500]})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/scene_capture", vol.Required("entity_ids"): [str]})
@websocket_api.async_response
@_scenes
async def ws_scene_capture(hass, connection, msg):
    if len(msg["entity_ids"]) > su.MAX_SCENE_ENTITIES:
        connection.send_error(msg["id"], "invalid", f"At most {su.MAX_SCENE_ENTITIES} devices")
        return
    out, skipped = {}, []
    for eid in msg["entity_ids"]:
        st = hass.states.get(eid)
        c = su.capture(eid.split(".", 1)[0], st.state, dict(st.attributes)) if st else None
        if c is None:
            skipped.append(eid)
        else:
            out[eid] = c
    connection.send_result(msg["id"], {"entities": out, "skipped": skipped})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/scene_save", vol.Optional("scene_id"): str, vol.Required("name"): str, vol.Required("entities"): dict,
})
@websocket_api.async_response
@_scenes
async def ws_scene_save(hass, connection, msg):
    try:
        name = su.clean_name(msg["name"])
        ents = su.clean_scene_entities(msg["entities"])
    except su.Invalid as err:
        connection.send_error(msg["id"], "invalid", str(err))
        return
    for eid in ents:
        if hass.states.get(eid) is None:
            connection.send_error(msg["id"], "invalid", f"{eid} is not available on this node")
            return
    sp, _ = _paths(hass)
    async with _LOCK:
        items = await hass.async_add_executor_job(_read, sp)
        sid = msg.get("scene_id")
        if sid:
            idx = next((i for i, c in enumerate(items) if c.get("id") == sid), None)
            if idx is None or not str(sid).startswith(su.PREFIX):
                connection.send_error(msg["id"], "forbidden" if idx is not None else "not_found", "That scene cannot be edited here")
                return
        elif sum(1 for c in items if str(c.get("id", "")).startswith(su.PREFIX)) >= su.MAX_SCENES:
            connection.send_error(msg["id"], "limit", f"At most {su.MAX_SCENES} scenes")
            return
        if _dup(items, name, sid, "name"):
            connection.send_error(msg["id"], "duplicate", "A scene with that name already exists")
            return
        cfg = su.scene_config(sid or su.PREFIX + uuid.uuid4().hex[:12], name, ents)
        new = [cfg if c.get("id") == cfg["id"] else c for c in items]
        if not sid:
            new.append(cfg)
        await hass.async_add_executor_job(_write, sp, new)
        try:
            await _reload(hass, "scene")
        except Exception:  # noqa: BLE001
            await hass.async_add_executor_job(_write, sp, items)
            await _reload(hass, "scene")
            connection.send_error(msg["id"], "rejected", "The hub rejected that scene")
            return
    _audit(hass, connection.user, "scene_save", cfg["id"], "ok", {"name": name, "entities": len(ents)})
    connection.send_result(msg["id"], {"id": cfg["id"], "entity_id": _scene_eid(hass, cfg["id"])})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/scene_delete", vol.Required("scene_id"): str})
@websocket_api.async_response
@_scenes
async def ws_scene_delete(hass, connection, msg):
    sid = msg["scene_id"]
    sp, ap = _paths(hass)
    async with _LOCK:
        items = await hass.async_add_executor_job(_read, sp)
        if not sid.startswith(su.PREFIX) or not any(c.get("id") == sid for c in items):
            connection.send_error(msg["id"], "not_found", "That scene cannot be removed here")
            return
        eid = _scene_eid(hass, sid)
        autos = await hass.async_add_executor_job(_read, ap)
        users = [str(c.get("alias")) for c in autos if (s := su.rule_spec_from(c)) and any(a.get("scene_id") == eid for a in s["actions"] if a["type"] == "scene")]
        if users:
            connection.send_error(msg["id"], "in_use", "Used by rule: " + ", ".join(users[:3]))
            return
        await hass.async_add_executor_job(_write, sp, [c for c in items if c.get("id") != sid])
        await _reload(hass, "scene")
        if eid and er.async_get(hass).async_get(eid):
            er.async_get(hass).async_remove(eid)
    _audit(hass, connection.user, "scene_delete", sid, "ok")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/scene_activate", vol.Required("scene_id"): str})
@websocket_api.async_response
@_scenes
async def ws_scene_activate(hass, connection, msg):
    eid = _scene_eid(hass, msg["scene_id"])
    if not eid or hass.states.get(eid) is None:
        connection.send_error(msg["id"], "not_found", "Unknown scene")
        return
    try:
        await hass.services.async_call("scene", "turn_on", {"entity_id": eid}, blocking=True)
    except Exception as err:  # noqa: BLE001
        _audit(hass, connection.user, "scene_activate", msg["scene_id"], "error")
        connection.send_error(msg["id"], "failed", f"Could not run the scene ({type(err).__name__})")
        return
    _audit(hass, connection.user, "scene_activate", msg["scene_id"], "ok")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/rule_save", vol.Optional("rule_id"): str, vol.Required("rule"): dict})
@websocket_api.async_response
@_scenes
async def ws_rule_save(hass, connection, msg):
    try:
        spec = su.clean_rule(msg["rule"])
    except su.Invalid as err:
        connection.send_error(msg["id"], "invalid", str(err))
        return
    watch = [spec["trigger"].get("entity_id")] + [a.get("scene_id") or a.get("entity_id") for a in spec["actions"]]
    for eid in [w for w in watch if w]:
        if not _exists(hass, eid):
            connection.send_error(msg["id"], "invalid", f"{eid} is not available on this node")
            return
    _, ap = _paths(hass)
    async with _LOCK:
        items = await hass.async_add_executor_job(_read, ap)
        rid = msg.get("rule_id")
        if rid:
            cur = next((c for c in items if c.get("id") == rid), None)
            if cur is None or su.rule_spec_from(cur) is None:
                connection.send_error(msg["id"], "forbidden" if cur else "not_found", "That rule cannot be edited here")
                return
        elif sum(1 for c in items if str(c.get("id", "")).startswith(su.PREFIX)) >= su.MAX_RULES:
            connection.send_error(msg["id"], "limit", f"At most {su.MAX_RULES} rules")
            return
        if _dup(items, spec["name"], rid, "alias"):
            connection.send_error(msg["id"], "duplicate", "A rule with that name already exists")
            return
        cfg = su.build_automation(rid or su.PREFIX + uuid.uuid4().hex[:12], spec)
        new = [cfg if c.get("id") == cfg["id"] else c for c in items]
        if not rid:
            new.append(cfg)
        await hass.async_add_executor_job(_write, ap, new)
        await _reload(hass, "automation")
        eid = _auto_eid(hass, cfg["id"])
        if not eid or hass.states.get(eid) is None:
            await hass.async_add_executor_job(_write, ap, items)
            await _reload(hass, "automation")
            _audit(hass, connection.user, "rule_save", cfg["id"], "rejected")
            connection.send_error(msg["id"], "rejected", "The hub rejected that rule")
            return
        await hass.services.async_call("automation", "turn_on" if spec["enabled"] else "turn_off", {"entity_id": eid}, blocking=True)
    _audit(hass, connection.user, "rule_save", cfg["id"], "ok", {"name": spec["name"], "trigger": spec["trigger"]["type"]})
    connection.send_result(msg["id"], {"id": cfg["id"], "entity_id": eid})


async def _portal_rule(hass, connection, msg):
    _, ap = _paths(hass)
    items = await hass.async_add_executor_job(_read, ap)
    cfg = next((c for c in items if c.get("id") == msg["rule_id"]), None)
    if cfg is None or su.rule_spec_from(cfg) is None:
        connection.send_error(msg["id"], "not_found", "That rule cannot be changed here")
        return None, None, None
    return items, cfg, _auto_eid(hass, cfg["id"])


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/rule_delete", vol.Required("rule_id"): str})
@websocket_api.async_response
@_scenes
async def ws_rule_delete(hass, connection, msg):
    _, ap = _paths(hass)
    async with _LOCK:
        items, cfg, eid = await _portal_rule(hass, connection, msg)
        if cfg is None:
            return
        await hass.async_add_executor_job(_write, ap, [c for c in items if c.get("id") != cfg["id"]])
        await _reload(hass, "automation")
        if eid and er.async_get(hass).async_get(eid):
            er.async_get(hass).async_remove(eid)
    _audit(hass, connection.user, "rule_delete", msg["rule_id"], "ok")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/rule_set_enabled", vol.Required("rule_id"): str, vol.Required("enabled"): bool})
@websocket_api.async_response
@_scenes
async def ws_rule_set_enabled(hass, connection, msg):
    _, cfg, eid = await _portal_rule(hass, connection, msg)
    if cfg is None or not eid:
        if cfg is not None:
            connection.send_error(msg["id"], "not_found", "Rule is not loaded")
        return
    await hass.services.async_call("automation", "turn_on" if msg["enabled"] else "turn_off", {"entity_id": eid}, blocking=True)
    _audit(hass, connection.user, "rule_enable" if msg["enabled"] else "rule_disable", msg["rule_id"], "ok")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/rule_run", vol.Required("rule_id"): str})
@websocket_api.async_response
@_scenes
async def ws_rule_run(hass, connection, msg):
    _, cfg, eid = await _portal_rule(hass, connection, msg)
    if cfg is None or not eid:
        if cfg is not None:
            connection.send_error(msg["id"], "not_found", "Rule is not loaded")
        return
    try:
        await hass.services.async_call("automation", "trigger", {"entity_id": eid, "skip_condition": True}, blocking=True)
    except Exception as err:  # noqa: BLE001
        _audit(hass, connection.user, "rule_run", msg["rule_id"], "error")
        connection.send_error(msg["id"], "failed", f"The rule could not run ({type(err).__name__})")
        return
    _audit(hass, connection.user, "rule_run", msg["rule_id"], "ok")
    connection.send_result(msg["id"], {"ok": True})


COMMANDS = (ws_scene_list, ws_scene_candidates, ws_scene_capture, ws_scene_save, ws_scene_delete, ws_scene_activate,
            ws_rule_save, ws_rule_delete, ws_rule_set_enabled, ws_rule_run)
