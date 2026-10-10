"""Hub Mgmt phase 7: commissioning checklist, handover sheet and camera pages (capability `setup`, admin + installer).

The checklist reads the live node state, so it can never disagree with reality; it does not run the steps itself, it points to the
page that does. The handover sheet never contains a password or token. Cameras: list, still image, motion sensors, room assignment;
live streaming is out of scope.
"""
from __future__ import annotations

import base64
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.helpers import area_registry as ar, device_registry as dr, entity_registry as er

from . import setup_util as su
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_setup = _cap("setup", "Only installers and administrators can use commissioning")
MAX_IMAGE = 1_500_000


def _mgr(hass):
    from homeassistant.components.backup.const import DATA_MANAGER
    return hass.data.get(DATA_MANAGER)


async def _facts(hass) -> dict[str, Any]:
    from . import _role, _iter_devices, _removable_kind
    from .users import _mfa_on
    c = hass.config
    dreg, ereg = dr.async_get(hass), er.async_get(hass)
    devs = [d for d in _iter_devices(dreg) if _removable_kind(d) or d.config_entries]
    devs = [d for d in devs if not d.disabled_by]
    unplaced = 0
    for d in devs:
        if d.area_id:
            continue
        ents = [e for e in er.async_entries_for_device(ereg, d.id) if not e.disabled_by]
        if ents and not any(e.area_id for e in ents):
            unplaced += 1
    homeowners, no2fa = 0, []
    for u in await hass.auth.async_get_users():
        if not u.is_active or u.system_generated:
            continue
        role = _role(hass, u)
        if role == "homeowner":
            homeowners += 1
        if role in ("admin", "installer") and not await _mfa_on(hass, u):
            no2fa.append(u.name or "user")
    mgr = _mgr(hass)
    backups, sched = 0, "never"
    if mgr is not None:
        b, _e = await mgr.async_get_backups()
        backups = len(b)
        sched = mgr.config.data.schedule.recurrence.value
    st = hass.data.get("sentinel_link_api")
    clients = tokens = 0
    enabled = False
    if st is not None:
        try:
            enabled = bool(st.status().get("enabled"))
            clients = len(st.book.clients)
            tokens = len(getattr(st.book, "tokens", {}) or {})
        except Exception:  # noqa: BLE001
            _LOGGER.debug("link status unavailable", exc_info=True)
    return {"name": c.location_name, "time_zone": c.time_zone, "areas": len(ar.async_get(hass).areas), "devices": len(devs), "unplaced": unplaced,
            "homeowners": homeowners, "staff_without_2fa": no2fa, "backups": backups, "backup_schedule": sched,
            "link_enabled": enabled, "link_clients": clients, "link_tokens": tokens, "cameras": len(hass.states.async_entity_ids("camera"))}


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/setup_status"})
@websocket_api.async_response
@_setup
async def ws_setup_status(hass, connection, msg):
    items = su.steps(await _facts(hass))
    connection.send_result(msg["id"], {"steps": items, "progress": su.progress(items)})


def _qr(data: str) -> str | None:
    try:
        from homeassistant.auth.mfa_modules import totp as totp_mod
        return totp_mod._generate_qr_code(data)
    except Exception:  # noqa: BLE001
        return None


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/handover", vol.Optional("url"): vol.Any(str, None)})
@websocket_api.async_response
@_setup
async def ws_handover(hass, connection, msg):
    from . import _role
    from homeassistant.const import __version__ as core_version
    url = None
    if msg.get("url"):
        url = su.valid_public_url(msg["url"])
        if url is None:
            connection.send_error(msg["id"], "invalid", "Enter the address as https://name.example.com (no password or query)")
            return
    items = su.steps(await _facts(hass))
    admins = [u.name for u in await hass.auth.async_get_users() if u.is_active and not u.system_generated and _role(hass, u) in ("admin", "installer", "homeowner")]
    _audit(hass, connection.user, "handover_sheet", "view", "ok")
    connection.send_result(msg["id"], {
        "node": hass.config.location_name, "time_zone": hass.config.time_zone, "hub_version": core_version,
        "address": url, "qr_svg": _qr(url) if url else None, "api_docs": (url + "/api/sentinel_link/v1/docs") if url else None,
        "accounts": sorted(admins), "steps": items, "progress": su.progress(items),
        "note": "This sheet contains no passwords or tokens. Hand each person their own sign-in details separately."})


# ---------- cameras ----------
def _camera_rows(hass) -> list[dict[str, Any]]:
    from .ent_util import brand
    ereg, dreg, areg = er.async_get(hass), dr.async_get(hass), ar.async_get(hass)
    sens: list[dict[str, Any]] = []
    for eid in hass.states.async_entity_ids("binary_sensor"):
        e, s = ereg.async_get(eid), hass.states.get(eid)
        dc = s.attributes.get("device_class") if s else None
        if e is not None and dc in su.MOTION_CLASSES:
            sens.append({"entity_id": eid, "device_id": e.device_id, "device_class": dc,
                         "name": (s.attributes.get("friendly_name") if s else None) or eid, "state": s.state if s else "unknown"})
    out = []
    for eid in sorted(hass.states.async_entity_ids("camera")):
        s, e = hass.states.get(eid), ereg.async_get(eid)
        if s is None:
            continue
        area_id = (e.area_id if e else None) or (dreg.async_get(e.device_id).area_id if e and e.device_id and dreg.async_get(e.device_id) else None)
        label, level = su.camera_state_text(s.state)
        out.append({"entity_id": eid, "name": brand(s.attributes.get("friendly_name") or eid), "state": s.state, "label": label, "level": level,
                    "area_id": area_id, "area": areg.async_get_area(area_id).name if area_id and areg.async_get_area(area_id) else None,
                    "sensors": su.related_sensors(e.device_id if e else None, sens), "motion": s.attributes.get("motion_detection")})
    return out


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/camera_list"})
@websocket_api.async_response
@_cap("entities", "Not allowed to view cameras")
async def ws_camera_list(hass, connection, msg):
    areas = sorted(({"id": a.id, "name": a.name} for a in ar.async_get(hass).areas.values()), key=lambda x: x["name"].lower())
    connection.send_result(msg["id"], {"cameras": _camera_rows(hass), "areas": areas,
                                       "note": "Still images only. Live video is shown in the AINVR app."})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/camera_snapshot", vol.Required("entity_id"): str})
@websocket_api.async_response
@_cap("entities", "Not allowed to view cameras")
async def ws_camera_snapshot(hass, connection, msg):
    eid = msg["entity_id"]
    if not su.is_camera_id(eid) or hass.states.get(eid) is None:
        connection.send_error(msg["id"], "not_found", "Unknown camera")
        return
    try:
        from homeassistant.components.camera import async_get_image
        img = await async_get_image(hass, eid, timeout=8)
    except Exception:  # noqa: BLE001
        connection.send_error(msg["id"], "unavailable", "The camera did not answer")
        return
    if len(img.content) > MAX_IMAGE:
        connection.send_error(msg["id"], "too_large", "The image is too large to show here")
        return
    _audit(hass, connection.user, "camera_snapshot", eid, "ok")
    connection.send_result(msg["id"], {"content_type": img.content_type if img.content_type in ("image/jpeg", "image/png") else "image/jpeg",
                                       "data": base64.b64encode(img.content).decode()})


COMMANDS = (ws_setup_status, ws_handover, ws_camera_list, ws_camera_snapshot)
