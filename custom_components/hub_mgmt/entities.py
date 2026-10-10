"""Hub Mgmt phase 1: device pages and entity settings/control for the node portal.

Every command re-checks the caller's capability (hub_mgmt CAPS) server-side. Entity control reuses the Sentinel Link
command allowlist (sentinel_link/api/commands.py) so the portal and the third-party API accept exactly the same
commands and fields; nothing here forwards an arbitrary service call.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import (
    area_registry as ar,
    device_registry as dr,
    entity_registry as er,
)
from homeassistant.util import dt as dt_util

from . import ent_util as eu

DOMAIN = "hub_mgmt"
_LOGGER = logging.getLogger(__name__)


def _cap(cap: str, message: str):
    """Decorator: the caller needs capability `cap` (looked up live in the parent module)."""

    def deco(fn):
        import inspect
        from functools import wraps

        def ok(hass, connection, msg) -> bool:
            from . import _has_cap
            if _has_cap(hass, connection.user, cap):
                return True
            connection.send_error(msg["id"], "unauthorized", message)
            return False

        if inspect.iscoroutinefunction(fn):
            @wraps(fn)
            async def aw(hass, connection, msg):
                if ok(hass, connection, msg):
                    await fn(hass, connection, msg)
            return aw

        @wraps(fn)
        def w(hass, connection, msg):
            if ok(hass, connection, msg):
                return fn(hass, connection, msg)
        return w

    return deco


_entities = _cap("entities", "Not allowed to use devices and entities")
_devices = _cap("devices", "Not an installer user")


def _role(hass, user) -> str:
    from . import _role as r
    return r(hass, user)


def _integration(hass: HomeAssistant, dev: dr.DeviceEntry) -> str:
    for cid in dev.config_entries:
        ent = hass.config_entries.async_get_entry(cid)
        if ent is not None:
            return ent.domain
    return "other"


def _ent_name(hass: HomeAssistant, e: er.RegistryEntry) -> str:
    st = hass.states.get(e.entity_id)
    return (e.name or (st.attributes.get("friendly_name") if st else None) or e.original_name or e.entity_id)


def _device_row(hass: HomeAssistant, dev: dr.DeviceEntry, ereg: er.EntityRegistry, areg: ar.AreaRegistry) -> dict[str, Any]:
    ents = er.async_entries_for_device(ereg, dev.id, include_disabled_entities=True)
    live = [e for e in ents if not e.disabled]
    unavailable = bool(live)
    battery = None
    for e in live:
        st = hass.states.get(e.entity_id)
        if st is None:
            continue
        if st.state not in ("unavailable",):
            unavailable = False
        if e.original_device_class == "battery" or st.attributes.get("device_class") == "battery":
            try:
                battery = float(st.state)
            except ValueError:
                pass
    area = areg.async_get_area(dev.area_id) if dev.area_id else None
    return {
        "id": dev.id,
        "name": eu.brand(dev.name_by_user or dev.name or "Device"),
        "default_name": eu.brand(dev.name),
        "manufacturer": eu.brand(dev.manufacturer),
        "model": dev.model,
        "sw_version": dev.sw_version,
        "hw_version": dev.hw_version,
        "integration": _integration(hass, dev),
        "area_id": dev.area_id,
        "area": area.name if area else None,
        "entities": len(ents),
        "available": not unavailable,
        "disabled": dev.disabled_by is not None,
        "battery": battery,
        "via": dev.via_device_id,
    }


NO_DEVICE = "_none"   # pseudo device id: entities that belong to no device (helpers, template entities, ...)


def _loose_entities(ereg: er.EntityRegistry) -> list[er.RegistryEntry]:
    return [e for e in ereg.entities.values()
            if e.device_id is None and e.entity_id.split(".", 1)[0] not in eu.HARD_DENY_DOMAINS and e.platform != "sun"]


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/device_list"})
@_entities
def ws_device_list(hass, connection, msg):
    dreg, ereg, areg = dr.async_get(hass), er.async_get(hass), ar.async_get(hass)
    from . import _iter_devices
    rows = [
        _device_row(hass, d, ereg, areg)
        for d in _iter_devices(dreg)
        if d.entry_type != dr.DeviceEntryType.SERVICE
    ]
    rows.sort(key=lambda r: (r["name"] or "").lower())
    loose = _loose_entities(ereg)
    if loose:
        rows.insert(0, {"id": NO_DEVICE, "name": "Entities without a device", "default_name": None, "manufacturer": None,
                        "model": "Helpers, templates and groups", "sw_version": None, "hw_version": None,
                        "integration": "helpers", "area_id": None, "area": None, "entities": len(loose),
                        "available": True, "disabled": False, "battery": None, "via": None})
    connection.send_result(msg["id"], rows)


def _entity_row(hass: HomeAssistant, e: er.RegistryEntry, role: str) -> dict[str, Any]:
    st = hass.states.get(e.entity_id)
    domain = e.entity_id.split(".", 1)[0]
    ok, _ = eu.control_allowed(role, domain, e.platform)
    from .api_bridge import commands_for
    cmds = commands_for(domain) if ok and st is not None else []
    return {
        "entity_id": e.entity_id,
        "name": _ent_name(hass, e),
        "domain": domain,
        "platform": e.platform,
        "state": st.state if st else None,
        "attrs": eu.clip_attrs(st.attributes) if st else {},
        "ctl": eu.control_attrs(st.attributes) if st else {},
        "unit": (st.attributes.get("unit_of_measurement") if st else None) or e.unit_of_measurement,
        "device_class": (st.attributes.get("device_class") if st else None) or e.original_device_class,
        "icon": e.icon,
        "hidden": e.hidden_by is not None,
        "disabled": e.disabled_by is not None,
        "category": e.entity_category.value if e.entity_category else None,
        "commands": [c for c in cmds if c != "snapshot"],
        "changed": st.last_changed.isoformat() if st else None,
    }


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/device_detail", vol.Required("device_id"): str})
@_entities
def ws_device_detail(hass, connection, msg):
    dreg, ereg, areg = dr.async_get(hass), er.async_get(hass), ar.async_get(hass)
    role = _role(hass, connection.user)
    if msg["device_id"] == NO_DEVICE:
        loose = _loose_entities(ereg)
        connection.send_result(msg["id"], {
            "id": NO_DEVICE, "name": "Entities without a device", "manufacturer": None, "model": "Helpers, templates and groups",
            "integration": "helpers", "sw_version": None, "hw_version": None, "area_id": None, "area": None, "entities": len(loose),
            "available": True, "disabled": False, "battery": None, "serial": None, "connections": [], "config_entry_titles": [],
            "removable": False, "pseudo": True,
            "entity_list": sorted((_entity_row(hass, e, role) for e in loose), key=lambda r: (r["disabled"], r["domain"], r["name"].lower()))})
        return
    dev = dreg.async_get(msg["device_id"])
    if dev is None or dev.entry_type == dr.DeviceEntryType.SERVICE:
        connection.send_error(msg["id"], "not_found", "Unknown device")
        return
    row = _device_row(hass, dev, ereg, areg)
    row["serial"] = None  # never exposed
    row["connections"] = sorted({c[0] for c in dev.connections})
    row["config_entry_titles"] = [
        e.title for e in (hass.config_entries.async_get_entry(c) for c in dev.config_entries) if e is not None
    ]
    ents = er.async_entries_for_device(ereg, dev.id, include_disabled_entities=True)
    row["entity_list"] = sorted(
        (_entity_row(hass, e, role) for e in ents),
        key=lambda r: (r["disabled"], r["category"] is not None, r["domain"], r["name"].lower()),
    )
    row["removable"] = _removable(dev)
    connection.send_result(msg["id"], row)


def _removable(dev: dr.DeviceEntry) -> bool:
    try:
        from . import _removable_kind
        return _removable_kind(dev) is not None
    except Exception:  # noqa: BLE001
        return False


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/device_states", vol.Required("device_id"): str})
@_entities
def ws_device_states(hass, connection, msg):
    """Light-weight poll for the open device page: state + control attributes per entity."""
    ereg = er.async_get(hass)
    out = {}
    ents = _loose_entities(ereg) if msg["device_id"] == NO_DEVICE else er.async_entries_for_device(ereg, msg["device_id"])
    for e in ents:
        st = hass.states.get(e.entity_id)
        if st is not None:
            out[e.entity_id] = {"state": st.state, "ctl": eu.control_attrs(st.attributes),
                                "attrs": eu.clip_attrs(st.attributes), "changed": st.last_changed.isoformat()}
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/entity_update",
    vol.Required("entity_id"): str,
    vol.Optional("name"): vol.Any(None, vol.All(str, vol.Length(max=80))),
    vol.Optional("icon"): vol.Any(None, vol.All(str, vol.Length(max=60))),
    vol.Optional("hidden"): bool,
    vol.Optional("disabled"): bool,
    vol.Optional("area_id"): vol.Any(None, str),
})
@_entities
def ws_entity_update(hass, connection, msg):
    ereg = er.async_get(hass)
    ent = ereg.async_get(msg["entity_id"])
    if ent is None:
        connection.send_error(msg["id"], "not_found", "Unknown entity")
        return
    domain = ent.entity_id.split(".", 1)[0]
    if domain in eu.HARD_DENY_DOMAINS and _role(hass, connection.user) != "admin":
        connection.send_error(msg["id"], "forbidden", "Only an administrator can change this entity")
        return
    kw: dict[str, Any] = {}
    if "name" in msg:
        kw["name"] = (msg["name"] or "").strip() or None
    if "icon" in msg:
        kw["icon"] = msg["icon"] or None
    if "hidden" in msg:
        kw["hidden_by"] = er.RegistryEntryHider.USER if msg["hidden"] else None
    if "disabled" in msg:
        kw["disabled_by"] = er.RegistryEntryDisabler.USER if msg["disabled"] else None
    if "area_id" in msg:
        if msg["area_id"] is not None and ar.async_get(hass).async_get_area(msg["area_id"]) is None:
            connection.send_error(msg["id"], "not_found", "Unknown area")
            return
        kw["area_id"] = msg["area_id"]
    if not kw:
        connection.send_result(msg["id"], {"ok": True})
        return
    ereg.async_update_entity(msg["entity_id"], **kw)
    _audit(hass, connection.user, "entity_update", msg["entity_id"], "ok", {k: str(v) for k, v in kw.items()})
    connection.send_result(msg["id"], {"ok": True, "reload_note": "Enabling or disabling can take up to 30 seconds to apply."})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/entity_control",
    vol.Required("entity_id"): str,
    vol.Required("command"): str,
    vol.Optional("data"): dict,
})
@websocket_api.async_response
@_entities
async def ws_entity_control(hass, connection, msg):
    from .api_bridge import validate, CommandError
    eid = msg["entity_id"]
    ereg = er.async_get(hass)
    ent = ereg.async_get(eid)
    domain = eid.split(".", 1)[0]
    role = _role(hass, connection.user)
    ok, why = eu.control_allowed(role, domain, ent.platform if ent else None)
    if not ok:
        _audit(hass, connection.user, "entity_control", eid, "denied", {"command": msg["command"]})
        connection.send_error(msg["id"], "forbidden", why)
        return
    if hass.states.get(eid) is None:
        connection.send_error(msg["id"], "not_found", "That entity is not available")
        return
    try:
        service, data = validate(domain, msg["command"], msg.get("data"))
    except CommandError as err:
        connection.send_error(msg["id"], err.code, err.message)
        return
    try:
        await hass.services.async_call(domain, service, {**data, "entity_id": eid}, blocking=True)
    except Exception as err:  # noqa: BLE001
        _audit(hass, connection.user, "entity_control", eid, "error", {"command": msg["command"]})
        connection.send_error(msg["id"], "failed", f"The device did not accept the command ({type(err).__name__})")
        return
    _audit(hass, connection.user, "entity_control", eid, "ok", {"command": msg["command"], "data": data})
    st = hass.states.get(eid)
    connection.send_result(msg["id"], {"ok": True, "state": st.state if st else None})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/entity_history",
    vol.Required("entity_id"): str,
    vol.Optional("hours", default=24): vol.All(int, vol.Range(min=1, max=168)),
})
@websocket_api.async_response
@_entities
async def ws_entity_history(hass, connection, msg):
    eid = msg["entity_id"]
    if er.async_get(hass).async_get(eid) is None and hass.states.get(eid) is None:
        connection.send_error(msg["id"], "not_found", "Unknown entity")
        return
    try:
        from homeassistant.components.recorder import get_instance, history
    except Exception:  # noqa: BLE001
        connection.send_result(msg["id"], {"kind": "none", "points": []})
        return
    end = dt_util.utcnow()
    start = end - timedelta(hours=msg["hours"])

    def _query():
        return history.get_significant_states(
            hass, start, end, [eid], include_start_time_state=True,
            significant_changes_only=False, minimal_response=True, no_attributes=True)

    try:
        res = await get_instance(hass).async_add_executor_job(_query)
    except Exception:  # noqa: BLE001
        connection.send_result(msg["id"], {"kind": "none", "points": []})
        return
    rows: list[tuple[float, str]] = []
    for item in res.get(eid, []):
        if isinstance(item, dict):
            state, ts = item.get("state"), item.get("last_changed") or item.get("last_updated")
        else:
            state, ts = item.state, item.last_changed
        if isinstance(ts, str):
            ts = dt_util.parse_datetime(ts)
        if isinstance(ts, (int, float)):
            rows.append((float(ts), state))
        elif isinstance(ts, datetime):
            rows.append((ts.timestamp(), state))
    out = eu.history_points(rows)
    out["hours"] = msg["hours"]
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/device_diagnostics", vol.Required("device_id"): str})
@_devices
def ws_device_diagnostics(hass, connection, msg):
    """Support bundle for one device: registry data + entity states. No credentials, no serial numbers."""
    dreg, ereg, areg = dr.async_get(hass), er.async_get(hass), ar.async_get(hass)
    dev = dreg.async_get(msg["device_id"])
    if dev is None:
        connection.send_error(msg["id"], "not_found", "Unknown device")
        return
    role = _role(hass, connection.user)
    row = _device_row(hass, dev, ereg, areg)
    row["connections"] = sorted({c[0] for c in dev.connections})
    row["identifiers"] = sorted({i[0] for i in dev.identifiers})
    row["config_entries"] = [
        {"domain": e.domain, "title": e.title, "state": str(e.state.value)}
        for e in (hass.config_entries.async_get_entry(c) for c in dev.config_entries) if e is not None
    ]
    row["entity_list"] = [
        {k: v for k, v in _entity_row(hass, e, role).items() if k not in ("ctl", "commands")}
        for e in er.async_entries_for_device(ereg, dev.id, include_disabled_entities=True)
    ]
    row["generated"] = dt_util.utcnow().isoformat()
    connection.send_result(msg["id"], row)


def _audit(hass, user, action: str, target: str, result: str, data: Any = None) -> None:
    """Best effort: write into the Sentinel Link audit trail so the portal and the API share one history."""
    try:
        st = hass.data.get("sentinel_link_api")
        if st is not None:
            st.log(user, f"portal:{_role(hass, user)}", action, target, result, data)
    except Exception:  # noqa: BLE001
        _LOGGER.debug("audit write failed", exc_info=True)


COMMANDS = (ws_device_list, ws_device_detail, ws_device_states, ws_entity_update, ws_entity_control,
            ws_entity_history, ws_device_diagnostics)
