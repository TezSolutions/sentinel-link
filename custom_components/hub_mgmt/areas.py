"""Hub Mgmt phase 2: areas, floors, labels and bulk assignment for the node portal.

Capability `areas` (admin, installer, homeowner). Every command validates its input (area_util), refuses duplicate
names, and writes to the shared audit trail. Deleting an area never touches Sentinel Link API settings; it reports
where they still mention it (see area_util.area_refs for why).
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.helpers import (
    area_registry as ar,
    device_registry as dr,
    entity_registry as er,
    floor_registry as fr,
    label_registry as lr,
)

from . import area_util as au
from .entities import NO_DEVICE, _audit, _cap, _ent_name, _role  # noqa: F401  (shared helpers)

_LOGGER = logging.getLogger(__name__)
_areas = _cap("areas", "Not allowed to manage areas")
NONE_AREA = "_none"


def _bad(connection, msg, err: Exception) -> None:
    connection.send_error(msg["id"], "invalid", str(err))


def _area_of_entity(e: er.RegistryEntry, dreg: dr.DeviceRegistry) -> str | None:
    if e.area_id:
        return e.area_id
    if e.device_id:
        d = dreg.async_get(e.device_id)
        return d.area_id if d else None
    return None


def _label_names(hass, ids) -> list[dict[str, Any]]:
    lreg = lr.async_get(hass)
    out = []
    for i in sorted(ids or ()):
        l = lreg.async_get_label(i)
        if l:
            out.append({"id": l.label_id, "name": l.name, "color": l.color})
    return out


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/area_overview"})
@_areas
def ws_area_overview(hass, connection, msg):
    areg, freg, lreg = ar.async_get(hass), fr.async_get(hass), lr.async_get(hass)
    dreg, ereg = dr.async_get(hass), er.async_get(hass)
    from . import _iter_devices
    dev_count: dict[str | None, int] = {}
    ent_states: dict[str | None, list] = {}
    for d in _iter_devices(dreg):
        if d.entry_type == dr.DeviceEntryType.SERVICE:
            continue
        dev_count[d.area_id] = dev_count.get(d.area_id, 0) + 1
    for e in ereg.entities.values():
        if e.disabled_by is not None or e.entity_id.split(".", 1)[0] in {"person", "zone", "device_tracker", "update"}:
            continue
        a = _area_of_entity(e, dreg)
        st = hass.states.get(e.entity_id)
        if st is not None:
            ent_states.setdefault(a, []).append((e.entity_id.split(".", 1)[0], st.state, st.last_changed.isoformat()))
    def card(a: ar.AreaEntry) -> dict[str, Any]:
        s = ent_states.get(a.id, [])
        return {"id": a.id, "name": a.name, "floor_id": a.floor_id, "icon": a.icon, "labels": _label_names(hass, a.labels),
                "devices": dev_count.get(a.id, 0), "entities": len(s), **au.activity(s)}
    floors = sorted(freg.floors.values(), key=lambda f: (f.level if f.level is not None else 999, f.name.casefold()))
    out = {
        "floors": [{"id": f.floor_id, "name": f.name, "level": f.level, "icon": f.icon} for f in floors],
        "areas": sorted((card(a) for a in areg.areas.values()), key=lambda a: a["name"].casefold()),
        "labels": [{"id": l.label_id, "name": l.name, "color": l.color, "icon": l.icon, "description": l.description}
                   for l in sorted(lreg.labels.values(), key=lambda l: l.name.casefold())],
        "unassigned": {"devices": dev_count.get(None, 0), "entities": len(ent_states.get(None, []))},
    }
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/area_detail", vol.Required("area_id"): str})
@_areas
def ws_area_detail(hass, connection, msg):
    areg, dreg, ereg = ar.async_get(hass), dr.async_get(hass), er.async_get(hass)
    from . import _iter_devices
    aid = msg["area_id"]
    area = None
    if aid != NONE_AREA:
        area = areg.async_get_area(aid)
        if area is None:
            connection.send_error(msg["id"], "not_found", "Unknown area")
            return
    want = None if aid == NONE_AREA else aid
    devices = []
    for d in _iter_devices(dreg):
        if d.entry_type == dr.DeviceEntryType.SERVICE or d.area_id != want:
            continue
        ents = er.async_entries_for_device(ereg, d.id)
        devices.append({"id": d.id, "name": d.name_by_user or d.name or "Device", "manufacturer": d.manufacturer, "model": d.model,
                        "available": any((hass.states.get(e.entity_id) or 0) and hass.states.get(e.entity_id).state != "unavailable" for e in ents) or not ents,
                        "entities": len(ents), "labels": _label_names(hass, d.labels)})
    devices.sort(key=lambda x: x["name"].casefold())
    loose = []
    for e in ereg.entities.values():
        if e.disabled_by is not None or e.entity_id.split(".", 1)[0] in {"person", "zone", "device_tracker", "update"}:
            continue
        # entities placed in this area directly (their own area), or helper entities with no device and no area
        direct = (e.area_id == want) if want else (e.area_id is None and e.device_id is None)
        if direct and (e.device_id is None or e.area_id is not None):
            st = hass.states.get(e.entity_id)
            loose.append({"entity_id": e.entity_id, "name": _ent_name(hass, e), "state": st.state if st else None, "labels": _label_names(hass, e.labels)})
    loose.sort(key=lambda x: x["name"].casefold())
    out = {"id": aid, "name": area.name if area else "Not in any area", "floor_id": area.floor_id if area else None,
           "icon": area.icon if area else None, "labels": _label_names(hass, area.labels) if area else [],
           "devices": devices[:500], "entities": loose[:500], "pseudo": area is None}
    connection.send_result(msg["id"], out)


def _check_floor(hass, connection, msg, floor_id) -> bool:
    if floor_id is not None and fr.async_get(hass).async_get_floor(floor_id) is None:
        connection.send_error(msg["id"], "not_found", "Unknown floor")
        return False
    return True


def _check_labels(hass, connection, msg, ids) -> bool:
    lreg = lr.async_get(hass)
    for i in ids:
        if lreg.async_get_label(i) is None:
            connection.send_error(msg["id"], "not_found", "Unknown label")
            return False
    return True


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/area_create", vol.Required("name"): str,
    vol.Optional("floor_id"): vol.Any(None, str), vol.Optional("icon"): vol.Any(None, str),
})
@_areas
def ws_area_create(hass, connection, msg):
    areg = ar.async_get(hass)
    try:
        name = au.clean_name(msg["name"], "Area name"); icon = au.clean_icon(msg.get("icon"))
    except au.Bad as err:
        return _bad(connection, msg, err)
    if au.name_taken(name, ((a.id, a.name) for a in areg.areas.values())):
        connection.send_error(msg["id"], "exists", "An area with that name already exists")
        return
    if not _check_floor(hass, connection, msg, msg.get("floor_id")):
        return
    a = areg.async_create(name, floor_id=msg.get("floor_id"), icon=icon)
    _audit(hass, connection.user, "area_create", a.id, "ok", {"name": name})
    connection.send_result(msg["id"], {"id": a.id})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/area_update", vol.Required("area_id"): str,
    vol.Optional("name"): str, vol.Optional("floor_id"): vol.Any(None, str), vol.Optional("icon"): vol.Any(None, str),
    vol.Optional("labels"): [str],
})
@_areas
def ws_area_update(hass, connection, msg):
    areg = ar.async_get(hass)
    cur = areg.async_get_area(msg["area_id"])
    if cur is None:
        connection.send_error(msg["id"], "not_found", "Unknown area")
        return
    kw: dict[str, Any] = {}
    try:
        if "name" in msg:
            kw["name"] = au.clean_name(msg["name"], "Area name")
            if au.name_taken(kw["name"], ((a.id, a.name) for a in areg.areas.values()), ignore_id=cur.id):
                connection.send_error(msg["id"], "exists", "An area with that name already exists")
                return
        if "icon" in msg:
            kw["icon"] = au.clean_icon(msg["icon"])
        if "labels" in msg:
            ids = au.clean_ids(msg["labels"], "labels")
            if not _check_labels(hass, connection, msg, ids):
                return
            kw["labels"] = set(ids)
    except au.Bad as err:
        return _bad(connection, msg, err)
    if "floor_id" in msg:
        if not _check_floor(hass, connection, msg, msg["floor_id"]):
            return
        kw["floor_id"] = msg["floor_id"]
    if kw:
        areg.async_update(cur.id, **kw)
        _audit(hass, connection.user, "area_update", cur.id, "ok", {k: str(v) for k, v in kw.items()})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/area_delete", vol.Required("area_id"): str,
    vol.Optional("move_to"): vol.Any(None, str), vol.Optional("dry_run", default=False): bool,
})
@_areas
def ws_area_delete(hass, connection, msg):
    areg, dreg, ereg = ar.async_get(hass), dr.async_get(hass), er.async_get(hass)
    from . import _iter_devices
    a = areg.async_get_area(msg["area_id"])
    if a is None:
        connection.send_error(msg["id"], "not_found", "Unknown area")
        return
    dest = msg.get("move_to")
    if dest is not None and (dest == a.id or areg.async_get_area(dest) is None):
        connection.send_error(msg["id"], "invalid", "Choose a different existing area to move things to")
        return
    devs = [d for d in _iter_devices(dreg) if d.area_id == a.id]
    ents = [e for e in ereg.entities.values() if e.area_id == a.id]
    refs: list[str] = []
    st = hass.data.get("sentinel_link_api")
    if st is not None:
        refs = au.area_refs(st.exposure, st.custom_roles, a.id)
    info = {"devices": len(devs), "entities": len(ents), "api_refs": refs}
    if msg["dry_run"]:
        connection.send_result(msg["id"], info)
        return
    for d in devs:
        dreg.async_update_device(d.id, area_id=dest)
    for e in ents:
        ereg.async_update_entity(e.entity_id, area_id=dest)
    areg.async_delete(a.id)
    _audit(hass, connection.user, "area_delete", a.id, "ok", {"name": a.name, **info, "moved_to": dest})
    connection.send_result(msg["id"], info)


def _floor_fields(connection, msg):
    try:
        out: dict[str, Any] = {}
        if "name" in msg:
            out["name"] = au.clean_name(msg["name"], "Floor name")
        if "level" in msg:
            out["level"] = au.clean_level(msg["level"])
        if "icon" in msg:
            out["icon"] = au.clean_icon(msg["icon"])
        return out
    except au.Bad as err:
        _bad(connection, msg, err)
        return None


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/floor_create", vol.Required("name"): str,
    vol.Optional("level"): vol.Any(None, int), vol.Optional("icon"): vol.Any(None, str),
})
@_areas
def ws_floor_create(hass, connection, msg):
    freg = fr.async_get(hass)
    kw = _floor_fields(connection, msg)
    if kw is None:
        return
    if au.name_taken(kw["name"], ((f.floor_id, f.name) for f in freg.floors.values())):
        connection.send_error(msg["id"], "exists", "A floor with that name already exists")
        return
    f = freg.async_create(kw["name"], level=kw.get("level"), icon=kw.get("icon"))
    _audit(hass, connection.user, "floor_create", f.floor_id, "ok", {"name": kw["name"]})
    connection.send_result(msg["id"], {"id": f.floor_id})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/floor_update", vol.Required("floor_id"): str,
    vol.Optional("name"): str, vol.Optional("level"): vol.Any(None, int), vol.Optional("icon"): vol.Any(None, str),
})
@_areas
def ws_floor_update(hass, connection, msg):
    freg = fr.async_get(hass)
    cur = freg.async_get_floor(msg["floor_id"])
    if cur is None:
        connection.send_error(msg["id"], "not_found", "Unknown floor")
        return
    kw = _floor_fields(connection, msg)
    if kw is None:
        return
    if "name" in kw and au.name_taken(kw["name"], ((f.floor_id, f.name) for f in freg.floors.values()), ignore_id=cur.floor_id):
        connection.send_error(msg["id"], "exists", "A floor with that name already exists")
        return
    if kw:
        freg.async_update(cur.floor_id, **kw)
        _audit(hass, connection.user, "floor_update", cur.floor_id, "ok", {k: str(v) for k, v in kw.items()})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/floor_delete", vol.Required("floor_id"): str})
@_areas
def ws_floor_delete(hass, connection, msg):
    freg, areg = fr.async_get(hass), ar.async_get(hass)
    f = freg.async_get_floor(msg["floor_id"])
    if f is None:
        connection.send_error(msg["id"], "not_found", "Unknown floor")
        return
    n = sum(1 for a in areg.areas.values() if a.floor_id == f.floor_id)
    freg.async_delete(f.floor_id)   # areas on it simply lose their floor
    _audit(hass, connection.user, "floor_delete", f.floor_id, "ok", {"name": f.name, "areas_unfloored": n})
    connection.send_result(msg["id"], {"areas_unfloored": n})


def _label_fields(connection, msg):
    try:
        out: dict[str, Any] = {}
        if "name" in msg:
            out["name"] = au.clean_name(msg["name"], "Label name")
        if "color" in msg:
            out["color"] = au.clean_color(msg["color"])
        if "icon" in msg:
            out["icon"] = au.clean_icon(msg["icon"])
        if "description" in msg:
            d = msg["description"]
            if d is not None and (not isinstance(d, str) or len(d) > 200):
                raise au.Bad("Description is too long (max 200)")
            out["description"] = d or None
        return out
    except au.Bad as err:
        _bad(connection, msg, err)
        return None


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/label_create", vol.Required("name"): str,
    vol.Optional("color"): vol.Any(None, str), vol.Optional("icon"): vol.Any(None, str), vol.Optional("description"): vol.Any(None, str),
})
@_areas
def ws_label_create(hass, connection, msg):
    lreg = lr.async_get(hass)
    kw = _label_fields(connection, msg)
    if kw is None:
        return
    if au.name_taken(kw["name"], ((l.label_id, l.name) for l in lreg.labels.values())):
        connection.send_error(msg["id"], "exists", "A label with that name already exists")
        return
    l = lreg.async_create(kw.pop("name"), **kw)
    _audit(hass, connection.user, "label_create", l.label_id, "ok", {"name": l.name})
    connection.send_result(msg["id"], {"id": l.label_id})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/label_update", vol.Required("label_id"): str,
    vol.Optional("name"): str, vol.Optional("color"): vol.Any(None, str), vol.Optional("icon"): vol.Any(None, str),
    vol.Optional("description"): vol.Any(None, str),
})
@_areas
def ws_label_update(hass, connection, msg):
    lreg = lr.async_get(hass)
    cur = lreg.async_get_label(msg["label_id"])
    if cur is None:
        connection.send_error(msg["id"], "not_found", "Unknown label")
        return
    kw = _label_fields(connection, msg)
    if kw is None:
        return
    if "name" in kw and au.name_taken(kw["name"], ((l.label_id, l.name) for l in lreg.labels.values()), ignore_id=cur.label_id):
        connection.send_error(msg["id"], "exists", "A label with that name already exists")
        return
    if kw:
        lreg.async_update(cur.label_id, **kw)
        _audit(hass, connection.user, "label_update", cur.label_id, "ok", {k: str(v) for k, v in kw.items()})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/label_delete", vol.Required("label_id"): str})
@_areas
def ws_label_delete(hass, connection, msg):
    lreg = lr.async_get(hass)
    l = lreg.async_get_label(msg["label_id"])
    if l is None:
        connection.send_error(msg["id"], "not_found", "Unknown label")
        return
    lreg.async_delete(l.label_id)
    _audit(hass, connection.user, "label_delete", l.label_id, "ok", {"name": l.name})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/bulk_assign",
    vol.Optional("device_ids"): list, vol.Optional("entity_ids"): list,
    vol.Optional("area_id"): vol.Any(None, str),
    vol.Optional("add_labels"): list, vol.Optional("remove_labels"): list,
})
@_areas
def ws_bulk_assign(hass, connection, msg):
    """Move devices/entities to an area (area_id null = unassign) and/or add/remove labels. All-or-nothing validation
    first (unknown ids reject the whole request), then apply."""
    dreg, ereg, areg = dr.async_get(hass), er.async_get(hass), ar.async_get(hass)
    try:
        dids = au.clean_ids(msg.get("device_ids"), "devices")
        eids = au.clean_ids(msg.get("entity_ids"), "entities")
        add = au.clean_ids(msg.get("add_labels"), "labels")
        rem = au.clean_ids(msg.get("remove_labels"), "labels")
    except au.Bad as err:
        return _bad(connection, msg, err)
    if not dids and not eids:
        connection.send_error(msg["id"], "invalid", "Nothing selected")
        return
    if "area_id" not in msg and not add and not rem:
        connection.send_error(msg["id"], "invalid", "Choose an area or a label change")
        return
    if "area_id" in msg and msg["area_id"] is not None and areg.async_get_area(msg["area_id"]) is None:
        connection.send_error(msg["id"], "not_found", "Unknown area")
        return
    if not _check_labels(hass, connection, msg, add + rem):
        return
    devs = [dreg.async_get(i) for i in dids]
    ents = [ereg.async_get(i) for i in eids]
    if any(d is None or d.entry_type == dr.DeviceEntryType.SERVICE for d in devs) or any(e is None for e in ents):
        connection.send_error(msg["id"], "not_found", "One of the selected items no longer exists")
        return
    role = _role(hass, connection.user)
    from . import ent_util as eu
    if any(e.entity_id.split(".", 1)[0] in eu.HARD_DENY_DOMAINS for e in ents) and role not in ("admin", "superadmin"):
        connection.send_error(msg["id"], "forbidden", "Only an administrator can change those entities")
        return
    for d in devs:
        kw: dict[str, Any] = {}
        if "area_id" in msg:
            kw["area_id"] = msg["area_id"]
        if add or rem:
            kw["labels"] = (set(d.labels) | set(add)) - set(rem)
        dreg.async_update_device(d.id, **kw)
    for e in ents:
        kw = {}
        if "area_id" in msg:
            kw["area_id"] = msg["area_id"]
        if add or rem:
            kw["labels"] = (set(e.labels) | set(add)) - set(rem)
        ereg.async_update_entity(e.entity_id, **kw)
    _audit(hass, connection.user, "bulk_assign", f"{len(devs)} devices, {len(ents)} entities", "ok",
           {"area_id": msg.get("area_id", "unchanged"), "add": add, "remove": rem})
    connection.send_result(msg["id"], {"devices": len(devs), "entities": len(ents)})


COMMANDS = (ws_area_overview, ws_area_detail, ws_area_create, ws_area_update, ws_area_delete,
            ws_floor_create, ws_floor_update, ws_floor_delete,
            ws_label_create, ws_label_update, ws_label_delete, ws_bulk_assign)
