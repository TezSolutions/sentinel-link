"""Hub Mgmt phase 4: integrations (curated add, reconfigure, health, reload, remove) for the node portal.

Capability `integrations` (admin, installer). Rules: only catalog domains can be started; a client may only continue or
abort flows it started itself (or discovered ones, exactly like the existing Hub Mgmt panel); user input is bounded;
protected integrations (the product's own plumbing) can never be removed here; error text is scrubbed of credentials;
every action is audited. Flow results never echo the saved credentials back (`_prepare` strips `data`).
"""
from __future__ import annotations

import logging
import time
from typing import Any

import voluptuous as vol

from homeassistant import data_entry_flow
from homeassistant.components import websocket_api
from homeassistant.helpers import device_registry as dr, entity_registry as er

from . import integ_util as iu
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_integ = _cap("integrations", "Not allowed to manage integrations")
MAX_OWN_FLOWS = 20


def _own(hass) -> dict[str, dict[str, Any]]:
    d = hass.data.setdefault("hub_mgmt_portal_flows", {})
    now = time.time()
    for k in [k for k, v in d.items() if v["exp"] < now]:
        d.pop(k, None)
    return d


def _flow_alive(hass, flow_id: str) -> bool:
    return any(f["flow_id"] == flow_id for f in hass.config_entries.flow.async_progress())


def _allowed_flow(hass, connection, flow_id: str) -> bool:
    """Flows this user started, or discovered flows (same trust level as the existing Hub Mgmt panel)."""
    from . import _is_discovered
    own = _own(hass).get(flow_id)
    if own is not None:
        return own["user"] == connection.user.id
    return _is_discovered(hass, flow_id)


def _reauth_entries(hass) -> set[str]:
    out = set()
    for f in hass.config_entries.flow.async_progress():
        ctx = f.get("context") or {}
        if ctx.get("source") == "reauth" and ctx.get("entry_id"):
            out.add(ctx["entry_id"])
    return out


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_overview"})
@websocket_api.async_response
@_integ
async def ws_integ_overview(hass, connection, msg):
    from . import _flow_summary, HIDDEN_SOURCES
    dreg, ereg = dr.async_get(hass), er.async_get(hass)
    reauth = _reauth_entries(hass)
    entries, counts = [], {}
    for e in hass.config_entries.async_entries():
        if e.source in ("ignore", "system") or e.domain in iu.HIDDEN_DOMAINS:
            continue
        nd = len(dr.async_entries_for_config_entry(dreg, e.entry_id))
        ne = len(er.async_entries_for_config_entry(ereg, e.entry_id))
        counts[e.domain] = counts.get(e.domain, 0) + 1
        entries.append(iu.entry_view(e.domain, e.title, e.state.value, getattr(e, "reason", None), e.entry_id in reauth, nd, ne,
                                     bool(getattr(e, "supports_reconfigure", False)), e.entry_id, e.source, e.disabled_by is not None))
    entries.sort(key=lambda x: ({"bad": 0, "warn": 1, "info": 2, "ok": 3}[x["health"]["level"]], x["name"].casefold(), x["title"].casefold()))
    disc = [_flow_summary(f) for f in hass.config_entries.flow.async_progress() if f["context"].get("source") not in HIDDEN_SOURCES and f["context"].get("source") != "reauth"]
    connection.send_result(msg["id"], {"entries": entries, "catalog": iu.catalog_view(counts), "discovered": disc,
                                       "attention": sum(1 for x in entries if not x["health"]["ok"] and x["health"]["level"] in ("bad", "warn"))})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_flow_start", vol.Required("domain"): str, vol.Optional("entry_id"): str})
@websocket_api.async_response
@_integ
async def ws_integ_flow_start(hass, connection, msg):
    from . import _prepare
    dom = msg["domain"]
    entry = None
    if msg.get("entry_id"):
        entry = hass.config_entries.async_get_entry(msg["entry_id"])
        if entry is None or entry.domain != dom:
            connection.send_error(msg["id"], "not_found", "Unknown integration")
            return
        if not iu.can_reconfigure(dom, bool(getattr(entry, "supports_reconfigure", False))):
            connection.send_error(msg["id"], "forbidden", "This integration cannot be reconfigured here")
            return
        ctx = {"source": "reconfigure", "entry_id": entry.entry_id}
    else:
        if dom not in iu.CATALOG_BY_DOMAIN:
            connection.send_error(msg["id"], "forbidden", "That integration is not in the list")
            return
        ctx = {"source": "user"}
    own = _own(hass)
    mine = [k for k, v in own.items() if v["user"] == connection.user.id]
    if len(mine) >= MAX_OWN_FLOWS:
        connection.send_error(msg["id"], "busy", "Finish or cancel your open setups first")
        return
    try:
        res = await hass.config_entries.flow.async_init(dom, context=ctx)
    except data_entry_flow.UnknownHandler:
        connection.send_error(msg["id"], "unavailable", "This integration is not available on this node")
        return
    except Exception as err:  # noqa: BLE001
        connection.send_error(msg["id"], "flow_error", iu.clean_reason(err) or "Could not start")
        return
    if res.get("flow_id") and res["type"] in (data_entry_flow.FlowResultType.FORM, data_entry_flow.FlowResultType.MENU,
                                               data_entry_flow.FlowResultType.EXTERNAL_STEP, data_entry_flow.FlowResultType.SHOW_PROGRESS):
        own[res["flow_id"]] = {"user": connection.user.id, "domain": dom, "exp": time.time() + 1800}
    _audit(hass, connection.user, "integ_flow_start", dom, "ok", {"reconfigure": bool(entry)})
    out = _prepare(res)
    out["domain"] = dom
    if res["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY:
        _audit(hass, connection.user, "integ_added", dom, "ok")
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/integ_flow_step", vol.Required("flow_id"): str, vol.Optional("user_input"): vol.Any(dict, None),
})
@websocket_api.async_response
@_integ
async def ws_integ_flow_step(hass, connection, msg):
    from . import _prepare
    fid = msg["flow_id"]
    if not _allowed_flow(hass, connection, fid):
        connection.send_error(msg["id"], "forbidden", "Not your setup")
        return
    try:
        ui = iu.clean_user_input(msg.get("user_input"))
    except ValueError as err:
        connection.send_error(msg["id"], "invalid", str(err))
        return
    try:
        res = await hass.config_entries.flow.async_configure(fid, ui)
    except data_entry_flow.UnknownFlow:
        _own(hass).pop(fid, None)
        connection.send_error(msg["id"], "not_found", "That setup has expired. Start again")
        return
    except Exception as err:  # noqa: BLE001
        connection.send_error(msg["id"], "flow_error", iu.clean_reason(err) or "Something went wrong")
        return
    dom = (_own(hass).get(fid) or {}).get("domain") or str(res.get("handler") or "")
    if res["type"] in (data_entry_flow.FlowResultType.CREATE_ENTRY, data_entry_flow.FlowResultType.ABORT):
        _own(hass).pop(fid, None)
        if res["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY:
            _audit(hass, connection.user, "integ_added", dom, "ok")
    out = _prepare(res)
    out["domain"] = dom
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_flow_abort", vol.Required("flow_id"): str})
@websocket_api.async_response
@_integ
async def ws_integ_flow_abort(hass, connection, msg):
    fid = msg["flow_id"]
    if not _allowed_flow(hass, connection, fid):
        connection.send_error(msg["id"], "forbidden", "Not your setup")
        return
    try:
        hass.config_entries.flow.async_abort(fid)
    except data_entry_flow.UnknownFlow:
        pass
    _own(hass).pop(fid, None)
    connection.send_result(msg["id"], {"ok": True})


def _entry_or_err(hass, connection, msg):
    e = hass.config_entries.async_get_entry(msg["entry_id"])
    if e is None:
        connection.send_error(msg["id"], "not_found", "Unknown integration")
    return e


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_reload", vol.Required("entry_id"): str})
@websocket_api.async_response
@_integ
async def ws_integ_reload(hass, connection, msg):
    e = _entry_or_err(hass, connection, msg)
    if e is None:
        return
    if not iu.can_reload(e.domain) or e.disabled_by is not None:
        connection.send_error(msg["id"], "forbidden", "This integration cannot be restarted here")
        return
    try:
        ok = await hass.config_entries.async_reload(e.entry_id)
    except Exception as err:  # noqa: BLE001
        _audit(hass, connection.user, "integ_reload", e.domain, "error")
        connection.send_error(msg["id"], "reload_failed", iu.clean_reason(err) or "Could not restart")
        return
    _audit(hass, connection.user, "integ_reload", e.domain, "ok" if ok else "error")
    connection.send_result(msg["id"], {"ok": bool(ok), "state": e.state.value, "reason": iu.clean_reason(getattr(e, "reason", None))})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_remove", vol.Required("entry_id"): str, vol.Optional("dry_run", default=False): bool})
@websocket_api.async_response
@_integ
async def ws_integ_remove(hass, connection, msg):
    e = _entry_or_err(hass, connection, msg)
    if e is None:
        return
    if not iu.can_remove(e.domain):
        connection.send_error(msg["id"], "forbidden", "This integration is part of the system and cannot be removed here")
        return
    dreg, ereg = dr.async_get(hass), er.async_get(hass)
    info = {"devices": len(dr.async_entries_for_config_entry(dreg, e.entry_id)),
            "entities": len(er.async_entries_for_config_entry(ereg, e.entry_id)), "name": e.title[:80]}
    if msg["dry_run"]:
        connection.send_result(msg["id"], info)
        return
    dom, title = e.domain, e.title
    try:
        await hass.config_entries.async_remove(e.entry_id)
    except Exception as err:  # noqa: BLE001
        connection.send_error(msg["id"], "remove_failed", iu.clean_reason(err) or "Could not remove")
        return
    _audit(hass, connection.user, "integ_remove", dom, "ok", {"title": title, **{k: v for k, v in info.items() if k != "name"}})
    connection.send_result(msg["id"], info)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/integ_set_disabled", vol.Required("entry_id"): str, vol.Required("disabled"): bool})
@websocket_api.async_response
@_integ
async def ws_integ_set_disabled(hass, connection, msg):
    from homeassistant.config_entries import ConfigEntryDisabler
    e = _entry_or_err(hass, connection, msg)
    if e is None:
        return
    if not iu.can_remove(e.domain):
        connection.send_error(msg["id"], "forbidden", "This integration is part of the system and cannot be switched off here")
        return
    await hass.config_entries.async_set_disabled_by(e.entry_id, ConfigEntryDisabler.USER if msg["disabled"] else None)
    _audit(hass, connection.user, "integ_disable" if msg["disabled"] else "integ_enable", e.domain, "ok")
    connection.send_result(msg["id"], {"ok": True})


COMMANDS = (ws_integ_overview, ws_integ_flow_start, ws_integ_flow_step, ws_integ_flow_abort, ws_integ_reload, ws_integ_remove,
            ws_integ_set_disabled)
