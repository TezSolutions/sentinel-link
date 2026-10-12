"""Hub Mgmt: sign-in history commands for the node portal (capability `logins`: every role that can open the portal).

What a caller gets is decided in `login_log.py` (homeowner/admin/vendor: everybody; everyone else: only their own; the vendor
appears to others as "Tez Solutions support").  Settings (retention, which alerts, extra notify services) can be changed by the
homeowner and the administrator ONLY - the vendor account can read them but never weaken them.
Nothing here can edit or delete an entry.
"""
from __future__ import annotations

import ipaddress
import logging

import voluptuous as vol

from homeassistant.components import websocket_api

from . import login_log as ll
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_logins = _cap("logins", "Sign in first")
SETTINGS_ROLES = ("homeowner", "admin")


def _svc(hass):
    return hass.data["hub_mgmt"].get("logins")


def _role(hass, user):
    from . import _role as r
    return r(hass, user)


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/login_list",
    vol.Optional("user"): vol.All(str, vol.Length(max=80)), vol.Optional("door"): vol.In(ll.DOORS), vol.Optional("outcome"): vol.In(ll.OUTCOMES),
    vol.Optional("since"): vol.Coerce(float), vol.Optional("until"): vol.Coerce(float), vol.Optional("alerts_only", default=False): bool,
    vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=1000)), vol.Optional("before"): int})
@websocket_api.async_response
@_logins
async def ws_login_list(hass, connection, msg):
    s = _svc(hass)
    if s is None:
        connection.send_error(msg["id"], "unavailable", "Sign-in history is not available")
        return
    u = connection.user
    q = {k: msg[k] for k in ("user", "door", "outcome", "since", "until", "before") if k in msg}
    connection.send_result(msg["id"], s.log.query(u.id, _role(hass, u), None, alerts_only=msg["alerts_only"], limit=msg["limit"], **q))


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/login_summary"})
@websocket_api.async_response
@_logins
async def ws_login_summary(hass, connection, msg):
    s = _svc(hass)
    if s is None:
        connection.send_error(msg["id"], "unavailable", "Sign-in history is not available")
        return
    u = connection.user
    connection.send_result(msg["id"], s.log.summary(u.id, _role(hass, u)))


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/login_settings"})
@websocket_api.async_response
@_logins
async def ws_login_settings(hass, connection, msg):
    s = _svc(hass)
    role = _role(hass, connection.user)
    if s is None or role not in ll.FULL_ROLES:
        connection.send_error(msg["id"], "unauthorized", "Not allowed")
        return
    connection.send_result(msg["id"], {**s.log.settings, "min_retention_days": ll.MIN_RETENTION_DAYS, "can_change": role in SETTINGS_ROLES})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/login_settings_save", vol.Required("values"): dict})
@websocket_api.async_response
@_logins
async def ws_login_settings_save(hass, connection, msg):
    s = _svc(hass)
    role = _role(hass, connection.user)
    if s is None or role not in SETTINGS_ROLES:
        connection.send_error(msg["id"], "unauthorized", "Only the home owner and the administrator can change these settings")
        return
    st, errs = s.log.set_settings(msg["values"])
    if errs:
        connection.send_error(msg["id"], "invalid", "; ".join(errs))
        return
    s._save()
    _audit(hass, connection.user, "login_settings", ",".join(sorted(msg["values"])), "ok")
    connection.send_result(msg["id"], {**st, "min_retention_days": ll.MIN_RETENTION_DAYS, "can_change": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/login_note", vol.Required("what"): vol.In(("support_bundle",)),
                                  vol.Required("ip"): vol.All(str, vol.Length(max=45)), vol.Optional("ua", default=""): vol.All(str, vol.Length(max=300))})
@websocket_api.async_response
@_logins
async def ws_login_note(hass, connection, msg):
    """Portal-only: the node portal reports a support-file download (it knows the real client address; the browser cannot call this)."""
    s = _svc(hass)
    try:
        ipaddress.ip_address(msg["ip"])
        ok_ip = msg["ip"]
    except ValueError:
        ok_ip = None
    if s is None or not _has_debug(hass, connection.user):
        connection.send_error(msg["id"], "unauthorized", "Not allowed")
        return
    await s.record(user=connection.user, door="portal", outcome="downloaded", ip=ok_ip, ua=msg["ua"], kind="support_bundle")
    connection.send_result(msg["id"], {"ok": True})


def _has_debug(hass, user) -> bool:
    from . import _has_cap
    return _has_cap(hass, user, "debug")


COMMANDS = (ws_login_list, ws_login_summary, ws_login_settings, ws_login_settings_save, ws_login_note)
