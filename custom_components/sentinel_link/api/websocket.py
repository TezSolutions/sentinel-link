"""WebSocket commands: realtime subscription + management (used by the node portal)."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from . import rbac
from .core import API_DATA, MAX_STREAMS_PER_USER, ApiState


def _state(hass: HomeAssistant) -> ApiState | None:
    return hass.data.get(API_DATA)


def _need_enabled(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> ApiState | None:
    st = _state(hass)
    if st is None or not st.enabled:
        connection.send_error(msg["id"], "api_disabled", "Sentinel Link API is disabled on this node")
        return None
    return st


@websocket_api.websocket_command({
    vol.Required("type"): "sentinel_link/subscribe",
    vol.Optional("domains"): [str],
    vol.Optional("entity_ids"): [str],
    vol.Optional("initial", default=True): bool,
})
@callback
def ws_subscribe(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    """Role-filtered realtime state stream (events: snapshot, state, removed)."""
    st = _need_enabled(hass, connection, msg)
    if st is None:
        return
    user = connection.user
    role = st.role_for(user)
    if role is None:
        connection.send_error(msg["id"], "no_role", "No API role is assigned to this user")
        return
    if st.streams_for(user.id) >= MAX_STREAMS_PER_USER:
        connection.send_error(msg["id"], "too_many_streams", f"Max {MAX_STREAMS_PER_USER} streams per user")
        return
    mid = msg["id"]
    domains = set(msg.get("domains") or [])
    ents = set(msg.get("entity_ids") or [])

    def send(payload: dict[str, Any]) -> None:
        connection.send_message(websocket_api.event_message(mid, payload))

    sid = st.add_subscriber(user, send, lambda: None, domains, ents)

    @callback
    def unsub() -> None:
        st.remove_subscriber(sid)

    connection.subscriptions[mid] = unsub
    connection.send_result(mid)
    if msg.get("initial", True):
        cfg, role, states = st.visible_states(user)
        snap = [st.serialize(s, cfg, role) for s in states
                if (not domains or s.domain in domains) and (not ents or s.entity_id in ents)]
        send({"type": "snapshot", "entities": snap})


# --------------------------------------------------------------------------- management (HA admins only)
@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/status"})
@websocket_api.require_admin
@callback
def ws_status(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    if st is None:
        connection.send_result(msg["id"], {"available": False, "enabled": False})
        return
    out = st.status()
    out["available"] = True
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/users"})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_users(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    if st is None:
        connection.send_result(msg["id"], {"users": []})
        return
    users = await hass.auth.async_get_users()
    connection.send_result(msg["id"], {"users": st.users_overview(users)})


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/set_enabled", vol.Required("enabled"): bool})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_set_enabled(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    from .setup import async_set_enabled  # local import: avoids a cycle at load time

    st = _state(hass)
    if st is None:
        connection.send_error(msg["id"], "unavailable", "Sentinel Link is not set up")
        return
    await async_set_enabled(hass, bool(msg["enabled"]))
    st.log(connection.user, rbac.ROLE_ADMIN, "api_enabled", "-", "ok", {"enabled": bool(msg["enabled"])})
    out = st.status()
    out["available"] = True
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/config_set", vol.Required("config"): dict})
@websocket_api.require_admin
@callback
def ws_config_set(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    if st is None:
        connection.send_error(msg["id"], "unavailable", "Sentinel Link is not set up")
        return
    errs = st.apply_config(msg["config"])
    if errs:
        st.log(connection.user, rbac.ROLE_ADMIN, "config", "-", "rejected", {"errors": errs})
        connection.send_error(msg["id"], "validation_failed", "; ".join(errs))
        return
    st.log(connection.user, rbac.ROLE_ADMIN, "config", "-", "ok", {"keys": sorted(msg["config"])})
    out = st.status()
    out["available"] = True
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/audit", vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=200))})
@websocket_api.require_admin
@callback
def ws_audit(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    connection.send_result(msg["id"], {"entries": list(st.audit)[: msg["limit"]] if st else []})


ALL_COMMANDS = (ws_subscribe, ws_status, ws_users, ws_set_enabled, ws_config_set, ws_audit)
