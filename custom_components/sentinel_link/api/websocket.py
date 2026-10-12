"""WebSocket commands for MANAGEMENT (hub admins only; used by the node portal). App realtime lives in auth.py."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from . import rbac
from . import tokens as tok
from .core import API_DATA, ApiState


def _state(hass: HomeAssistant) -> ApiState | None:
    return hass.data.get(API_DATA)


def _need_enabled(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> ApiState | None:
    st = _state(hass)
    if st is None or not st.enabled:
        connection.send_error(msg["id"], "api_disabled", "Sentinel Link API is disabled on this node")
        return None
    return st


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


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/tokens"})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_tokens(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    """All long-lived tokens + app sessions + registered apps (never secrets)."""
    st = _state(hass)
    if st is None:
        connection.send_result(msg["id"], {"tokens": [], "clients": []})
        return
    names = {u.id: u.name for u in await hass.auth.async_get_users()}
    rows = st.book.list()
    for r in rows:
        r["user"] = names.get(r["user_id"])
    connection.send_result(msg["id"], {"tokens": rows, "clients": list(st.book.clients.values())})


@websocket_api.websocket_command({
    vol.Required("type"): "sentinel_link/token_create", vol.Required("user_id"): str, vol.Required("name"): str,
    vol.Optional("expires_in_days"): vol.Any(None, int), vol.Optional("max_role"): vol.Any(None, str),
    vol.Optional("scopes", default=[]): [str],
})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_token_create(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    """Admin creates a long-lived token for a hub user (e.g. a wall panel). The secret is returned ONCE."""
    st = _state(hass)
    user = await hass.auth.async_get_user(msg["user_id"])
    if st is None or user is None or not user.is_active or user.system_generated:
        connection.send_error(msg["id"], "not_found", "User not found or disabled")
        return
    if st.role_for(user) is None:
        connection.send_error(msg["id"], "no_role", "That user has no API role; assign one in Hub Mgmt first")
        return
    rec, secret = st.book.create_long_lived(user.id, msg["name"], expires_in_days=msg.get("expires_in_days"),
                                            max_role=msg.get("max_role"), created_by=connection.user.id, scopes=msg.get("scopes"))
    if rec is None:
        connection.send_error(msg["id"], "validation_failed", "; ".join(secret))  # type: ignore[arg-type]
        return
    st.log(connection.user, rbac.ROLE_ADMIN, "auth:create_token", rec["id"], "ok",
           {"name": rec["name"], "for": user.name, "max_role": rec["max_role"], "scopes": rec.get("scopes"), "expires": rec["expires"]})
    st.persist()
    out = st.book.public(rec)
    out["token"] = secret
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/token_revoke", vol.Required("token_id"): str})
@websocket_api.require_admin
@callback
def ws_token_revoke(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    rec = st.book.tokens.get(msg["token_id"]) if st else None
    if st is None or rec is None:
        connection.send_error(msg["id"], "not_found", "Token not found")
        return
    st.close_tokens(st.book.revoke(msg["token_id"]))
    st.log(connection.user, rbac.ROLE_ADMIN, "auth:revoke_token", msg["token_id"], "ok", {"name": rec.get("name")})
    st.persist()
    connection.send_result(msg["id"], {"revoked": True})


@websocket_api.websocket_command({
    vol.Required("type"): "sentinel_link/client_save", vol.Required("client_id"): str, vol.Required("name"): str,
    vol.Required("redirect_uris"): [str],
})
@websocket_api.require_admin
@callback
def ws_client_save(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    if st is None:
        connection.send_error(msg["id"], "unavailable", "Sentinel Link is not set up")
        return
    errs = st.book.save_client(msg["client_id"], msg["name"], msg["redirect_uris"])
    if errs:
        connection.send_error(msg["id"], "validation_failed", "; ".join(errs))
        return
    st.log(connection.user, rbac.ROLE_ADMIN, "auth:client_save", msg["client_id"], "ok")
    st.persist()
    connection.send_result(msg["id"], st.book.clients[msg["client_id"]])


@websocket_api.websocket_command({vol.Required("type"): "sentinel_link/client_remove", vol.Required("client_id"): str})
@websocket_api.require_admin
@callback
def ws_client_remove(hass: HomeAssistant, connection: Any, msg: dict[str, Any]) -> None:
    st = _state(hass)
    if st is None or msg["client_id"] not in st.book.clients:
        connection.send_error(msg["id"], "not_found", "App not found")
        return
    st.close_tokens(st.book.remove_client(msg["client_id"]))
    st.log(connection.user, rbac.ROLE_ADMIN, "auth:client_remove", msg["client_id"], "ok")
    st.persist()
    connection.send_result(msg["id"], {"removed": True})


ALL_COMMANDS = (ws_status, ws_users, ws_set_enabled, ws_config_set, ws_audit, ws_tokens, ws_token_create, ws_token_revoke, ws_client_save,
                ws_client_remove)
