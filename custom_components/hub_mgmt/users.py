"""Hub Mgmt phase 3: accounts, two-step sign-in (authenticator app) and sessions for the node portal.

Capabilities: `profile` (everyone who can sign in: own name, password, 2FA, sessions) and `users` (admin, homeowner:
manage the roles they are allowed to manage, same rule as the existing user commands via _removable_user).
Rules: current password required for password and 2FA changes; failures are throttled per user; changing a password
or turning 2FA on/off signs out every OTHER session of that user; disabling a user signs them out at once; nobody
can disable, remove or reset themselves through the "manage users" commands; admins cannot be managed here.
"""
from __future__ import annotations

import logging
import secrets
import time
from typing import Any

import voluptuous as vol

from homeassistant.auth.providers import homeassistant as auth_ha
from homeassistant.components import websocket_api
from homeassistant.auth.const import GROUP_ID_ADMIN  # noqa: F401

from . import user_util as uu
from .entities import _audit, _cap, _role

_LOGGER = logging.getLogger(__name__)
_profile = _cap("profile", "Sign in first")
_users = _cap("users", "Not allowed to manage users")

THROTTLE = uu.Throttle(5, 300.0)       # wrong current password / wrong 2FA code, per user id
PENDING_TTL = 600.0
BRAND = "Sentinel Hub"


def _bad(connection, msg, err: Exception) -> None:
    connection.send_error(msg["id"], "invalid", str(err))


def _pending(hass) -> dict[str, dict[str, Any]]:
    return hass.data.setdefault("hub_mgmt_mfa_pending", {})


def _totp(hass):
    return hass.auth.get_auth_mfa_module("totp")


async def _mfa_on(hass, user) -> bool:
    mod = _totp(hass)
    return bool(mod and await mod.async_is_user_setup(user.id))


def _drop_other_sessions(hass, user, keep_id: str | None) -> int:
    n = 0
    for rt in list(user.refresh_tokens.values()):
        if rt.id != keep_id and rt.token_type == "normal":
            hass.auth.async_remove_refresh_token(rt)
            n += 1
    return n


async def _check_current_password(hass, connection, msg, user) -> bool:
    from . import _ha_username
    username = _ha_username(user)
    key = "pw:" + user.id
    w = THROTTLE.wait(key)
    if w:
        connection.send_error(msg["id"], "throttled", f"Too many wrong attempts. Try again in {w // 60 + 1} min.")
        return False
    if not username:
        connection.send_error(msg["id"], "no_login", "This account has no local password")
        return False
    try:
        await auth_ha.async_get_provider(hass).async_validate_login(username, msg.get("current_password", ""))
    except auth_ha.InvalidAuth:
        THROTTLE.fail(key)
        _audit(hass, user, "profile_reauth_failed", user.id, "denied")
        connection.send_error(msg["id"], "wrong_password", "Current password is not correct")
        return False
    THROTTLE.ok(key)
    return True


# ------------------------------------------------------------------ own account
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/profile"})
@websocket_api.async_response
@_profile
async def ws_profile(hass, connection, msg):
    from . import _ha_username
    u = connection.user
    mod = _totp(hass)
    toks = [t for t in u.refresh_tokens.values() if t.token_type == "normal"]
    connection.send_result(msg["id"], {
        "id": u.id, "name": u.name, "username": _ha_username(u), "role": _role(hass, u),
        "mfa_available": mod is not None, "mfa_enabled": await _mfa_on(hass, u),
        "sessions": len(toks), "last_seen": uu.newest(t.last_used_at for t in toks),
    })


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/profile_update", vol.Required("name"): str})
@websocket_api.async_response
@_profile
async def ws_profile_update(hass, connection, msg):
    try:
        name = uu.clean_display_name(msg["name"])
    except uu.Bad as err:
        return _bad(connection, msg, err)
    await hass.auth.async_update_user(connection.user, name=name)
    _audit(hass, connection.user, "profile_update", connection.user.id, "ok", {"name": name})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/profile_password",
    vol.Required("current_password"): str, vol.Required("new_password"): str,
})
@websocket_api.async_response
@_profile
async def ws_profile_password(hass, connection, msg):
    from . import _ha_username
    u = connection.user
    try:
        uu.check_password(msg["new_password"], _ha_username(u) or "", u.name or "")
    except uu.Bad as err:
        return _bad(connection, msg, err)
    if msg["new_password"] == msg["current_password"]:
        connection.send_error(msg["id"], "invalid", "Choose a password you have not used just now")
        return
    if not await _check_current_password(hass, connection, msg, u):
        return
    try:
        await auth_ha.async_get_provider(hass).async_change_password(_ha_username(u), msg["new_password"])
    except auth_ha.InvalidUser:
        connection.send_error(msg["id"], "no_login", "This account has no local password")
        return
    n = _drop_other_sessions(hass, u, getattr(connection, "refresh_token_id", None))
    _audit(hass, u, "profile_password", u.id, "ok", {"other_sessions_signed_out": n})
    connection.send_result(msg["id"], {"ok": True, "signed_out": n})


# ------------------------------------------------------------------ two-step sign-in
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/mfa_start", vol.Required("current_password"): str})
@websocket_api.async_response
@_profile
async def ws_mfa_start(hass, connection, msg):
    import pyotp
    from homeassistant.auth.mfa_modules import totp as totp_mod
    from . import _ha_username
    u = connection.user
    if _totp(hass) is None:
        connection.send_error(msg["id"], "unavailable", "Two-step sign-in is not enabled on this node")
        return
    if await _mfa_on(hass, u):
        connection.send_error(msg["id"], "already", "Two-step sign-in is already on")
        return
    if not await _check_current_password(hass, connection, msg, u):
        return
    secret = pyotp.random_base32()
    label = _ha_username(u) or u.name or "user"
    url = pyotp.totp.TOTP(secret).provisioning_uri(label, issuer_name=BRAND)
    try:
        qr = await hass.async_add_executor_job(totp_mod._generate_qr_code, url)
    except Exception:  # noqa: BLE001 - the secret alone is enough to set up
        qr = None
    pend = _pending(hass)
    for k in [k for k, v in pend.items() if v["exp"] < time.time()]:
        pend.pop(k, None)
    pend[u.id] = {"secret": secret, "exp": time.time() + PENDING_TTL}
    _audit(hass, u, "mfa_start", u.id, "ok")
    connection.send_result(msg["id"], {"secret": secret, "qr_svg": qr, "expires_in": int(PENDING_TTL)})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/mfa_confirm", vol.Required("code"): str})
@websocket_api.async_response
@_profile
async def ws_mfa_confirm(hass, connection, msg):
    import pyotp
    u = connection.user
    try:
        code = uu.clean_code(msg["code"])
    except uu.Bad as err:
        return _bad(connection, msg, err)
    key = "mfa:" + u.id
    w = THROTTLE.wait(key)
    if w:
        connection.send_error(msg["id"], "throttled", f"Too many wrong codes. Try again in {w // 60 + 1} min.")
        return
    p = _pending(hass).get(u.id)
    mod = _totp(hass)
    if not p or p["exp"] < time.time() or mod is None:
        connection.send_error(msg["id"], "expired", "Start the setup again")
        return
    if not await hass.async_add_executor_job(pyotp.TOTP(p["secret"]).verify, code):
        THROTTLE.fail(key)
        connection.send_error(msg["id"], "wrong_code", "That code is not right. Check the time on your phone and try again")
        return
    THROTTLE.ok(key)
    await mod.async_setup_user(u.id, {"secret": p["secret"]})
    _pending(hass).pop(u.id, None)
    n = _drop_other_sessions(hass, u, getattr(connection, "refresh_token_id", None))
    _audit(hass, u, "mfa_enabled", u.id, "ok", {"other_sessions_signed_out": n})
    connection.send_result(msg["id"], {"ok": True, "signed_out": n})


@websocket_api.websocket_command({
    vol.Required("type"): "hub_mgmt/mfa_disable", vol.Required("current_password"): str,
})
@websocket_api.async_response
@_profile
async def ws_mfa_disable(hass, connection, msg):
    u = connection.user
    mod = _totp(hass)
    if mod is None or not await _mfa_on(hass, u):
        connection.send_error(msg["id"], "not_on", "Two-step sign-in is not on")
        return
    if not await _check_current_password(hass, connection, msg, u):
        return
    await mod.async_depose_user(u.id)
    n = _drop_other_sessions(hass, u, getattr(connection, "refresh_token_id", None))
    _audit(hass, u, "mfa_disabled", u.id, "ok", {"other_sessions_signed_out": n})
    connection.send_result(msg["id"], {"ok": True, "signed_out": n})


# ------------------------------------------------------------------ own sessions
def _sessions_of(hass, user, current_id):
    out = []
    for t in user.refresh_tokens.values():
        if t.token_type != "normal":
            continue
        out.append(uu.session_view(t.id, t.client_id, t.client_name, t.created_at, t.last_used_at, t.last_used_ip, current_id))
    out.sort(key=lambda s: (not s["current"], s["last_used"] or ""), reverse=False)
    return out


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/my_sessions"})
@websocket_api.async_response
@_profile
async def ws_my_sessions(hass, connection, msg):
    connection.send_result(msg["id"], {"sessions": _sessions_of(hass, connection.user, getattr(connection, "refresh_token_id", None))})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/my_session_revoke", vol.Required("session_id"): str})
@websocket_api.async_response
@_profile
async def ws_my_session_revoke(hass, connection, msg):
    u = connection.user
    cur = getattr(connection, "refresh_token_id", None)
    rt = u.refresh_tokens.get(msg["session_id"])
    if rt is None or rt.token_type != "normal":
        connection.send_error(msg["id"], "not_found", "Unknown session")
        return
    if rt.id == cur:
        connection.send_error(msg["id"], "invalid", "That is this session. Use Sign out instead")
        return
    hass.auth.async_remove_refresh_token(rt)
    _audit(hass, u, "session_revoke", rt.id[:8], "ok")
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/my_sessions_revoke_others"})
@websocket_api.async_response
@_profile
async def ws_my_sessions_revoke_others(hass, connection, msg):
    n = _drop_other_sessions(hass, connection.user, getattr(connection, "refresh_token_id", None))
    _audit(hass, connection.user, "sessions_revoke_others", connection.user.id, "ok", {"count": n})
    connection.send_result(msg["id"], {"ok": True, "count": n})


# ------------------------------------------------------------------ managing other users
async def _target(hass, connection, msg):
    from . import _removable_user
    user = await hass.auth.async_get_user(msg["user_id"])
    if user is None:
        connection.send_error(msg["id"], "not_found", "Unknown user")
        return None
    if not _removable_user(hass, user, connection.user):
        connection.send_error(msg["id"], "forbidden", "You cannot manage this account")
        return None
    return user


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_detail", vol.Required("user_id"): str})
@websocket_api.async_response
@_users
async def ws_user_detail(hass, connection, msg):
    from . import _ha_username, _removable_user
    user = await hass.auth.async_get_user(msg["user_id"])
    if user is None or user.system_generated:
        connection.send_error(msg["id"], "not_found", "Unknown user")
        return
    manageable = _removable_user(hass, user, connection.user)
    toks = [t for t in user.refresh_tokens.values() if t.token_type == "normal"]
    cur = getattr(connection, "refresh_token_id", None) if user.id == connection.user.id else None
    connection.send_result(msg["id"], {
        "id": user.id, "name": user.name, "username": _ha_username(user), "role": _role(hass, user), "active": user.is_active,
        "manageable": manageable, "self": user.id == connection.user.id,
        "mfa_available": _totp(hass) is not None, "mfa_enabled": await _mfa_on(hass, user),
        "last_seen": uu.newest(t.last_used_at for t in toks),
        "sessions": _sessions_of(hass, user, cur) if manageable or user.id == connection.user.id else [],
    })


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_rename", vol.Required("user_id"): str, vol.Required("name"): str})
@websocket_api.async_response
@_users
async def ws_user_rename(hass, connection, msg):
    user = await _target(hass, connection, msg)
    if user is None:
        return
    try:
        name = uu.clean_display_name(msg["name"])
    except uu.Bad as err:
        return _bad(connection, msg, err)
    await hass.auth.async_update_user(user, name=name)
    _audit(hass, connection.user, "user_rename", user.id, "ok", {"name": name})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_set_active", vol.Required("user_id"): str, vol.Required("active"): bool})
@websocket_api.async_response
@_users
async def ws_user_set_active(hass, connection, msg):
    user = await _target(hass, connection, msg)
    if user is None:
        return
    if msg["active"]:
        await hass.auth.async_activate_user(user)
    else:
        await hass.auth.async_deactivate_user(user)   # also drops every refresh token = signed out now
    _audit(hass, connection.user, "user_enable" if msg["active"] else "user_disable", user.id, "ok", {"name": user.name})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_mfa_reset", vol.Required("user_id"): str})
@websocket_api.async_response
@_users
async def ws_user_mfa_reset(hass, connection, msg):
    user = await _target(hass, connection, msg)
    if user is None:
        return
    mod = _totp(hass)
    if mod is None or not await _mfa_on(hass, user):
        connection.send_error(msg["id"], "not_on", "That user has no two-step sign-in")
        return
    await mod.async_depose_user(user.id)
    n = _drop_other_sessions(hass, user, None)
    _audit(hass, connection.user, "user_mfa_reset", user.id, "ok", {"name": user.name, "sessions_signed_out": n})
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_signout", vol.Required("user_id"): str})
@websocket_api.async_response
@_users
async def ws_user_signout(hass, connection, msg):
    user = await _target(hass, connection, msg)
    if user is None:
        return
    n = _drop_other_sessions(hass, user, None)
    _audit(hass, connection.user, "user_signout", user.id, "ok", {"name": user.name, "sessions": n})
    connection.send_result(msg["id"], {"ok": True, "count": n})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/user_session_revoke", vol.Required("user_id"): str, vol.Required("session_id"): str})
@websocket_api.async_response
@_users
async def ws_user_session_revoke(hass, connection, msg):
    user = await _target(hass, connection, msg)
    if user is None:
        return
    rt = user.refresh_tokens.get(msg["session_id"])
    if rt is None or rt.token_type != "normal":
        connection.send_error(msg["id"], "not_found", "Unknown session")
        return
    hass.auth.async_remove_refresh_token(rt)
    _audit(hass, connection.user, "user_session_revoke", user.id, "ok", {"name": user.name})
    connection.send_result(msg["id"], {"ok": True})


COMMANDS = (ws_profile, ws_profile_update, ws_profile_password, ws_mfa_start, ws_mfa_confirm, ws_mfa_disable,
            ws_my_sessions, ws_my_session_revoke, ws_my_sessions_revoke_others,
            ws_user_detail, ws_user_rename, ws_user_set_active, ws_user_mfa_reset, ws_user_signout, ws_user_session_revoke)
