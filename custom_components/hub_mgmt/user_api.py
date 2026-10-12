"""User management operations shared by the node portal (WebSocket) and the Sentinel Link API (REST /users).

One implementation, so the two can never drift: every rule (who may manage whom, password policy, last-admin / self protection,
the hidden vendor account, role assignment) lives here. Callers pass the acting hub user; nothing here trusts a role string from outside.
Every change fires the hub event `hub_mgmt_user_changed` (the Link API turns it into a realtime event for admins).
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.providers import homeassistant as auth_ha

from . import user_util

_LOGGER = logging.getLogger(__name__)
EVENT = "hub_mgmt_user_changed"


class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class UserApi:
    def __init__(self, hass) -> None:
        self.hass = hass

    # ------------------------------------------------------------------ helpers (late import: hub_mgmt/__init__ imports this module)
    def _fire(self, action: str, caller, user, **extra: Any) -> None:
        from . import _role
        self.hass.bus.async_fire(EVENT, {"action": action, "user_id": user.id, "name": user.name,
                                         "role": _role(self.hass, user), "by": getattr(caller, "name", None), **extra})

    async def _get(self, user_id: str, caller):
        """The target, or `not_found` (the vendor account is not found for anyone but the vendor)."""
        from . import _role
        user = await self.hass.auth.async_get_user(user_id) if isinstance(user_id, str) else None
        if user is None or user.system_generated or (_role(self.hass, user) == "superadmin" and _role(self.hass, caller) != "superadmin"):
            raise ApiError("not_found", "Unknown user", 404)
        return user

    async def _manageable(self, user_id: str, caller):
        from . import _removable_user
        user = await self._get(user_id, caller)
        if not _removable_user(self.hass, user, caller):
            raise ApiError("forbidden", "You cannot manage this account", 403)
        return user

    # ------------------------------------------------------------------ read
    async def list(self, caller) -> dict[str, Any]:
        from . import _manageable_roles, user_row
        rows = [r for r in [await user_row(self.hass, u, caller) for u in await self.hass.auth.async_get_users()] if r]
        order = ("superadmin", "admin", "installer", "homeowner", "manager", "operator", "viewer", "user")
        rows.sort(key=lambda x: (order.index(x["role"]) if x["role"] in order else 99, (x["name"] or "").lower()))
        return {"users": rows, "assignable": sorted(_manageable_roles(self.hass, caller) - {"user"})}

    async def get(self, user_id: str, caller) -> dict[str, Any]:
        from . import user_row
        user = await self._get(user_id, caller)
        row = await user_row(self.hass, user, caller)
        if row is None:
            raise ApiError("not_found", "Unknown user", 404)
        return row

    # ------------------------------------------------------------------ write
    async def create(self, caller, *, name: str, username: str, password: str, role: str) -> dict[str, Any]:
        from . import DOMAIN, USERNAME_RE, STORED_ROLES, _manageable_roles, _save
        username = (username or "").strip().lower()
        try:
            name = user_util.clean_display_name(name)
        except user_util.Bad as err:
            raise ApiError("invalid_name", str(err))
        if role not in ("user", *STORED_ROLES) or role not in _manageable_roles(self.hass, caller):
            raise ApiError("forbidden", f"You cannot create a '{role}'", 403)
        if not isinstance(password, str) or not (8 <= len(password) <= 128):
            raise ApiError("weak_password", "Password must be 8-128 characters")
        try:
            user_util.check_password(password, username, name)
        except user_util.Bad as err:
            raise ApiError("weak_password", str(err))
        if not USERNAME_RE.match(username):
            raise ApiError("invalid_username", "Username: 3-32 chars, letters, digits, . _ -")
        provider = auth_ha.async_get_provider(self.hass)
        try:
            await provider.async_add_auth(username, password)
        except auth_ha.InvalidUser:
            raise ApiError("username_taken", "That username is already in use", 409)
        try:
            user = await self.hass.auth.async_create_user(name, group_ids=[GROUP_ID_USER])
            creds = await provider.async_get_or_create_credentials({"username": username})
            await self.hass.auth.async_link_user(user, creds)
        except Exception as err:  # noqa: BLE001 - roll back the login we just added
            try:
                await provider.async_remove_auth(username)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("rollback of auth for %s failed", username)
            raise ApiError("create_failed", str(err), 500)
        if role != "user":
            self.hass.data[DOMAIN]["user_roles"][user.id] = role
            await _save(self.hass)
        _LOGGER.info("%s created user %s (%s) role=%s", caller.name, name, username, role)
        self._fire("created", caller, user)
        return {"id": user.id}

    async def remove(self, caller, user_id: str) -> None:
        from . import DOMAIN, _save
        user = await self._manageable(user_id, caller)
        name = user.name
        event_user = user
        await self.hass.auth.async_remove_user(user)
        if self.hass.data[DOMAIN]["user_roles"].pop(user.id, None) is not None:
            await _save(self.hass)
        _LOGGER.info("%s removed user %s", caller.name, name)
        self._fire("removed", caller, event_user)

    async def set_password(self, caller, user_id: str, password: str) -> None:
        from . import _ha_username, _removable_user, users
        user = await self._get(user_id, caller)
        username = _ha_username(user)
        if not _removable_user(self.hass, user, caller) or not username:
            raise ApiError("forbidden", "Passwords can only be reset for accounts you manage", 403)
        if not isinstance(password, str) or not (8 <= len(password) <= 128):
            raise ApiError("weak_password", "Password must be 8-128 characters")
        try:
            user_util.check_password(password, username, user.name or "")
        except user_util.Bad as err:
            raise ApiError("weak_password", str(err))
        try:
            await auth_ha.async_get_provider(self.hass).async_change_password(username, password)
        except auth_ha.InvalidUser:
            raise ApiError("not_found", "No local login for this user", 404)
        users._drop_other_sessions(self.hass, user, None)
        _LOGGER.info("%s reset the password of %s", caller.name, user.name)
        self._fire("password_reset", caller, user)

    async def set_role(self, caller, user_id: str, role: str) -> None:
        from . import DOMAIN, STORED_ROLES, _manageable_roles, _save
        user = await self._manageable(user_id, caller)
        if role not in ("user", *STORED_ROLES) or role not in _manageable_roles(self.hass, caller):
            raise ApiError("forbidden", "You cannot assign that role to this user", 403)
        roles = self.hass.data[DOMAIN]["user_roles"]
        if role == "user":
            roles.pop(user.id, None)
        else:
            roles[user.id] = role
        await _save(self.hass)
        _LOGGER.info("%s set role of %s to %s", caller.name, user.name, role)
        self._fire("role_changed", caller, user)

    async def set_active(self, caller, user_id: str, active: bool) -> None:
        user = await self._manageable(user_id, caller)
        if active:
            await self.hass.auth.async_activate_user(user)
        else:
            await self.hass.auth.async_deactivate_user(user)   # also drops every refresh token = signed out now
        self._fire("enabled" if active else "disabled", caller, user)

    async def rename(self, caller, user_id: str, name: str) -> None:
        user = await self._manageable(user_id, caller)
        try:
            name = user_util.clean_display_name(name)
        except user_util.Bad as err:
            raise ApiError("invalid_name", str(err))
        await self.hass.auth.async_update_user(user, name=name)
        self._fire("renamed", caller, user)
