"""Sign-in history service for Hub Mgmt: storage, recording, alert delivery, and the hook on the hub's own sign-in flow.

The pure rules live in `login_log.py`.  This module connects them to Home Assistant:
  * `LoginService.record()` is called in-process by the node portal commands, the Link API sign-in pages and the support-file download.
  * `install_flow_hook()` wraps the hub's login-flow endpoint so sign-ins on the native door (:8123, including old integrations
    and the mobile app) are recorded too, with the real client address.
  * Alerts (repeated failures, sign-in from a new address, Tez Solutions support access) become a persistent notification in the
    hub, optional notify services, and a realtime `login_alert` event for the Link API (which cloud and user apps consume).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from homeassistant.helpers.storage import Store

from . import login_log as ll

_LOGGER = logging.getLogger(__name__)
STORE_KEY = "hub_mgmt_logins"
EVENT = "hub_mgmt_login"
SAVE_DELAY = 5


def classify(data: Any, result: Any) -> str | None:
    """Outcome of one login-flow request, or None when it is not a final answer (first form view, or the step before 2FA)."""
    if not isinstance(data, dict) or not isinstance(result, dict):
        return None
    typ, errs = result.get("type"), result.get("errors") or {}
    if "code" in data and "password" not in data:                 # second factor step
        if typ == "create_entry":
            return "success"
        if typ == "abort":
            return "blocked"
        return "wrong_2fa" if errs else None
    if "username" in data and "password" in data:                 # first step
        if typ == "create_entry":
            return "success"
        return "wrong_password" if errs else None
    return None


def door_for(client_id: str | None) -> str:
    c = (client_id or "").rstrip("/")
    return "portal" if c in ("http://127.0.0.1:8123", "http://localhost:8123") else "hub"


class LoginService:
    def __init__(self, hass) -> None:
        self.hass = hass
        self.log = ll.LoginLog()
        self.store: Store = Store(hass, 1, STORE_KEY)
        self.node = ""
        self._flow_users: dict[str, str] = {}      # login-flow id -> username typed in step 1 (so a failed 2FA names the account)

    async def async_load(self) -> None:
        self.log.load(await self.store.async_load())
        if self.log.prune():
            self._save()

    def _save(self) -> None:
        self.store.async_delay_save(self.log.dump, SAVE_DELAY)

    async def async_flush(self) -> None:
        await self.store.async_save(self.log.dump())

    # ------------------------------------------------------------------ identity helpers
    def role_of(self, user) -> str:
        from . import _role
        return _role(self.hass, user)

    async def _find(self, username: str | None):
        if not username:
            return None
        from . import _ha_username
        want = username.strip().casefold()
        for u in await self.hass.auth.async_get_users():
            if not u.system_generated and (_ha_username(u) or "").casefold() == want:
                return u
        return None

    # ------------------------------------------------------------------ recording
    async def record(self, *, user=None, username: str | None = None, door: str, outcome: str, ip: str | None = None,
                     ua: str | None = None, kind: str = "signin") -> dict[str, Any] | None:
        try:
            from . import _ha_username
            if user is None and username:
                user = await self._find(username)
            if user is not None:
                uname, name, role, uid = _ha_username(user) or username, user.name, self.role_of(user), user.id
            else:
                uname, name, role, uid = None, ll.UNKNOWN_NAME, None, None     # what was typed is not stored for unknown accounts
            e = self.log.append(kind=kind, user_id=uid, username=uname, name=name, role=role, door=door, outcome=outcome,
                                ip=(ip or None), device=ll.device_label(ua))
            self.log.prune()
            self._save()
            self._announce(e)
            return e
        except Exception:  # noqa: BLE001 - recording must never break a sign-in
            _LOGGER.exception("sign-in history: could not record an entry")
            return None

    def _announce(self, e: dict[str, Any]) -> None:
        kinds = self.log.alert_kinds(e)
        self.hass.bus.async_fire(EVENT, {"entry": e, "alerts": kinds})
        if not kinds:
            return
        from homeassistant.components import persistent_notification
        for k in kinds:
            title, msg = ll.alert_text(e, k, self.node)
            persistent_notification.async_create(self.hass, msg, title, f"sentinel_login_{k}_{e['seq']}")
            for svc in self.log.settings.get("notify_services", []):
                self.hass.async_create_task(self._notify(svc, title, msg))

    async def _notify(self, svc: str, title: str, msg: str) -> None:
        try:
            await self.hass.services.async_call("notify", svc, {"title": title, "message": msg}, blocking=False)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("notify.%s failed", svc, exc_info=True)

    # ------------------------------------------------------------------ the hub's native sign-in flow
    async def after_flow(self, request, flow_id: str | None, response) -> None:
        if getattr(response, "status", 0) != 200:
            return
        try:
            data = await request.json()
            result = json.loads(response.body)
        except Exception:  # noqa: BLE001
            return
        outcome = classify(data, result)
        username = data.get("username") if isinstance(data, dict) else None
        if flow_id and username:
            self._flow_users[flow_id] = str(username)[:60]
            if len(self._flow_users) > 200:
                self._flow_users.pop(next(iter(self._flow_users)))
        if outcome is None:
            return
        if not username and flow_id:
            username = self._flow_users.get(flow_id)
        if flow_id and outcome in ("success", "blocked"):
            self._flow_users.pop(flow_id, None)
        door = door_for(data.get("client_id"))
        await self.record(username=username, door=door, outcome=outcome,
                          ip=real_ip(request, door), ua=request.headers.get("User-Agent"))


def real_ip(request, door: str) -> str | None:
    """The portal signs in on the visitor's behalf from inside the local Docker network, so the hub sees the bridge address.  For the portal's
    own client id, and only from a loopback / private source, the address the portal reports is used.  Anything else keeps the socket address."""
    remote = request.remote
    if door == "portal" and remote:
        try:
            ip = ipaddress.ip_address(remote)
            if ip.is_loopback or ip.is_private:
                given = (request.headers.get("X-Tez-Client-IP") or "").strip()[:45]
                ipaddress.ip_address(given)
                return given
        except ValueError:
            pass
    return remote


_HOOKED = {"done": False}
_FLOW_PATH = "/auth/login_flow/{flow_id}"


def install_flow_hook(hass, svc: LoginService) -> bool:
    """Wrap the hub's login-flow route once.  HA binds a view's method to its route when the view is registered, so patching the
    class later has no effect; the route's handler is replaced instead.  Everything the original does is unchanged: we only look at
    the answer, and any failure in here is swallowed so a sign-in can never break because of the history."""
    if _HOOKED["done"]:
        return True
    try:
        routes = [r for res in hass.http.app.router.resources() if getattr(res, "canonical", "") == _FLOW_PATH for r in res]
        routes = [r for r in routes if r.method == "POST"]
        if not routes:
            raise LookupError("login flow route not found")
        for route in routes:
            orig = route.handler

            async def handler(request, _orig=orig):
                resp = await _orig(request)
                try:
                    s = hass.data.get("hub_mgmt", {}).get("logins")
                    if s is not None:
                        await s.after_flow(request, request.match_info.get("flow_id"), resp)
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("sign-in history hook failed", exc_info=True)
                return resp

            handler.__wrapped__ = orig      # type: ignore[attr-defined]
            route._handler = handler        # noqa: SLF001 - routes cannot be added after start, but a handler can be replaced
        _HOOKED["done"] = True
        return True
    except Exception:  # noqa: BLE001
        _LOGGER.warning("sign-in history: could not hook the native sign-in flow; portal and Link API sign-ins are still recorded", exc_info=True)
        return False
