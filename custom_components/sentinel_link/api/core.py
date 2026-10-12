"""Runtime state + helpers shared by the REST, realtime and management layers."""
from __future__ import annotations

import logging
import time
from collections import deque
from datetime import timedelta
from typing import Any, Callable

from homeassistant.const import EVENT_STATE_CHANGED
from homeassistant.core import Event, HomeAssistant, State, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store

from . import commands as cmds
from . import netaddr
from . import rbac
from . import tokens as tok

_LOGGER = logging.getLogger(__name__)

API_VERSION = "1"
API_DATA = "sentinel_link_api"
STORE_KEY = "sentinel_link_api"
HUB_DOMAIN = "hub_mgmt"
AUDIT_MAX = 200
MAX_STREAMS_PER_USER = 5

# Attributes that carry per-session secrets/tokens and must never leave HA.
_STRIP_ATTRS = ("access_token", "entity_picture", "entity_picture_local")
_REDACT_DATA = ("code",)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


class ApiState:
    """Everything the API needs at request time."""

    def __init__(self, hass: HomeAssistant, entry_id: str, enabled: bool, node_id: str, version: str) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self.enabled = enabled
        self.node_id = node_id
        self.version = version
        self.store: Store = Store(hass, 1, STORE_KEY)
        self.exposure: dict[str, Any] = rbac.default_exposure()
        self.custom_roles: dict[str, dict[str, Any]] = {}
        self.group_roles: dict[str, str] = {}
        self.default_role: str | None = None
        self.audit: deque[dict[str, Any]] = deque(maxlen=AUDIT_MAX)
        # token -> (user_id, role_fn, send_fn, filters)
        self.subscribers: dict[int, dict[str, Any]] = {}
        self._next_sub = 1
        self._unsub_bus: Callable[[], None] | None = None
        self.skip_reload = False  # set when an option change must not reload the entry
        self.book = tok.TokenBook()          # OAuth apps, long-lived tokens, sessions
        self.throttle = tok.Throttle()        # sign-in failure lockout
        self.pending: dict[str, dict[str, Any]] = {}   # second-factor tickets (memory only)
        self._unsub_sweep: Callable[[], None] | None = None
        from .cloud import CloudChannel
        self.cloud = CloudChannel(self)       # optional pairing with a cloud platform (outbound channel)

    # ------------------------------------------------------------------ life
    async def async_load(self) -> None:
        data = await self.store.async_load() or {}
        self.exposure = {**rbac.default_exposure(), **(data.get("exposure") or {})}
        self.custom_roles = dict(data.get("roles") or {})
        self.group_roles = dict(data.get("group_roles") or {})
        self.default_role = data.get("default_role") or None
        for item in data.get("audit") or []:
            self.audit.append(item)
        self.book.load(data.get("auth"))
        self.cloud.load(data.get("cloud"))

    @callback
    def async_start(self) -> None:
        self._unsub_bus = self.hass.bus.async_listen(EVENT_STATE_CHANGED, self._on_state_changed)
        self._unsub_sweep = async_track_time_interval(self.hass, self._sweep, timedelta(seconds=60))
        self._unsub_users = self.hass.bus.async_listen("hub_mgmt_user_changed", self._on_user_changed)
        self._unsub_logins = self.hass.bus.async_listen("hub_mgmt_login", self._on_login)
        self.cloud.start()

    @callback
    def async_stop(self) -> None:
        self.cloud.stop()
        if getattr(self, "_unsub_logins", None):
            self._unsub_logins()
            self._unsub_logins = None
        if self._unsub_bus:
            self._unsub_bus()
            self._unsub_bus = None
        if self._unsub_sweep:
            self._unsub_sweep()
            self._unsub_sweep = None
        if getattr(self, "_unsub_users", None):
            self._unsub_users()
            self._unsub_users = None
        for sub in list(self.subscribers.values()):
            try:
                sub["close"]()
            except Exception:  # noqa: BLE001
                pass
        self.subscribers.clear()

    @callback
    def _schedule_save(self) -> None:
        self.store.async_delay_save(self._data_to_save, 5)

    def _data_to_save(self) -> dict[str, Any]:
        return {
            "exposure": self.exposure,
            "roles": self.custom_roles,
            "group_roles": self.group_roles,
            "default_role": self.default_role,
            "audit": list(self.audit),
            "auth": self.book.to_dict(),
            "cloud": self.cloud.to_dict(),
        }

    # ------------------------------------------------------------------ rbac
    def hub_roles(self) -> dict[str, str]:
        hub = self.hass.data.get(HUB_DOMAIN)
        if isinstance(hub, dict):
            roles = hub.get("user_roles")
            if isinstance(roles, dict):
                return dict(roles)
        return {}

    def rbac(self) -> rbac.RbacConfig:
        return rbac.RbacConfig(
            exposure=self.exposure,
            roles=self.custom_roles,
            user_roles=self.hub_roles(),
            group_roles=self.group_roles,
            default_role=self.default_role,
        )

    def role_for(self, user: Any, cap: str | None = None) -> str | None:
        """Current role of a hub user (read live), optionally lowered by a token's cap."""
        is_admin = bool(getattr(user, "is_admin", False) or getattr(user, "is_owner", False))
        role = self.rbac().resolve_role(user.id, is_admin, getattr(user, "group_ids", ()) or ())
        return tok.effective_role(role, cap)

    # ------------------------------------------------------------------ Link credentials
    async def authenticate(self, token: str) -> tuple[Any, dict[str, Any], str | None] | None:
        """Validate a Link bearer token -> (hub user, token record, effective role). Users and roles are read
        LIVE from the hub, so removing/disabling a user or changing a role takes effect on the next call."""
        rec = self.book.authenticate(token)
        if rec is None:
            return None
        user = await self.hass.auth.async_get_user(rec["user_id"])
        if user is None or not user.is_active or user.system_generated:
            self.close_tokens(self.book.revoke_user(rec["user_id"]))
            self.persist()
            return None
        return user, rec, self.role_for(user, rec.get("max_role"))

    @callback
    def persist(self) -> None:
        self.book.dirty = False
        self._schedule_save()

    @callback
    def close_tokens(self, token_ids: list[str]) -> None:
        """Drop live streams that were opened with any of these (now revoked) tokens."""
        ids = set(token_ids)
        if not ids:
            return
        for sid, sub in list(self.subscribers.items()):
            if sub.get("token_id") in ids:
                try:
                    sub["close"]()
                except Exception:  # noqa: BLE001
                    pass
                self.subscribers.pop(sid, None)

    async def _sweep(self, _now: Any = None) -> None:
        """Every minute: expire tokens, revoke those of removed/disabled users, close their streams, flush to disk."""
        self.book.purge()
        users = {u.id: u for u in await self.hass.auth.async_get_users()}
        owners = {r["user_id"] for r in list(self.book.tokens.values()) + list(self.book.access.values())}
        for uid in owners:
            u = users.get(uid)
            if u is None or not u.is_active:
                self.close_tokens(self.book.revoke_user(uid))
        live = set(self.book.tokens) | set(self.book.access)
        self.close_tokens([s["token_id"] for s in self.subscribers.values() if s.get("token_id") and s["token_id"] not in live])
        for t in [t for t, p in self.pending.items() if p["exp"] < time.time()]:
            self.pending.pop(t, None)
        if self.book.dirty:
            self.persist()

    def entity_ctx(self, entity_id: str) -> rbac.EntityCtx:
        ent = er.async_get(self.hass).async_get(entity_id)
        if ent is None:
            return rbac.EntityCtx(entity_id=entity_id, pid=entity_id)
        area = ent.area_id
        if not area and ent.device_id:
            dev = dr.async_get(self.hass).async_get(ent.device_id)
            area = dev.area_id if dev else None
        return rbac.EntityCtx(
            entity_id=entity_id,
            pid=ent.id,
            area_id=area,
            labels=tuple(sorted(ent.labels or ())),
            diagnostic=ent.entity_category is not None,
            platform=ent.platform or "",
        )

    def can(self, cfg: rbac.RbacConfig, role: str | None, entity_id: str, action: str) -> bool:
        return cfg.can(role, self.entity_ctx(entity_id), action)

    # ------------------------------------------------------------- serialise
    def serialize(self, state: State, cfg: rbac.RbacConfig | None = None, role: str | None = None) -> dict[str, Any]:
        domain = state.domain
        attrs = {k: v for k, v in state.attributes.items() if k not in _STRIP_ATTRS}
        ctx = self.entity_ctx(state.entity_id)
        reg = er.async_get(self.hass).async_get(state.entity_id)
        out: dict[str, Any] = {
            "entity_id": state.entity_id,
            "id": ctx.pid,
            "domain": domain,
            "name": state.name,
            "state": state.state,
            "attributes": _jsonable(attrs),
            "device_id": reg.device_id if reg else None,
            "area_id": ctx.area_id,
            "last_changed": state.last_changed.isoformat(),
            "last_updated": state.last_updated.isoformat(),
        }
        if cfg is not None:
            allowed = [c for c in cmds.commands_for(domain) if cfg.can(role, ctx, c)]
            out["commands"] = allowed
        return out

    def visible_states(self, user: Any, cap: str | None = None) -> tuple[rbac.RbacConfig, str | None, list[State]]:
        cfg = self.rbac()
        role = self.role_for(user, cap)
        if role is None:
            return cfg, role, []
        states = [s for s in self.hass.states.async_all() if cfg.can(role, self.entity_ctx(s.entity_id), rbac.READ)]
        return cfg, role, states

    # ---------------------------------------------------------------- audit
    @callback
    def log(self, user: Any, role: str | None, action: str, target: str, result: str, data: Any = None) -> None:
        if isinstance(data, dict):
            data = {k: ("***" if k in _REDACT_DATA else v) for k, v in data.items()}
        self.audit.appendleft({
            "ts": time.time(),
            "user_id": getattr(user, "id", None),
            "user": getattr(user, "name", None),
            "role": role,
            "action": action,
            "target": target,
            "result": result,
            "data": _jsonable(data) if data else None,
        })
        self._schedule_save()

    # ------------------------------------------------------------- realtime
    def add_subscriber(self, user: Any, send: Callable[[dict[str, Any]], None], close: Callable[[], None],
                       domains: set[str] | None = None, entity_ids: set[str] | None = None,
                       token_id: str | None = None, cap: str | None = None) -> int:
        sid = self._next_sub
        self._next_sub += 1
        self.subscribers[sid] = {"user": user, "send": send, "close": close,
                                 "domains": domains or set(), "entity_ids": entity_ids or set(),
                                 "token_id": token_id, "cap": cap}
        return sid

    def remove_subscriber(self, sid: int) -> None:
        self.subscribers.pop(sid, None)

    def streams_for(self, user_id: str) -> int:
        return sum(1 for s in self.subscribers.values() if s["user"].id == user_id)

    @callback
    def _on_state_changed(self, event: Event) -> None:
        if not self.enabled or not self.subscribers:
            return
        entity_id: str = event.data["entity_id"]
        new: State | None = event.data.get("new_state")
        domain = entity_id.split(".", 1)[0]
        cfg = self.rbac()
        ctx = self.entity_ctx(entity_id)
        by_user: dict[tuple[str, str | None], tuple[str | None, bool]] = {}
        payloads: dict[str | None, dict[str, Any]] = {}
        for sub in list(self.subscribers.values()):
            if sub["domains"] and domain not in sub["domains"]:
                continue
            if sub["entity_ids"] and entity_id not in sub["entity_ids"]:
                continue
            user = sub["user"]
            key = (user.id, sub.get("cap"))
            if key not in by_user:
                role = self.role_for(user, sub.get("cap"))
                by_user[key] = (role, cfg.can(role, ctx, rbac.READ))
            role, visible = by_user[key]
            if not visible:
                continue
            if new is None:
                msg = {"type": "removed", "entity_id": entity_id}
            else:
                if role not in payloads:
                    payloads[role] = {"type": "state", "entity": self.serialize(new, cfg, role)}
                msg = payloads[role]
            try:
                sub["send"](msg)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("realtime send failed", exc_info=True)

    @callback
    def _on_user_changed(self, event: Event) -> None:
        """User created / removed / role changed ... -> realtime event for ADMIN subscribers only."""
        if not self.enabled or not self.subscribers:
            return
        d = event.data
        msg = {"type": "user", "action": d.get("action"), "user_id": d.get("user_id"), "name": d.get("name"), "role": d.get("role")}
        cfg = self.rbac()
        for sub in list(self.subscribers.values()):
            if cfg.is_admin_role(self.role_for(sub["user"], sub.get("cap"))):
                try:
                    sub["send"](msg)
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("realtime send failed", exc_info=True)

    @callback
    def _on_login(self, event: Event) -> None:
        """Sign-in history -> realtime `login` event (and `login_alert` when it triggers an alert), each subscriber getting only what
        they may read: homeowner/admin/vendor see everybody's, everyone else only their own.  Passwords/tokens are never in an entry."""
        if not self.enabled or not self.subscribers:
            return
        svc = (self.hass.data.get("hub_mgmt") or {}).get("logins")
        if svc is None:
            return
        e, alerts = event.data.get("entry"), event.data.get("alerts") or []
        if not e:
            return
        for sub in list(self.subscribers.values()):
            try:
                u = sub["user"]
                hub_role = svc.role_of(u)
                link_role = self.role_for(u, sub.get("cap"))
                if not svc.log.visible(e, u.id, hub_role, link_role):
                    continue
                p = svc.log.present(e, hub_role)
                sub["send"]({"type": "login", "entry": p})
                if alerts and svc.log.scope_for(hub_role, link_role) == "all":
                    sub["send"]({"type": "login_alert", "kinds": alerts, "entry": p})
            except Exception:  # noqa: BLE001
                _LOGGER.debug("realtime send failed", exc_info=True)

    # --------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        cfg = self.rbac()
        return {
            "enabled": self.enabled,
            "api_version": API_VERSION,
            "integration_version": self.version,
            "node_id": self.node_id,
            "base_path": "/api/sentinel_link/v1",
            "local_urls": [u + "/api/sentinel_link/v1" for u in netaddr.local_urls(netaddr.local_addresses(netaddr.read_adapters()))],
            "docs_path": "/api/sentinel_link/v1/docs",
            "openapi_path": "/api/sentinel_link/v1/openapi.json",
            "exposure": self.exposure,
            "default_role": self.default_role,
            "group_roles": self.group_roles,
            "custom_roles": self.custom_roles,
            "builtin_roles": {k: v.get("description", "") for k, v in rbac.BUILTIN_ROLES.items()},
            "exposed_entities": sum(
                1 for s in self.hass.states.async_all() if cfg.exposure and rbac.is_exposed(cfg.exposure, self.entity_ctx(s.entity_id))
            ),
            "live_streams": len(self.subscribers),
            "auth": {
                "clients": len(self.book.clients),
                "long_lived_tokens": sum(1 for t in self.book.tokens.values() if t["kind"] == tok.KIND_LONG),
                "sessions": sum(1 for t in self.book.tokens.values() if t["kind"] == tok.KIND_REFRESH),
            },
            "authorize_path": "/api/sentinel_link/v1/auth/authorize",
            "new_token_path": "/api/sentinel_link/v1/auth/new-token",
            "audit_entries": len(self.audit),
        }

    def users_overview(self, users: list[Any]) -> list[dict[str, Any]]:
        out = []
        vendor = set((self.hass.data.get("hub_mgmt") or {}).get("superadmins", ()))  # the vendor account is not listed for the customer
        for u in users:
            if not u.is_active or u.system_generated or u.id in vendor:
                continue
            out.append({"id": u.id, "name": u.name, "is_admin": bool(u.is_admin or u.is_owner),
                        "role": self.role_for(u)})
        return out

    @callback
    def apply_config(self, patch: dict[str, Any]) -> list[str]:
        """Validate + apply a partial config update; return a list of errors."""
        errs: list[str] = []
        new_exp = None
        if "exposure" in patch:
            exp = patch["exposure"]
            if not isinstance(exp, dict):
                errs.append("exposure must be an object")
            else:
                allowed = set(rbac.default_exposure())
                unknown = set(exp) - allowed
                if unknown:
                    errs.append(f"unknown exposure keys: {sorted(unknown)}")
                for k in ("domains", "include_areas", "include_entities", "exclude_entities"):
                    if k in exp and not (isinstance(exp[k], list) and all(isinstance(x, str) for x in exp[k])):
                        errs.append(f"exposure.{k} must be a list of strings")
                if "include_diagnostic" in exp and not isinstance(exp["include_diagnostic"], bool):
                    errs.append("exposure.include_diagnostic must be boolean")
                new_exp = {**self.exposure, **exp}
        new_roles = None
        if "roles" in patch:
            roles = patch["roles"]
            if not isinstance(roles, dict):
                errs.append("roles must be an object")
            else:
                for name, rdef in roles.items():
                    if not isinstance(rdef, dict):
                        errs.append(f"role {name}: must be an object")
                        continue
                    errs.extend(f"role {name}: {e}" for e in rbac.validate_role_def(name, rdef))
                new_roles = roles
        new_groups = None
        if "group_roles" in patch:
            gr = patch["group_roles"]
            if not (isinstance(gr, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in gr.items())):
                errs.append("group_roles must map group id -> role name")
            else:
                new_groups = gr
        new_default = self.default_role
        if "default_role" in patch:
            dr_ = patch["default_role"] or None
            all_roles = {**(new_roles if new_roles is not None else self.custom_roles), **rbac.BUILTIN_ROLES}
            if dr_ is not None and (dr_ not in all_roles or dr_ == rbac.ROLE_ADMIN):
                errs.append("default_role must be an existing non-admin role or null")
            else:
                new_default = dr_
        if errs:
            return errs
        if new_exp is not None:
            self.exposure = new_exp
        if new_roles is not None:
            self.custom_roles = new_roles
        if new_groups is not None:
            self.group_roles = new_groups
        self.default_role = new_default
        self._schedule_save()
        return []
