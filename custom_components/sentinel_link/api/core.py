"""Runtime state + helpers shared by the REST, realtime and management layers."""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Callable

from homeassistant.const import EVENT_STATE_CHANGED
from homeassistant.core import Event, HomeAssistant, State, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import Store

from . import commands as cmds
from . import rbac

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

    # ------------------------------------------------------------------ life
    async def async_load(self) -> None:
        data = await self.store.async_load() or {}
        self.exposure = {**rbac.default_exposure(), **(data.get("exposure") or {})}
        self.custom_roles = dict(data.get("roles") or {})
        self.group_roles = dict(data.get("group_roles") or {})
        self.default_role = data.get("default_role") or None
        for item in data.get("audit") or []:
            self.audit.append(item)

    @callback
    def async_start(self) -> None:
        self._unsub_bus = self.hass.bus.async_listen(EVENT_STATE_CHANGED, self._on_state_changed)

    @callback
    def async_stop(self) -> None:
        if self._unsub_bus:
            self._unsub_bus()
            self._unsub_bus = None
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

    def role_for(self, user: Any) -> str | None:
        is_admin = bool(getattr(user, "is_admin", False) or getattr(user, "is_owner", False))
        return self.rbac().resolve_role(user.id, is_admin, getattr(user, "group_ids", ()) or ())

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

    def visible_states(self, user: Any) -> tuple[rbac.RbacConfig, str | None, list[State]]:
        cfg = self.rbac()
        role = self.role_for(user)
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
                       domains: set[str] | None = None, entity_ids: set[str] | None = None) -> int:
        sid = self._next_sub
        self._next_sub += 1
        self.subscribers[sid] = {"user": user, "send": send, "close": close,
                                 "domains": domains or set(), "entity_ids": entity_ids or set()}
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
        by_user: dict[str, tuple[str | None, bool]] = {}
        payloads: dict[str | None, dict[str, Any]] = {}
        for sub in list(self.subscribers.values()):
            if sub["domains"] and domain not in sub["domains"]:
                continue
            if sub["entity_ids"] and entity_id not in sub["entity_ids"]:
                continue
            user = sub["user"]
            if user.id not in by_user:
                role = self.role_for(user)
                by_user[user.id] = (role, cfg.can(role, ctx, rbac.READ))
            role, visible = by_user[user.id]
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

    # --------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        cfg = self.rbac()
        return {
            "enabled": self.enabled,
            "api_version": API_VERSION,
            "integration_version": self.version,
            "node_id": self.node_id,
            "base_path": "/api/sentinel_link/v1",
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
            "audit_entries": len(self.audit),
        }

    def users_overview(self, users: list[Any]) -> list[dict[str, Any]]:
        out = []
        for u in users:
            if not u.is_active or u.system_generated:
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
