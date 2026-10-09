"""Pure-Python RBAC core for the Sentinel Link API (no HA imports).

Model
-----
* Exposure  : node-wide filter of what the API may EVER show (domains, areas,
              explicit include/exclude).  Applied before roles.
* Role      : named list of grants (+ optional ``extends``).
* Grant     : {effect: allow|deny, domains, areas, entities, labels, actions}.
              Empty/missing selector = any.  ``actions`` is mandatory and
              contains "read" and/or command names; "*" = every action.
* Decision  : default-deny; any matching deny wins over any allow.

A user resolves to exactly one role (HA admin -> "admin"; else explicit user
mapping; else HA-group mapping; else the configured default; else none).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

READ = "read"
ANY = "*"

ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

DEFAULT_EXPOSED_DOMAINS = [
    "light", "switch", "climate", "cover", "fan", "lock", "sensor",
    "binary_sensor", "media_player", "scene", "camera",
]

_OPERATOR_DOMAINS = ["light", "switch", "fan", "climate", "cover", "media_player", "button"]
_MANAGER_DOMAINS = _OPERATOR_DOMAINS + ["lock", "alarm_control_panel", "scene", "script"]

BUILTIN_ROLES: dict[str, dict[str, Any]] = {
    ROLE_VIEWER: {
        "description": "Read state, subscribe to realtime, camera snapshots.",
        "grants": [{"effect": "allow", "actions": [READ, "snapshot"]}],
    },
    ROLE_OPERATOR: {
        "description": "Viewer + control lights, switches, climate, covers, fans, media.",
        "extends": ROLE_VIEWER,
        "grants": [{"effect": "allow", "domains": _OPERATOR_DOMAINS, "actions": [ANY]}],
    },
    ROLE_MANAGER: {
        "description": "Operator + locks, alarm panels, scenes, scripts.",
        "extends": ROLE_OPERATOR,
        "grants": [{"effect": "allow", "domains": _MANAGER_DOMAINS, "actions": [ANY]}],
    },
    ROLE_ADMIN: {
        "description": "Everything exposed + role/audit administration.",
        "grants": [{"effect": "allow", "actions": [ANY]}],
        "admin": True,
    },
}

BUILTIN_NAMES = frozenset(BUILTIN_ROLES)


@dataclass(frozen=True)
class EntityCtx:
    """What the RBAC engine needs to know about an entity."""

    entity_id: str
    pid: str
    area_id: str | None = None
    labels: tuple[str, ...] = ()
    diagnostic: bool = False

    @property
    def domain(self) -> str:
        return self.entity_id.split(".", 1)[0]


def default_exposure() -> dict[str, Any]:
    return {
        "domains": list(DEFAULT_EXPOSED_DOMAINS),
        "include_areas": [],      # empty = all areas (incl. no area)
        "include_entities": [],   # extra entity_ids/pids exposed regardless of domain
        "exclude_entities": [],
        "include_diagnostic": False,
    }


def _sel(values: Iterable[str] | None) -> set[str]:
    return {str(v) for v in (values or [])}


def is_exposed(exposure: dict[str, Any], ent: EntityCtx) -> bool:
    ids = {ent.entity_id, ent.pid}
    if ids.intersection(_sel(exposure.get("exclude_entities"))):
        return False
    if ids.intersection(_sel(exposure.get("include_entities"))):
        return True
    if ent.diagnostic and not exposure.get("include_diagnostic", False):
        return False
    if ent.domain not in _sel(exposure.get("domains")):
        return False
    areas = _sel(exposure.get("include_areas"))
    if areas and ent.area_id not in areas:
        return False
    return True


def _match(selector: Iterable[str] | None, *candidates: str | None) -> bool:
    sel = _sel(selector)
    if not sel or ANY in sel:
        return True
    return any(c is not None and c in sel for c in candidates)


def grant_matches(grant: dict[str, Any], ent: EntityCtx, action: str) -> bool:
    actions = grant.get("actions")
    if not actions:  # actions mandatory: a grant without them matches nothing
        return False
    return (
        _match(actions, action)
        and _match(grant.get("domains"), ent.domain)
        and _match(grant.get("areas"), ent.area_id)
        and _match(grant.get("entities"), ent.entity_id, ent.pid)
        and _match(grant.get("labels"), *ent.labels)
    )


def flatten_role(name: str, roles: dict[str, dict[str, Any]], _seen: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Return the effective grant list of *name* (follows ``extends``)."""
    role = roles.get(name)
    if role is None or name in _seen:
        return []
    grants: list[dict[str, Any]] = []
    parent = role.get("extends")
    if parent:
        grants.extend(flatten_role(parent, roles, _seen + (name,)))
    grants.extend(role.get("grants", []))
    return grants


def decide(grants: list[dict[str, Any]], ent: EntityCtx, action: str) -> bool:
    """Default-deny; deny wins."""
    allowed = False
    for g in grants:
        if not grant_matches(g, ent, action):
            continue
        if g.get("effect") == "deny":
            return False
        if g.get("effect", "allow") == "allow":
            allowed = True
    return allowed


def validate_role_def(name: str, role: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        errs.append("role name must be alphanumeric/_/-")
    if name in BUILTIN_NAMES:
        errs.append("cannot redefine built-in role")
    if role.get("admin"):
        errs.append("custom roles cannot be admin")
    for g in role.get("grants", []):
        if g.get("effect", "allow") not in ("allow", "deny"):
            errs.append("grant effect must be allow|deny")
        if not g.get("actions"):
            errs.append("grant needs non-empty actions")
        for k in ("domains", "areas", "entities", "labels", "actions"):
            if k in g and not isinstance(g[k], list):
                errs.append(f"grant.{k} must be a list")
    return errs


@dataclass
class RbacConfig:
    exposure: dict[str, Any] = field(default_factory=default_exposure)
    roles: dict[str, dict[str, Any]] = field(default_factory=dict)   # custom
    user_roles: dict[str, str] = field(default_factory=dict)
    group_roles: dict[str, str] = field(default_factory=dict)
    default_role: str | None = None

    def all_roles(self) -> dict[str, dict[str, Any]]:
        merged = dict(self.roles)
        merged.update(BUILTIN_ROLES)  # built-ins can't be overridden
        return merged

    def resolve_role(self, user_id: str, is_admin: bool, group_ids: Iterable[str] = ()) -> str | None:
        if is_admin:
            return ROLE_ADMIN
        roles = self.all_roles()
        r = self.user_roles.get(user_id)
        if r in roles and r != ROLE_ADMIN:
            return r
        for gid in group_ids:
            r = self.group_roles.get(gid)
            if r in roles and r != ROLE_ADMIN:
                return r
        if self.default_role in roles and self.default_role != ROLE_ADMIN:
            return self.default_role
        return None

    def is_admin_role(self, role: str | None) -> bool:
        return bool(role and self.all_roles().get(role, {}).get("admin"))

    def can(self, role: str | None, ent: EntityCtx, action: str) -> bool:
        if role is None or not is_exposed(self.exposure, ent):
            return False
        return decide(flatten_role(role, self.all_roles()), ent, action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exposure": self.exposure,
            "roles": self.roles,
            "user_roles": self.user_roles,
            "group_roles": self.group_roles,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, default_role: str | None = None) -> "RbacConfig":
        data = data or {}
        exp = default_exposure()
        exp.update(data.get("exposure") or {})
        return cls(
            exposure=exp,
            roles=dict(data.get("roles") or {}),
            user_roles=dict(data.get("user_roles") or {}),
            group_roles=dict(data.get("group_roles") or {}),
            default_role=default_role or None,
        )
