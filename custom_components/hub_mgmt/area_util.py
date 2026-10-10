"""Pure helpers for the portal area / floor / label commands (no hub-core imports, unit-tested)."""
from __future__ import annotations

import re
from typing import Any, Iterable

_NAME_MAX = 60
_COLOR = re.compile(r"^(#[0-9a-fA-F]{6}|[a-z]{3,20})$")
_ICON = re.compile(r"^mdi:[a-z0-9\-]{1,60}$")
BULK_MAX = 200


class Bad(ValueError):
    """User-facing validation error."""


def clean_name(value: Any, what: str = "Name") -> str:
    if not isinstance(value, str):
        raise Bad(f"{what} must be text")
    v = " ".join(value.split())
    if not v:
        raise Bad(f"{what} cannot be empty")
    if len(v) > _NAME_MAX:
        raise Bad(f"{what} is too long (max {_NAME_MAX})")
    if any(ord(c) < 32 for c in v):
        raise Bad(f"{what} contains invalid characters")
    return v


def clean_color(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _COLOR.match(value):
        raise Bad("Color must be a #rrggbb value or a simple color name")
    return value


def clean_icon(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _ICON.match(value):
        raise Bad("Icon must look like mdi:sofa")
    return value


def clean_level(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not -20 <= value <= 200:
        raise Bad("Floor level must be a whole number from -20 to 200")
    return value


def clean_ids(values: Any, what: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(v, str) and 0 < len(v) <= 120 for v in values):
        raise Bad(f"{what} must be a list of ids")
    if len(values) > BULK_MAX:
        raise Bad(f"At most {BULK_MAX} {what} at a time")
    return list(dict.fromkeys(values))


def name_taken(name: str, existing: Iterable[tuple[str, str]], ignore_id: str | None = None) -> bool:
    """existing = [(id, name)]; case-insensitive uniqueness."""
    low = name.casefold()
    return any(i != ignore_id and n.casefold() == low for i, n in existing)


def area_refs(exposure: dict[str, Any] | None, roles: dict[str, Any] | None, area_id: str) -> list[str]:
    """Where the Link API settings mention an area id (for the delete warning). Never modifies anything: an emptied
    area list would mean 'all areas' and silently widen access, so stale ids are left (they match nothing)."""
    out: list[str] = []
    if area_id in ((exposure or {}).get("include_areas") or []):
        out.append("API exposure (areas shown to apps)")
    for name, rdef in (roles or {}).items():
        for g in (rdef or {}).get("grants", []) if isinstance(rdef, dict) else []:
            if isinstance(g, dict) and area_id in (g.get("areas") or []):
                out.append(f"API role '{name}'")
                break
    return out


def activity(states: Iterable[tuple[str, str, str | None]]) -> dict[str, Any]:
    """states = [(domain, state, last_changed_iso)] -> {active, unavailable, last}."""
    active = unavailable = 0
    last: str | None = None
    for domain, state, changed in states:
        if state == "unavailable":
            unavailable += 1
        elif domain in ("light", "switch", "fan", "media_player", "cover", "lock") and state in ("on", "open", "playing", "unlocked"):
            active += 1
        if changed and (last is None or changed > last):
            last = changed
    return {"active": active, "unavailable": unavailable, "last": last}
