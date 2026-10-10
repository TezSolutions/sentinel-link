"""Pure helpers for the portal device/entity commands (no hub-core imports, unit-tested)."""
from __future__ import annotations

from typing import Any

# keep in step with sentinel_link/api/rbac.py (a test compares them)
HARD_DENY_DOMAINS = frozenset({
    "device_tracker", "person", "zone", "update", "persistent_notification",
    "conversation", "tts", "stt", "assist_satellite", "backup", "remote",
})
HARD_DENY_PLATFORM_DOMAIN = frozenset({("sentinel_link", "button"), ("hub_mgmt", "button")})

# only admin and homeowner may operate these (installers commission devices, they do not open doors)
SENSITIVE_DOMAINS = frozenset({"lock", "alarm_control_panel"})

# attributes a control needs (sent with every state so the UI can draw sliders / pickers)
CONTROL_ATTRS = (
    "brightness", "color_temp_kelvin", "min_color_temp_kelvin", "max_color_temp_kelvin", "rgb_color",
    "supported_color_modes", "color_mode", "effect_list", "effect",
    "percentage", "preset_mode", "preset_modes",
    "current_position", "temperature", "target_temp_high", "target_temp_low", "current_temperature",
    "min_temp", "max_temp", "target_temp_step", "hvac_modes", "hvac_action", "fan_mode", "fan_modes",
    "volume_level", "is_volume_muted", "media_title", "media_artist",
    "device_class", "unit_of_measurement", "state_class", "battery_level",
)
_SKIP_ATTRS = frozenset({"friendly_name", "entity_picture", "supported_features", "icon", "access_token", "stream_url"})
_MAX_ATTRS, _MAX_STR = 40, 160


BRAND = {"frigate": "AINVR"}


def brand(v: Any) -> Any:
    """Product name shown to people: the NVR engine is presented as AINVR."""
    if isinstance(v, str):
        return BRAND.get(v.strip().casefold(), v)
    return v


def clip_attrs(attrs: dict[str, Any] | None) -> dict[str, Any]:
    """Scalar / short-list attributes only, bounded in size (never ship a huge blob to the browser)."""
    out: dict[str, Any] = {}
    for k, v in (attrs or {}).items():
        if k in _SKIP_ATTRS or len(out) >= _MAX_ATTRS:
            continue
        if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
            out[k] = v
        elif isinstance(v, str):
            out[k] = v[:_MAX_STR]
        elif isinstance(v, (list, tuple)) and len(v) <= 12 and all(isinstance(i, (str, int, float, bool)) for i in v):
            out[k] = [i[:_MAX_STR] if isinstance(i, str) else i for i in v]
    return out


def control_attrs(attrs: dict[str, Any] | None) -> dict[str, Any]:
    src = attrs or {}
    return {k: src[k] for k in CONTROL_ATTRS if k in src and isinstance(src[k], (str, int, float, bool, list, tuple, type(None)))}


def control_allowed(role: str, domain: str, platform: str | None) -> tuple[bool, str]:
    """May a portal user of `role` (admin/installer/homeowner) operate this entity? Returns (ok, reason)."""
    if domain in HARD_DENY_DOMAINS or (platform, domain) in HARD_DENY_PLATFORM_DOMAIN:
        return False, "This entity cannot be controlled from the portal"
    if domain in SENSITIVE_DOMAINS and role not in ("admin", "superadmin", "homeowner"):
        return False, "Only an administrator or home owner can operate locks and alarms"
    return True, ""


def downsample(points: list[list[Any]], limit: int = 240) -> list[list[Any]]:
    """Evenly thin a [ts, value] list to at most `limit` points, always keeping the first and last."""
    n = len(points)
    if n <= limit or limit < 2:
        return points
    step = (n - 1) / (limit - 1)
    idx = sorted({round(i * step) for i in range(limit)} | {0, n - 1})
    return [points[i] for i in idx]


def history_points(rows: list[tuple[float, str]]) -> dict[str, Any]:
    """rows = [(unix_seconds, state)] -> numeric series when every real state is a number, else state changes."""
    rows = [(t, s) for t, s in rows if s not in ("unknown", "unavailable", "", None)]
    numeric = bool(rows)
    vals = []
    for t, s in rows:
        try:
            vals.append([int(t * 1000), float(s)])
        except (TypeError, ValueError):
            numeric = False
            break
    if numeric:
        return {"kind": "number", "points": downsample(vals)}
    changes = []
    last = None
    for t, s in rows:
        if s != last:
            changes.append([int(t * 1000), str(s)[:40]])
            last = s
    return {"kind": "state", "points": changes[-120:]}
