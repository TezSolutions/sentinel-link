"""Command allowlist + validation (pure Python).

The public API never forwards arbitrary HA services.  Only the commands in
COMMANDS exist, each with a strict field schema.  Anything else -> 400.
"""
from __future__ import annotations

from typing import Any

SNAPSHOT_ACTION = "snapshot"  # RBAC action for camera images (domain camera)


class CommandError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _i(lo, hi): return ("int", (lo, hi))
def _f(lo, hi): return ("float", (lo, hi))
def _s(*allowed): return ("str", allowed or None)


_NONE: dict[str, tuple] = {}

# domain -> command -> (ha_service, {field: spec})
COMMANDS: dict[str, dict[str, tuple[str, dict[str, tuple]]]] = {
    "light": {
        "turn_on": ("turn_on", {"brightness": _i(0, 255), "brightness_pct": _i(0, 100),
                                "color_temp_kelvin": _i(1000, 10000), "rgb_color": ("rgb", None),
                                "transition": _f(0, 300), "effect": _s()}),
        "turn_off": ("turn_off", {"transition": _f(0, 300)}),
        "toggle": ("toggle", _NONE),
    },
    "switch": {"turn_on": ("turn_on", _NONE), "turn_off": ("turn_off", _NONE), "toggle": ("toggle", _NONE)},
    "fan": {
        "turn_on": ("turn_on", {"percentage": _i(0, 100), "preset_mode": _s()}),
        "turn_off": ("turn_off", _NONE),
        "set_percentage": ("set_percentage", {"percentage": _i(0, 100)}),
    },
    "climate": {
        "turn_on": ("turn_on", _NONE),
        "turn_off": ("turn_off", _NONE),
        "set_temperature": ("set_temperature", {"temperature": _f(-50, 100), "target_temp_high": _f(-50, 100),
                                                "target_temp_low": _f(-50, 100), "hvac_mode": _s()}),
        "set_hvac_mode": ("set_hvac_mode", {"hvac_mode": _s()}),
        "set_fan_mode": ("set_fan_mode", {"fan_mode": _s()}),
        "set_preset_mode": ("set_preset_mode", {"preset_mode": _s()}),
    },
    "cover": {
        "open_cover": ("open_cover", _NONE), "close_cover": ("close_cover", _NONE),
        "stop_cover": ("stop_cover", _NONE),
        "set_cover_position": ("set_cover_position", {"position": _i(0, 100)}),
    },
    "lock": {"lock": ("lock", {"code": _s()}), "unlock": ("unlock", {"code": _s()})},
    "alarm_control_panel": {
        "arm_home": ("alarm_arm_home", {"code": _s()}), "arm_away": ("alarm_arm_away", {"code": _s()}),
        "arm_night": ("alarm_arm_night", {"code": _s()}), "disarm": ("alarm_disarm", {"code": _s()}),
    },
    "media_player": {
        "turn_on": ("turn_on", _NONE), "turn_off": ("turn_off", _NONE),
        "media_play": ("media_play", _NONE), "media_pause": ("media_pause", _NONE),
        "media_stop": ("media_stop", _NONE), "next_track": ("media_next_track", _NONE),
        "previous_track": ("media_previous_track", _NONE),
        "volume_set": ("volume_set", {"volume_level": _f(0, 1)}),
        "volume_mute": ("volume_mute", {"is_volume_muted": ("bool", None)}),
    },
    "scene": {"turn_on": ("turn_on", _NONE)},
    "script": {"turn_on": ("turn_on", _NONE)},
    "button": {"press": ("press", _NONE)},
}

REQUIRED: dict[tuple[str, str], tuple[str, ...]] = {
    ("fan", "set_percentage"): ("percentage",),
    ("cover", "set_cover_position"): ("position",),
    ("climate", "set_hvac_mode"): ("hvac_mode",),
    ("climate", "set_fan_mode"): ("fan_mode",),
    ("climate", "set_preset_mode"): ("preset_mode",),
    ("media_player", "volume_set"): ("volume_level",),
    ("media_player", "volume_mute"): ("is_volume_muted",),
}


def commands_for(domain: str) -> list[str]:
    cmds = list(COMMANDS.get(domain, {}))
    if domain == "camera":
        cmds.append(SNAPSHOT_ACTION)
    return cmds


def _check(name: str, spec: tuple, value: Any) -> Any:
    kind, cons = spec
    if kind in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CommandError("invalid_field", f"{name}: expected number")
        if kind == "int":
            if int(value) != value:
                raise CommandError("invalid_field", f"{name}: expected integer")
            value = int(value)
        lo, hi = cons
        if not lo <= value <= hi:
            raise CommandError("invalid_field", f"{name}: must be {lo}..{hi}")
        return value
    if kind == "str":
        if not isinstance(value, str) or not value or len(value) > 64:
            raise CommandError("invalid_field", f"{name}: expected non-empty string (<=64)")
        if cons and value not in cons:
            raise CommandError("invalid_field", f"{name}: must be one of {list(cons)}")
        return value
    if kind == "bool":
        if not isinstance(value, bool):
            raise CommandError("invalid_field", f"{name}: expected boolean")
        return value
    if kind == "rgb":
        if (not isinstance(value, list) or len(value) != 3
                or any(isinstance(c, bool) or not isinstance(c, int) or not 0 <= c <= 255 for c in value)):
            raise CommandError("invalid_field", f"{name}: expected [r,g,b] 0..255")
        return value
    raise CommandError("internal", f"bad spec for {name}")


def validate(domain: str, command: str, data: Any) -> tuple[str, dict[str, Any]]:
    """Return (ha_service, service_data) or raise CommandError."""
    table = COMMANDS.get(domain)
    if table is None or command not in table:
        raise CommandError("unknown_command", f"{domain} has no command '{command}'")
    service, fields = table[command]
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise CommandError("invalid_body", "'data' must be an object")
    out: dict[str, Any] = {}
    for key, val in data.items():
        if key not in fields:
            raise CommandError("invalid_field", f"unknown field '{key}' for {domain}.{command}")
        out[key] = _check(key, fields[key], val)
    for req in REQUIRED.get((domain, command), ()):
        if req not in out:
            raise CommandError("missing_field", f"'{req}' is required for {domain}.{command}")
    return service, out
