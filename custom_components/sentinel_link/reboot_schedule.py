"""Scheduled-reboot time maths, kept free of Home Assistant imports.

The schedule is a wall-clock time (``HH:MM``, 24h) in the hub's configured
time zone, either every day or on one weekday. Pure functions so the unit
tests can load this file directly without Home Assistant installed.
"""
from __future__ import annotations

import re
from datetime import datetime, time, timedelta, tzinfo

# Option value -> Python weekday number (Monday == 0). "daily" means every day.
WEEKDAY_DAILY = "daily"
WEEKDAYS: dict[str, int] = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}
WEEKDAY_NAMES: dict[str, str] = {
    "mon": "Monday",
    "tue": "Tuesday",
    "wed": "Wednesday",
    "thu": "Thursday",
    "fri": "Friday",
    "sat": "Saturday",
    "sun": "Sunday",
}
WEEKDAY_OPTIONS: tuple[str, ...] = (WEEKDAY_DAILY, *WEEKDAYS)

_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def parse_reboot_time(value: str) -> tuple[int, int]:
    """Return ``(hour, minute)`` for ``"HH:MM"`` (24h); ValueError otherwise."""
    m = _TIME_RE.match(str(value).strip())
    if not m:
        raise ValueError(f"invalid reboot time {value!r}, expected HH:MM (24h)")
    return int(m.group(1)), int(m.group(2))


def parse_weekday(value: str | None) -> int | None:
    """Return the Python weekday number, or None for every day.

    ``None``/missing/``"daily"`` all mean every day, so entries created before
    the weekday option existed keep their daily behaviour. Anything else that
    is not a known weekday raises ValueError (the caller must not fall back to
    a daily reboot on a typo).
    """
    if value is None:
        return None
    key = str(value).strip().lower()
    if key in ("", WEEKDAY_DAILY):
        return None
    if key in WEEKDAYS:
        return WEEKDAYS[key]
    raise ValueError(f"invalid reboot weekday {value!r}, expected one of {WEEKDAY_OPTIONS}")


def describe_schedule(weekday: str | None) -> str:
    """Short label used in log lines: ``daily`` or ``weekly (Monday)``."""
    wd = parse_weekday(weekday)
    if wd is None:
        return "daily"
    name = next(WEEKDAY_NAMES[k] for k, v in WEEKDAYS.items() if v == wd)
    return f"weekly ({name})"


def next_reboot_local(
    now: datetime, tz: tzinfo, reboot_time: str, weekday: str | None = None
) -> datetime:
    """Next reboot strictly after *now*, as an aware datetime in *tz*.

    *now* must be timezone-aware (any zone). The weekday is evaluated in *tz*
    (the hub's configured zone), not UTC, so a Monday 03:00 IST reboot is
    found from a Sunday-evening UTC clock.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    hour, minute = parse_reboot_time(reboot_time)
    wd = parse_weekday(weekday)
    local_now = now.astimezone(tz)
    # 0..7 days covers "today, later" through "same weekday next week".
    for offset in range(8):
        day = local_now.date() + timedelta(days=offset)
        if wd is not None and day.weekday() != wd:
            continue
        target = datetime.combine(day, time(hour, minute), tzinfo=tz)
        if target > local_now:
            return target
    raise RuntimeError("no reboot slot found in 8 days")  # unreachable
