"""Pure helpers for the portal System pages (settings, backups, logs). No hub-core imports, unit-tested."""
from __future__ import annotations

import re
from typing import Any, Callable

NAME_MAX = 60
UNIT_SYSTEMS = ("metric", "us_customary")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
RECURRENCE = ("never", "daily", "custom_days")
RESTORE_PHRASE = "RESTORE"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LOG_LINES_MAX = 2000

# ---------- log redaction ----------
_URL_CRED = re.compile(r"(?i)(\w+://)[^/\s:@]+:[^/\s@]+@")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_KEYVAL = re.compile(
    r"""(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization|credential|access_token|refresh_token|client_secret)s?["']?"""
    r"""(\s*[=:]\s*|\s+)(?:"[^"]*"|'[^']*'|(?:(?:bearer|basic)\s+)?[^\s,;&"'}]+)""")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_QUERY_SECRET = re.compile(r"(?i)([?&](?:token|access_token|api_key|apikey|password|code|secret)=)[^&\s]+")


def redact(text: str) -> str:
    """Remove anything that looks like a credential from one log line (the line is otherwise kept whole)."""
    t = _URL_CRED.sub(r"\1***@", text)
    t = _QUERY_SECRET.sub(r"\1***", t)
    t = _JWT.sub("***jwt***", t)
    t = _BEARER.sub(lambda m: m.group(1) + " ***", t)
    t = _KEYVAL.sub(lambda m: m.group(1) + "=***", t)
    return _LONG_HEX.sub("***hex***", t)


_LEVEL_RE = re.compile(r"^\d{4}-\d\d-\d\d[ T][\d:.]+\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b")


def line_level(line: str) -> str | None:
    m = _LEVEL_RE.match(line)
    return m.group(1) if m else None


def select_log(lines: list[str], level: str | None, text: str | None, limit: int) -> list[str]:
    """Newest `limit` lines at or above `level` that contain `text`. Continuation lines (tracebacks) follow their entry."""
    limit = max(1, min(int(limit or 500), LOG_LINES_MAX))
    floor = LOG_LEVELS.index(level) if level in LOG_LEVELS else 0
    needle = (text or "").strip().lower()
    out: list[str] = []
    keep = True
    for ln in lines:
        lv = line_level(ln)
        if lv is not None:
            keep = LOG_LEVELS.index(lv) >= floor
        if keep and (not needle or needle in ln.lower()):
            out.append(redact(ln.rstrip("\n")))
    return out[-limit:]


# ---------- settings ----------
def validate_settings(d: dict[str, Any], tz_ok: Callable[[str], bool]) -> tuple[dict[str, Any], dict[str, str]]:
    """Return (clean changes, field -> error). Only fields present in `d` are checked."""
    clean: dict[str, Any] = {}
    err: dict[str, str] = {}
    if "name" in d:
        v = str(d["name"]).strip()
        if not v or len(v) > NAME_MAX or any(c in v for c in "\n\r<>"):
            err["name"] = f"Enter a name of up to {NAME_MAX} characters"
        else:
            clean["location_name"] = v
    if "time_zone" in d:
        v = str(d["time_zone"]).strip()
        if not v or not tz_ok(v):
            err["time_zone"] = "Unknown time zone (use a name such as Asia/Kolkata)"
        else:
            clean["time_zone"] = v
    if "unit_system" in d:
        v = str(d["unit_system"]).strip()
        if v not in UNIT_SYSTEMS:
            err["unit_system"] = "Choose metric or US customary"
        else:
            clean["unit_system"] = v
    for k, lo, hi in (("latitude", -90, 90), ("longitude", -180, 180), ("elevation", -500, 9000)):
        if k in d:
            try:
                f = float(d[k])
                if not lo <= f <= hi or f != f:
                    raise ValueError
                clean[k] = round(f, 6)
            except (TypeError, ValueError):
                err[k] = f"Enter a number between {lo} and {hi}"
    if "country" in d:
        v = str(d["country"]).strip().upper()
        if v and not re.fullmatch(r"[A-Z]{2}", v):
            err["country"] = "Use a two-letter country code such as IN"
        else:
            clean["country"] = v or None
    return clean, err


# ---------- backups ----------
def fmt_size(n: Any) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return "?"


def valid_backup_name(v: Any) -> str | None:
    s = str(v or "").strip()
    return s if s and len(s) <= NAME_MAX and not any(c in s for c in "\n\r<>/\\") else None


def validate_schedule(d: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Backup schedule + retention from the portal. Returns (clean, error)."""
    rec = d.get("recurrence", "never")
    if rec not in RECURRENCE:
        return {}, "Choose never, daily or custom days"
    days = d.get("days") or []
    if not isinstance(days, list) or any(x not in DAYS for x in days):
        return {}, "Days must be mon..sun"
    if rec == "custom_days" and not days:
        return {}, "Pick at least one day"
    tm = d.get("time")
    if tm in (None, ""):
        tm = None
    elif not isinstance(tm, str) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", tm):
        return {}, "Time must look like 03:00"
    copies = d.get("copies", 7)
    if not isinstance(copies, int) or isinstance(copies, bool) or not 1 <= copies <= 50:
        return {}, "Keep between 1 and 50 backups"
    return {"recurrence": rec, "days": sorted(set(days), key=DAYS.index), "time": tm, "copies": copies}, None


def restore_allowed(confirm: Any, typed_name: Any, backup_name: str) -> str | None:
    """Double confirmation for a restore. Returns an error text, or None when both confirmations match."""
    if str(confirm or "").strip() != RESTORE_PHRASE:
        return f"Type {RESTORE_PHRASE} to confirm"
    if str(typed_name or "").strip() != str(backup_name).strip():
        return "Type the exact backup name to confirm"
    return None
