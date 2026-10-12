"""Cloud channel rules (pure Python, no Home Assistant imports, unit-tested).

The cloud channel lets a node be managed by a third-party cloud platform (white-label / Lumyn).  Design rules enforced here:

* The NODE dials out.  The cloud never connects in, so no port is opened.
* The node admin decides the sharing level; the cloud can never raise it:
    health  - node status only (heartbeat).  No entity data, no commands.
    events  - health + entity state changes + read-only API calls (viewer role at most; no camera snapshots).
    full    - events + camera snapshots + device commands (manager role at most: lights, switches, climate, covers, locks, scenes ...).
* The cloud channel can reach ONLY the paths in `relay_allowed`.  It can never manage users, tokens, apps, settings, the audit trail or the
  cloud settings themselves, whatever level is chosen.
* A remote debug report needs on-node approval (time-boxed, 1 hour by default).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

LEVELS = ("health", "events", "full")
LEVEL_RANK = {lv: i for i, lv in enumerate(LEVELS)}
DEFAULT_LEVEL = "health"
RELAY_ROLE_CAP = {"health": None, "events": "viewer", "full": "manager"}   # the Link role cap of the relay token

DEFAULT_APPROVAL_MIN = 60
MAX_APPROVAL_MIN = 1440
MAX_FRAME = 65536                  # bytes, frames FROM the cloud (requests are small)
MAX_RESPONSE = 1048576             # bytes, frames TO the cloud (an entity list can be large)
HEARTBEAT_MIN, HEARTBEAT_MAX, HEARTBEAT_DEFAULT = 10, 300, 30
SILENT_WARN_DAYS = 7               # the portal warns when the cloud has not been heard for this long

_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_ENTITY_RE = r"[a-z_]+\.[a-z0-9_]+"
_SAFE_QUERY_RE = re.compile(r"^[A-Za-z0-9_.,=&%-]{0,200}$")

# method, path pattern, minimum level
_RELAY_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("GET", re.compile(r"^/(info|me|devices|areas|entities)$"), "events"),
    ("GET", re.compile(rf"^/entities/{_ENTITY_RE}$"), "events"),
    ("GET", re.compile(rf"^/entities/{_ENTITY_RE}/snapshot$"), "full"),     # live camera images need the highest level
    ("POST", re.compile(rf"^/entities/{_ENTITY_RE}/command$"), "full"),
)


def level_ok(level: Any) -> bool:
    return isinstance(level, str) and level in LEVEL_RANK


def validate_endpoint(url: Any) -> str | None:
    """Error text, or None if the cloud address may be used.  https only (http only for localhost, for development)."""
    if not isinstance(url, str) or not url or len(url) > 200 or any(c in url for c in " \r\n\t\\\"'<>"):
        return "the address is empty, too long or has invalid characters"
    try:
        u = urlparse(url)
    except ValueError:
        return "the address is not valid"
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    if scheme not in ("https", "http") or not host:
        return "the address must start with https://"
    if u.username or u.password:
        return "the address must not contain a user name or password"
    if u.fragment or u.query:
        return "the address must not contain a query or fragment"
    loop = host in ("localhost", "127.0.0.1", "::1")
    if scheme == "http" and not loop:
        return "http is only allowed for localhost; use https://"
    if _is_ip(host):
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return "that address cannot be used"
    return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_endpoint(url: str) -> str:
    return url.strip().rstrip("/")


def validate_channel_url(channel: Any, endpoint: str) -> str | None:
    """The cloud tells the node where to open the channel.  wss:// only (ws:// only when the endpoint itself is localhost)."""
    if not isinstance(channel, str) or not channel or len(channel) > 300 or any(c in channel for c in " \r\n\t\\\"'<>"):
        return "channel address is missing or invalid"
    try:
        u = urlparse(channel)
        e = urlparse(endpoint)
    except ValueError:
        return "channel address is not valid"
    scheme, host = (u.scheme or "").lower(), (u.hostname or "").lower()
    if not host or u.username or u.password or u.fragment:
        return "channel address is not valid"
    if host != (e.hostname or "").lower():
        return "channel address must be on the same host as the cloud address"
    if scheme == "wss":
        return None
    loop = host in ("localhost", "127.0.0.1", "::1")
    if scheme == "ws" and loop:
        return None
    return "channel address must be wss://"


def validate_code(code: Any) -> str | None:
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code.strip()):
        return "the pairing code must be 8-64 letters, digits, - or _"
    return None


def validate_cloud_node_id(v: Any) -> bool:
    return isinstance(v, str) and bool(_NODE_ID_RE.fullmatch(v))


def clamp_heartbeat(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return HEARTBEAT_DEFAULT
    return int(min(HEARTBEAT_MAX, max(HEARTBEAT_MIN, v)))


def split_path(raw: Any) -> tuple[str, str] | None:
    """('/entities', 'domain=light') or None when the request path is unusable.  No dot segments, no encoded slashes, no double slashes."""
    if not isinstance(raw, str) or not raw.startswith("/") or len(raw) > 300:
        return None
    path, _, query = raw.partition("?")
    if "//" in path or ".." in path or "%" in path or "\\" in path or "#" in raw or any(ord(c) < 33 for c in raw):
        return None
    if query and not _SAFE_QUERY_RE.fullmatch(query):
        return None
    return path, query


def relay_allowed(level: str, method: Any, raw_path: Any) -> tuple[bool, str]:
    """(allowed, reason).  reason is a short machine code: ok, bad_request, path_not_allowed, level_too_low."""
    if not level_ok(level):
        return False, "level_too_low"
    parts = split_path(raw_path)
    if parts is None or not isinstance(method, str):
        return False, "bad_request"
    path, _q = parts
    m = method.upper()
    for rm, pat, need in _RELAY_RULES:
        if pat.fullmatch(path) and rm == m:
            if LEVEL_RANK[level] >= LEVEL_RANK[need]:
                return True, "ok"
            return False, "level_too_low"
    return False, "path_not_allowed"


def relay_cap(level: str) -> str | None:
    return RELAY_ROLE_CAP.get(level)


class Approval:
    """Time-boxed on-node approval for the remote debug report."""

    def __init__(self) -> None:
        self.until: float = 0.0
        self.requested: float = 0.0
        self.approved_by: str | None = None

    def approve(self, minutes: Any, who: str | None, now: float) -> tuple[bool, str]:
        if minutes is None:
            minutes = DEFAULT_APPROVAL_MIN
        if isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or not 1 <= minutes <= MAX_APPROVAL_MIN:
            return False, f"minutes must be 1-{MAX_APPROVAL_MIN}"
        self.until, self.approved_by = now + minutes * 60, who
        return True, ""

    def revoke(self) -> None:
        self.until, self.approved_by = 0.0, None

    def active(self, now: float) -> bool:
        return now < self.until

    def ask(self, now: float) -> None:
        self.requested = now

    def public(self, now: float) -> dict[str, Any]:
        return {"approved_until": self.until if self.active(now) else None, "requested": self.requested or None,
                "approved_by": self.approved_by if self.active(now) else None}


_SECRET_WORDS = r"password|passwd|secret|token|api[_-]?key|authorization|code"
_REDACT = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1***"),
    (re.compile(r"\bsl[lra]_[A-Za-z0-9_-]{8,}"), "sl*_***"),
    (re.compile(rf"(?i)(\b(?:{_SECRET_WORDS})\b[\\\"']*\s*[:=]\s*[\\\"']*)[^\s\\\"',}}&]{{3,}}"), r"\1***"),
    (re.compile(r"(?i)([?&](?:token|key|password|code|access_token)=)[^&\s]+"), r"\1***"),
)
_SECRET_KEY = re.compile(rf"(?i)(?:^|[_-])(?:{_SECRET_WORDS})(?:$|[_-])")
_MAX_DEPTH = 40


def redact(text: str) -> str:
    for pat, rep in _REDACT:
        text = pat.sub(rep, text)
    return text


def redact_obj(obj: Any, _depth: int = 0) -> Any:
    """Redact every string VALUE of a JSON-like structure (never the serialized text, which would corrupt the JSON), and
    blank string values that sit under a secret-looking key."""
    if _depth > _MAX_DEPTH:
        return "***"
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: ("***" if isinstance(v, str) and isinstance(k, str) and _SECRET_KEY.search(k) else redact_obj(v, _depth + 1)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _depth + 1) for v in obj]
    return obj


def backoff(attempt: int) -> float:
    """Reconnect delay in seconds: 2, 4, 8 ... capped at 300."""
    return float(min(300, 2 ** max(1, min(attempt, 9))))


def backoff_jitter(attempt: int, rnd: float) -> float:
    """backoff() spread over 0.5x-1.5x so a fleet does not reconnect in lockstep.  `rnd` is a random number in [0, 1)."""
    return backoff(attempt) * (0.5 + min(max(rnd, 0.0), 1.0))


STABLE_S = 60.0                    # a connection must stay up this long before the attempt counter resets
REJECT_AFTER = 3                   # consecutive 401/403/410 handshakes before the channel is marked rejected


def next_attempt(attempt: int, uptime_s: float | None) -> int:
    return 0 if uptime_s is not None and uptime_s >= STABLE_S else attempt + 1


def handshake_rejected(status: Any) -> bool:
    return status in (401, 403, 410)


class RateLimiter:
    """Token bucket: `rate` tokens per second, up to `burst`."""

    def __init__(self, rate: float = 20.0, burst: float = 40.0) -> None:
        self.rate, self.burst, self.tokens, self.t = rate, burst, burst, None

    def allow(self, now: float) -> bool:
        if self.t is not None:
            self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class AuditSampler:
    """Collapses repeated audit lines: the first event per key in a window is logged at once; the rest are counted and reported
    with the next logged one, so a flood cannot push the admin's own entries out of the (small) shared audit ring."""

    def __init__(self, window: float = 60.0) -> None:
        self.window, self.last, self.skipped = window, {}, {}

    def note(self, key: str, now: float, window: float | None = None) -> tuple[bool, int]:
        """(log_it, suppressed_since_last_log)"""
        t = self.last.get(key)
        if t is None or now - t >= (self.window if window is None else window):
            n = self.skipped.pop(key, 0)
            self.last[key] = now
            return True, n
        self.skipped[key] = self.skipped.get(key, 0) + 1
        return False, 0


def silent_days(last_seen: float | None, now: float) -> float | None:
    return None if not last_seen else max(0.0, (now - last_seen) / 86400)


def parse_frame(text: Any) -> dict[str, Any] | None:
    """A frame from the cloud: JSON object with a string `type`.  Anything else is dropped."""
    import json
    if not isinstance(text, (str, bytes)) or len(text) > MAX_FRAME:
        return None
    try:
        d = json.loads(text)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return d if isinstance(d, dict) and isinstance(d.get("type"), str) and len(d["type"]) <= 32 else None


def public_config(cfg: dict[str, Any], now: float) -> dict[str, Any]:
    """The configuration as shown to the admin (and the API): never the node secret or the relay token."""
    return {
        "enrolled": bool(cfg.get("secret")),
        "endpoint": cfg.get("endpoint"),
        "cloud_node_id": cfg.get("cloud_node_id"),
        "name": cfg.get("name"),
        "level": cfg.get("level", DEFAULT_LEVEL),
        "paused": bool(cfg.get("paused")),
        "enrolled_at": cfg.get("enrolled_at"),
        "enrolled_by": cfg.get("enrolled_by_name"),
        "heartbeat_s": cfg.get("heartbeat_s", HEARTBEAT_DEFAULT),
        "last_seen": cfg.get("last_seen"),
        "silent_days": silent_days(cfg.get("last_seen"), now),
    }
