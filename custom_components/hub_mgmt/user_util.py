"""Pure helpers for the portal user / profile / 2FA / session commands (no hub-core imports, unit-tested)."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

PW_MIN, PW_MAX = 8, 128
_WEAK = {
    "password", "password1", "password12", "password123", "passw0rd", "12345678", "123456789", "1234567890",
    "qwertyui", "qwerty123", "11111111", "00000000", "abcd1234", "admin123", "administrator", "letmein1",
    "welcome1", "iloveyou", "sentinel", "sentinel1", "sentinel123", "changeme", "changeme1", "tezsolutions",
}
_NAME_MAX = 60
_CODE_RE = re.compile(r"^\d{6}$")


class Bad(ValueError):
    """User-facing validation error."""


def check_password(pw: Any, username: str = "", name: str = "") -> str:
    if not isinstance(pw, str):
        raise Bad("Password must be text")
    if len(pw) < PW_MIN:
        raise Bad(f"Password must be at least {PW_MIN} characters")
    if len(pw) > PW_MAX:
        raise Bad(f"Password is too long (max {PW_MAX})")
    low = pw.casefold()
    if low in _WEAK:
        raise Bad("That password is too common. Choose something less guessable")
    if len(set(low)) <= 2:
        raise Bad("Password is too repetitive")
    for ref in (username, name):
        r = (ref or "").casefold().strip()
        if len(r) >= 3 and (low == r or low.strip("0123456789!._-") == r):
            raise Bad("Password must not be your name or username")
    if pw != pw.strip():
        raise Bad("Password must not start or end with a space")
    return pw


def clean_display_name(v: Any) -> str:
    if not isinstance(v, str):
        raise Bad("Name must be text")
    v = re.sub(r"\s+", " ", v).strip()
    if not v:
        raise Bad("Name is required")
    if len(v) > _NAME_MAX:
        raise Bad(f"Name is too long (max {_NAME_MAX})")
    if re.search(r"[\x00-\x1f<>]", v):
        raise Bad("Name contains characters that are not allowed")
    return v


def clean_code(v: Any) -> str:
    v = re.sub(r"\s+", "", str(v or ""))
    if not _CODE_RE.match(v):
        raise Bad("Enter the 6-digit code from your authenticator app")
    return v


class Throttle:
    """Max `limit` failures per key inside `window` seconds; success clears the key. Clock is injectable for tests."""

    def __init__(self, limit: int = 5, window: float = 300.0, clock: Callable[[], float] = time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._f: dict[str, list[float]] = {}

    def _live(self, key: str) -> list[float]:
        now = self.clock()
        lst = [t for t in self._f.get(key, []) if now - t < self.window]
        if lst:
            self._f[key] = lst
        else:
            self._f.pop(key, None)
        return lst

    def wait(self, key: str) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        lst = self._live(key)
        if len(lst) < self.limit:
            return 0
        return max(1, int(self.window - (self.clock() - lst[0])))

    def fail(self, key: str) -> None:
        self._live(key)
        self._f.setdefault(key, []).append(self.clock())
        if len(self._f) > 2000:  # bound memory
            for k in list(self._f)[:500]:
                self._live(k)

    def ok(self, key: str) -> None:
        self._f.pop(key, None)


def client_label(client_id: str | None, client_name: str | None) -> str:
    cid = (client_id or "").strip()
    if client_name:
        return client_name[:60]
    m = re.match(r"^https?://([^/:]+)", cid)
    host = m.group(1) if m else ""
    if host in {"127.0.0.1", "localhost"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return "Node portal"
    return host[:60] or "App"


def session_view(token_id: str, client_id: str | None, client_name: str | None, created: Any, last_used: Any,
                 ip: str | None, current_id: str | None) -> dict[str, Any]:
    def iso(v):
        return v.isoformat() if hasattr(v, "isoformat") else None
    return {
        "id": token_id, "client": client_label(client_id, client_name),
        "created": iso(created), "last_used": iso(last_used), "ip": (ip or "")[:45] or None,
        "current": bool(current_id) and token_id == current_id,
    }


def newest(dts) -> str | None:
    best = None
    for d in dts:
        if d is not None and (best is None or d > best):
            best = d
    return best.isoformat() if best is not None else None
