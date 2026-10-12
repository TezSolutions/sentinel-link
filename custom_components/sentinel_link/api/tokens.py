"""Sentinel Link API tokens, OAuth2 clients, authorization codes and sign-in throttling.

Pure Python (no hub-core imports) so it is unit-testable. Design:

* Link tokens are issued by Sentinel Link itself and are valid ONLY on the Link API
  (``/api/sentinel_link/*``) - never on the rest of the hub core.
* Secrets are random, shown once and stored only as SHA-256 hashes (256-bit random secrets, so a plain hash is safe).
* Long-lived tokens and refresh tokens never expire by default (home-automation apps run for years);
  an expiry is optional and every token can be revoked instantly.
* Access tokens (from the OAuth flow) are short lived and kept in memory only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from typing import Any
from urllib.parse import urlparse

KIND_LONG = "long_lived"
KIND_REFRESH = "refresh"
KIND_ACCESS = "access"

PREFIX = {KIND_LONG: "sll_", KIND_REFRESH: "slr_", KIND_ACCESS: "sla_"}
_PREFIX_KIND = {v: k for k, v in PREFIX.items()}

ACCESS_TTL = 30 * 60          # seconds
CODE_TTL = 300                # authorization code lifetime
REFRESH_GRACE = 60            # the previous refresh token still works this long (lost-response retry)
MAX_TOKENS_PER_USER = 50
MAX_CLIENTS = 50
MAX_REDIRECTS = 10

ROLE_RANK = {"viewer": 1, "operator": 2, "manager": 3, "admin": 4}
SCOPES = ("users:write", "users:password", "logins:settings")      # extra powers a token must be GRANTED; roles alone never give them
CAPPABLE = ("viewer", "operator", "manager")   # a token can be limited to these

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$")
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")           # base64url(SHA-256) without padding
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")      # RFC 7636
_BAD_SCHEMES = frozenset({"javascript", "data", "file", "vbscript", "blob", "about", "ftp", "ws", "wss", "chrome", "intent"})


def effective_role(role: str | None, cap: str | None) -> str | None:
    """A token can never exceed its user's CURRENT role; an optional cap lowers it further.
    A custom role combined with a cap is denied rather than guessed (custom roles have no rank)."""
    if role is None or not cap:
        return role
    if role not in ROLE_RANK or cap not in ROLE_RANK:
        return None
    return role if ROLE_RANK[role] <= ROLE_RANK[cap] else cap


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def new_token_string(kind: str) -> tuple[str, str, str]:
    """Return (token_id, secret_hash, full_token). Format: <prefix><id>.<secret>."""
    tid = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    return tid, _hash(secret), f"{PREFIX[kind]}{tid}.{secret}"


def parse_token(token: str) -> tuple[str, str, str] | None:
    """Split a presented token into (kind, id, secret); None if it is not a Link token."""
    if not isinstance(token, str) or len(token) > 200:
        return None
    for pre, kind in _PREFIX_KIND.items():
        if token.startswith(pre):
            body = token[len(pre):]
            tid, dot, secret = body.partition(".")
            if dot and re.fullmatch(r"[0-9a-f]{12}", tid) and 20 <= len(secret) <= 100:
                return kind, tid, secret
            return None
    return None


# ----------------------------------------------------------------------------------------------- PKCE / URIs
def pkce_ok(verifier: str, challenge: str) -> bool:
    if not (isinstance(verifier, str) and isinstance(challenge, str) and _VERIFIER_RE.fullmatch(verifier)):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    calc = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return hmac.compare_digest(calc.encode(), challenge.encode())


def valid_challenge(challenge: Any) -> bool:
    return isinstance(challenge, str) and bool(_CHALLENGE_RE.fullmatch(challenge))


def validate_redirect_uri(uri: str) -> str | None:
    """Return an error text, or None if the redirect URI may be registered."""
    if not isinstance(uri, str) or not uri or len(uri) > 300 or any(c in uri for c in " \r\n\t\\"):
        return "redirect URI is empty or contains invalid characters"
    try:
        u = urlparse(uri)
    except ValueError:
        return "redirect URI is not valid"
    scheme = (u.scheme or "").lower()
    if not scheme:
        return "redirect URI needs a scheme"
    if u.fragment:
        return "redirect URI must not contain a fragment"
    if scheme in _BAD_SCHEMES:
        return f"scheme '{scheme}' is not allowed"
    if scheme == "https":
        return None if u.hostname else "https redirect URI needs a host"
    if scheme == "http":
        return None if u.hostname in ("localhost", "127.0.0.1", "::1") else "http is only allowed for localhost"
    # app deep links: reverse-DNS or dashed custom scheme (com.example.app://callback), never a bare word
    if "." in scheme or "-" in scheme:
        return None
    return "custom schemes must look like com.example.app or my-app"


# ------------------------------------------------------------------------------------------------ throttle
class Throttle:
    """Sliding-window failure counter with lockout, keyed by user name and by client IP."""

    def __init__(self, max_fail: int = 8, window: float = 600.0, lock: float = 900.0) -> None:
        self.max_fail, self.window, self.lock = max_fail, window, lock
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}

    def locked(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        until = self._locked.get(key)
        if until is None:
            return False
        if now >= until:
            self._locked.pop(key, None)
            self._fails.pop(key, None)
            return False
        return True

    def fail(self, key: str, now: float | None = None) -> bool:
        """Record a failure; return True if the key is now locked."""
        now = time.time() if now is None else now
        recent = [t for t in self._fails.get(key, []) if now - t < self.window] + [now]
        self._fails[key] = recent
        if len(recent) >= self.max_fail:
            self._locked[key] = now + self.lock
            return True
        if len(self._fails) > 5000:   # bound memory
            self._fails.pop(next(iter(self._fails)))
        return False

    def ok(self, key: str) -> None:
        self._fails.pop(key, None)


# ------------------------------------------------------------------------------------------------ the book
class TokenBook:
    """Clients, authorization codes and tokens. Persisted: clients + long-lived + refresh tokens."""

    def __init__(self) -> None:
        self.clients: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}      # long_lived + refresh (persisted)
        self.access: dict[str, dict[str, Any]] = {}      # access (memory only)
        self.codes: dict[str, dict[str, Any]] = {}       # code-hash -> record (memory only)
        self.dirty = False

    # ------------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        return {"clients": self.clients, "tokens": self.tokens}

    def load(self, data: dict[str, Any] | None) -> None:
        data = data or {}
        self.clients = {k: v for k, v in (data.get("clients") or {}).items() if isinstance(v, dict)}
        self.tokens = {k: v for k, v in (data.get("tokens") or {}).items() if isinstance(v, dict) and v.get("hash")}

    # ------------------------------------------------------------------ clients (OAuth apps)
    def save_client(self, client_id: str, name: str, redirect_uris: list[str]) -> list[str]:
        errs: list[str] = []
        if not isinstance(client_id, str) or not _CLIENT_ID_RE.fullmatch(client_id):
            errs.append("client_id must be 2-128 characters: letters, digits and . _ : / -")
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 60):
            errs.append("name must be 1-60 characters")
        if not isinstance(redirect_uris, list) or not (1 <= len(redirect_uris) <= MAX_REDIRECTS):
            errs.append(f"1-{MAX_REDIRECTS} redirect URIs are required")
        else:
            for u in redirect_uris:
                e = validate_redirect_uri(u)
                if e:
                    errs.append(f"{u!r}: {e}")
        if client_id not in self.clients and len(self.clients) >= MAX_CLIENTS:
            errs.append("too many registered apps")
        if errs:
            return errs
        old = self.clients.get(client_id, {})
        self.clients[client_id] = {"client_id": client_id, "name": name.strip(),
                                   "redirect_uris": sorted(set(redirect_uris)),
                                   "created": old.get("created") or time.time()}
        self.dirty = True
        return []

    def remove_client(self, client_id: str) -> list[str]:
        """Remove an app and revoke every session it holds. Returns the revoked token ids."""
        if self.clients.pop(client_id, None) is None:
            return []
        gone = [tid for tid, t in self.tokens.items() if t.get("client_id") == client_id]
        gone += [tid for tid, t in self.access.items() if t.get("client_id") == client_id]
        for tid in gone:
            self.tokens.pop(tid, None)
            self.access.pop(tid, None)
        self.dirty = True
        return gone

    def redirect_ok(self, client_id: str, redirect_uri: str) -> bool:
        c = self.clients.get(client_id)
        return bool(c) and redirect_uri in c["redirect_uris"]

    # ------------------------------------------------------------------ long-lived tokens
    def create_long_lived(self, user_id: str, name: str, *, expires_in_days: int | None = None,
                          max_role: str | None = None, created_by: str | None = None,
                          scopes: list[str] | None = None, now: float | None = None) -> tuple[dict[str, Any] | None, str | list[str]]:
        """Return (record, plaintext_token) or (None, [errors])."""
        now = time.time() if now is None else now
        errs: list[str] = []
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 60):
            errs.append("name must be 1-60 characters")
        if expires_in_days is not None and not (isinstance(expires_in_days, int) and not isinstance(expires_in_days, bool)
                                                and 1 <= expires_in_days <= 3650):
            errs.append("expires_in_days must be 1-3650 or null (no expiry)")
        if max_role is not None and max_role not in CAPPABLE:
            errs.append(f"max_role must be one of {list(CAPPABLE)} or null")
        scopes = sorted(set(scopes or []))
        if any(s not in SCOPES for s in scopes):
            errs.append(f"scopes must be among {list(SCOPES)}")
        if sum(1 for t in self.tokens.values() if t["kind"] == KIND_LONG and t["user_id"] == user_id) >= MAX_TOKENS_PER_USER:
            errs.append(f"limit of {MAX_TOKENS_PER_USER} long-lived tokens per user reached")
        if errs:
            return None, errs
        tid, h, tok = new_token_string(KIND_LONG)
        rec = {"id": tid, "kind": KIND_LONG, "hash": h, "user_id": user_id, "name": name.strip(),
               "created": now, "last_used": None, "expires": (now + expires_in_days * 86400) if expires_in_days else None,
               "max_role": max_role, "created_by": created_by or user_id, "client_id": None, "scopes": scopes}
        self.tokens[tid] = rec
        self.dirty = True
        return rec, tok

    # ------------------------------------------------------------------ OAuth: codes, access, refresh
    def new_code(self, client_id: str, redirect_uri: str, challenge: str, user_id: str,
                 now: float | None = None) -> str:
        now = time.time() if now is None else now
        self.codes = {h: c for h, c in self.codes.items() if c["exp"] > now}   # purge
        if len(self.codes) > 500:
            self.codes.clear()
        code = secrets.token_urlsafe(32)
        self.codes[_hash(code)] = {"client_id": client_id, "redirect_uri": redirect_uri, "challenge": challenge,
                                   "user_id": user_id, "exp": now + CODE_TTL}
        return code

    def redeem_code(self, code: str, client_id: str, redirect_uri: str, verifier: str,
                    now: float | None = None) -> dict[str, Any] | None:
        """Single use: the code is consumed even if the other checks fail."""
        now = time.time() if now is None else now
        rec = self.codes.pop(_hash(code or ""), None)
        if rec is None or rec["exp"] <= now:
            return None
        if rec["client_id"] != client_id or rec["redirect_uri"] != redirect_uri:
            return None
        if not pkce_ok(verifier, rec["challenge"]):
            return None
        return rec

    def _issue_access(self, user_id: str, client_id: str | None, refresh_id: str | None, max_role: str | None,
                      now: float) -> tuple[str, dict[str, Any]]:
        tid, h, tok = new_token_string(KIND_ACCESS)
        rec = {"id": tid, "kind": KIND_ACCESS, "hash": h, "user_id": user_id, "client_id": client_id,
               "refresh_id": refresh_id, "max_role": max_role, "expires": now + ACCESS_TTL, "created": now}
        self.access[tid] = rec
        if len(self.access) > 5000:
            self.purge(now)
        return tok, rec

    def issue_session(self, user_id: str, client_id: str, now: float | None = None) -> dict[str, Any]:
        """Create a refresh token (never expires, rotates on use) + its first access token."""
        now = time.time() if now is None else now
        rid, rh, rtok = new_token_string(KIND_REFRESH)
        name = (self.clients.get(client_id) or {}).get("name") or client_id
        self.tokens[rid] = {"id": rid, "kind": KIND_REFRESH, "hash": rh, "prev_hash": None, "prev_until": 0,
                            "user_id": user_id, "client_id": client_id, "name": name, "created": now,
                            "last_used": now, "expires": None, "max_role": None, "created_by": user_id}
        self.dirty = True
        atok, arec = self._issue_access(user_id, client_id, rid, None, now)
        return {"access_token": atok, "refresh_token": rtok, "token_type": "Bearer",
                "expires_in": ACCESS_TTL, "access_id": arec["id"], "refresh_id": rid}

    def refresh(self, refresh_token: str, client_id: str, now: float | None = None) -> dict[str, Any] | None:
        now = time.time() if now is None else now
        p = parse_token(refresh_token)
        if not p or p[0] != KIND_REFRESH:
            return None
        rec = self.tokens.get(p[1])
        if not rec or rec["kind"] != KIND_REFRESH or rec.get("client_id") != client_id:
            return None
        h = _hash(p[2])
        current = _eq(h, rec["hash"])
        in_grace = (not current and bool(rec.get("prev_hash")) and now < rec.get("prev_until", 0)
                    and _eq(h, rec["prev_hash"]))
        if not (current or in_grace):
            # a retired refresh token came back after the grace window: treat as theft, kill the whole session
            if any(_eq(h, old) for old in rec.get("old") or []):
                self.revoke(rec["id"])
            return None
        if rec.get("expires") and rec["expires"] <= now:
            return None
        secret = secrets.token_urlsafe(32)
        rec["old"] = ((rec.get("old") or []) + [rec["hash"]])[-8:]
        if current:
            rec["prev_hash"], rec["prev_until"] = rec["hash"], now + REFRESH_GRACE   # lost-response retry window
        rec["hash"] = _hash(secret)
        rec["last_used"] = now
        self.dirty = True
        atok, arec = self._issue_access(rec["user_id"], client_id, rec["id"], rec.get("max_role"), now)
        return {"access_token": atok, "refresh_token": f"{PREFIX[KIND_REFRESH]}{rec['id']}.{secret}",
                "token_type": "Bearer", "expires_in": ACCESS_TTL, "access_id": arec["id"], "refresh_id": rec["id"],
                "user_id": rec["user_id"]}

    # ------------------------------------------------------------------ authenticate / revoke
    def authenticate(self, token: str, now: float | None = None) -> dict[str, Any] | None:
        """Return the token record for an access or long-lived token (not refresh), else None."""
        now = time.time() if now is None else now
        p = parse_token(token)
        if not p or p[0] == KIND_REFRESH:
            return None
        kind, tid, secret = p
        rec = (self.access if kind == KIND_ACCESS else self.tokens).get(tid)
        if not rec or rec["kind"] != kind or not _eq(_hash(secret), rec["hash"]):
            return None
        if rec.get("expires") and rec["expires"] <= now:
            return None
        if kind == KIND_LONG and (rec.get("last_used") is None or now - rec["last_used"] > 300):
            rec["last_used"] = now      # at most one write per 5 minutes
            self.dirty = True
        return rec

    def revoke(self, token_id: str) -> list[str]:
        """Revoke a session/token by id. Returns every token id removed (incl. access tokens of a session)."""
        gone: list[str] = []
        if self.tokens.pop(token_id, None) is not None:
            gone.append(token_id)
            self.dirty = True
        if self.access.pop(token_id, None) is not None:
            gone.append(token_id)
        for aid, a in list(self.access.items()):
            if a.get("refresh_id") == token_id:
                self.access.pop(aid, None)
                gone.append(aid)
        return gone

    def revoke_presented(self, token: str) -> list[str]:
        """RFC 7009: revoke the token the caller holds (any kind), only if its secret is right."""
        p = parse_token(token)
        if not p:
            return []
        kind, tid, secret = p
        rec = (self.access if kind == KIND_ACCESS else self.tokens).get(tid)
        if not rec or not _eq(_hash(secret), rec["hash"]):
            return []
        return self.revoke(tid)

    def revoke_user(self, user_id: str) -> list[str]:
        gone: list[str] = []
        for tid in [t for t, r in self.tokens.items() if r["user_id"] == user_id]:
            gone += self.revoke(tid)
        for tid in [t for t, r in self.access.items() if r["user_id"] == user_id]:
            gone += self.revoke(tid)
        return gone

    def purge(self, now: float | None = None) -> list[str]:
        """Drop expired access/long-lived tokens and codes; return ids that were live-expired."""
        now = time.time() if now is None else now
        dead = [t for t, r in self.access.items() if r["expires"] <= now]
        dead += [t for t, r in self.tokens.items() if r.get("expires") and r["expires"] <= now]
        for t in dead:
            self.access.pop(t, None)
            if self.tokens.pop(t, None) is not None:
                self.dirty = True
        self.codes = {h: c for h, c in self.codes.items() if c["exp"] > now}
        return dead

    # ------------------------------------------------------------------ listing (never returns secrets)
    @staticmethod
    def public(rec: dict[str, Any]) -> dict[str, Any]:
        return {"id": rec["id"], "kind": rec["kind"], "name": rec.get("name"), "user_id": rec["user_id"],
                "client_id": rec.get("client_id"), "created": rec.get("created"), "last_used": rec.get("last_used"),
                "expires": rec.get("expires"), "max_role": rec.get("max_role"), "scopes": rec.get("scopes") or []}

    def list(self, user_id: str | None = None) -> list[dict[str, Any]]:
        rows = [self.public(r) for r in self.tokens.values() if user_id is None or r["user_id"] == user_id]
        rows.sort(key=lambda r: r.get("created") or 0, reverse=True)
        return rows
