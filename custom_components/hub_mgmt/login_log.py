"""Sign-in history: persistent, tamper-evident, role-scoped.  Pure Python (no Home Assistant imports) so it is unit-testable.

What is recorded: every sign-in attempt on every door (portal, native hub on :8123, Link API app sign-in, Link API token page)
and every support-file download.  Never recorded: passwords, tokens, 2FA codes, or what a person typed into the username box
when it is not an existing account (that is stored as "(unknown account)").

Who sees what (the privacy rule):
  homeowner, admin, superadmin  -> everybody's entries, including administrators
  everyone else                 -> only their own entries
  vendor (superadmin) entries   -> shown to everyone else as "Tez Solutions support", so the vendor cannot look without it being visible
Nobody can edit or delete entries through any API.  Each entry carries the hash of the one before it; `verify()` detects a missing,
changed or reordered entry.  Entries older than the retention (default 365 days, never below 90) are dropped and the chain is
re-anchored on the last dropped entry, so a pruned log still verifies.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

DOORS = ("portal", "hub", "link_app", "link_token", "support")
OUTCOMES = ("success", "wrong_password", "wrong_2fa", "blocked", "downloaded")
KINDS = ("signin", "support_bundle")
FLAGS = ("new_ip", "failed_burst", "support", "bundle")
FULL_ROLES = ("homeowner", "admin", "superadmin")
FULL_LINK_ROLES = (None, "manager", "admin")     # a token capped below manager only ever sees its own user's entries
MIN_RETENTION_DAYS = 90
DEFAULT_RETENTION_DAYS = 365
MAX_ENTRIES = 50000
MAX_IPS_PER_USER = 25
BURST_COUNT, BURST_WINDOW_S = 3, 600
SUPPORT_NAME = "Tez Solutions support"
UNKNOWN_NAME = "(unknown account)"
GENESIS = "0" * 64
DEFAULT_SETTINGS: dict[str, Any] = {
    "retention_days": DEFAULT_RETENTION_DAYS,
    "alerts": {"failed": True, "new_ip": True, "support": True},
    "notify_services": [],            # extra Home Assistant notify services (e.g. "mobile_app_phone") that also get every alert
}
_HASHED = ("seq", "ts", "kind", "user_id", "username", "name", "role", "door", "outcome", "ip", "device", "flags")


def device_label(ua: str | None) -> str:
    """A short, non-identifying description of the browser/app from a User-Agent string."""
    ua = (ua or "").strip()
    if not ua:
        return "unknown"
    os_ = next((n for p, n in ((r"iPhone|iPad|iOS", "iOS"), (r"Android", "Android"), (r"Windows", "Windows"), (r"Mac OS X|Macintosh", "macOS"),
                                (r"CrOS", "ChromeOS"), (r"Linux", "Linux")) if re.search(p, ua)), "")
    br = next((n for p, n in ((r"Edg/", "Edge"), (r"OPR/|Opera", "Opera"), (r"Firefox/", "Firefox"), (r"Chrome/|CriOS/", "Chrome"),
                              (r"Safari/", "Safari"), (r"HomeAssistant|Home Assistant", "Sentinel app"), (r"okhttp|aiohttp|python|curl|requests", "API client"))
               if re.search(p, ua)), "")
    return (f"{br} on {os_}" if br and os_ else br or os_ or "other")[:60]


def _digest(prev: str, entry: dict[str, Any]) -> str:
    body = json.dumps({k: entry.get(k) for k in _HASHED}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev + body).encode()).hexdigest()


class LoginLog:
    DOORS, OUTCOMES, DEFAULT_SETTINGS, MIN_RETENTION_DAYS = DOORS, OUTCOMES, DEFAULT_SETTINGS, MIN_RETENTION_DAYS

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.anchor = GENESIS            # hash of the last pruned entry (or GENESIS)
        self.next_seq = 1
        self.known_ips: dict[str, list[str]] = {}
        self.settings: dict[str, Any] = json.loads(json.dumps(DEFAULT_SETTINGS))
        self.dirty = False

    # ------------------------------------------------------------------ persistence
    def dump(self) -> dict[str, Any]:
        return {"entries": self.entries, "anchor": self.anchor, "next_seq": self.next_seq,
                "known_ips": self.known_ips, "settings": self.settings}

    def load(self, data: dict[str, Any] | None) -> None:
        data = data or {}
        self.entries = [e for e in data.get("entries", []) if isinstance(e, dict) and "hash" in e]
        self.anchor = data.get("anchor") or GENESIS
        self.next_seq = int(data.get("next_seq") or (self.entries[-1]["seq"] + 1 if self.entries else 1))
        self.known_ips = {k: list(v)[:MAX_IPS_PER_USER] for k, v in (data.get("known_ips") or {}).items()}
        st = json.loads(json.dumps(DEFAULT_SETTINGS))
        st.update({k: v for k, v in (data.get("settings") or {}).items() if k in st})
        st["alerts"] = {**DEFAULT_SETTINGS["alerts"], **{k: bool(v) for k, v in (st.get("alerts") or {}).items() if k in DEFAULT_SETTINGS["alerts"]}}
        self.settings = st

    # ------------------------------------------------------------------ writing
    def append(self, *, now: float | None = None, kind: str = "signin", user_id: str | None, username: str | None, name: str | None,
               role: str | None, door: str, outcome: str, ip: str | None, device: str | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        kind = kind if kind in KINDS else "signin"
        door = door if door in DOORS else "hub"
        outcome = outcome if outcome in OUTCOMES else "blocked"
        flags: list[str] = []
        if kind == "signin" and outcome == "success" and user_id and ip:
            seen = self.known_ips.setdefault(user_id, [])
            if seen and ip not in seen:
                flags.append("new_ip")           # the first sign-in ever is not "new"; every later unseen address is
            if ip not in seen:
                seen.append(ip)
                del seen[:-MAX_IPS_PER_USER]
        if kind == "signin" and outcome in ("wrong_password", "wrong_2fa", "blocked"):
            recent = 1 + sum(1 for e in self.entries[-200:] if e["ts"] >= now - BURST_WINDOW_S and e["kind"] == "signin"
                             and e["outcome"] in ("wrong_password", "wrong_2fa", "blocked")
                             and ((username and e.get("username") == username) or (ip and e.get("ip") == ip)))
            if recent == BURST_COUNT or (recent > BURST_COUNT and recent % 10 == 0):
                flags.append("failed_burst")
        if role == "superadmin" and ((kind == "signin" and outcome == "success") or kind == "support_bundle"):
            flags.append("support")
        if kind == "support_bundle":
            flags.append("bundle")
        e = {"seq": self.next_seq, "ts": round(now, 3), "kind": kind, "user_id": user_id, "username": username, "name": name, "role": role,
             "door": door, "outcome": outcome, "ip": ip, "device": (device or "unknown")[:60], "flags": flags}
        prev = self.entries[-1]["hash"] if self.entries else self.anchor
        e["prev"] = prev
        e["hash"] = _digest(prev, e)
        self.entries.append(e)
        self.next_seq += 1
        self.dirty = True
        return e

    def prune(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        days = max(MIN_RETENTION_DAYS, int(self.settings.get("retention_days") or DEFAULT_RETENTION_DAYS))
        cut = now - days * 86400
        n = 0
        while self.entries and (self.entries[0]["ts"] < cut or len(self.entries) > MAX_ENTRIES):
            self.anchor = self.entries.pop(0)["hash"]
            n += 1
        if n:
            self.dirty = True
        return n

    def verify(self) -> dict[str, Any]:
        prev = self.anchor
        for e in self.entries:
            if e.get("prev") != prev or e.get("hash") != _digest(prev, e):
                return {"ok": False, "entries": len(self.entries), "broken_at": e.get("seq")}
            prev = e["hash"]
        return {"ok": True, "entries": len(self.entries), "since": self.entries[0]["ts"] if self.entries else None}

    # ------------------------------------------------------------------ settings
    def set_settings(self, values: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        errs: list[str] = []
        st = json.loads(json.dumps(self.settings))
        if "retention_days" in values:
            try:
                d = int(values["retention_days"])
                if d < MIN_RETENTION_DAYS or d > 3650:
                    errs.append(f"retention_days must be between {MIN_RETENTION_DAYS} and 3650")
                else:
                    st["retention_days"] = d
            except (TypeError, ValueError):
                errs.append("retention_days must be a number")
        if "alerts" in values:
            a = values["alerts"]
            if not isinstance(a, dict) or any(k not in DEFAULT_SETTINGS["alerts"] or not isinstance(v, bool) for k, v in a.items()):
                errs.append("alerts must be {failed, new_ip, support: true|false}")
            else:
                st["alerts"].update(a)
        if "notify_services" in values:
            ns = values["notify_services"]
            if not isinstance(ns, list) or len(ns) > 10 or any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", x) for x in ns):
                errs.append("notify_services must be a list of up to 10 service names like mobile_app_phone")
            else:
                st["notify_services"] = sorted(set(ns))
        if not errs:
            self.settings = st
            self.dirty = True
        return self.settings, errs

    def alert_kinds(self, entry: dict[str, Any]) -> list[str]:
        a = self.settings["alerts"]
        out = []
        if "failed_burst" in entry["flags"] and a.get("failed"):
            out.append("failed")
        if "new_ip" in entry["flags"] and a.get("new_ip"):
            out.append("new_ip")
        if ("support" in entry["flags"] or "bundle" in entry["flags"]) and a.get("support"):
            out.append("support")
        return out

    # ------------------------------------------------------------------ reading (the privacy rules live here)
    @staticmethod
    def scope_for(role: str | None, link_role: str | None = None) -> str:
        return "all" if role in FULL_ROLES and link_role in FULL_LINK_ROLES else "own"

    @staticmethod
    def present(e: dict[str, Any], viewer_role: str | None) -> dict[str, Any]:
        out = {k: e.get(k) for k in ("seq", "ts", "kind", "user_id", "username", "name", "role", "door", "outcome", "ip", "device", "flags")}
        out["id"] = out["seq"]
        if e.get("role") == "superadmin" and viewer_role != "superadmin":
            out.update(user_id=None, username="tez-solutions-support", name=SUPPORT_NAME, role="support")
        return out

    def visible(self, e: dict[str, Any], viewer_id: str | None, viewer_role: str | None, link_role: str | None = None) -> bool:
        if self.scope_for(viewer_role, link_role) == "all":
            return True
        return bool(viewer_id) and e.get("user_id") == viewer_id

    def query(self, viewer_id: str | None, viewer_role: str | None, link_role: str | None = None, *, user: str | None = None,
              door: str | None = None, outcome: str | None = None, since: float | None = None, until: float | None = None,
              alerts_only: bool = False, limit: int = 100, before: int | None = None) -> dict[str, Any]:
        limit = max(1, min(int(limit or 100), 1000))
        rows = []
        total = 0
        for e in reversed(self.entries):
            if not self.visible(e, viewer_id, viewer_role, link_role):
                continue
            p = self.present(e, viewer_role)
            if user and user.casefold() not in {str(p.get("username") or "").casefold(), str(p.get("name") or "").casefold(), str(p.get("user_id") or "")}:
                continue
            if door and p["door"] != door:
                continue
            if outcome and p["outcome"] != outcome:
                continue
            if since is not None and p["ts"] < since:
                continue
            if until is not None and p["ts"] > until:
                continue
            if alerts_only and not p["flags"]:
                continue
            total += 1
            if before is not None and p["seq"] >= before:
                continue
            if len(rows) < limit:
                rows.append(p)
        return {"logins": rows, "total": total, "scope": self.scope_for(viewer_role, link_role),
                "next_before": rows[-1]["seq"] if len(rows) == limit and total > len(rows) else None,
                "integrity": self.verify(), "retention_days": self.settings["retention_days"]}

    def summary(self, viewer_id: str | None, viewer_role: str | None, link_role: str | None = None, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        out: dict[str, Any] = {"scope": self.scope_for(viewer_role, link_role), "integrity": self.verify(), "retention_days": self.settings["retention_days"]}
        for label, secs in (("last_24h", 86400), ("last_7d", 7 * 86400)):
            c = {"success": 0, "failed": 0, "new_ip": 0, "support": 0}
            for e in reversed(self.entries):
                if e["ts"] < now - secs:
                    break
                if not self.visible(e, viewer_id, viewer_role, link_role):
                    continue
                if e["kind"] == "signin" and e["outcome"] == "success":
                    c["success"] += 1
                elif e["kind"] == "signin":
                    c["failed"] += 1
                c["new_ip"] += "new_ip" in e["flags"]
                c["support"] += ("support" in e["flags"] or "bundle" in e["flags"])
            out[label] = c
        last = next((self.present(e, viewer_role) for e in reversed(self.entries)
                     if e["kind"] == "signin" and e["outcome"] == "success" and e.get("user_id") == viewer_id), None)
        out["your_last_sign_in"] = last
        return out


def alert_text(e: dict[str, Any], kind: str, node: str = "") -> tuple[str, str]:
    """(title, message) for a notification.  Written for the person receiving it; mentions the address, never a secret."""
    who = SUPPORT_NAME if e.get("role") == "superadmin" else (e.get("name") or e.get("username") or UNKNOWN_NAME)
    where = f" from {e['ip']}" if e.get("ip") else ""
    how = {"portal": "the portal", "hub": "the hub", "link_app": "an app", "link_token": "the token page"}.get(e.get("door"), "the system")
    site = f" on {node}" if node else ""
    if kind == "failed":
        return "Repeated failed sign-ins", f"Several failed sign-in attempts{site} for {who}{where} via {how}."
    if kind == "new_ip":
        return "Sign-in from a new location", f"{who} signed in{site} from a new address{where} via {how} ({e.get('device') or 'unknown device'})."
    if e.get("kind") == "support_bundle":
        return "Support file downloaded", f"{who} downloaded a support file{site}{where}."
    return "Tez Solutions support signed in", f"{SUPPORT_NAME} signed in{site}{where}."
