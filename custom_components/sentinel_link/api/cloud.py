"""Cloud channel (Part B): pairs this node with a third-party cloud platform and keeps one OUTBOUND secure WebSocket open to it.

* The node dials out; nothing listens for the cloud.  Rules (levels, what the relay may reach, approval, redaction) live in `cloud_rules.py`.
* Requests from the cloud are NOT handled by separate code: they are replayed against this node's own Link API on loopback with a short-lived
  in-memory relay token (scope `cloud`, role capped by the sharing level), so every role check, exposure filter, validation and audit entry of the
  normal API applies unchanged.
* The cloud can never change the sharing level, manage users/tokens/apps/settings, or read the audit trail.  The node admin can pause or disconnect any time.

Wire protocol (JSON frames, both directions, `type` string):
  node -> cloud   hello {node_id, cloud_node_id, version, api_version, level}          first frame after connecting
                  heartbeat {ts, level, status{...}}                                    every `heartbeat_s`
                  response {id, status, body | body_b64}                                answer to a request (413 = reply over 1 MiB, 429 = rate limited / busy)
                  event {event{...}}                                                    entity state changes only: type state/removed (level events/full only)
                  debug_report {id, report} / debug_denied {id, reason}                 answer to debug_request
  cloud -> node   ack {}                                                                 any frame counts as proof of life
                  request {id, method, path, body?, by?}                                 relayed to the Link API (see cloud_rules.relay_allowed)
                  debug_request {id, by?}                                                needs on-node approval
                  unenroll {}                                                            the cloud removes this node

The channel address must be on the same host as the cloud address.  After repeated 401/403/410 at the handshake the node stops retrying and
reports `rejected` (re-pair required).  If the pairing admin is removed/deactivated/demoted the status shows a `problem` and the feed and relay stop.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import random
import socket
import time
from typing import Any

import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import cloud_rules as rules
from .tokens import parse_token

_LOGGER = logging.getLogger(__name__)
ENROLL_PATH = "/v1/nodes/enroll"
UNENROLL_PATH = "/v1/nodes/{id}/unenroll"
MAX_INFLIGHT = 4
PERSIST_EVERY = 300.0
_BIG = 16384            # largest reply we accept from the enrol endpoint
MAX_PENDING = 16        # relayed requests running or queued at once; more get a 429
MAX_SENDS = 256         # outgoing frames in flight; events and heartbeats are dropped beyond this
MAX_SENDS_HARD = 512    # even answers are refused beyond this
_CHUNK = 65536


async def read_capped(content: Any, limit: int) -> bytes | None:
    """Read a response body in chunks.  A single `content.read(n)` returns only what is buffered, not n bytes, so large replies were cut
    short.  Returns None as soon as the body exceeds `limit` bytes."""
    buf = bytearray()
    async for chunk in content.iter_chunked(_CHUNK):
        buf += chunk
        if len(buf) > limit:
            return None
    return bytes(buf)


class CloudError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class CloudChannel:
    def __init__(self, st: Any) -> None:
        self.st = st
        self.hass = st.hass
        self.cfg: dict[str, Any] = {}
        self.approval = rules.Approval()
        self._task: asyncio.Task | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._sub: int | None = None
        self._relay_tok: tuple[str, float] | None = None
        self._sem = asyncio.Semaphore(MAX_INFLIGHT)
        self._last_persist = 0.0
        self._lock = asyncio.Lock()                       # enrol / disconnect must not interleave
        self._reqs: set[asyncio.Task] = set()
        self._sends = 0
        self._limiter = rules.RateLimiter()
        self._audit = rules.AuditSampler()
        self._up_mono: float | None = None
        self.rt: dict[str, Any] = {"connected": False, "since": None, "last_error": None, "attempt": 0, "frames_in": 0, "frames_out": 0,
                                "rejected": False, "problem": None}

    # ------------------------------------------------------------------ persistence
    def load(self, data: dict[str, Any] | None) -> None:
        self.cfg = dict(data or {})
        a = self.cfg.pop("approval", None) or {}
        if isinstance(a, dict) and a.get("until", 0) > time.time():     # an approval survives a restart only until it expires
            self.approval.until, self.approval.approved_by = float(a["until"]), a.get("by")

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.cfg)
        if self.approval.active(time.time()):
            d["approval"] = {"until": self.approval.until, "by": self.approval.approved_by}
        return d

    @property
    def enrolled(self) -> bool:
        return bool(self.cfg.get("secret"))

    # ------------------------------------------------------------------ lifecycle (called from ApiState.async_start/async_stop)
    def start(self) -> None:
        if self._task is None or self._task.done():
            if self.enrolled and not self.cfg.get("paused") and self.st.enabled:
                self._task = self.hass.async_create_background_task(self._run(), "sentinel_link_cloud_channel")

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None
        self._unsubscribe()
        self._revoke_relay()
        for t in list(self._reqs):                       # queued / running relay requests must not outlive a pause or disconnect
            t.cancel()
        self._reqs.clear()
        self.rt.update(connected=False, since=None)

    def _revoke_relay(self) -> None:
        """Drop the relay token AND revoke it, so a request that already captured the string cannot use it."""
        if self._relay_tok is not None:
            p = parse_token(self._relay_tok[0])
            self._relay_tok = None
            if p:
                try:
                    self.st.book.revoke(p[1])
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("relay token revoke failed", exc_info=True)

    def restart(self) -> None:
        self.stop()
        self.start()

    # ------------------------------------------------------------------ status for the portal / API
    def status(self) -> dict[str, Any]:
        now = time.time()
        pub = rules.public_config(self.cfg, now)
        pub.update(connected=bool(self.rt["connected"]), connected_since=self.rt["since"], last_error=self.rt["last_error"],
                   frames_in=self.rt["frames_in"], frames_out=self.rt["frames_out"], debug=self.approval.public(now),
                   silent_warning=bool(pub["enrolled"] and not pub["paused"] and pub["silent_days"] is not None and pub["silent_days"] >= rules.SILENT_WARN_DAYS),
                   levels=list(rules.LEVELS), can_enroll=not pub["enrolled"], rejected=bool(self.rt.get("rejected")),
                   problem=self.rt.get("problem"))
        return pub

    # ------------------------------------------------------------------ enrol / configure / disconnect
    async def _host_ok(self, url: str) -> None:
        """Refuse addresses that resolve to link-local / multicast / unspecified (cloud metadata and similar)."""
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as e:
            raise CloudError("unreachable", f"Cannot resolve {host}", 502) from e
        for info in infos:
            ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise CloudError("bad_endpoint", "That address cannot be used", 400)

    async def enroll(self, user: Any, endpoint: Any, code: Any, level: Any = None, name: Any = None) -> dict[str, Any]:
        async with self._lock:
            return await self._enroll(user, endpoint, code, level, name)

    async def _enroll(self, user: Any, endpoint: Any, code: Any, level: Any = None, name: Any = None) -> dict[str, Any]:
        if self.enrolled:
            raise CloudError("already_enrolled", "This node is already connected. Disconnect it first.", 409)
        err = rules.validate_endpoint(endpoint) or rules.validate_code(code)
        if err:
            raise CloudError("invalid", err)
        if level is not None and not rules.level_ok(level):
            raise CloudError("invalid", f"level must be one of {list(rules.LEVELS)}")
        if name is not None and (not isinstance(name, str) or len(name) > 60):
            raise CloudError("invalid", "name must be at most 60 characters")
        endpoint = rules.normalize_endpoint(endpoint)
        await self._host_ok(endpoint)
        body = {"code": code.strip(), "node_id": self.st.node_id, "node_name": (name or self.hass.config.location_name or self.st.node_id)[:60],
                "version": self.st.version, "api_version": "1", "capabilities": ["levels", "relay", "events", "debug_report"]}
        try:
            async with async_get_clientsession(self.hass).post(endpoint + ENROLL_PATH, json=body, allow_redirects=False,
                                                              timeout=aiohttp.ClientTimeout(total=15)) as r:
                raw = await read_capped(r.content, _BIG)
                status = r.status
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise CloudError("unreachable", f"Cannot reach the cloud platform ({type(e).__name__})", 502) from e
        if raw is None:
            raise CloudError("bad_reply", "The cloud platform sent an oversized reply", 502)
        if status in (400, 401, 403, 404, 409, 410):
            raise CloudError("code_rejected", "The cloud platform did not accept this pairing code (wrong, used or expired)", 400)
        if status != 200:
            raise CloudError("bad_reply", f"The cloud platform answered {status}", 502)
        try:
            d = json.loads(raw)
            cid, secret, channel = d["cloud_node_id"], d["node_secret"], d["channel_url"]
        except (ValueError, KeyError, TypeError) as e:
            raise CloudError("bad_reply", "The cloud platform's reply is incomplete", 502) from e
        if not rules.validate_cloud_node_id(cid) or not isinstance(secret, str) or not 16 <= len(secret) <= 256 or rules.validate_channel_url(channel, endpoint):
            raise CloudError("bad_reply", rules.validate_channel_url(channel, endpoint) or "The cloud platform's reply is not valid", 502)
        await self._host_ok(channel)                     # the channel host is checked like the endpoint (it must also equal it, see validate_channel_url)
        self.cfg = {"endpoint": endpoint, "cloud_node_id": cid, "secret": secret, "channel_url": channel, "name": body["node_name"],
                    "level": level or rules.DEFAULT_LEVEL, "paused": False, "enrolled_at": time.time(), "enrolled_by": user.id,
                    "enrolled_by_name": user.name, "heartbeat_s": rules.clamp_heartbeat(d.get("heartbeat_s")), "last_seen": None}
        self.approval.revoke()
        self.rt.update(rejected=False, problem=None, last_error=None)
        self.start()
        return self.status()

    def configure(self, changes: dict[str, Any]) -> list[str]:
        """Admin settings.  Returns a list of problems (empty = applied)."""
        errs: list[str] = []
        allowed = {"level", "paused", "name", "endpoint"}
        bad = sorted(set(changes) - allowed)
        if bad:
            return [f"unknown setting: {', '.join(bad)}"]
        if not self.enrolled and set(changes) - {"endpoint"}:
            return ["this node is not connected to a cloud platform; connect it first"]
        if "endpoint" in changes:
            if self.enrolled:
                errs.append("the address cannot be changed while connected; disconnect first")
            else:
                e = rules.validate_endpoint(changes["endpoint"])
                if e:
                    errs.append(e)
        if "level" in changes and not rules.level_ok(changes["level"]):
            errs.append(f"level must be one of {list(rules.LEVELS)}")
        if "paused" in changes and not isinstance(changes["paused"], bool):
            errs.append("paused must be true or false")
        if "name" in changes and (not isinstance(changes["name"], str) or not 1 <= len(changes["name"].strip()) <= 60):
            errs.append("name must be 1-60 characters")
        if errs:
            return errs
        if "endpoint" in changes:
            self.cfg["endpoint"] = rules.normalize_endpoint(changes["endpoint"])
        if "name" in changes:
            self.cfg["name"] = changes["name"].strip()
        relevel = "level" in changes and changes["level"] != self.cfg.get("level", rules.DEFAULT_LEVEL)
        if "level" in changes:
            self.cfg["level"] = changes["level"]
        if "paused" in changes:
            self.cfg["paused"] = changes["paused"]
            if not changes["paused"]:
                self.rt["rejected"] = False
        if self.enrolled:
            if self.cfg.get("paused"):
                self.stop()
            elif relevel and self.rt["connected"]:
                self._unsubscribe()           # the new level applies at once; events/relay are re-evaluated per frame
                self._revoke_relay()
                for t in list(self._reqs):    # work admitted under the old level must not run under the new one
                    t.cancel()
                self._reqs.clear()
                self._subscribe_if_needed()
                self._send_nowait({"type": "hello", "node_id": self.st.node_id, "cloud_node_id": self.cfg.get("cloud_node_id"),
                                   "version": self.st.version, "api_version": "1", "level": self.cfg["level"]})
            else:
                self.start()
        return []

    async def disconnect(self, tell_cloud: bool = True) -> None:
        async with self._lock:
            await self._disconnect(tell_cloud)

    async def _disconnect(self, tell_cloud: bool = True) -> None:
        cfg = dict(self.cfg)
        self.stop()
        self.cfg = {}                                  # forget everything, the address included
        self.approval.revoke()
        if tell_cloud and cfg.get("secret"):
            try:
                async with async_get_clientsession(self.hass).post(cfg["endpoint"] + UNENROLL_PATH.format(id=cfg["cloud_node_id"]),
                                                                  headers={"Authorization": "Bearer " + cfg["secret"]}, allow_redirects=False,
                                                                  timeout=aiohttp.ClientTimeout(total=8)):
                    pass
            except Exception:  # noqa: BLE001 - best effort: the node forgets the pairing regardless
                _LOGGER.debug("cloud unenroll notice failed", exc_info=True)

    def approve_debug(self, minutes: Any, user: Any) -> str | None:
        ok, err = self.approval.approve(minutes, getattr(user, "name", None), time.time())
        return None if ok else err

    # ------------------------------------------------------------------ the channel
    def _persist_soon(self, force: bool = False) -> None:
        now = time.time()
        if force or now - self._last_persist >= PERSIST_EVERY:
            self._last_persist = now
            self.st.persist()

    async def _run(self) -> None:
        attempt = rejects = 0
        while self.enrolled and not self.cfg.get("paused"):
            self._up_mono = None
            try:
                await self._session()
                rejects = 0
                attempt = rules.next_attempt(attempt, self._uptime())
            except asyncio.CancelledError:
                raise
            except aiohttp.WSServerHandshakeError as e:
                attempt = rules.next_attempt(attempt, self._uptime())
                rejects = rejects + 1 if rules.handshake_rejected(e.status) else 0
                self.rt["last_error"] = f"WSServerHandshakeError: {e.status}"
                if rejects >= rules.REJECT_AFTER:
                    self.rt.update(connected=False, since=None, attempt=attempt, rejected=True,
                                   last_error="rejected by the platform; reconnect (re-pair) required")
                    self._unsubscribe()
                    self._revoke_relay()
                    self._ws = None
                    self.st.log(None, None, "cloud.rejected", str(self.cfg.get("cloud_node_id")), "error", {"status": e.status})
                    return
            except Exception as e:  # noqa: BLE001
                attempt = rules.next_attempt(attempt, self._uptime())
                self.rt["last_error"] = rules.redact(f"{type(e).__name__}: {e}")[:200]
                _LOGGER.debug("cloud channel error", exc_info=True)
            self.rt.update(connected=False, since=None, attempt=attempt)
            self._unsubscribe()
            self._revoke_relay()
            self._ws = None
            await asyncio.sleep(rules.backoff_jitter(attempt, random.random()))

    def _uptime(self) -> float | None:
        return None if self._up_mono is None else time.monotonic() - self._up_mono

    async def _session(self) -> None:
        cfg = self.cfg
        await self._host_ok(cfg["endpoint"])
        await self._host_ok(cfg["channel_url"])
        if rules.validate_channel_url(cfg["channel_url"], cfg["endpoint"]):
            raise CloudError("bad_reply", "The stored channel address is not valid", 502)
        sess = async_get_clientsession(self.hass)
        self._limiter = rules.RateLimiter()
        async with sess.ws_connect(cfg["channel_url"], headers={"Authorization": "Bearer " + cfg["secret"], "X-Node-Id": self.st.node_id},
                                   heartbeat=30, max_msg_size=rules.MAX_FRAME) as ws:
            # ws_connect (aiohttp) has no allow_redirects switch: refuse a connection that was reached through a redirect
            if getattr(getattr(ws, "_response", None), "history", None):
                raise CloudError("redirect", "The cloud platform redirected the channel; refused", 502)
            self._ws = ws
            self._up_mono = time.monotonic()
            self.rt.update(connected=True, since=time.time(), last_error=None, attempt=0)
            self.rt["problem"] = None
            self.cfg["last_seen"] = time.time()          # an accepted connection is proof of life
            self._persist_soon()
            self._send_nowait({"type": "hello", "node_id": self.st.node_id, "cloud_node_id": cfg.get("cloud_node_id"), "version": self.st.version,
                               "api_version": "1", "level": cfg.get("level", rules.DEFAULT_LEVEL)})
            self._subscribe_if_needed()
            hb = asyncio.create_task(self._heartbeats())
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        self.rt["frames_in"] += 1
                        f = rules.parse_frame(msg.data)
                        if f is None:
                            continue
                        self.cfg["last_seen"] = time.time()
                        self._persist_soon()
                        await self._frame(f)
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
            finally:
                hb.cancel()

    async def _heartbeats(self) -> None:
        while True:
            await self.check_admin()
            self._send_nowait({"type": "heartbeat", "ts": int(time.time()), "level": self.cfg.get("level", rules.DEFAULT_LEVEL), "status": await self._health()})
            await asyncio.sleep(rules.clamp_heartbeat(self.cfg.get("heartbeat_s")))

    async def _health(self) -> dict[str, Any]:
        h: dict[str, Any] = {"node": self.cfg.get("name"), "version": self.st.version, "api_enabled": self.st.enabled}
        try:
            states = self.hass.states.async_all()
            h.update(entities=len(states), unavailable=sum(1 for s in states if s.state in ("unavailable", "unknown")))
            sup = (self.hass.data.get("hub_mgmt") or {}).get("support")
            if sup:
                h["host"] = await self.hass.async_add_executor_job(sup["host"])
        except Exception:  # noqa: BLE001
            pass
        return h

    def _send_nowait(self, frame: dict[str, Any]) -> bool:
        ws = self._ws
        if ws is None or ws.closed:
            return False
        # back-pressure: when the cloud stops reading, drop events/heartbeats first, answers last
        if self._sends >= (MAX_SENDS_HARD if frame.get("type") == "response" else MAX_SENDS):
            return False
        try:
            data = json.dumps(frame, separators=(",", ":"), default=str)
            if len(data) > rules.MAX_RESPONSE:
                return False
            t = self.hass.async_create_background_task(ws.send_str(data), "sentinel_link_cloud_send")
            self._sends += 1
            t.add_done_callback(self._send_done)
            self.rt["frames_out"] += 1
            return True
        except Exception:  # noqa: BLE001
            return False

    def _send_done(self, _t: Any) -> None:
        self._sends = max(0, self._sends - 1)

    # ------------------------------------------------------------------ frames from the cloud
    async def _frame(self, f: dict[str, Any]) -> None:
        t = f["type"]
        if t == "request":
            self._spawn_request(f)
        elif t == "debug_request":
            await self._debug(f)
        elif t == "unenroll":
            self.st.log(None, None, "cloud.unenrolled_by_cloud", str(self.cfg.get("cloud_node_id")), "ok")
            await self.disconnect(tell_cloud=False)
            self.st.persist()
        # ack and unknown types: proof of life only

    def _safe_id(self, v: Any) -> str | None:
        return v if isinstance(v, str) and 1 <= len(v) <= 64 and v.isprintable() else None

    def _respond_error(self, rid: str, status: int, code: str, msg: str) -> None:
        self._send_nowait({"type": "response", "id": rid, "status": status, "body": {"error": {"code": code, "message": msg}}})

    def _audit_relay(self, key: str, target: str, result: str, data: dict[str, Any], window: float = 60.0) -> None:
        """Audit a relayed request, sampled so a flood of cloud requests cannot push the admin's own entries out of the shared ring."""
        ok, skipped = self._audit.note(key, time.time(), window)
        if ok:
            if skipped:
                data = {**data, "suppressed": skipped}
            self.st.log(None, None, "cloud.relay", target[:120], result, data)

    def _spawn_request(self, f: dict[str, Any]) -> None:
        rid = self._safe_id(f.get("id"))
        if rid is None:
            return
        if not self._limiter.allow(time.monotonic()):
            self._audit_relay("rate", "-", "denied", {"reason": "rate_limited"})
            self._respond_error(rid, 429, "rate_limited", "Too many requests")
            return
        if len(self._reqs) >= MAX_PENDING:
            self._audit_relay("busy", "-", "denied", {"reason": "too_many_pending"})
            self._respond_error(rid, 429, "busy", "Too many requests in progress")
            return
        t = self.hass.async_create_background_task(self._request(f), "sentinel_link_cloud_request")
        self._reqs.add(t)
        t.add_done_callback(self._reqs.discard)

    def _relay_level(self) -> str | None:
        """The current level if the relay may run at all right now, else None."""
        if not self.enrolled or self.cfg.get("paused") or not self.rt["connected"] or self.rt.get("problem"):
            return None
        return self.cfg.get("level", rules.DEFAULT_LEVEL)

    async def _request(self, f: dict[str, Any]) -> None:
        rid = self._safe_id(f.get("id"))
        if rid is None:
            return
        by = self._safe_id(f.get("by")) or "cloud"
        level = self.cfg.get("level", rules.DEFAULT_LEVEL)
        method, path = f.get("method"), f.get("path")
        allowed, why = rules.relay_allowed(level, method, path)
        if not allowed:
            self._audit_relay("denied:" + why, str(path), "denied", {"by": by, "method": str(method)[:8], "reason": why})
            self._respond_error(rid, 403 if why == "level_too_low" else 400 if why == "bad_request" else 404, why,
                                "Not available at the current sharing level" if why == "level_too_low" else "Not allowed")
            return
        meth, path = str(method).upper(), str(path)
        body = f.get("body")
        if meth == "POST" and not isinstance(body, dict):
            body = {}
        async with self._sem:
            cur = self._relay_level()                    # re-check: the level / pause may have changed while this request was queued
            if cur is None or not rules.relay_allowed(cur, method, path)[0]:
                self._respond_error(rid, 403, "level_too_low", "Not available at the current sharing level")
                return
            status, out, b64 = await self._local_call(meth, path, body if meth == "POST" else None)
        self._audit_relay(f"{meth}:{'ok' if status < 400 else 'error'}", path, "ok" if status < 400 else "error",
                          {"by": by, "method": meth, "status": status}, 5.0 if meth == "POST" else 60.0)
        frame: dict[str, Any] = {"type": "response", "id": rid, "status": status}
        frame["body_b64" if b64 else "body"] = out
        if not self._send_nowait(frame):
            self._respond_error(rid, 413, "too_large", "Reply too large")

    async def _admin_problem(self) -> tuple[Any, str | None]:
        """(user, problem).  The enrolling administrator must still exist, be active and still be an administrator."""
        uid = self.cfg.get("enrolled_by")
        user = await self.hass.auth.async_get_user(uid) if uid else None
        if user is None:
            return None, "The administrator who paired this node was removed. Disconnect and pair again."
        if not user.is_active:
            return user, "The administrator who paired this node was deactivated. Disconnect and pair again."
        try:
            if not self.st.rbac().is_admin_role(self.st.role_for(user)):
                return user, "The administrator who paired this node is no longer an administrator. Disconnect and pair again."
        except Exception:  # noqa: BLE001
            _LOGGER.debug("admin role check failed", exc_info=True)
        return user, None

    async def check_admin(self) -> None:
        """Called every heartbeat and from the hub's minute sweep: close the event feed and relay when the enrolling admin is gone."""
        if not self.enrolled:
            return
        _user, problem = await self._admin_problem()
        if problem:
            if self.rt.get("problem") != problem:
                self.st.log(None, None, "cloud.admin_gone", str(self.cfg.get("cloud_node_id")), "error", {"reason": problem[:80]})
            self.rt["problem"] = problem
            self._unsubscribe()
            self._revoke_relay()
        elif self.rt.get("problem"):
            self.rt["problem"] = None
            if self.rt["connected"]:
                self._subscribe_if_needed()

    async def _relay_token(self) -> str | None:
        now = time.time()
        if self._relay_tok is None or self._relay_tok[1] - now < 120:
            uid = self.cfg.get("enrolled_by")
            level = self.cfg.get("level", rules.DEFAULT_LEVEL)
            cap = rules.relay_cap(level)
            if cap is None or rules.LEVEL_RANK.get(level, 0) < rules.LEVEL_RANK["events"]:      # no token at `health`
                return None
            _user, problem = await self._admin_problem()
            if problem:
                self.rt["problem"] = problem
                return None
            if self.cfg.get("level", rules.DEFAULT_LEVEL) != level or self.cfg.get("paused"):      # changed during the await
                return None
            self._revoke_relay()
            tok = self.st.book.issue_relay(uid, cap, ttl=3600)
            self._relay_tok = (tok, now + 3600)
        return self._relay_tok[0]

    async def _local_call(self, method: str, path: str, body: Any) -> tuple[int, Any, bool]:
        tok = await self._relay_token()
        if tok is None:
            return 401, {"error": {"code": "unauthorized", "message": "The administrator who paired this node is no longer active"}}, False
        url = f"http://127.0.0.1:{self.hass.http.server_port}/api/sentinel_link/v1{path}"
        try:
            async with async_get_clientsession(self.hass).request(method, url, json=body, headers={"Authorization": "Bearer " + tok},
                                                                  allow_redirects=False, timeout=aiohttp.ClientTimeout(total=20)) as r:
                raw = await read_capped(r.content, rules.MAX_RESPONSE)
                if raw is None:
                    return 413, {"error": {"code": "too_large", "message": "Reply too large"}}, False
                ctype = r.headers.get("Content-Type", "")
                if "json" in ctype:
                    try:
                        return r.status, json.loads(raw), False
                    except ValueError:
                        pass
                return r.status, base64.b64encode(raw).decode(), True
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 504, {"error": {"code": "timeout", "message": "The node did not answer in time"}}, False

    async def _debug(self, f: dict[str, Any]) -> None:
        rid = self._safe_id(f.get("id"))
        if rid is None:
            return
        by = self._safe_id(f.get("by")) or "cloud"
        now = time.time()
        if not self.approval.active(now):
            self.approval.ask(now)
            self.st.log(None, None, "cloud.debug_report", "-", "denied", {"by": by, "reason": "approval_required"})
            try:
                from homeassistant.components import persistent_notification
                persistent_notification.async_create(self.hass, "The cloud platform asked for a support report. Approve it in the node portal (Cloud page) if you want to share one.",
                                                     title="Support report requested", notification_id="sentinel_link_cloud_debug")
            except Exception:  # noqa: BLE001
                pass
            self._send_nowait({"type": "debug_denied", "id": rid, "reason": "approval_required"})
            return
        try:
            sup = (self.hass.data.get("hub_mgmt") or {}).get("support")
            report = rules.redact_obj(await sup["collect"](self.hass))      # each string value, never the serialized JSON
            text = json.dumps(report, default=str)
            while len(text) > rules.MAX_RESPONSE - 4096 and isinstance(report, dict) and report.get("log_lines"):
                report["log_lines"] = report["log_lines"][len(report["log_lines"]) // 4:]
                text = json.dumps(report, default=str)
        except Exception:  # noqa: BLE001
            self._send_nowait({"type": "debug_denied", "id": rid, "reason": "unavailable"})
            return
        self.st.log(None, None, "cloud.debug_report", "-", "ok", {"by": by, "bytes": len(text)})
        self._send_nowait({"type": "debug_report", "id": rid, "report": report})

    # ------------------------------------------------------------------ events to the cloud
    def _subscribe_if_needed(self) -> None:
        self._unsubscribe()
        if rules.LEVEL_RANK.get(self.cfg.get("level", rules.DEFAULT_LEVEL), 0) < rules.LEVEL_RANK["events"]:
            return
        self.hass.async_create_task(self._subscribe())

    def _on_event(self, p: dict[str, Any]) -> None:
        """Only entity state changes leave the node; sign-in history, user changes and anything else never do."""
        if p.get("type") in ("state", "removed") and not self.rt.get("problem"):
            self._send_nowait({"type": "event", "event": p})

    def _may_feed(self) -> str | None:
        """The role cap for the event feed, or None when no feed is allowed right now (level, pause, connection, admin problem)."""
        level = self.cfg.get("level", rules.DEFAULT_LEVEL)
        if rules.LEVEL_RANK.get(level, 0) < rules.LEVEL_RANK["events"] or self.cfg.get("paused") or not self.rt["connected"] or self.rt.get("problem"):
            return None
        return rules.relay_cap(level)

    async def _subscribe(self) -> None:
        uid = self.cfg.get("enrolled_by")
        user = await self.hass.auth.async_get_user(uid) if uid else None
        cap = self._may_feed()                       # re-read AFTER the await: the level may have dropped meanwhile
        if user is None or not user.is_active or self._sub is not None or cap is None:
            return
        self._sub = self.st.add_subscriber(user, self._on_event, lambda: None, cap=cap)

    def _unsubscribe(self) -> None:
        if self._sub is not None:
            self.st.remove_subscriber(self._sub)
            self._sub = None
