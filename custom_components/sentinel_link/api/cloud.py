"""Cloud channel (Part B): pairs this node with a third-party cloud platform and keeps one OUTBOUND secure WebSocket open to it.

* The node dials out; nothing listens for the cloud.  Rules (levels, what the relay may reach, approval, redaction) live in `cloud_rules.py`.
* Requests from the cloud are NOT handled by separate code: they are replayed against this node's own Link API on loopback with a short-lived
  in-memory relay token (scope `cloud`, role capped by the sharing level), so every role check, exposure filter, validation and audit entry of the
  normal API applies unchanged.
* The cloud can never change the sharing level, manage users/tokens/apps/settings, or read the audit trail.  The node admin can pause or disconnect any time.

Wire protocol (JSON frames, both directions, `type` string):
  node -> cloud   hello {node_id, cloud_node_id, version, api_version, level}          first frame after connecting
                  heartbeat {ts, level, status{...}}                                    every `heartbeat_s`
                  response {id, status, body | body_b64}                                answer to a request
                  event {event{...}}                                                    state changes (level events/full only)
                  debug_report {id, report} / debug_denied {id, reason}                 answer to debug_request
  cloud -> node   ack {}                                                                 any frame counts as proof of life
                  request {id, method, path, body?, by?}                                 relayed to the Link API (see cloud_rules.relay_allowed)
                  debug_request {id, by?}                                                needs on-node approval
                  unenroll {}                                                            the cloud removes this node
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import socket
import time
from typing import Any

import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import cloud_rules as rules

_LOGGER = logging.getLogger(__name__)
ENROLL_PATH = "/v1/nodes/enroll"
UNENROLL_PATH = "/v1/nodes/{id}/unenroll"
MAX_INFLIGHT = 4
PERSIST_EVERY = 300.0
_BIG = 16384            # largest reply we accept from the enrol endpoint


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
        self._wake = asyncio.Event()
        self.rt: dict[str, Any] = {"connected": False, "since": None, "last_error": None, "attempt": 0, "frames_in": 0, "frames_out": 0}

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
        if self._relay_tok is not None:
            self._relay_tok = None
        self.rt.update(connected=False, since=None)

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
                   levels=list(rules.LEVELS), can_enroll=not pub["enrolled"])
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
                raw = await r.content.read(_BIG + 1)
                status = r.status
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise CloudError("unreachable", f"Cannot reach the cloud platform ({type(e).__name__})", 502) from e
        if len(raw) > _BIG:
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
        self.cfg = {"endpoint": endpoint, "cloud_node_id": cid, "secret": secret, "channel_url": channel, "name": body["node_name"],
                    "level": level or rules.DEFAULT_LEVEL, "paused": False, "enrolled_at": time.time(), "enrolled_by": user.id,
                    "enrolled_by_name": user.name, "heartbeat_s": rules.clamp_heartbeat(d.get("heartbeat_s")), "last_seen": None}
        self.approval.revoke()
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
        if self.enrolled:
            if self.cfg.get("paused"):
                self.stop()
            elif relevel and self.rt["connected"]:
                self._unsubscribe()           # the new level applies at once; events/relay are re-evaluated per frame
                self._relay_tok = None
                self._subscribe_if_needed()
                self._send_nowait({"type": "hello", "node_id": self.st.node_id, "cloud_node_id": self.cfg.get("cloud_node_id"),
                                   "version": self.st.version, "api_version": "1", "level": self.cfg["level"]})
            else:
                self.start()
        return []

    async def disconnect(self, tell_cloud: bool = True) -> None:
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
        attempt = 0
        while self.enrolled and not self.cfg.get("paused"):
            try:
                await self._session()
                attempt = 0
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                attempt += 1
                self.rt["last_error"] = rules.redact(f"{type(e).__name__}: {e}")[:200]
                _LOGGER.debug("cloud channel error", exc_info=True)
            self.rt.update(connected=False, since=None, attempt=attempt)
            self._unsubscribe()
            self._ws = None
            try:
                await asyncio.wait_for(self._wake.wait(), rules.backoff(attempt))
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def _session(self) -> None:
        cfg = self.cfg
        await self._host_ok(cfg["endpoint"])
        sess = async_get_clientsession(self.hass)
        async with sess.ws_connect(cfg["channel_url"], headers={"Authorization": "Bearer " + cfg["secret"], "X-Node-Id": self.st.node_id},
                                   heartbeat=30, max_msg_size=rules.MAX_FRAME) as ws:
            self._ws = ws
            self.rt.update(connected=True, since=time.time(), last_error=None, attempt=0)
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
        try:
            data = json.dumps(frame, separators=(",", ":"), default=str)
            if len(data) > rules.MAX_RESPONSE:
                return False
            self.hass.async_create_background_task(ws.send_str(data), "sentinel_link_cloud_send")
            self.rt["frames_out"] += 1
            return True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------ frames from the cloud
    async def _frame(self, f: dict[str, Any]) -> None:
        t = f["type"]
        if t == "request":
            self.hass.async_create_background_task(self._request(f), "sentinel_link_cloud_request")
        elif t == "debug_request":
            await self._debug(f)
        elif t == "unenroll":
            self.st.log(None, None, "cloud.unenrolled_by_cloud", str(self.cfg.get("cloud_node_id")), "ok")
            await self.disconnect(tell_cloud=False)
            self.st.persist()
        # ack and unknown types: proof of life only

    def _safe_id(self, v: Any) -> str | None:
        return v if isinstance(v, str) and 1 <= len(v) <= 64 and v.isprintable() else None

    async def _request(self, f: dict[str, Any]) -> None:
        rid = self._safe_id(f.get("id"))
        if rid is None:
            return
        by = self._safe_id(f.get("by")) or "cloud"
        level = self.cfg.get("level", rules.DEFAULT_LEVEL)
        method, path = f.get("method"), f.get("path")
        allowed, why = rules.relay_allowed(level, method, path)
        if not allowed:
            self.st.log(None, None, "cloud.relay", str(path)[:120], "denied", {"by": by, "method": str(method)[:8], "reason": why})
            self._send_nowait({"type": "response", "id": rid, "status": 403 if why == "level_too_low" else 400 if why == "bad_request" else 404,
                               "body": {"error": {"code": why, "message": "Not available at the current sharing level" if why == "level_too_low" else "Not allowed"}}})
            return
        meth, path = str(method).upper(), str(path)
        body = f.get("body")
        if meth == "POST" and not isinstance(body, dict):
            body = {}
        async with self._sem:
            status, out, b64 = await self._local_call(meth, path, body if meth == "POST" else None)
        self.st.log(None, None, "cloud.relay", path[:120], "ok" if status < 400 else "error", {"by": by, "method": meth, "status": status})
        frame: dict[str, Any] = {"type": "response", "id": rid, "status": status}
        frame["body_b64" if b64 else "body"] = out
        if not self._send_nowait(frame):
            self._send_nowait({"type": "response", "id": rid, "status": 413, "body": {"error": {"code": "too_large", "message": "Reply too large"}}})

    async def _relay_token(self) -> str | None:
        now = time.time()
        if self._relay_tok is None or self._relay_tok[1] - now < 120:
            uid = self.cfg.get("enrolled_by")
            user = await self.hass.auth.async_get_user(uid) if uid else None
            if user is None or not user.is_active:
                return None
            tok = self.st.book.issue_relay(uid, rules.relay_cap(self.cfg.get("level", rules.DEFAULT_LEVEL)), ttl=3600)
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
                raw = await r.content.read(rules.MAX_RESPONSE + 1)
                if len(raw) > rules.MAX_RESPONSE:
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
            report = await sup["collect"](self.hass)
        except Exception:  # noqa: BLE001
            self._send_nowait({"type": "debug_denied", "id": rid, "reason": "unavailable"})
            return
        text = rules.redact(json.dumps(report, default=str))
        while len(text) > rules.MAX_RESPONSE - 4096 and report.get("log_lines"):
            report["log_lines"] = report["log_lines"][len(report["log_lines"]) // 4:]
            text = rules.redact(json.dumps(report, default=str))
        self.st.log(None, None, "cloud.debug_report", "-", "ok", {"by": by, "bytes": len(text)})
        self._send_nowait({"type": "debug_report", "id": rid, "report": json.loads(text)})

    # ------------------------------------------------------------------ events to the cloud
    def _subscribe_if_needed(self) -> None:
        self._unsubscribe()
        if rules.LEVEL_RANK.get(self.cfg.get("level", rules.DEFAULT_LEVEL), 0) < rules.LEVEL_RANK["events"]:
            return
        self.hass.async_create_task(self._subscribe())

    async def _subscribe(self) -> None:
        uid = self.cfg.get("enrolled_by")
        user = await self.hass.auth.async_get_user(uid) if uid else None
        if user is None or not user.is_active or self._sub is not None or not self.rt["connected"]:
            return
        cap = rules.relay_cap(self.cfg.get("level", rules.DEFAULT_LEVEL))
        self._sub = self.st.add_subscriber(user, lambda p: self._send_nowait({"type": "event", "event": p}), lambda: None, cap=cap)

    def _unsubscribe(self) -> None:
        if self._sub is not None:
            self.st.remove_subscriber(self._sub)
            self._sub = None
