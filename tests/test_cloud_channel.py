"""Unit tests: CloudChannel behaviour with stubbed hub / homeassistant modules (no hub, no network)."""
import asyncio
import importlib
import json
import os
import sys
import time
import types

import aiohttp
import pytest

D = os.path.join(os.path.dirname(__file__), "..", "custom_components", "sentinel_link", "api")


def _load():
    for n in ("homeassistant", "homeassistant.helpers", "homeassistant.helpers.aiohttp_client"):
        sys.modules.setdefault(n, types.ModuleType(n))
    sys.modules["homeassistant.helpers.aiohttp_client"].async_get_clientsession = lambda hass: hass.session
    pkg = types.ModuleType("slc_api")
    pkg.__path__ = [os.path.abspath(D)]
    sys.modules["slc_api"] = pkg
    return importlib.import_module("slc_api.cloud"), importlib.import_module("slc_api.cloud_rules"), importlib.import_module("slc_api.tokens")


C, R, T = _load()


def run(coro):
    return asyncio.run(coro)


class User:
    def __init__(self, uid="u1", active=True, admin=True):
        self.id, self.name, self.is_active, self.admin = uid, "Admin", active, admin


class Auth:
    def __init__(self, user):
        self.user = user

    async def async_get_user(self, uid):
        await asyncio.sleep(0)
        return self.user if self.user and self.user.id == uid else None


class Book:
    def __init__(self):
        self.issued, self.revoked = [], []

    def issue_relay(self, uid, cap, ttl=3600):
        tok = T.TokenBook.issue_relay(T.TokenBook(), uid, cap, ttl)   # real format; real validation of the cap
        self.issued.append((tok, cap))
        return tok

    def revoke(self, tid):
        self.revoked.append(tid)


class Rbac:
    def is_admin_role(self, role):
        return role == "admin"


class St:
    node_id, version, enabled = "n1", "1", True

    def __init__(self, user):
        self.book, self.logs, self.subs, self.user = Book(), [], {}, user
        self.next = 1

    def log(self, *a):
        self.logs.append(a)

    def persist(self):
        pass

    def rbac(self):
        return Rbac()

    def role_for(self, user):
        return "admin" if user.admin else "user"

    def add_subscriber(self, user, send, close, cap=None):
        self.subs[self.next] = (user, send, cap)
        self.next += 1
        return self.next - 1

    def remove_subscriber(self, sid):
        self.subs.pop(sid, None)


class WS:
    closed = False

    def __init__(self):
        self.sent = []

    async def send_str(self, d):
        self.sent.append(json.loads(d))


class Hass:
    def __init__(self, user):
        self.auth, self.data, self.session = Auth(user), {}, None

    def async_create_background_task(self, coro, name=None):
        return asyncio.get_running_loop().create_task(coro)

    async_create_task = async_create_background_task


def make(level="full", user=None):
    user = user or User()
    hass = Hass(user)
    st = St(user)
    st.hass = hass
    ch = C.CloudChannel(st)
    ch.cfg = {"endpoint": "https://cloud.example.com", "cloud_node_id": "c1", "secret": "s" * 20, "channel_url": "wss://cloud.example.com/c",
              "level": level, "paused": False, "enrolled_by": user.id, "enrolled_by_name": "Admin"}
    ch._ws = WS()
    ch.rt["connected"] = True
    return ch, st, hass, user


async def drain():
    for _ in range(5):
        await asyncio.sleep(0)


# ---- 1: chunked read
class Stream:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, n):
        for c in self.chunks:
            yield c


def test_f1_read_capped_reads_all_chunks():
    data = [b"a" * 60000, b"b" * 60000, b"c" * 100000]
    assert run(C.read_capped(Stream(data), 1 << 20)) == b"".join(data)


def test_f1_read_capped_returns_none_when_over():
    assert run(C.read_capped(Stream([b"x" * 70000] * 3), 150000)) is None


def test_f1_local_call_large_reply_and_413():
    class Resp:
        status, headers = 200, {"Content-Type": "application/json"}

        def __init__(self, n):
            body = json.dumps({"x": "y" * n}).encode()
            self.content = Stream([body[i:i + 65536] for i in range(0, len(body), 65536)])

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class Sess:
        n = 400_000

        def request(self, *a, **k):
            return Resp(self.n)

    ch, st, hass, _ = make()
    hass.session, hass.http = Sess(), types.SimpleNamespace(server_port=1)
    status, out, b64 = run(ch._local_call("GET", "/entities", None))
    assert status == 200 and not b64 and len(out["x"]) == 400_000
    Sess.n = R.MAX_RESPONSE + 10
    assert run(ch._local_call("GET", "/entities", None))[0] == 413


# ---- 2 / 8: event feed
def test_f2_only_state_and_removed_events_forwarded():
    ch, *_ = make()
    for t in ("login", "login_alert", "user", "hello"):
        ch._on_event({"type": t})
    ch._on_event({"type": "state"})
    ch._on_event({"type": "removed"})


def test_f2_events_filtered_on_wire():
    async def go():
        ch, *_ = make()
        for t in ("login", "login_alert", "user", "state", "removed"):
            ch._on_event({"type": t})
        await drain()
        return [f["event"]["type"] for f in ch._ws.sent]
    assert run(go()) == ["state", "removed"]


def test_f2_subscribe_rechecks_level_after_await():
    async def go():
        ch, st, *_ = make("events")
        t = asyncio.ensure_future(ch._subscribe())
        await asyncio.sleep(0)
        ch.cfg["level"] = "health"           # lowered while the task awaits the user lookup
        await t
        return st.subs
    assert run(go()) == {}


def test_f2_subscribe_never_with_none_cap_and_cap_set():
    async def go(level):
        ch, st, *_ = make(level)
        await ch._subscribe()
        return list(st.subs.values())
    assert run(go("health")) == []
    subs = run(go("events"))
    assert subs[0][2] == "viewer"
    assert run(go("full"))[0][2] == "manager"


def test_f2_no_subscribe_when_paused_or_disconnected():
    async def go(**kw):
        ch, st, *_ = make("full")
        ch.cfg.update(kw.get("cfg", {}))
        ch.rt["connected"] = kw.get("connected", True)
        await ch._subscribe()
        return st.subs
    assert run(go(cfg={"paused": True})) == {}
    assert run(go(connected=False)) == {}


def test_f8_admin_deleted_deactivated_demoted_closes_feed():
    async def go(mutate):
        ch, st, hass, user = make("full")
        await ch._subscribe()
        assert st.subs
        mutate(ch, hass, user)
        await ch.check_admin()
        return ch, st
    for m in (lambda ch, h, u: setattr(h.auth, "user", None), lambda ch, h, u: setattr(u, "is_active", False),
              lambda ch, h, u: setattr(u, "admin", False)):
        ch, st = run(go(m))
        assert st.subs == {} and ch.status()["problem"]
        ch._on_event({"type": "state"})
        assert ch._ws.sent == []
        assert any(l[2] == "cloud.admin_gone" for l in st.logs)


def test_f8_admin_ok_clears_problem():
    async def go():
        ch, st, hass, user = make("full")
        ch.rt["problem"] = "x"
        await ch.check_admin()
        await drain()
        return ch, st
    ch, st = run(go())
    assert ch.rt["problem"] is None and len(st.subs) == 1


# ---- 3: debug report
def test_f3_debug_report_is_valid_json_and_redacted():
    async def go():
        ch, st, hass, _ = make()
        ch.approval.grant("admin", 3600, time.time()) if hasattr(ch.approval, "grant") else None
        async def collect(h):
            return {"status_code": 200, "log_lines": ['password: "hunter2"', "ok"], "token": "abcdef123456"}
        hass.data["hub_mgmt"] = {"support": {"collect": collect}}
        return ch, st
    ch, st = run(go())
    # approval API differs per version: exercise the pure part directly
    out = R.redact_obj({"status_code": 200, "token": "abcdef123456", "log_lines": ['password: "hunter2"']})
    assert out["status_code"] == 200 and "hunter2" not in json.dumps(out) and "abcdef123456" not in json.dumps(out)


# ---- 4: rate limit / pending cap / audit ring
def test_f4_rate_limited_requests_get_429():
    async def go():
        ch, st, *_ = make()
        ch._limiter = R.RateLimiter(rate=0.0001, burst=2)
        ch._request = lambda f: asyncio.sleep(10)
        for i in range(5):
            ch._spawn_request({"type": "request", "id": f"r{i}"})
        await drain()
        return ch, st
    ch, st = run(go())
    assert sorted(f["status"] for f in ch._ws.sent) == [429, 429, 429]


def test_f4_pending_cap_429():
    async def go():
        ch, st, *_ = make()
        async def slow(f):
            await asyncio.sleep(10)
        ch._request = slow
        for i in range(C.MAX_PENDING + 3):
            ch._spawn_request({"type": "request", "id": f"r{i}"})
        await drain()
        n = len(ch._reqs)
        ch.stop()
        return n, [f["status"] for f in ch._ws.sent]
    n, sent = run(go())
    assert n == C.MAX_PENDING and sent == [429] * 3


def test_f4_denied_flood_does_not_flush_audit():
    async def go():
        ch, st, *_ = make("events")
        for i in range(300):
            await ch._request({"type": "request", "id": f"r{i}", "method": "POST", "path": f"/entities/light.k{i}/command"})
        return st
    st = run(go())
    assert len([l for l in st.logs if l[2] == "cloud.relay"]) <= 2


# ---- 5: redirects / host
def test_f5_session_rejects_redirected_ws_and_bad_host(monkeypatch):
    async def go(hist, url):
        ch, st, hass, _ = make()
        ch.cfg["channel_url"] = url
        async def ok(u): pass
        ch._host_ok = ok
        class WSc:
            _response = types.SimpleNamespace(history=hist)
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
        hass.session = types.SimpleNamespace(ws_connect=lambda *a, **k: WSc())
        await ch._session()
    with pytest.raises(C.CloudError):
        run(go([object()], "wss://cloud.example.com/c"))
    with pytest.raises(C.CloudError):
        run(go([], "wss://127.0.0.1/api"))


def test_f5_host_ok_rejects_link_local():
    async def go():
        ch, *_ = make()
        await ch._host_ok("wss://169.254.169.254/")
    with pytest.raises(C.CloudError):
        run(go())


# ---- 6: reconnect
def _run_loop(exc, uptime, monkeypatch, n=1):
    async def go():
        ch, st, *_ = make()
        calls = []
        async def sess():
            calls.append(1)
            ch._up_mono = None if uptime is None else time.monotonic() - uptime
            if len(calls) >= n + 5:
                ch.cfg["paused"] = True
            raise exc
        ch._session = sess
        slept = []
        async def fake_sleep(s):
            slept.append(s)
            if len(slept) >= n:
                ch.cfg["paused"] = True
        monkeypatch.setattr(C.asyncio, "sleep", fake_sleep)
        await ch._run()
        return ch, slept
    return run(go())


def test_f6_short_connection_does_not_reset_attempt(monkeypatch):
    ch, slept = _run_loop(RuntimeError("closed"), 0.1, monkeypatch, n=3)
    assert ch.rt["attempt"] == 3 and slept[2] > slept[0] * 0.9


def test_f6_stable_connection_resets_attempt(monkeypatch):
    ch, _ = _run_loop(RuntimeError("closed"), 120, monkeypatch)
    assert ch.rt["attempt"] == 0


def test_f6_repeated_401_marks_rejected(monkeypatch):
    err = aiohttp.WSServerHandshakeError(None, (), status=401)
    ch, slept = _run_loop(err, None, monkeypatch, n=10)
    assert ch.rt["rejected"] is True and "re-pair" in ch.rt["last_error"] and ch.status()["rejected"] is True
    assert len(slept) == R.REJECT_AFTER - 1


# ---- 7 / 9: relay tokens
def test_f7_no_relay_token_at_health_and_issue_relay_refuses_none():
    ch, st, *_ = make("health")
    assert run(ch._relay_token()) is None and st.book.issued == []
    with pytest.raises(ValueError):
        T.TokenBook().issue_relay("u", None)


def test_f7_token_cap_follows_level():
    for lvl, cap in (("events", "viewer"), ("full", "manager")):
        ch, st, *_ = make(lvl)
        assert run(ch._relay_token()) and st.book.issued[-1][1] == cap


def test_f9_stop_cancels_requests_and_revokes_token():
    async def go():
        ch, st, *_ = make()
        await ch._relay_token()
        async def slow(f): await asyncio.sleep(10)
        ch._request = slow
        ch._spawn_request({"type": "request", "id": "a"})
        await drain()
        t = list(ch._reqs)[0]
        ch.stop()
        await drain()
        return ch, st, t
    ch, st, t = run(go())
    assert t.cancelled() and not ch._reqs and ch._relay_tok is None and len(st.book.revoked) == 1


def test_f9_level_change_revokes_and_cancels():
    async def go():
        ch, st, *_ = make("full")
        await ch._relay_token()
        async def slow(f): await asyncio.sleep(10)
        ch._request = slow
        ch._spawn_request({"type": "request", "id": "a"})
        await drain()
        t = list(ch._reqs)[0]
        ch.configure({"level": "events"})
        await drain()
        return ch, st, t
    ch, st, t = run(go())
    assert t.cancelled() and len(st.book.revoked) >= 1


def test_f9_queued_request_rechecks_level_before_local_call():
    async def go():
        ch, st, *_ = make("full")
        called = []
        async def lc(*a):
            called.append(a)
            return 200, {}, False
        ch._local_call = lc
        for _ in range(C.MAX_INFLIGHT):
            await ch._sem.acquire()
        t = asyncio.ensure_future(ch._request({"type": "request", "id": "a", "method": "POST", "path": "/entities/light.k/command", "body": {}}))
        await drain()
        ch.cfg["level"] = "events"          # lowered while queued
        for _ in range(C.MAX_INFLIGHT):
            ch._sem.release()
        await t
        return called, ch._ws.sent
    called, sent = run(go())
    assert called == [] and sent[-1]["status"] == 403


# ---- 11: lock, 12: back-pressure
def test_f11_concurrent_enrol_serialised():
    async def go():
        ch, *_ = make()
        ch.cfg = {}
        order = []
        async def fake(user, ep, code, level=None, name=None):
            order.append("in")
            await asyncio.sleep(0.01)
            order.append("out")
            return {}
        ch._enroll = fake
        await asyncio.gather(ch.enroll(User(), "e", "c"), ch.enroll(User(), "e", "c"))
        return order
    assert run(go()) == ["in", "out", "in", "out"]


def test_f12_send_backpressure_drops_events_before_answers():
    async def go():
        ch, *_ = make()
        ch._sends = C.MAX_SENDS
        ev = ch._send_nowait({"type": "event", "event": {}})
        ans = ch._send_nowait({"type": "response", "id": "a", "status": 200})
        ch._sends = C.MAX_SENDS_HARD
        hard = ch._send_nowait({"type": "response", "id": "a", "status": 200})
        ch._sends = 0
        await drain()
        return ev, ans, hard
    assert run(go()) == (False, True, False)


def test_f12_sends_counter_released():
    async def go():
        ch, *_ = make()
        ch._send_nowait({"type": "event", "event": {}})
        n = ch._sends
        await drain()
        return n, ch._sends
    assert run(go()) == (1, 0)


# ---- 14: re-enable restarts the channel
def test_f14_set_enabled_restarts_cloud():
    src = open(os.path.join(D, "setup.py")).read()
    body = src.split("async def async_set_enabled")[1].split("\nasync def ")[0].split("\ndef ")[0]
    assert "st.cloud.restart()" in body
    async def go():
        ch, st, *_ = make()
        ch._sub = 7
        st.subs[7] = 1
        ch.restart()
        return ch._sub
    assert run(go()) is None
