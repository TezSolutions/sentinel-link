"""Unit tests: cloud channel rules (no hub needed)."""
import importlib.util
import json
import os
import sys
import time

import pytest

D = os.path.join(os.path.dirname(__file__), "..", "custom_components", "sentinel_link", "api")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(D, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


R = _load("cloud_rules")


@pytest.mark.parametrize("url", ["https://cloud.example.com", "https://cloud.example.com:8443/base", "http://localhost:9000", "http://127.0.0.1:1",
                                 "https://8.8.4.4"])
def test_endpoint_ok(url):
    assert R.validate_endpoint(url) is None


@pytest.mark.parametrize("url", ["", None, 5, "ftp://x.com", "http://cloud.example.com", "https://", "https://u:p@x.com", "https://x.com/?a=1", "https://x.com/#f",
                                 "https://x.com/ a", "https://169.254.169.254", "https://0.0.0.0", "https://224.0.0.1", "javascript:alert(1)",
                                 "https://x.com\\evil", "https://" + "a" * 250 + ".com"])
def test_endpoint_bad(url):
    assert R.validate_endpoint(url)


def test_endpoint_normalised():
    assert R.normalize_endpoint(" https://a.com/x/ ".strip()) == "https://a.com/x"


def test_channel_url_rules():
    assert R.validate_channel_url("wss://c.example.com/ch", "https://c.example.com") is None
    assert R.validate_channel_url("ws://c.example.com/ch", "https://c.example.com")
    assert R.validate_channel_url("ws://127.0.0.1:1/ch", "http://127.0.0.1:1") is None
    assert R.validate_channel_url("ws://evil.com/ch", "http://127.0.0.1:1")
    assert R.validate_channel_url("https://c.example.com", "https://c.example.com")
    assert R.validate_channel_url("wss://u:p@c.example.com", "https://c.example.com")
    assert R.validate_channel_url(None, "https://c.example.com")


@pytest.mark.parametrize("code,ok", [("ABCD-1234", True), ("a" * 64, True), ("short", False), ("a" * 65, False), ("has space1", False),
                                     ("semi;colon1", False), (None, False), (12345678, False), ("", False)])
def test_code(code, ok):
    assert (R.validate_code(code) is None) is ok


def test_levels():
    assert R.level_ok("health") and R.level_ok("events") and R.level_ok("full")
    assert not R.level_ok("admin") and not R.level_ok(None) and not R.level_ok(3)
    assert R.DEFAULT_LEVEL == "health"
    assert R.relay_cap("health") is None and R.relay_cap("events") == "viewer" and R.relay_cap("full") == "manager"


E = "light.kitchen"


@pytest.mark.parametrize("level,method,path,ok,why", [
    ("health", "GET", "/info", False, "level_too_low"),
    ("health", "GET", "/entities", False, "level_too_low"),
    ("events", "GET", "/info", True, "ok"),
    ("events", "GET", "/me", True, "ok"),
    ("events", "GET", "/entities", True, "ok"),
    ("events", "GET", "/entities?domain=light&limit=50", True, "ok"),
    ("events", "get", f"/entities/{E}", True, "ok"),
    ("events", "GET", f"/entities/{E}/snapshot", False, "level_too_low"),
    ("full", "GET", f"/entities/{E}/snapshot", True, "ok"),
    ("events", "GET", "/devices", True, "ok"),
    ("events", "GET", "/areas", True, "ok"),
    ("events", "POST", f"/entities/{E}/command", False, "level_too_low"),
    ("full", "POST", f"/entities/{E}/command", True, "ok"),
    ("full", "GET", "/entities", True, "ok"),
    # never reachable, at any level
    ("full", "GET", "/users", False, "path_not_allowed"),
    ("full", "POST", "/users", False, "path_not_allowed"),
    ("full", "GET", "/logins", False, "path_not_allowed"),
    ("full", "GET", "/logins/summary", False, "path_not_allowed"),
    ("full", "PUT", "/logins/settings", False, "path_not_allowed"),
    ("full", "GET", "/admin/config", False, "path_not_allowed"),
    ("full", "GET", "/admin/audit", False, "path_not_allowed"),
    ("full", "GET", "/cloud", False, "path_not_allowed"),
    ("full", "PUT", "/cloud", False, "path_not_allowed"),
    ("full", "DELETE", "/cloud", False, "path_not_allowed"),
    ("full", "PUT", "/cloud/debug", False, "path_not_allowed"),
    ("full", "POST", "/auth/token", False, "path_not_allowed"),
    ("full", "GET", "/auth/tokens", False, "path_not_allowed"),
    ("full", "GET", "/events", False, "path_not_allowed"),
    ("full", "GET", "/ws", False, "path_not_allowed"),
    ("full", "DELETE", f"/entities/{E}", False, "path_not_allowed"),
    ("full", "PUT", f"/entities/{E}/command", False, "path_not_allowed"),
    ("full", "GET", f"/entities/{E}/command", False, "path_not_allowed"),
    # malformed
    ("full", "GET", "/entities/../users", False, "bad_request"),
    ("full", "GET", "//users", False, "bad_request"),
    ("full", "GET", "/entities/%2e%2e/users", False, "bad_request"),
    ("full", "GET", "/entities\\..\\users", False, "bad_request"),
    ("full", "GET", "entities", False, "bad_request"),
    ("full", "GET", "/entities#x", False, "bad_request"),
    ("full", "GET", "/entities?x=<script>", False, "bad_request"),
    ("full", "GET", "/entities\nHost: x", False, "bad_request"),
    ("full", "GET", "/" + "a" * 400, False, "bad_request"),
    ("full", None, "/entities", False, "bad_request"),
    ("full", 5, "/entities", False, "bad_request"),
    ("full", "GET", None, False, "bad_request"),
    ("god", "GET", "/info", False, "level_too_low"),
    (None, "GET", "/info", False, "level_too_low"),
])
def test_relay(level, method, path, ok, why):
    assert R.relay_allowed(level, method, path) == (ok, why)


def test_split_path():
    assert R.split_path("/entities?domain=light") == ("/entities", "domain=light")
    assert R.split_path("/entities") == ("/entities", "")
    assert R.split_path("/a/../b") is None


def test_approval_window():
    a = R.Approval()
    assert not a.active(1000)
    ok, _ = a.approve(None, "Ann", 1000)
    assert ok and a.active(1000 + 3599) and not a.active(1000 + 3600)
    assert a.public(1000)["approved_by"] == "Ann"
    a.revoke()
    assert not a.active(1000) and a.public(1000)["approved_until"] is None
    for bad in (0, -5, 1441, "60", True, 1.5e9):
        assert not a.approve(bad, "x", 1000)[0]
    assert a.approve(1440, "x", 0)[0] and a.approve(1, "x", 0)[0]
    a.ask(50)
    assert a.public(60)["requested"] == 50


def test_redact():
    t = ('Authorization: Bearer slr_abcdefgh12345678 and password=hunter22 and {"token": "abcdefgh1234"} '
         'url?access_token=abcdef&x=1 slr_ABCDEFGH12345 secret: topsecretvalue api_key=zzzzzz1')
    out = R.redact(t)
    for leak in ("abcdefgh12345678", "hunter22", "abcdefgh1234", "access_token=abcdef", "ABCDEFGH12345", "topsecretvalue", "zzzzzz1"):
        assert leak not in out, (leak, out)
    assert "x=1" in out
    assert R.redact("nothing secret here") == "nothing secret here"


def test_backoff():
    assert [R.backoff(i) for i in (0, 1, 2, 3, 8, 9, 50)] == [2, 2, 4, 8, 256, 300, 300]
    assert all(R.backoff(i) <= 300 for i in range(100))


def test_heartbeat_clamp():
    assert R.clamp_heartbeat(None) == 30 and R.clamp_heartbeat(1) == 10 and R.clamp_heartbeat(9999) == 300 and R.clamp_heartbeat(45) == 45
    assert R.clamp_heartbeat(True) == 30 and R.clamp_heartbeat("20") == 30


def test_frames():
    assert R.parse_frame('{"type":"ack"}') == {"type": "ack"}
    for bad in ("", "nope", "[]", '{"type":5}', '{"type":"' + "a" * 40 + '"}', "x" * (R.MAX_FRAME + 1), None, 7, '{"a":1}'):
        assert R.parse_frame(bad) is None
    assert R.parse_frame(b'{"type":"request","id":"1"}')["id"] == "1"


def test_public_config_hides_secrets():
    cfg = {"secret": "s" * 40, "endpoint": "https://c.example.com", "cloud_node_id": "n1", "name": "Home", "level": "events", "enrolled_at": 5,
           "last_seen": 1000.0, "channel_url": "wss://c.example.com/x", "enrolled_by": "uid", "approval": {"until": 1}}
    pub = R.public_config(cfg, 1000.0 + 8 * 86400)
    blob = json.dumps(pub)
    assert "s" * 40 not in blob and "channel_url" not in blob and "uid" not in blob and "approval" not in blob
    assert pub["enrolled"] is True and pub["level"] == "events" and 7.9 < pub["silent_days"] < 8.1
    assert R.public_config({}, 1)["enrolled"] is False and R.public_config({}, 1)["level"] == "health"
    assert R.silent_days(None, 5) is None


def test_node_id():
    assert R.validate_cloud_node_id("node-1_a.b:c") and not R.validate_cloud_node_id("a b") and not R.validate_cloud_node_id("") and not R.validate_cloud_node_id(None)


def test_relay_token_is_memory_only_and_scoped():
    T = _load("tokens")
    b = T.TokenBook()
    tok = b.issue_relay("u1", "viewer")
    rec = b.authenticate(tok)
    assert rec and rec["scopes"] == ["cloud"] and rec["max_role"] == "viewer" and rec.get("relay")
    assert not any(r.get("relay") for r in b.to_dict().get("tokens", {}).values()) if isinstance(b.to_dict().get("tokens"), dict) else True
    assert json.dumps(b.to_dict()).find(rec["id"]) == -1                       # never persisted
    assert all(r["id"] != rec["id"] for r in b.list())                         # never listed
    assert b.authenticate(tok, now=time.time() + 4000) is None                 # expires
    assert "cloud:manage" in T.SCOPES
    assert b.create_long_lived("u1", "x", scopes=["cloud"])[0] is None         # `cloud` itself cannot be requested as a scope


# ------------------------------------------------------------------------------------------------ review fixes
def test_f3_redact_obj_keeps_json_valid_and_redacts_values():
    rep = {"status_code": 200, "code": 5, "log_lines": ['password: "hunter2" ok', 'api_key=abcdef123', "Bearer abcdefghijklmnop"],
           "api_key": "zzzzzzzz", "n": [{"token": "abc12345"}]}
    out = R.redact_obj(rep)
    json.dumps(out)
    assert out["status_code"] == 200 and out["code"] == 5
    assert out["api_key"] == "***" and out["n"][0]["token"] == "***"
    txt = json.dumps(out)
    assert "hunter2" not in txt and "abcdef123" not in txt and "abcdefghijklmnop" not in txt


def test_f3_redact_escaped_quotes_and_deep():
    assert "hunter2" not in R.redact('{"m": "password: \\"hunter2\\""}')
    deep = cur = []
    for _ in range(200):
        n = []
        cur.append(n)
        cur = n
    json.dumps(R.redact_obj(deep))


@pytest.mark.parametrize("ch,ep,ok", [
    ("wss://cloud.example.com/chan", "https://cloud.example.com", True),
    ("wss://127.0.0.1:8123/api/websocket", "https://cloud.example.com", False),
    ("wss://other.example.com/chan", "https://cloud.example.com", False),
    ("wss://169.254.169.254/", "https://cloud.example.com", False),
    ("ws://localhost:9/c", "http://localhost:9000", True),
    ("ws://localhost:9/c", "https://cloud.example.com", False),
])
def test_f5_channel_host_must_match_endpoint(ch, ep, ok):
    assert (R.validate_channel_url(ch, ep) is None) is ok


def test_f6_attempt_reset_only_after_stable_uptime():
    assert R.next_attempt(3, 0.2) == 4 and R.next_attempt(3, None) == 4 and R.next_attempt(3, 59) == 4
    assert R.next_attempt(3, 60) == 0
    assert R.backoff_jitter(3, 0.0) == R.backoff(3) * 0.5 and R.backoff_jitter(3, 1.0) == R.backoff(3) * 1.5
    assert R.backoff_jitter(0, 0.5) >= 2.0


def test_f6_handshake_rejected_statuses():
    assert all(R.handshake_rejected(s) for s in (401, 403, 410)) and not R.handshake_rejected(500)


def test_f4_rate_limiter_burst_and_refill():
    rl = R.RateLimiter(rate=10, burst=5)
    assert [rl.allow(0.0) for _ in range(6)] == [True] * 5 + [False]
    assert rl.allow(0.5)


def test_f4_audit_sampler_collapses():
    a = R.AuditSampler()
    assert a.note("k", 0) == (True, 0)
    assert a.note("k", 1)[0] is False and a.note("k", 2)[0] is False
    assert a.note("k", 61) == (True, 2)
    assert a.note("other", 61) == (True, 0)


def test_f13_parse_frame_recursion():
    assert R.parse_frame('{"type":"a","x":' + "[" * 30000 + "]" * 30000 + "}") is None
    assert R.parse_frame('{"type":"ok"}') == {"type": "ok"}


def test_f7_no_cap_at_health():
    assert R.relay_cap("health") is None and R.relay_cap("events") == "viewer"
