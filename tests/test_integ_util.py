"""Unit tests for hub_mgmt_work/integ_util.py."""
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("integ_util_t", pathlib.Path.home() / "hub_mgmt_work" / "integ_util.py")
iu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iu)


def test_catalog_consistent():
    doms = [c[0] for c in iu.CATALOG]
    assert len(doms) == len(set(doms))
    assert not (set(doms) & iu.HIDDEN_DOMAINS), "hidden plumbing must not be addable"
    assert not ({"hub_mgmt", "sentinel_link", "tez_sentinel", "backup", "go2rtc", "hacs"} & set(doms))
    for dom, title, grp, blurb in iu.CATALOG:
        assert title and grp and blurb and dom.islower()
    groups = iu.catalog_view({"mqtt": 1})
    assert sum(len(g["items"]) for g in groups) == len(iu.CATALOG)
    assert next(i for g in groups for i in g["items"] if i["domain"] == "mqtt")["added"] == 1


def test_protection_rules():
    for d in ("hub_mgmt", "sentinel_link", "tez_sentinel", "backup", "frigate", "mqtt", "matter", "zha", "hacs"):
        assert not iu.can_remove(d), d
    assert iu.can_remove("tuya") and iu.can_remove("sonos")
    assert iu.can_reload("mqtt") and iu.can_reload("zha") and iu.can_reload("tuya")
    assert not iu.can_reload("hub_mgmt") and not iu.can_reload("sentinel_link") and not iu.can_reload("backup")
    assert iu.can_reconfigure("tuya", True) and not iu.can_reconfigure("tuya", False) and not iu.can_reconfigure("mqtt", True)


def test_health():
    assert iu.health("loaded", False)["ok"]
    assert iu.health("loaded", True)["level"] == "warn" and not iu.health("loaded", True)["ok"]
    assert iu.health("setup_error", False)["level"] == "bad"
    assert iu.health("setup_retry", False)["label"].startswith("Not reachable")
    assert iu.health("setup_in_progress", False)["level"] == "info"
    assert iu.health("weird_new_state", False)["label"] == "Weird new state"


@pytest.mark.parametrize("raw,expect_absent", [
    ("login failed password=hunter2 for user", "hunter2"),
    ("auth error token: abc123def456", "abc123def456"),
    ("GET http://admin:s3cr3t@192.168.1.5/x failed", "s3cr3t"),
    ("Authorization Bearer eyJhbGciOi.xxx", "eyJhbGciOi"),
    ("api_key=ZZZZ1111 invalid", "ZZZZ1111"),
    ("Authorization: Basic dXNlcjpwYXNz failed", "dXNlcjpwYXNz"),
    ("bad Bearer abcdef123456 here", "abcdef123456"),
    ('{"password": "p4ss-w0rd!"}', "p4ss-w0rd"),
])
def test_reason_scrubbed(raw, expect_absent):
    assert expect_absent not in iu.clean_reason(raw)


def test_reason_limits():
    assert iu.clean_reason(None) is None and iu.clean_reason("") is None
    assert len(iu.clean_reason("x" * 1000)) == 240 and "\n" not in iu.clean_reason("a\nb")


def test_user_input_bounds():
    assert iu.clean_user_input({"host": "10.0.0.5", "port": 80, "ssl": True, "n": None, "l": [1, "a"]}) == {"host": "10.0.0.5", "port": 80, "ssl": True, "n": None, "l": [1, "a"]}
    for bad in ({"a" * 100: 1}, {"x y": 1}, {"k": "x" * 5000}, {"k": [0] * 201}, {str(i): 1 for i in range(61)}, {"k": {"a": {"b": {"c": {"d": {"e": 1}}}}}}, {"k": object()}, {1: 2}):
        with pytest.raises(ValueError):
            iu.clean_user_input(bad)


def test_entry_view_hides_reason_when_ok_and_scrubs_when_not():
    ok = iu.entry_view("tuya", "me@x.com", "loaded", "password=zzz", False, 3, 9, True, "e1", "user", False)
    assert ok["reason"] is None and ok["name"] == "Tuya" and ok["can_remove"] and ok["can_reconfigure"] and not ok["protected"]
    bad = iu.entry_view("tuya", "me@x.com", "setup_error", "login failed password=zzz", False, 0, 0, True, "e1", "user", False)
    assert "zzz" not in bad["reason"] and bad["health"]["level"] == "bad"
    prot = iu.entry_view("frigate", "127.0.0.1:5000", "loaded", None, False, 1, 1, True, "e2", "user", False)
    assert prot["protected"] and not prot["can_remove"] and prot["can_reload"] and not prot["can_reconfigure"]
    off = iu.entry_view("sonos", "Sonos", "not_loaded", None, False, 0, 0, True, "e3", "zeroconf", True)
    assert off["disabled"] and not off["can_reload"] and not off["can_reconfigure"]
    assert iu.entry_view("zzz_unknown", "", "loaded", None, False, 0, 0, False, "e4", "user", False)["name"] == "Zzz Unknown"


def test_frigate_is_shown_as_ainvr():
    v = iu.entry_view("frigate", "127.0.0.1:5000", "loaded", None, False, 1, 1, True, "e", "user", False)
    assert v["name"] == "AINVR" and "rigate" not in v["name"]
