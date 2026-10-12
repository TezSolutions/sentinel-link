"""Unit tests for hub_mgmt/login_log.py (pure) and the classifier in login_service.py."""
import importlib.util
import json
import pathlib
import re
import sys
import types

import pytest

C = pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


L = _load("login_log_under_test", C / "login_log.py")
SVC_SRC = (C / "login_service.py").read_text()
# the classifier is pure; pull it out of the service module without importing Home Assistant
_ns: dict = {"Any": object}
exec(SVC_SRC[SVC_SRC.index("def classify("):SVC_SRC.index("class LoginService")], _ns)  # noqa: S102
classify, door_for = _ns["classify"], _ns["door_for"]

T0 = 1_800_000_000.0


def mk(**kw):
    d = dict(user_id="u1", username="amy", name="Amy", role="homeowner", door="portal", outcome="success", ip="10.0.0.5", device="Chrome on macOS")
    d.update(kw)
    return d


def log_with_people():
    lg = L.LoginLog()
    lg.append(now=T0, **mk(user_id="own", username="olivia", name="Olivia", role="homeowner"))
    lg.append(now=T0 + 1, **mk(user_id="adm", username="admin", name="Admin", role="admin", ip="10.0.0.9"))
    lg.append(now=T0 + 2, **mk(user_id="ins", username="ivan", name="Ivan", role="installer", ip="10.0.0.8"))
    lg.append(now=T0 + 3, **mk(user_id="vnd", username="tez-admin", name="Tez Admin", role="superadmin", door="portal", ip="203.0.113.7"))
    lg.append(now=T0 + 4, **mk(user_id=None, username=None, name=L.UNKNOWN_NAME, role=None, outcome="wrong_password", ip="198.51.100.2"))
    return lg


# ------------------------------------------------------------------ chain
def test_chain_verifies_and_links_entries():
    lg = log_with_people()
    assert lg.verify()["ok"] and lg.verify()["entries"] == 5
    assert lg.entries[1]["prev"] == lg.entries[0]["hash"] and lg.entries[0]["prev"] == L.GENESIS


@pytest.mark.parametrize("field,value", [("outcome", "success"), ("ip", "1.2.3.4"), ("username", "someoneelse"), ("ts", 5.0), ("role", "admin")])
def test_editing_any_field_breaks_the_chain(field, value):
    lg = log_with_people()
    lg.entries[2][field] = value if lg.entries[2].get(field) != value else "x"
    v = lg.verify()
    assert not v["ok"] and v["broken_at"] == lg.entries[2]["seq"]


def test_deleting_or_reordering_is_detected():
    lg = log_with_people()
    del lg.entries[2]
    assert not lg.verify()["ok"]
    lg = log_with_people()
    lg.entries[1], lg.entries[2] = lg.entries[2], lg.entries[1]
    assert not lg.verify()["ok"]


def test_persistence_roundtrip_keeps_the_chain():
    lg = log_with_people()
    lg2 = L.LoginLog()
    lg2.load(json.loads(json.dumps(lg.dump())))
    assert lg2.verify()["ok"] and lg2.next_seq == lg.next_seq
    lg2.append(now=T0 + 50, **mk())
    assert lg2.verify()["ok"] and lg2.entries[-1]["seq"] == 6


# ------------------------------------------------------------------ retention
def test_retention_prunes_and_chain_still_verifies():
    lg = L.LoginLog()
    for i in range(5):
        lg.append(now=T0 + i * 86400 * 100, **mk())           # 100-day steps
    assert lg.prune(now=T0 + 4 * 86400 * 100 + 10) == 1        # 365-day default: only the entry older than 365 days goes
    assert len(lg.entries) == 4 and lg.verify()["ok"] and lg.anchor != L.GENESIS
    assert lg.prune(now=T0 + 4 * 86400 * 100 + 10 + 200 * 86400) == 2 and len(lg.entries) == 2 and lg.verify()["ok"]


def test_retention_never_below_ninety_days():
    lg = L.LoginLog()
    lg.settings["retention_days"] = 1          # even a hand-edited store cannot shorten it
    lg.append(now=T0, **mk())
    assert lg.prune(now=T0 + 80 * 86400) == 0 and lg.prune(now=T0 + 91 * 86400) == 1
    _s, errs = lg.set_settings({"retention_days": 30})
    assert errs and lg.settings["retention_days"] == 1


def test_size_cap_drops_oldest():
    lg = L.LoginLog()
    for i in range(L.MAX_ENTRIES + 5):
        lg.append(now=T0 + i, **mk())
    lg.prune(now=T0 + L.MAX_ENTRIES)
    assert len(lg.entries) == L.MAX_ENTRIES and lg.verify()["ok"]


# ------------------------------------------------------------------ privacy rules
@pytest.mark.parametrize("role", ["homeowner", "admin", "superadmin"])
def test_homeowner_admin_and_vendor_see_everybody(role):
    lg = log_with_people()
    r = lg.query("someone", role)
    assert r["scope"] == "all" and r["total"] == 5


@pytest.mark.parametrize("role", ["installer", "manager", "operator", "viewer", "user", None])
def test_other_roles_see_only_their_own(role):
    lg = log_with_people()
    r = lg.query("ins", role)
    assert r["scope"] == "own" and [e["user_id"] for e in r["logins"]] == ["ins"]
    assert lg.query("nobody", role)["total"] == 0


def test_admin_logins_are_visible_to_the_homeowner():
    lg = log_with_people()
    names = [e["username"] for e in lg.query("own", "homeowner")["logins"]]
    assert "admin" in names


def test_a_capped_token_sees_only_its_own_user():
    lg = log_with_people()
    assert lg.query("own", "homeowner", "viewer")["scope"] == "own"
    assert lg.query("own", "homeowner", "operator")["total"] == 1
    assert lg.query("own", "homeowner", "manager")["total"] == 5


def test_vendor_is_masked_for_everyone_but_the_vendor():
    lg = log_with_people()
    for role in ("homeowner", "admin"):
        row = next(e for e in lg.query("x", role)["logins"] if "support" in e["flags"])
        assert row["name"] == L.SUPPORT_NAME and row["username"] == "tez-solutions-support" and row["role"] == "support" and row["user_id"] is None
        assert "tez-admin" not in json.dumps(lg.query("x", role)) and "Tez Admin" not in json.dumps(lg.query("x", role))
    row = next(e for e in lg.query("vnd", "superadmin")["logins"] if "support" in e["flags"])
    assert row["username"] == "tez-admin"


def test_filtering_by_the_masked_vendor_name_works_and_cannot_unmask():
    lg = log_with_people()
    assert lg.query("own", "homeowner", user="tez-solutions-support")["total"] == 1
    assert lg.query("own", "homeowner", user="tez-admin")["total"] == 0


def test_unknown_accounts_never_store_what_was_typed():
    lg = log_with_people()
    e = lg.entries[-1]
    assert e["username"] is None and e["name"] == L.UNKNOWN_NAME


def test_no_secret_fields_exist():
    lg = log_with_people()
    blob = json.dumps(lg.dump())
    assert not re.search(r"(?i)password\"\s*:|token\"\s*:|\"code\"", blob)
    assert set(lg.entries[0]) <= {"seq", "ts", "kind", "user_id", "username", "name", "role", "door", "outcome", "ip", "device", "flags", "prev", "hash"}


# ------------------------------------------------------------------ query
def test_filters_and_paging():
    lg = L.LoginLog()
    for i in range(30):
        lg.append(now=T0 + i, **mk(outcome="wrong_password" if i % 3 == 0 else "success", door="hub" if i % 2 else "portal"))
    assert lg.query("o", "admin", outcome="wrong_password")["total"] == 10
    assert lg.query("o", "admin", door="hub")["total"] == 15
    assert lg.query("o", "admin", since=T0 + 20)["total"] == 10 and lg.query("o", "admin", until=T0 + 4)["total"] == 5
    p1 = lg.query("o", "admin", limit=10)
    assert len(p1["logins"]) == 10 and p1["next_before"] == p1["logins"][-1]["seq"]
    p2 = lg.query("o", "admin", limit=10, before=p1["next_before"])
    assert p2["logins"][0]["seq"] < p1["logins"][-1]["seq"] and not set(e["seq"] for e in p1["logins"]) & set(e["seq"] for e in p2["logins"])
    assert [e["seq"] for e in p1["logins"]] == sorted((e["seq"] for e in p1["logins"]), reverse=True)


# ------------------------------------------------------------------ flags and alerts
def test_new_ip_flag_not_on_first_sign_in():
    lg = L.LoginLog()
    a = lg.append(now=T0, **mk(ip="10.0.0.1"))
    b = lg.append(now=T0 + 1, **mk(ip="10.0.0.1"))
    c = lg.append(now=T0 + 2, **mk(ip="10.0.0.2"))
    d = lg.append(now=T0 + 3, **mk(ip="10.0.0.2"))
    assert "new_ip" not in a["flags"] + b["flags"] + d["flags"] and "new_ip" in c["flags"]


def test_failed_sign_in_never_marks_an_ip_as_known():
    lg = L.LoginLog()
    lg.append(now=T0, **mk(ip="10.0.0.1"))
    lg.append(now=T0 + 1, **mk(ip="9.9.9.9", outcome="wrong_password"))
    assert "new_ip" in lg.append(now=T0 + 2, **mk(ip="9.9.9.9"))["flags"]


def test_failed_burst_flags_on_the_third_failure_within_ten_minutes():
    lg = L.LoginLog()
    f = [lg.append(now=T0 + i * 30, **mk(outcome="wrong_password", ip="8.8.8.8"))["flags"] for i in range(4)]
    assert f[0] == [] and f[1] == [] and f[2] == ["failed_burst"] and f[3] == []
    far = lg.append(now=T0 + 5000, **mk(outcome="wrong_password", ip="8.8.8.8"))
    assert far["flags"] == []


def test_failed_burst_by_username_even_from_different_addresses():
    lg = L.LoginLog()
    out = [lg.append(now=T0 + i, **mk(outcome="wrong_2fa", ip=f"7.7.7.{i}"))["flags"] for i in range(3)]
    assert out[2] == ["failed_burst"]


def test_vendor_sign_in_and_bundle_are_flagged_support():
    lg = L.LoginLog()
    s = lg.append(now=T0, **mk(role="superadmin"))
    b = lg.append(now=T0 + 1, kind="support_bundle", **mk(role="superadmin", outcome="downloaded"))
    fail = lg.append(now=T0 + 2, **mk(role="superadmin", outcome="wrong_password"))
    assert "support" in s["flags"] and set(b["flags"]) == {"support", "bundle"} and "support" not in fail["flags"]
    adm = lg.append(now=T0 + 3, kind="support_bundle", **mk(role="admin", outcome="downloaded"))
    assert adm["flags"] == ["bundle"]


def test_alert_kinds_follow_settings():
    lg = L.LoginLog()
    e = {"flags": ["failed_burst", "new_ip", "support"], "kind": "signin"}
    assert lg.alert_kinds(e) == ["failed", "new_ip", "support"]
    lg.set_settings({"alerts": {"failed": False}})
    assert lg.alert_kinds(e) == ["new_ip", "support"]
    lg.set_settings({"alerts": {"new_ip": False, "support": False}})
    assert lg.alert_kinds(e) == []
    assert lg.alert_kinds({"flags": [], "kind": "signin"}) == []


def test_alert_text_for_vendor_never_leaks_the_account_name():
    e = {"role": "superadmin", "name": "Tez Admin", "username": "tez-admin", "ip": "203.0.113.7", "door": "portal", "device": "Chrome on Linux", "kind": "signin"}
    for k in ("support", "new_ip", "failed"):
        t, m = L.alert_text(e, k, "Home")
        assert "tez-admin" not in t + m and "Tez Admin" not in t + m and L.SUPPORT_NAME in t + m
    t, m = L.alert_text({**e, "kind": "support_bundle"}, "support", "Home")
    assert "support file" in (t + m).lower() and "203.0.113.7" in m


# ------------------------------------------------------------------ settings
def test_settings_validation():
    lg = L.LoginLog()
    ok_, errs = lg.set_settings({"retention_days": 400, "alerts": {"failed": False}, "notify_services": ["mobile_app_phone", "mobile_app_phone"]})
    assert not errs and ok_["retention_days"] == 400 and ok_["notify_services"] == ["mobile_app_phone"] and ok_["alerts"]["failed"] is False
    for bad in ({"retention_days": 89}, {"retention_days": "x"}, {"retention_days": 99999}, {"alerts": {"nope": True}}, {"alerts": {"failed": "yes"}},
                {"notify_services": ["bad name!"]}, {"notify_services": "x"}, {"notify_services": ["a"] * 11}):
        before = json.dumps(lg.settings)
        _s, errs = lg.set_settings(bad)
        assert errs and json.dumps(lg.settings) == before, bad


# ------------------------------------------------------------------ summary
def test_summary_counts_in_scope_only():
    lg = L.LoginLog()
    lg.append(now=T0, **mk(user_id="a"))
    lg.append(now=T0 + 1, **mk(user_id="a", outcome="wrong_password"))
    lg.append(now=T0 + 2, **mk(user_id="b"))
    s = lg.summary("b", "viewer", None, now=T0 + 100)
    assert s["scope"] == "own" and s["last_24h"] == {"success": 1, "failed": 0, "new_ip": 0, "support": 0}
    s = lg.summary("b", "homeowner", None, now=T0 + 100)
    assert s["last_24h"]["success"] == 2 and s["last_24h"]["failed"] == 1
    assert s["your_last_sign_in"]["user_id"] == "b"
    assert lg.summary("b", "homeowner", None, now=T0 + 8 * 86400)["last_7d"]["success"] == 0


# ------------------------------------------------------------------ device label
@pytest.mark.parametrize("ua,exp", [
    ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/120 Safari/537", "Chrome on Windows"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17) Safari/604", "Safari on iOS"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:120) Firefox/120", "Firefox on Linux"),
    ("aiohttp/3.9", "API client"), ("", "unknown"), (None, "unknown")])
def test_device_label(ua, exp):
    assert L.device_label(ua) == exp


def test_device_label_is_short_and_has_no_version_or_identifiers():
    out = L.device_label("Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AB12.3456) Chrome/120.0.6099.43 Mobile Safari/537.36 serial=ABC123")
    assert len(out) <= 60 and "ABC123" not in out and "120" not in out


# ------------------------------------------------------------------ classifier (native sign-in flow)
@pytest.mark.parametrize("data,result,exp", [
    ({"username": "a", "password": "p", "client_id": "x"}, {"type": "create_entry"}, "success"),
    ({"username": "a", "password": "p"}, {"type": "form", "errors": {"base": "invalid_auth"}}, "wrong_password"),
    ({"username": "a", "password": "p"}, {"type": "form", "step_id": "mfa", "errors": {}}, None),
    ({"code": "123456"}, {"type": "create_entry"}, "success"),
    ({"code": "123456"}, {"type": "form", "errors": {"base": "invalid_code"}}, "wrong_2fa"),
    ({"code": "123456"}, {"type": "abort", "reason": "too_many_retry"}, "blocked"),
    ({"client_id": "x"}, {"type": "form"}, None), (None, None, None), ({"username": "a", "password": "p"}, None, None)])
def test_classify(data, result, exp):
    assert classify(data, result) == exp


class _Req:
    def __init__(self, remote, hdr=None):
        self.remote, self.headers = remote, hdr or {}


def test_real_ip_only_trusted_for_the_portal_from_the_local_network():
    ns = {"ipaddress": __import__("ipaddress")}
    exec(SVC_SRC[SVC_SRC.index("def real_ip("):SVC_SRC.index("_HOOKED = {")], ns)  # noqa: S102
    r = ns["real_ip"]
    h = {"X-Tez-Client-IP": "203.0.113.9"}
    assert r(_Req("172.18.0.1", h), "portal") == "203.0.113.9" and r(_Req("127.0.0.1", h), "portal") == "203.0.113.9"
    assert r(_Req("172.18.0.1", h), "hub") == "172.18.0.1"                        # other doors never trust the header
    assert r(_Req("8.8.4.4", h), "portal") == "8.8.4.4"               # nor does a public source
    assert r(_Req("172.18.0.1", {"X-Tez-Client-IP": "not-an-ip"}), "portal") == "172.18.0.1"
    assert r(_Req("172.18.0.1"), "portal") == "172.18.0.1"


def test_shutdown_flush_is_a_coroutine_not_a_lambda():
    assert "lambda _e: hass.async_create_task" not in (C / "__init__.py").read_text()


def test_door_for_the_portal_client_id():
    assert door_for("http://127.0.0.1:8123/") == "portal" and door_for("https://app.example/") == "hub" and door_for(None) == "hub"


# ------------------------------------------------------------------ wiring guards (static)
def test_recording_never_stores_typed_text_for_unknown_accounts():
    assert "(what was typed is not stored for unknown accounts)" in SVC_SRC or "what was typed is not stored" in SVC_SRC


def test_no_api_can_delete_or_edit_entries():
    for f in ("login_log.py", "login_service.py", "logins.py"):
        src = (C / f).read_text()
        assert not re.search(r"hub_mgmt/login_(delete|clear|edit|remove|purge)", src), f
    views = (C.parent / "sentinel_link" / "api" / "views.py").read_text()
    seg = views[views.index("class LoginsView"):views.index("# ---------------------------------------------------------------------------------------------- cloud")]  # the three sign-in history classes only
    assert "async def delete" not in seg and "async def post" not in seg and "async def patch" not in seg


def test_settings_cannot_be_changed_by_the_vendor():
    src = (C / "logins.py").read_text()
    assert 'SETTINGS_ROLES = ("homeowner", "admin")' in src and "superadmin" not in src[src.index("SETTINGS_ROLES"):src.index("SETTINGS_ROLES") + 60]
    views = (C.parent / "sentinel_link" / "api" / "views.py").read_text()
    assert 'hub_role not in ("homeowner", "admin")' in views and "logins:settings" in views


def test_every_role_that_can_open_the_portal_has_the_logins_capability():
    init = (C / "__init__.py").read_text()
    for role in ('"installer": {', '"homeowner": {'):
        assert '"logins"' in init[init.index(role):init.index(role) + 200]
    assert '"logins"}' in init[init.index("_ADMIN_CAPS ="):init.index("_ADMIN_CAPS =") + 220]


def test_portal_blocks_the_internal_note_command_from_browsers():
    p = pathlib.Path.home() / "tez-sentinel-image/stack/portal/portal.py"
    if p.exists():
        src = p.read_text()
        assert 'PORTAL_ONLY = {"hub_mgmt/login_note"}' in src and "if t in PORTAL_ONLY" in src


def test_every_sign_in_door_records():
    a = (C.parent / "sentinel_link" / "api" / "auth.py").read_text()
    for needle in ('"link_app", "success"', '"blocked" if why == "inactive" else "wrong_password"', '"link_app", "wrong_2fa"', '"link_app", "blocked"',
                   '"link_token", "success"', '"link_token", "blocked"'):
        assert needle in a, needle
    users = (C / "users.py").read_text() + (C / "__init__.py").read_text()
    assert "install_flow_hook" in users
    portal = pathlib.Path.home() / "tez-sentinel-image/stack/portal/portal.py"
    if portal.exists():
        assert "login_note" in portal.read_text()
