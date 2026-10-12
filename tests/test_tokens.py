"""Unit tests for api/tokens.py (pure Python)."""
import base64
import hashlib
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "custom_components/sentinel_link/api"))
import tokens as T  # noqa: E402

VER = "A" * 64
CHAL = base64.urlsafe_b64encode(hashlib.sha256(VER.encode()).digest()).rstrip(b"=").decode()


def book_with_app():
    b = T.TokenBook()
    assert b.save_client("com.acme.app", "Acme", ["com.acme.app://cb", "https://acme.example/cb"]) == []
    return b


# ---------------------------------------------------------------- PKCE / redirect URIs
def test_pkce_roundtrip_and_rejects():
    assert T.valid_challenge(CHAL) and T.pkce_ok(VER, CHAL)
    assert not T.pkce_ok("B" * 64, CHAL)
    assert not T.pkce_ok("short", CHAL)                       # RFC 7636: 43-128 chars
    assert not T.valid_challenge("x" * 10) and not T.valid_challenge(None)


@pytest.mark.parametrize("uri,ok", [
    ("com.acme.app://cb", True), ("my-app://cb", True), ("https://a.example/cb", True),
    ("http://localhost:8080/cb", True), ("http://127.0.0.1/cb", True),
    ("http://evil.example/cb", False), ("javascript:alert(1)", False), ("data:text/html,x", False),
    ("file:///etc/passwd", False), ("myapp://cb", False), ("https://a.example/cb#frag", False),
    ("", False), ("https:///nohost", False), ("https://a.example/ cb", False), ("/relative", False),
])
def test_redirect_uri_rules(uri, ok):
    assert (T.validate_redirect_uri(uri) is None) is ok


def test_client_registration_validation_and_limits():
    b = T.TokenBook()
    assert b.save_client("x", "n", ["com.a.b://c"])                        # id too short
    assert b.save_client("good.id", "", ["com.a.b://c"])                   # empty name
    assert b.save_client("good.id", "n", [])                              # no redirect
    assert b.save_client("good.id", "n", ["http://evil.example/"])        # bad redirect
    assert b.save_client("good.id", "n", ["com.a.b://c"]) == []
    assert b.redirect_ok("good.id", "com.a.b://c") and not b.redirect_ok("good.id", "com.a.b://other")
    assert not b.redirect_ok("nope", "com.a.b://c")


# ---------------------------------------------------------------- authorization code
def test_code_flow_single_use_and_bound():
    b = book_with_app()
    code = b.new_code("com.acme.app", "com.acme.app://cb", CHAL, "u1")
    assert b.redeem_code(code, "com.acme.app", "com.acme.app://cb", VER)["user_id"] == "u1"
    assert b.redeem_code(code, "com.acme.app", "com.acme.app://cb", VER) is None      # single use
    # wrong verifier / client / redirect all consume the code too
    for args in (("com.acme.app", "com.acme.app://cb", "B" * 64), ("other", "com.acme.app://cb", VER),
                 ("com.acme.app", "https://acme.example/cb", VER)):
        c = b.new_code("com.acme.app", "com.acme.app://cb", CHAL, "u1")
        assert b.redeem_code(c, *args) is None
        assert b.redeem_code(c, "com.acme.app", "com.acme.app://cb", VER) is None


def test_code_expires():
    b = book_with_app()
    code = b.new_code("com.acme.app", "com.acme.app://cb", CHAL, "u1", now=1000)
    assert b.redeem_code(code, "com.acme.app", "com.acme.app://cb", VER, now=1000 + T.CODE_TTL + 1) is None


# ---------------------------------------------------------------- sessions: access + refresh
def test_session_access_then_refresh_rotation_and_replay():
    b = book_with_app()
    s = b.issue_session("u1", "com.acme.app", now=1000)
    assert b.authenticate(s["access_token"], now=1001)["user_id"] == "u1"
    assert b.authenticate(s["refresh_token"], now=1001) is None                        # refresh is not an API credential
    assert b.authenticate(s["access_token"], now=1000 + T.ACCESS_TTL + 1) is None      # access expires
    assert b.tokens[s["refresh_id"]]["expires"] is None                                # refresh never expires
    r1 = b.refresh(s["refresh_token"], "com.acme.app", now=5000)
    assert r1 and r1["refresh_token"] != s["refresh_token"]
    assert b.refresh(s["refresh_token"], "com.acme.app", now=5000 + 5)                  # inside grace: lost response retry
    assert b.refresh(s["refresh_token"], "com.acme.app", now=5000 + T.REFRESH_GRACE + 5) is None
    assert s["refresh_id"] not in b.tokens                                              # replay after grace revokes the session
    assert b.refresh(r1["refresh_token"], "com.acme.app", now=9999) is None


def test_refresh_requires_matching_client_and_valid_secret():
    b = book_with_app()
    s = b.issue_session("u1", "com.acme.app")
    assert b.refresh(s["refresh_token"], "someone.else") is None
    forged = s["refresh_token"][:-3] + "AAA"
    assert b.refresh(forged, "com.acme.app") is None
    assert b.refresh(s["refresh_token"], "com.acme.app")


def test_revoking_session_kills_its_access_tokens():
    b = book_with_app()
    s = b.issue_session("u1", "com.acme.app")
    b.revoke(s["refresh_id"])
    assert b.authenticate(s["access_token"]) is None
    assert b.refresh(s["refresh_token"], "com.acme.app") is None


def test_removing_client_revokes_everything():
    b = book_with_app()
    s = b.issue_session("u1", "com.acme.app")
    b.remove_client("com.acme.app")
    assert b.authenticate(s["access_token"]) is None and not b.tokens


# ---------------------------------------------------------------- long-lived tokens
def test_long_lived_default_never_expires_and_authenticates():
    b = T.TokenBook()
    rec, tok = b.create_long_lived("u1", "Wall panel")
    assert rec["expires"] is None and tok.startswith("sll_")
    assert b.authenticate(tok, now=10 ** 11)["user_id"] == "u1"                         # ~3000 years later
    assert b.authenticate(tok + "x") is None and b.authenticate("sll_nope") is None
    assert b.authenticate(tok.replace("sll_", "sla_")) is None


def test_long_lived_optional_expiry_and_cap_validation():
    b = T.TokenBook()
    rec, tok = b.create_long_lived("u1", "Temp", expires_in_days=1, max_role="viewer", now=1000)
    assert rec["max_role"] == "viewer"
    assert b.authenticate(tok, now=1000 + 86400 + 1) is None
    for bad in ({"name": ""}, {"name": "x", "expires_in_days": 0}, {"name": "x", "expires_in_days": True},
                {"name": "x", "max_role": "admin"}, {"name": "x", "max_role": "root"}):
        r, e = b.create_long_lived("u1", **bad)
        assert r is None and e


def test_per_user_token_limit():
    b = T.TokenBook()
    for i in range(T.MAX_TOKENS_PER_USER):
        assert b.create_long_lived("u1", f"t{i}")[0]
    assert b.create_long_lived("u1", "one more")[0] is None
    assert b.create_long_lived("u2", "other user")[0]


def test_revoke_user_and_presented_revoke():
    b = book_with_app()
    _, t1 = b.create_long_lived("u1", "a")
    s = b.issue_session("u1", "com.acme.app")
    _, t2 = b.create_long_lived("u2", "b")
    assert b.revoke_presented("sll_aaaaaaaaaaaa.zzzzzzzzzzzzzzzzzzzzzzzz") == []        # wrong secret revokes nothing
    assert b.revoke_presented(t2)
    assert b.authenticate(t2) is None
    b.revoke_user("u1")
    assert b.authenticate(t1) is None and b.authenticate(s["access_token"]) is None and not b.tokens


# ---------------------------------------------------------------- secrets never stored / leaked
def test_only_hashes_are_stored_or_listed():
    b = book_with_app()
    rec, tok = b.create_long_lived("u1", "Panel")
    s = b.issue_session("u1", "com.acme.app")
    blob = json.dumps(b.to_dict()) + json.dumps(b.list())
    for secret in (tok.split(".", 1)[1], s["refresh_token"].split(".", 1)[1], s["access_token"].split(".", 1)[1]):
        assert secret not in blob
    assert all("hash" not in r for r in b.list())


def test_persistence_roundtrip_keeps_tokens_not_access():
    b = book_with_app()
    _, tok = b.create_long_lived("u1", "Panel")
    s = b.issue_session("u1", "com.acme.app")
    b2 = T.TokenBook()
    b2.load(json.loads(json.dumps(b.to_dict())))
    assert b2.authenticate(tok)["user_id"] == "u1"
    assert b2.refresh(s["refresh_token"], "com.acme.app")                               # sessions survive a restart
    assert b2.authenticate(s["access_token"]) is None                                   # access tokens are memory only


def test_parse_token_rejects_garbage():
    for bad in ("", None, 5, "Bearer x", "sll_", "sll_zz.yy", "sll_" + "g" * 12 + "." + "a" * 30, "x" * 500):
        assert T.parse_token(bad) is None


# ---------------------------------------------------------------- throttle
def test_throttle_locks_and_expires():
    t = T.Throttle(max_fail=3, window=100, lock=50)
    assert not t.fail("u", 0) and not t.fail("u", 1) and t.fail("u", 2)
    assert t.locked("u", 3) and not t.locked("other", 3)
    assert not t.locked("u", 60)
    assert not t.fail("u", 61)
    t.ok("u")
    assert not t.fail("u", 62) and not t.fail("u", 63)


# ---------------------------------------------------------------- scopes (users:write / users:password)
def test_token_has_no_scopes_by_default():
    rec, _tok = book_with_app().create_long_lived("u1", "panel")
    assert rec["scopes"] == [] and T.TokenBook.public(rec)["scopes"] == []


def test_scopes_are_stored_sorted_and_deduplicated():
    rec, _t = book_with_app().create_long_lived("u1", "cloud", scopes=["users:write", "users:password", "users:write"])
    assert rec["scopes"] == ["users:password", "users:write"]


@pytest.mark.parametrize("bad", [["admin"], ["users:*"], ["users:write", "root"]])
def test_unknown_scope_refused(bad):
    rec, errs = book_with_app().create_long_lived("u1", "x", scopes=bad)
    assert rec is None and any("scopes" in e for e in errs)


def test_scopes_survive_persistence_and_authenticate():
    b = book_with_app()
    rec, tok = b.create_long_lived("u1", "cloud", scopes=["users:write"])
    b2 = T.TokenBook(); b2.load(json.loads(json.dumps(b.to_dict())))
    got = b2.authenticate(tok)
    assert got and got["scopes"] == ["users:write"]


def test_oauth_session_tokens_carry_no_scopes():
    b = book_with_app()
    s = b.issue_session("u1", "com.acme.app")
    assert not (b.authenticate(s["access_token"]) or {}).get("scopes")


def test_scope_list_is_closed():
    assert T.SCOPES == ("users:write", "users:password", "logins:settings", "cloud:manage")
