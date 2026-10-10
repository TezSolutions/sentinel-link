"""Unit tests for hub_mgmt_work/user_util.py."""
import datetime as dt
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("user_util_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt" / "user_util.py")
uu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uu)


@pytest.mark.parametrize("pw", ["short", "x" * 129, "password", "Password123"[:0] + "12345678", "aaaaaaaa", "abababab", " leading-space1", "trailing-space1 "])
def test_bad_passwords(pw):
    with pytest.raises(uu.Bad):
        uu.check_password(pw)


def test_password_not_username_or_name():
    for pw in ("maitri", "Maitri2024"[:6] + "!!"):
        pass
    with pytest.raises(uu.Bad):
        uu.check_password("maitri123", "maitri", "")
    with pytest.raises(uu.Bad):
        uu.check_password("Vignan Tej", "", "vignan tej")
    assert uu.check_password("correct-horse-battery", "maitri", "Maitri K")


def test_good_password():
    assert uu.check_password("T3z-solar-Kite-77") == "T3z-solar-Kite-77"
    with pytest.raises(uu.Bad):
        uu.check_password(12345678)


def test_display_name():
    assert uu.clean_display_name("  Asha   Rao ") == "Asha Rao"
    for bad in ("", "   ", "x" * 61, "a<b", "a\x00b", None, 5):
        with pytest.raises(uu.Bad):
            uu.clean_display_name(bad)


def test_code():
    assert uu.clean_code("123 456") == "123456"
    for bad in ("12345", "1234567", "abcdef", "", None):
        with pytest.raises(uu.Bad):
            uu.clean_code(bad)


def test_throttle():
    t = [0.0]
    th = uu.Throttle(3, 100, lambda: t[0])
    assert th.wait("a") == 0
    for _ in range(3):
        th.fail("a")
    assert th.wait("a") > 0 and th.wait("b") == 0
    t[0] = 101
    assert th.wait("a") == 0
    th.fail("a"); th.ok("a")
    assert th.wait("a") == 0


def test_client_label_and_session_view():
    assert uu.client_label("http://127.0.0.1:8123/", None) == "Node portal"
    assert uu.client_label("https://app.example.com/x", None) == "app.example.com"
    assert uu.client_label("https://x/", "My App") == "My App"
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    v = uu.session_view("t1", "http://100.1.2.3:8123/", None, now, now, "10.0.0.5", "t1")
    assert v["current"] and v["client"] == "Node portal" and v["ip"] == "10.0.0.5" and v["created"].startswith("2026-01-01")
    assert not uu.session_view("t2", None, None, None, None, None, "t1")["current"]
    assert uu.newest([None, now, now - dt.timedelta(days=1)]) == now.isoformat()
    assert uu.newest([None]) is None
