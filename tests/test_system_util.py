"""Unit tests for hub_mgmt_work/system_util.py."""
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("system_util_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt" / "system_util.py")
su = importlib.util.module_from_spec(spec)
spec.loader.exec_module(su)

TZ = lambda z: z in ("Asia/Kolkata", "UTC")


@pytest.mark.parametrize("raw,leak", [
    ("Authorization: Bearer abcdef123456789", "abcdef123456789"),
    ("auth failed token=supersecretvalue now", "supersecretvalue"),
    ('{"access_token": "abc.def.ghi-123456"}', "abc.def.ghi-123456"),
    ("GET /api/x?access_token=zzzzTOPSECRET&a=1", "zzzzTOPSECRET"),
    ("connect mqtt://user:hunter2pw@host:1883", "hunter2pw"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36", "SflKxwRJSMeKKF2QT4fwpMeJf36"),
    ("hash 0123456789abcdef0123456789abcdef0123", "0123456789abcdef0123456789abcdef0123"),
    ("password: 'my pass'", "pass'"),
    ("client_secret=ABCDEF&x=1", "ABCDEF"),
])
def test_redact_removes_secret(raw, leak):
    assert leak not in su.redact(raw)


def test_redact_keeps_normal_text():
    t = "2026-10-10 07:51:23.650 WARNING (MainThread) [homeassistant.helpers.service] light.kitchen is unavailable"
    assert su.redact(t) == t


def test_line_level():
    assert su.line_level("2026-10-10 07:51:23.650 WARNING (Main) x") == "WARNING"
    assert su.line_level("2026-10-10T07:51:23 ERROR y") == "ERROR"
    assert su.line_level("Traceback (most recent call last):") is None


LOG = ["2026-10-10 07:00:00 INFO a started", "2026-10-10 07:00:01 WARNING b slow", "2026-10-10 07:00:02 ERROR c failed",
       "Traceback (most recent call last):", '  File "x.py", line 1', "ValueError: bad token=SECRET123",
       "2026-10-10 07:00:03 INFO d fine"]


def test_select_level_keeps_traceback_with_its_entry():
    out = su.select_log(LOG, "ERROR", None, 100)
    assert len(out) == 4 and out[0].endswith("c failed") and "SECRET123" not in " ".join(out)


def test_select_drops_continuation_of_hidden_entry():
    out = su.select_log(LOG, "WARNING", None, 100)
    assert not any("a started" in x or "fine" in x for x in out) and len(out) == 5


def test_select_text_filter_and_limit():
    assert su.select_log(LOG, None, "SLOW", 100) == [LOG[1]]
    assert len(su.select_log(LOG, None, None, 2)) == 2
    assert len(su.select_log(["x"] * 5000, None, None, 99999)) == su.LOG_LINES_MAX


def test_settings_valid():
    c, e = su.validate_settings({"name": " Home ", "time_zone": "Asia/Kolkata", "unit_system": "metric", "latitude": "17.4",
                                 "longitude": 78.4, "elevation": 500, "country": "in"}, TZ)
    assert not e and c["location_name"] == "Home" and c["latitude"] == 17.4 and c["country"] == "IN"


@pytest.mark.parametrize("bad,field", [({"name": ""}, "name"), ({"name": "x" * 61}, "name"), ({"name": "a<b"}, "name"),
                                       ({"time_zone": "Mars/Base"}, "time_zone"), ({"unit_system": "furlongs"}, "unit_system"),
                                       ({"latitude": 91}, "latitude"), ({"longitude": "abc"}, "longitude"),
                                       ({"latitude": float("nan")}, "latitude"), ({"elevation": 99999}, "elevation"),
                                       ({"country": "India"}, "country")])
def test_settings_invalid(bad, field):
    c, e = su.validate_settings(bad, TZ)
    assert field in e and not c


def test_settings_only_checks_present_fields():
    assert su.validate_settings({}, TZ) == ({}, {})


def test_fmt_size():
    assert su.fmt_size(512) == "512 B" and su.fmt_size(2048) == "2.0 KB" and su.fmt_size(5 * 1024 ** 2) == "5.0 MB"
    assert su.fmt_size(None) == "?"


def test_backup_name():
    assert su.valid_backup_name(" Before update ") == "Before update"
    for bad in ("", "  ", "a/b", "x" * 61, "<script>", None):
        assert su.valid_backup_name(bad) is None


def test_schedule_ok():
    c, e = su.validate_schedule({"recurrence": "custom_days", "days": ["wed", "mon"], "time": "03:30", "copies": 5})
    assert e is None and c["days"] == ["mon", "wed"] and c["copies"] == 5
    assert su.validate_schedule({"recurrence": "never"})[1] is None


@pytest.mark.parametrize("bad", [{"recurrence": "hourly"}, {"recurrence": "custom_days", "days": []},
                                 {"recurrence": "daily", "days": ["funday"]}, {"recurrence": "daily", "time": "25:00"},
                                 {"recurrence": "daily", "copies": 0}, {"recurrence": "daily", "copies": 99},
                                 {"recurrence": "daily", "copies": True}, {"recurrence": "daily", "time": 300}])
def test_schedule_bad(bad):
    assert su.validate_schedule(bad)[1]


def test_restore_double_confirmation():
    assert su.restore_allowed("RESTORE", "Nightly", "Nightly") is None
    assert su.restore_allowed("restore", "Nightly", "Nightly")
    assert su.restore_allowed("RESTORE", "Other", "Nightly")
    assert su.restore_allowed(None, None, "Nightly")
