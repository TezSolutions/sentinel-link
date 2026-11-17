"""Unit tests for sentinel_link/reboot_schedule.py (scheduled reboot, daily or one weekday)."""
import importlib.util
import pathlib
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

spec = importlib.util.spec_from_file_location(
    "reboot_schedule_t",
    pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "sentinel_link" / "reboot_schedule.py",
)
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)

IST = ZoneInfo("Asia/Kolkata")
UTC = timezone.utc


def at(tz, y, mo, d, h, mi, s=0):
    return datetime(y, mo, d, h, mi, s, tzinfo=tz)


# 2026-11-16 is a Monday, 2026-11-15 a Sunday.
MON = (2026, 11, 16)
SUN = (2026, 11, 15)


# --- daily behaviour is unchanged (absent key / None / "daily" all mean every day) ---

@pytest.mark.parametrize("weekday", [None, "daily", "", "DAILY"])
def test_daily_later_today(weekday):
    now = at(IST, *MON, 1, 0)
    assert rs.next_reboot_local(now, IST, "03:00", weekday) == at(IST, *MON, 3, 0)


@pytest.mark.parametrize("weekday", [None, "daily"])
def test_daily_passed_today_goes_to_tomorrow(weekday):
    now = at(IST, *MON, 3, 0)  # exactly at the slot: strictly-after, so tomorrow
    assert rs.next_reboot_local(now, IST, "03:00", weekday) == at(IST, 2026, 11, 17, 3, 0)


def test_daily_matches_previous_algorithm_every_hour_of_a_week():
    """Old code: local_now.replace(hour, minute) (+1 day if <= now). Same answer for daily."""
    from datetime import timedelta
    start = at(IST, *MON, 0, 0)
    for h in range(0, 24 * 7, 1):
        now = start + timedelta(hours=h, minutes=7)
        old = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if old <= now:
            old += timedelta(days=1)
        assert rs.next_reboot_local(now, IST, "03:00") == old


# --- weekday match / mismatch ---

def test_weekday_match_before_slot_is_today():
    now = at(IST, *MON, 2, 59)
    assert rs.next_reboot_local(now, IST, "03:00", "mon") == at(IST, *MON, 3, 0)


def test_weekday_match_after_slot_is_next_week():
    now = at(IST, *MON, 3, 1)
    assert rs.next_reboot_local(now, IST, "03:00", "mon") == at(IST, 2026, 11, 23, 3, 0)


def test_weekday_match_exactly_at_slot_is_next_week():
    # The timer callback re-schedules at the slot itself; it must not fire twice.
    now = at(IST, *MON, 3, 0)
    assert rs.next_reboot_local(now, IST, "03:00", "mon") == at(IST, 2026, 11, 23, 3, 0)


@pytest.mark.parametrize("now_day,expected_day", [
    ((2026, 11, 17), (2026, 11, 23)),  # Tue -> next Mon
    ((2026, 11, 21), (2026, 11, 23)),  # Sat -> Mon
    (SUN, MON),                        # Sun -> Mon
])
def test_weekday_mismatch_skips_to_next_monday(now_day, expected_day):
    now = at(IST, *now_day, 12, 0)
    got = rs.next_reboot_local(now, IST, "03:00", "mon")
    assert got == at(IST, *expected_day, 3, 0)
    assert got.weekday() == 0


@pytest.mark.parametrize("key,num", list(rs.WEEKDAYS.items()))
def test_every_weekday_lands_on_that_weekday_within_7_days(key, num):
    now = at(IST, *MON, 12, 0)
    got = rs.next_reboot_local(now, IST, "03:00", key)
    assert got.weekday() == num
    assert 0 < (got - now).total_seconds() <= 7 * 86400


def test_weekday_is_case_insensitive():
    now = at(IST, *SUN, 12, 0)
    assert rs.next_reboot_local(now, IST, "03:00", "Mon") == at(IST, *MON, 3, 0)


# --- midnight / timezone edges: the weekday is the HUB's local weekday, not UTC ---

def test_utc_sunday_evening_is_ist_monday_morning():
    # Sun 21:00 UTC == Mon 02:30 IST -> Monday 03:00 IST (Sun 21:30 UTC), not next week.
    now = at(UTC, *SUN, 21, 0)
    got = rs.next_reboot_local(now, IST, "03:00", "mon")
    assert got == at(IST, *MON, 3, 0)
    assert got.astimezone(UTC) == at(UTC, *SUN, 21, 30)


def test_utc_sunday_after_slot_is_next_week():
    # Sun 21:31 UTC == Mon 03:01 IST -> next Monday.
    now = at(UTC, *SUN, 21, 31)
    assert rs.next_reboot_local(now, IST, "03:00", "mon") == at(IST, 2026, 11, 23, 3, 0)


def test_utc_monday_is_already_ist_monday_afternoon():
    # Mon 10:00 UTC == Mon 15:30 IST: Monday's 03:00 IST slot has passed.
    now = at(UTC, *MON, 10, 0)
    assert rs.next_reboot_local(now, IST, "03:00", "mon") == at(IST, 2026, 11, 23, 3, 0)


def test_midnight_slot_one_minute_before():
    now = at(IST, *SUN, 23, 59)
    assert rs.next_reboot_local(now, IST, "00:00", "mon") == at(IST, *MON, 0, 0)


def test_midnight_slot_daily_across_day_boundary():
    now = at(IST, *SUN, 23, 59, 59)
    assert rs.next_reboot_local(now, IST, "00:00") == at(IST, *MON, 0, 0)


def test_23_59_on_sunday_from_monday_utc_clock():
    # Sun 18:29 UTC == Sun 23:59 IST: Sunday slot at 23:59 IST is already now -> next Sunday.
    now = at(UTC, *SUN, 18, 29)
    assert rs.next_reboot_local(now, IST, "23:59", "sun") == at(IST, 2026, 11, 22, 23, 59)


def test_dst_zone_keeps_wall_clock_time():
    # A DST zone: 2026-03-29 is the EU spring-forward Sunday. Weekly Monday 03:00 stays 03:00 local.
    berlin = ZoneInfo("Europe/Berlin")
    now = datetime(2026, 3, 28, 12, 0, tzinfo=berlin)  # Saturday, CET
    got = rs.next_reboot_local(now, berlin, "03:00", "mon")
    assert (got.year, got.month, got.day, got.hour, got.minute) == (2026, 3, 30, 3, 0)
    assert got.utcoffset().total_seconds() == 7200  # CEST


def test_naive_now_rejected():
    with pytest.raises(ValueError):
        rs.next_reboot_local(datetime(2026, 11, 16, 1, 0), IST, "03:00", "mon")


# --- parsing / validation ---

@pytest.mark.parametrize("bad", ["", "3", "24:00", "03:60", "aa:bb", "03:00:00", "-1:00"])
def test_bad_time_rejected(bad):
    with pytest.raises(ValueError):
        rs.parse_reboot_time(bad)


@pytest.mark.parametrize("good,expected", [("03:00", (3, 0)), ("3:05", (3, 5)), ("00:00", (0, 0)), ("23:59", (23, 59))])
def test_good_time(good, expected):
    assert rs.parse_reboot_time(good) == expected


@pytest.mark.parametrize("bad", ["monday", "tues", "weekly", "1", "everyday"])
def test_unknown_weekday_rejected_not_treated_as_daily(bad):
    with pytest.raises(ValueError):
        rs.parse_weekday(bad)


def test_describe_schedule_log_label():
    assert rs.describe_schedule(None) == "daily"
    assert rs.describe_schedule("daily") == "daily"
    assert rs.describe_schedule("mon") == "weekly (Monday)"
    assert rs.describe_schedule("sun") == "weekly (Sunday)"


def test_option_values_are_stable():
    # These strings are stored in config entries; renaming them breaks existing nodes.
    assert rs.WEEKDAY_OPTIONS == ("daily", "mon", "tue", "wed", "thu", "fri", "sat", "sun")
