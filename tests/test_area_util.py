"""Unit tests for hub_mgmt_work/area_util.py."""
import importlib.util, pathlib, sys

HM = pathlib.Path.home() / "hub_mgmt_work"
spec = importlib.util.spec_from_file_location("area_util_t", HM / "area_util.py")
au = importlib.util.module_from_spec(spec)
sys.modules["area_util_t"] = au
spec.loader.exec_module(au)
import pytest


def test_clean_name():
    assert au.clean_name("  Living   Room ") == "Living Room"
    for bad in ("", "   ", None, 5, "x" * 61, "a\x00b"):
        with pytest.raises(au.Bad):
            au.clean_name(bad)


def test_clean_color_icon_level():
    assert au.clean_color("#00ff7f") == "#00ff7f" and au.clean_color("red") == "red" and au.clean_color("") is None
    for bad in ("#12", "javascript:alert(1)", "red; x", "#gggggg", 5):
        with pytest.raises(au.Bad):
            au.clean_color(bad)
    assert au.clean_icon("mdi:sofa") == "mdi:sofa" and au.clean_icon(None) is None
    for bad in ("sofa", "mdi:<script>", "mdi:" + "a" * 80):
        with pytest.raises(au.Bad):
            au.clean_icon(bad)
    assert au.clean_level(0) == 0 and au.clean_level(-1) == -1 and au.clean_level(None) is None
    for bad in (True, 1.5, "1", 999, -99):
        with pytest.raises(au.Bad):
            au.clean_level(bad)


def test_clean_ids_limits_and_dedupe():
    assert au.clean_ids(["a", "b", "a"], "devices") == ["a", "b"]
    assert au.clean_ids(None, "devices") == []
    with pytest.raises(au.Bad):
        au.clean_ids(["x"] * 201 and [str(i) for i in range(201)], "devices")
    for bad in ("a", [1], [""], [None]):
        with pytest.raises(au.Bad):
            au.clean_ids(bad, "devices")


def test_name_taken_case_insensitive_and_ignore_self():
    ex = [("1", "Kitchen"), ("2", "Bedroom")]
    assert au.name_taken("kitchen", ex) and au.name_taken("BEDROOM", ex)
    assert not au.name_taken("kitchen", ex, ignore_id="1")
    assert not au.name_taken("Garage", ex)


def test_area_refs_reports_without_modifying():
    exp = {"include_areas": ["a1", "a2"]}
    roles = {"guest": {"grants": [{"effect": "allow", "areas": ["a1"]}]}, "other": {"grants": [{"areas": ["zz"]}]}, "bad": 5}
    import copy
    e0, r0 = copy.deepcopy(exp), copy.deepcopy(roles)
    refs = au.area_refs(exp, roles, "a1")
    assert any("exposure" in r for r in refs) and any("guest" in r for r in refs) and not any("other" in r for r in refs)
    assert exp == e0 and roles == r0
    assert au.area_refs({}, {}, "a1") == [] and au.area_refs(None, None, "a1") == []


def test_activity():
    r = au.activity([("light", "on", "2026-01-01T10:00:00"), ("switch", "off", "2026-01-01T12:00:00"), ("sensor", "unavailable", None), ("lock", "unlocked", "2026-01-01T09:00:00")])
    assert r == {"active": 2, "unavailable": 1, "last": "2026-01-01T12:00:00"}
    assert au.activity([]) == {"active": 0, "unavailable": 0, "last": None}
