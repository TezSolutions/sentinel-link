"""Unit tests for hub_mgmt_work/ent_util.py and its agreement with the Link API rules."""
import importlib.util, pathlib, sys

HM = pathlib.Path.home() / "hub_mgmt_work"
SL = pathlib.Path(__file__).parents[1] / "custom_components" / "sentinel_link" / "api"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


eu = _load("ent_util_t", HM / "ent_util.py")
rbac = _load("rbac_t", SL / "rbac.py")


def test_hard_deny_matches_link_api():
    assert eu.HARD_DENY_DOMAINS == rbac.HARD_DENY_DOMAINS
    assert eu.HARD_DENY_PLATFORM_DOMAIN == rbac.HARD_DENY_PLATFORM_DOMAIN


def test_control_allowed_matrix():
    assert eu.control_allowed("installer", "light", "zha")[0]
    assert eu.control_allowed("homeowner", "lock", "zha")[0]
    assert eu.control_allowed("admin", "alarm_control_panel", "x")[0]
    assert not eu.control_allowed("installer", "lock", "zha")[0]
    assert not eu.control_allowed("installer", "alarm_control_panel", "x")[0]
    assert not eu.control_allowed("admin", "person", "person")[0]
    assert not eu.control_allowed("admin", "button", "sentinel_link")[0]
    assert not eu.control_allowed("admin", "button", "hub_mgmt")[0]
    assert eu.control_allowed("admin", "button", "zha")[0]


def test_clip_attrs_bounds_and_types():
    big = {f"k{i}": i for i in range(100)}
    assert len(eu.clip_attrs(big)) == 40
    out = eu.clip_attrs({"friendly_name": "x", "entity_picture": "/p", "s": "a" * 500, "d": {"a": 1}, "l": [1, 2], "ll": list(range(50)), "b": True, "n": None})
    assert "friendly_name" not in out and "entity_picture" not in out and "d" not in out and "ll" not in out
    assert len(out["s"]) == 160 and out["l"] == [1, 2] and out["b"] is True and out["n"] is None


def test_control_attrs_only_known_keys():
    out = eu.control_attrs({"brightness": 5, "secret": "x", "hvac_modes": ["heat"], "rgb_color": [1, 2, 3]})
    assert out == {"brightness": 5, "hvac_modes": ["heat"], "rgb_color": [1, 2, 3]}


def test_downsample_keeps_ends_and_limit():
    pts = [[i, i] for i in range(1000)]
    d = eu.downsample(pts, 100)
    assert d[0] == pts[0] and d[-1] == pts[-1] and len(d) <= 101
    assert eu.downsample(pts[:10], 100) == pts[:10]


def test_history_numeric_and_state():
    r = eu.history_points([(1, "1.5"), (2, "unavailable"), (3, "2")])
    assert r["kind"] == "number" and [p[1] for p in r["points"]] == [1.5, 2.0]
    r = eu.history_points([(1, "on"), (2, "on"), (3, "off")])
    assert r["kind"] == "state" and [p[1] for p in r["points"]] == ["on", "off"]
    assert eu.history_points([])["points"] == []


def test_bridge_uses_link_allowlist():
    br = _load("hub_mgmt_bridge_t", HM / "api_bridge.py")
    br.__dict__["__file__"] = str(HM / "api_bridge.py")
    # bridge resolves ../sentinel_link relative to hub_mgmt; emulate the HA layout
    import tempfile, os
    d = pathlib.Path(tempfile.mkdtemp()); (d / "hub_mgmt").mkdir(); (d / "sentinel_link").symlink_to(SL.parent)
    for f in ("api_bridge.py",):
        (d / "hub_mgmt" / f).write_text((HM / f).read_text())
    br2 = _load("hub_mgmt_bridge_t2", d / "hub_mgmt" / "api_bridge.py")
    assert "turn_on" in br2.commands_for("light")
    svc, data = br2.validate("light", "turn_on", {"brightness": 10})
    assert svc == "turn_on" and data == {"brightness": 10}
    try:
        br2.validate("light", "format_disk", {})
        assert False
    except br2.CommandError as e:
        assert e.code == "unknown_command"


def test_brand_frigate_to_ainvr():
    assert eu.brand("Frigate") == "AINVR" and eu.brand("frigate ") == "AINVR"
    assert eu.brand("Sonos") == "Sonos" and eu.brand(None) is None and eu.brand("My Frigate cam") == "My Frigate cam"
