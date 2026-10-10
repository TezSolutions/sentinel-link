"""Unit tests for hub_mgmt_work/scene_util.py."""
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("scene_util_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt" / "scene_util.py")
su = importlib.util.module_from_spec(spec)
spec.loader.exec_module(su)

ACT = [{"type": "entity", "entity_id": "switch.a", "command": "turn_on"}]


def rule(**kw):
    base = {"name": "R", "trigger": {"type": "time", "at": "07:30"}, "actions": ACT}
    base.update(kw)
    return base


def test_names():
    assert su.clean_name("  Movie   night ") == "Movie night"
    for bad in ("", "   ", None, 5, "x" * 61, "a{{b}}", "<b>"):
        with pytest.raises(su.Invalid):
            su.clean_name(bad)


def test_capture():
    assert su.capture("light", "on", {"brightness": 120, "rgb_color": (1, 2, 3), "junk": 1, "color_temp_kelvin": 3000}) == {
        "state": "on", "brightness": 120, "rgb_color": [1, 2, 3], "color_temp_kelvin": 3000}
    assert su.capture("light", "off", {"brightness": 5}) == {"state": "off"}
    assert su.capture("cover", "open", {"current_position": 40}) == {"state": "open", "current_position": 40}
    assert su.capture("climate", "heat", {"temperature": 21}) == {"state": "heat", "temperature": 21}
    for dom in ("lock", "alarm_control_panel", "sensor", "camera"):
        assert su.capture(dom, "on", {}) is None
    assert su.capture("light", "unavailable", {}) is None


def test_scene_entities():
    ok = su.clean_scene_entities({"light.x": {"state": "on", "brightness": 100, "rgb_color": [1, 2, 3]}, "switch.y": {"state": "off"}})
    assert ok["light.x"]["brightness"] == 100
    bads = [{}, None, {"lock.door": {"state": "on"}}, {"sensor.t": {"state": "on"}}, {"light.x": {"state": "ON!"}}, {"light.x": {"state": "on", "brightness": 999}},
            {"light.x": {"state": "on", "brightness": True}}, {"light.x": {"state": "on", "rgb_color": [1, 2]}}, {"light.x": "on"}, {"../x.y": {"state": "on"}},
            {f"light.l{i}": {"state": "on"} for i in range(41)}]
    for b in bads:
        with pytest.raises(su.Invalid):
            su.clean_scene_entities(b)
    # unknown extra keys are dropped, never copied through
    assert "service" not in su.clean_scene_entities({"light.x": {"state": "on", "service": "shell_command.x"}})["light.x"]


def test_rule_validation_accepts_catalog():
    assert su.clean_rule(rule())["trigger"]["days"] == list(su.DAYS)
    assert su.clean_rule(rule(trigger={"type": "time", "at": "06:00", "days": ["sun", "mon"]}))["trigger"]["days"] == ["mon", "sun"]
    assert su.clean_rule(rule(trigger={"type": "sun", "event": "sunset", "offset_min": -30}))["trigger"]["offset_min"] == -30
    assert su.clean_rule(rule(trigger={"type": "state", "entity_id": "binary_sensor.door", "to": "on", "for_min": 5}))["trigger"]["for_min"] == 5
    assert su.clean_rule(rule(trigger={"type": "presence", "entity_id": "person.a", "to": "home"}))
    assert su.clean_rule(rule(only_between={"from": "18:00", "to": "23:00"}))["only_between"]
    assert su.clean_rule(rule(actions=[{"type": "scene", "scene_id": "scene.movie"}]))


@pytest.mark.parametrize("bad", [
    rule(name=""), rule(trigger=None), rule(trigger={"type": "template", "value_template": "{{ 1 }}"}),
    rule(trigger={"type": "time", "at": "25:00"}), rule(trigger={"type": "time", "at": "7:30"}), rule(trigger={"type": "time", "at": "07:30", "days": ["xyz"]}),
    rule(trigger={"type": "sun", "event": "noon"}), rule(trigger={"type": "sun", "event": "sunset", "offset_min": 999}),
    rule(trigger={"type": "state", "entity_id": "person.a", "to": "home"}), rule(trigger={"type": "state", "entity_id": "x", "to": "on"}),
    rule(trigger={"type": "state", "entity_id": "switch.a", "to": "{{ evil }}"}), rule(trigger={"type": "state", "entity_id": "switch.a", "to": "on", "for_min": 99999}),
    rule(trigger={"type": "presence", "entity_id": "switch.a", "to": "home"}), rule(trigger={"type": "presence", "entity_id": "person.a", "to": "away"}),
    rule(actions=[]), rule(actions=ACT * 9), rule(actions=[{"type": "entity", "entity_id": "lock.door", "command": "turn_on"}]),
    rule(actions=[{"type": "entity", "entity_id": "switch.a", "command": "toggle"}]), rule(actions=[{"type": "service", "service": "shell_command.rm"}]),
    rule(actions=[{"type": "scene", "scene_id": "light.x"}]), rule(actions=["x"]), rule(only_between={"from": "6", "to": "7"}), "nope", None])
def test_rule_validation_rejects(bad):
    with pytest.raises(su.Invalid):
        su.clean_rule(bad)


def test_build_automation_shape_and_roundtrip():
    s = su.clean_rule(rule(trigger={"type": "time", "at": "07:30", "days": ["mon", "tue"]}, only_between={"from": "06:00", "to": "09:00"}))
    cfg = su.build_automation("portal_abc", s)
    assert cfg["triggers"] == [{"trigger": "time", "at": "07:30:00"}] and cfg["mode"] == "single"
    assert {"condition": "time", "weekday": ["mon", "tue"]} in cfg["conditions"]
    assert cfg["actions"] == [{"action": "switch.turn_on", "target": {"entity_id": "switch.a"}}]
    assert su.rule_spec_from(cfg) == s
    sun = su.build_automation("portal_s", su.clean_rule(rule(trigger={"type": "sun", "event": "sunset", "offset_min": -90})))
    assert sun["triggers"][0]["offset"] == "-01:30:00"
    st = su.build_automation("portal_t", su.clean_rule(rule(trigger={"type": "state", "entity_id": "switch.b", "to": "on", "for_min": 3})))
    assert st["triggers"][0]["for"] == {"minutes": 3}


def test_hand_edited_or_foreign_automations_are_not_editable():
    s = su.clean_rule(rule())
    cfg = su.build_automation("portal_abc", s)
    assert su.rule_spec_from(cfg) == s
    tampered = dict(cfg, actions=[{"action": "shell_command.x"}])
    assert su.rule_spec_from(tampered) is None
    assert su.rule_spec_from(dict(cfg, id="other_1")) is None
    assert su.rule_spec_from({"id": "portal_x", "alias": "a", "description": "hello"}) is None
    assert su.rule_spec_from(dict(cfg, description=su.TAG + "{not json")) is None


def test_scene_view_hides_foreign_scene_details():
    mine = su.scene_view({"id": "portal_1", "name": "A", "entities": {"light.x": {"state": "on"}}})
    assert mine["editable"] and mine["entities"] == {"light.x": {"state": "on"}} and mine["count"] == 1
    theirs = su.scene_view({"id": "12345", "name": "B", "entities": {"light.x": {"state": "on"}}})
    assert not theirs["editable"] and theirs["entities"] is None


def test_describe():
    s = su.clean_rule(rule(trigger={"type": "sun", "event": "sunset", "offset_min": -30}, actions=[{"type": "scene", "scene_id": "scene.movie"}]))
    assert su.describe(s, {"scene.movie": "Movie"}) == "30 min before sunset: run Movie"
    assert su.describe(su.clean_rule(rule())).startswith("At 07:30 (every day)")
