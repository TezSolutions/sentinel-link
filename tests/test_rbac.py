"""Unit tests for the pure-Python RBAC + command core (no HA required)."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "custom_components/sentinel_link/api"))
import commands as cmd  # noqa: E402
import rbac  # noqa: E402
from rbac import EntityCtx, RbacConfig  # noqa: E402


def E(eid, area=None, diag=False, labels=()):
    return EntityCtx(eid, "p_" + eid.replace(".", "_"), area, tuple(labels), diag)


def cfg(**kw):
    return RbacConfig(**kw)


def test_no_role_denied_everything():
    c = cfg()
    assert not c.can(None, E("light.a"), "read")


def test_viewer_reads_not_controls():
    c = cfg()
    assert c.can("viewer", E("light.a"), "read")
    assert not c.can("viewer", E("light.a"), "turn_on")
    assert c.can("viewer", E("camera.door"), "snapshot")


def test_operator_controls_but_not_locks():
    c = cfg()
    assert c.can("operator", E("light.a"), "turn_on")
    assert not c.can("operator", E("lock.front"), "unlock")
    assert c.can("operator", E("lock.front"), "read")


def test_manager_locks():
    assert cfg().can("manager", E("lock.front"), "unlock")


def test_exposure_filters_before_role():
    c = cfg()
    c.exposure["exclude_entities"] = ["light.secret"]
    assert not c.can("admin", E("light.secret"), "read")
    assert not c.can("admin", E("vacuum.x"), "read")  # domain not exposed
    c.exposure["include_entities"] = ["vacuum.x"]
    assert c.can("admin", E("vacuum.x"), "read")


def test_exclude_beats_include():
    c = cfg()
    c.exposure["include_entities"] = ["vacuum.x"]
    c.exposure["exclude_entities"] = ["vacuum.x"]
    assert not c.can("admin", E("vacuum.x"), "read")


def test_diagnostic_hidden_by_default():
    c = cfg()
    assert not c.can("admin", E("sensor.cpu", diag=True), "read")
    c.exposure["include_diagnostic"] = True
    assert c.can("admin", E("sensor.cpu", diag=True), "read")


def test_area_exposure():
    c = cfg()
    c.exposure["include_areas"] = ["living"]
    assert c.can("viewer", E("light.a", "living"), "read")
    assert not c.can("viewer", E("light.b", "kitchen"), "read")
    assert not c.can("viewer", E("light.c", None), "read")


def test_custom_guest_role_area_scoped_deny_wins():
    c = cfg(roles={"guest": {"grants": [
        {"effect": "allow", "domains": ["light", "climate"], "areas": ["living"], "actions": ["*"]},
        {"effect": "allow", "domains": ["sensor"], "actions": ["read"]},
        {"effect": "deny", "entities": ["light.living_tv"], "actions": ["*"]},
    ]}})
    assert c.can("guest", E("light.l1", "living"), "turn_on")
    assert not c.can("guest", E("light.k1", "kitchen"), "turn_on")
    assert not c.can("guest", E("light.k1", "kitchen"), "read")
    assert not c.can("guest", E("light.living_tv", "living"), "read")  # deny wins
    assert c.can("guest", E("sensor.t", "kitchen"), "read")
    assert not c.can("guest", E("camera.door"), "read")


def test_label_selector():
    c = cfg(roles={"r": {"grants": [{"effect": "allow", "labels": ["public"], "actions": ["read"]}]}})
    assert c.can("r", E("light.a", labels=["public"]), "read")
    assert not c.can("r", E("light.b"), "read")


def test_grant_without_actions_matches_nothing():
    c = cfg(roles={"r": {"grants": [{"effect": "allow"}]}})
    assert not c.can("r", E("light.a"), "read")


def test_builtin_cannot_be_overridden():
    c = cfg(roles={"viewer": {"grants": [{"effect": "allow", "actions": ["*"]}]}})
    assert not c.can("viewer", E("light.a"), "turn_on")


def test_extends_cycle_safe():
    c = cfg(roles={"a": {"extends": "b", "grants": []}, "b": {"extends": "a", "grants": []}})
    assert not c.can("a", E("light.a"), "read")


def test_resolve_role_priority():
    c = cfg(user_roles={"u1": "manager"}, group_roles={"g1": "viewer"}, default_role=None)
    assert c.resolve_role("u1", False, ["g1"]) == "manager"
    assert c.resolve_role("u2", False, ["g1"]) == "viewer"
    assert c.resolve_role("u3", False, []) is None
    assert c.resolve_role("u3", True, []) == "admin"
    c.default_role = "viewer"
    assert c.resolve_role("u3", False, []) == "viewer"


def test_cannot_map_user_to_admin_role():
    c = cfg(user_roles={"u1": "admin"})
    assert c.resolve_role("u1", False, []) is None  # only HA admins are admin
    assert c.resolve_role("u1", True, []) == "admin"


def test_unknown_role_mapping_ignored():
    assert cfg(user_roles={"u": "ghost"}).resolve_role("u", False, []) is None


def test_validate_role_def():
    assert rbac.validate_role_def("guest", {"grants": [{"effect": "allow", "actions": ["read"]}]}) == []
    assert rbac.validate_role_def("viewer", {"grants": []})
    assert rbac.validate_role_def("x", {"admin": True, "grants": []})
    assert rbac.validate_role_def("x", {"grants": [{"effect": "maybe", "actions": ["read"]}]})
    assert rbac.validate_role_def("x", {"grants": [{"effect": "allow"}]})


def test_roundtrip():
    c = cfg(user_roles={"u": "viewer"})
    c2 = RbacConfig.from_dict(c.to_dict())
    assert c2.user_roles == {"u": "viewer"} and c2.exposure == c.exposure


# ---- commands -------------------------------------------------------------

def test_cmd_ok():
    assert cmd.validate("light", "turn_on", {"brightness": 128, "rgb_color": [1, 2, 3]}) == (
        "turn_on", {"brightness": 128, "rgb_color": [1, 2, 3]})
    assert cmd.validate("alarm_control_panel", "arm_home", None)[0] == "alarm_arm_home"


@pytest.mark.parametrize("dom,c,data,code", [
    ("light", "explode", {}, "unknown_command"),
    ("sensor", "turn_on", {}, "unknown_command"),
    ("light", "turn_on", {"brightness": 300}, "invalid_field"),
    ("light", "turn_on", {"brightness": True}, "invalid_field"),
    ("light", "turn_on", {"bogus": 1}, "invalid_field"),
    ("light", "turn_on", {"rgb_color": [1, 2]}, "invalid_field"),
    ("light", "turn_on", [1], "invalid_body"),
    ("cover", "set_cover_position", {}, "missing_field"),
    ("climate", "set_temperature", {"temperature": "hot"}, "invalid_field"),
])
def test_cmd_rejects(dom, c, data, code):
    with pytest.raises(cmd.CommandError) as e:
        cmd.validate(dom, c, data)
    assert e.value.code == code


def test_no_dangerous_domains():
    for bad in ("homeassistant", "shell_command", "python_script", "rest_command", "hassio", "script_reload"):
        assert bad not in cmd.COMMANDS


def test_hard_deny_reboot_button_and_domains():
    r = rbac
    cfg = r.RbacConfig(exposure={**r.default_exposure(), "domains": ["button", "device_tracker"],
                                 "include_entities": ["button.x"]})
    reboot = r.EntityCtx("button.sentinel_reboot", "p1", platform="sentinel_link")
    other = r.EntityCtx("button.doorbell", "p2", platform="tuya")
    tracker = r.EntityCtx("device_tracker.phone", "p3")
    assert not cfg.can("admin", reboot, "press")
    assert cfg.can("admin", other, "press")
    assert not cfg.can("admin", tracker, "read")


def test_hub_mgmt_role_aliases():
    r = rbac
    cfg = r.RbacConfig(user_roles={"u1": "homeowner", "u2": "installer", "u3": "bogus"})
    assert cfg.resolve_role("u1", False) == "manager"
    assert cfg.resolve_role("u2", False) == "viewer"
    assert cfg.resolve_role("u3", False) is None
