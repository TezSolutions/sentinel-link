"""Capability matrix tests (parses CAPS/MANAGEABLE from __init__.py without importing the hub core)."""
import ast, pathlib

SRC = (pathlib.Path.home() / "hub_mgmt_work" / "__init__.py").read_text()


def _const(name):
    for n in ast.parse(SRC).body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == name:
            return n.value
    raise KeyError(name)


CAPS = ast.literal_eval(_const("CAPS"))


def test_admin_has_everything():
    allc = set().union(*CAPS.values())
    assert CAPS["admin"] == allc


def test_installer_cannot_touch_users_or_system():
    assert not ({"users", "system"} & CAPS["installer"])
    assert {"devices", "entities", "areas", "integrations", "scenes"} <= CAPS["installer"]


def test_homeowner_scope():
    assert CAPS["homeowner"] == {"users", "entities", "areas", "scenes", "profile"}
    assert not ({"devices", "integrations", "system"} & CAPS["homeowner"])


def test_system_is_admin_only():
    assert [r for r, c in CAPS.items() if "system" in c] == ["admin"]


def test_whoami_reports_caps():
    assert '"caps": sorted(CAPS.get(' in SRC
