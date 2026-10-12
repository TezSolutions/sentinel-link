"""Capability matrix tests (evaluates CAPS/MANAGEABLE from __init__.py without importing the hub core)."""
import ast, pathlib

SRC = (pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "hub_mgmt" / "__init__.py").read_text()


def _ns():
    """Run only the plain-data assignments we need (constants and set/dict expressions), nothing else from the module."""
    want = {"STORED_ROLES", "_ADMIN_CAPS", "CAPS", "MANAGEABLE", "ADMIN_ROLES"}
    ns = {}
    for n in ast.parse(SRC).body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") in want:
            exec(compile(ast.Module([n], []), "caps", "exec"), ns)
    return ns


NS = _ns()
CAPS, MANAGEABLE = NS["CAPS"], NS["MANAGEABLE"]


def test_superadmin_has_everything_admin_has_all_but_infra():
    allc = set().union(*CAPS.values())
    assert CAPS["superadmin"] == allc
    assert CAPS["admin"] == allc - {"infra"}


def test_infra_is_superadmin_only():
    assert [r for r, c in CAPS.items() if "infra" in c] == ["superadmin"]


def test_debug_download_is_admin_and_superadmin_only():
    assert sorted(r for r, c in CAPS.items() if "debug" in c) == ["admin", "superadmin"]


def test_installer_cannot_touch_users_system_or_debug():
    assert not ({"users", "system", "debug", "infra"} & CAPS["installer"])
    assert {"devices", "entities", "areas", "integrations", "scenes"} <= CAPS["installer"]


def test_homeowner_scope():
    assert CAPS["homeowner"] == {"users", "entities", "areas", "scenes", "profile"}
    assert not ({"devices", "integrations", "system", "debug", "infra"} & CAPS["homeowner"])


def test_system_is_admin_level_only():
    assert sorted(r for r, c in CAPS.items() if "system" in c) == ["admin", "superadmin"]


def test_superadmin_manages_the_same_roles_as_admin_and_cannot_be_assigned():
    assert MANAGEABLE["superadmin"] == MANAGEABLE["admin"]
    assert "superadmin" not in MANAGEABLE["admin"] and "superadmin" not in NS["STORED_ROLES"]


def test_superadmin_is_derived_from_config_not_from_a_stored_role():
    assert 'user.id in hass.data[DOMAIN].get("superadmins", ())' in SRC


def test_vendor_account_hidden_from_other_admins():
    seg = SRC[SRC.index("async def user_row("):]
    seg = seg[:seg.index("return {")]
    assert '_role(hass, u) == "superadmin" and _role(hass, caller) != "superadmin"' in seg and "return None" in seg


def test_whoami_reports_caps():
    assert '"caps": sorted(CAPS.get(' in SRC
