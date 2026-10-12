"""Static checks that keep the portal and the Link API on ONE implementation of user management."""
import pathlib, re

C = pathlib.Path(__file__).resolve().parents[1] / "custom_components"
UA = (C / "hub_mgmt" / "user_api.py").read_text()
INIT = (C / "hub_mgmt" / "__init__.py").read_text()
USERS = (C / "hub_mgmt" / "users.py").read_text()
VIEWS = (C / "sentinel_link" / "api" / "views.py").read_text()
OPENAPI = (C / "sentinel_link" / "api" / "openapi.py").read_text()


def test_portal_user_commands_delegate_to_the_shared_implementation():
    for fn in ("ws_user_create", "ws_user_remove", "ws_user_password", "ws_user_set_role"):
        body = INIT[INIT.index(f"async def {fn}("):]
        body = body[:body.index("\n\n\n")] if "\n\n\n" in body else body
        assert 'hass.data[DOMAIN]["user_api"]' in body, fn
        assert "async_add_auth" not in body and "async_remove_user" not in body, fn
    for fn in ("ws_user_rename", "ws_user_set_active"):
        body = USERS[USERS.index(f"async def {fn}("):]
        assert '["user_api"]' in body[:600], fn


def test_every_write_goes_through_manageable_check():
    assert "_removable_user" in UA and UA.count("_manageable(") >= 4


def test_vendor_account_is_not_found_for_others():
    assert 'and _role(self.hass, caller) != "superadmin"' in UA


def test_every_change_fires_a_realtime_event():
    for action in ("created", "removed", "password_reset", "role_changed", "enabled", "disabled", "renamed"):
        assert f'"{action}"' in UA, action


def test_link_api_users_routes_require_admin_and_scopes():
    assert "Admin role required" in VIEWS
    assert VIEWS.count('"users:write"') >= 3 and '"users:password"' in VIEWS
    assert "missing_scope" in VIEWS


def test_password_in_create_needs_password_scope():
    assert "Setting a password needs the 'users:password' scope" in VIEWS


def test_patch_validates_before_changing_anything():
    body = VIEWS[VIEWS.index("async def patch("):VIEWS.index("async def delete(", VIEWS.index("async def patch("))]
    assert body.index("extra or not b") < body.index("api.set_role") and body.index("api.get(uid, user)") < body.index("api.set_role")


def test_audit_never_logs_passwords():
    assert 'data={"password"' not in VIEWS and '"password": b.get' not in VIEWS
    seg = VIEWS[VIEWS.index("class UserPasswordView"):]
    assert "api.set_password(user, uid, b.get(\"password\", \"\"))" in seg and "{\"password\"" not in seg


def test_openapi_documents_users_endpoints():
    for frag in ("/users", "/users/{{user_id}}", "/users/{{user_id}}/password", '"UserCreate"', '"UserPatch"'):
        assert frag in OPENAPI, frag


def test_item_routes_accept_their_path_variable():
    """The hub passes {user_id} to the handler as a keyword argument; a handler without it answers 500 (found live)."""
    seg = VIEWS[VIEWS.index("class UserView("):VIEWS.index("ALL_VIEWS = (")]
    handlers = re.findall(r"async def (get|patch|delete|post)\(self, request: web\.Request(?:, (\w+): str)?\)", seg)
    assert len(handlers) == 4, handlers
    assert all(arg == "user_id" for _m, arg in handlers), handlers
    assert 'match_info["user_id"]' not in seg


def test_portal_evicts_lru_instead_of_refusing_when_table_full():
    P = (pathlib.Path.home() / "tez-sentinel-image/stack/portal/portal.py")
    if not P.exists():
        return
    src = P.read_text()
    i = src.index("async def h_login") if "async def h_login" in src else 0
    assert "session evicted (table full)" in src and "min(SESSIONS, key=lambda t: SESSIONS[t].last)" in src
    assert "len(SESSIONS) >= MAX_SESSIONS * 2" in src and "len(SESSIONS) >= MAX_SESSIONS:\n        return" not in src
