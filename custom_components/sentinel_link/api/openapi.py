"""OpenAPI 3.0 spec + Swagger UI page for the Sentinel Link API (pure Python)."""
from __future__ import annotations

from typing import Any

try:  # package import (inside HA) or flat import (unit tests)
    from . import commands as _cmds
except ImportError:  # pragma: no cover
    import commands as _cmds  # type: ignore[no-redef]

API_VERSION = "1"
BASE = "/api/sentinel_link/v1"


def _command_catalog() -> dict[str, Any]:
    cat: dict[str, Any] = {}
    for domain, table in _cmds.COMMANDS.items():
        cat[domain] = {}
        for name, (service, fields) in table.items():
            cat[domain][name] = {
                k: {"type": spec[0], **({"range": list(spec[1])} if spec[0] in ("int", "float") else
                                       {"enum": list(spec[1])} if spec[0] == "str" and spec[1] else {})}
                for k, spec in fields.items()
            }
    cat["camera"] = {"snapshot": {}}
    return cat


def _err(desc: str) -> dict[str, Any]:
    return {"description": desc, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}


def build_spec(version: str, server_url: str = "") -> dict[str, Any]:
    ok = lambda ref: {"description": "OK", "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{ref}"}}}}  # noqa: E731
    sec = [{"bearerAuth": []}]
    ent_id = {"name": "entity_id", "in": "path", "required": True, "schema": {"type": "string", "example": "light.living_room"}}
    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "Sentinel Link API",
            "version": f"{API_VERSION} (integration {version})",
            "description": (
                "Role-based control + realtime state for a Sentinel node, for third-party apps.\n\n"
                "**Authentication** - Sentinel Link issues its own tokens. They work only on this API "
                "(`/api/sentinel_link/*`), never on the rest of the hub, and are sent as `Authorization: Bearer <token>`. "
                "Two ways to get one:\n\n"
                "1. *Apps (OAuth2 authorization code + PKCE)* - an administrator registers the app once "
                "(`PUT /auth/clients`, or in the node portal under Link API). The app opens "
                "`/auth/authorize?response_type=code&client_id=..&redirect_uri=..&code_challenge=..&code_challenge_method=S256&state=..` "
                "in a browser; the user signs in with their hub account (and second factor, if enabled) and the hub redirects back "
                "with `?code=..`. The app then calls `POST /auth/token` with the code and its PKCE `code_verifier` and receives a "
                "30-minute access token and a refresh token. The refresh token does not expire; it rotates on every use and can be "
                "revoked at any time.\n"
                "2. *Long-lived token* - for panels, scripts and integrations: `POST /auth/tokens` (as a signed-in app) or the "
                "browser page `/auth/new-token`. It never expires unless you set `expires_in_days`, can be capped to a lower role "
                "(`max_role`), is shown only once and can be revoked instantly.\n\n"
                "Users and roles are the hub's own: disabling or deleting a user, or changing their role, applies to their tokens "
                "immediately. A token can never do more than its user's current role allows.\n\n"
                "**Roles** - `viewer`, `operator`, `manager`, `admin` (plus custom roles). Roles are assigned in the "
                "node's management interface (Users). Entities a role may not see are reported as `404`, "
                "never `403`, so their existence is not disclosed. `403` means the entity is visible but the "
                "command is not permitted.\n\n"
                "**Realtime** - WebSocket at `/ws`: after connect send `{\"type\":\"auth\",\"access_token\":\"<token>\"}`, then "
                "`{\"type\":\"subscribe\",\"domains\":[\"light\"],\"initial\":true}`; or Server-Sent Events: `GET /events` "
                "(see below). Both deliver only what the caller's role may read, and close if the token is revoked.\n\n"
                "**Internal vs external server** - the API is identical on the LAN address and the public address; "
                "switch the base URL depending on where the app is."
            ),
        },
        "servers": [{"url": server_url}] if server_url else [],
        "security": sec,
        "tags": [{"name": "Discovery"}, {"name": "Authentication"}, {"name": "Entities"}, {"name": "Realtime"}, {"name": "Admin"}],
        "paths": {
            f"{BASE}/info": {"get": {
                "tags": ["Discovery"], "summary": "Service info (no auth)", "security": [],
                "responses": {"200": ok("Info")}}},
            f"{BASE}/me": {"get": {
                "tags": ["Discovery"], "summary": "Caller identity and resolved role", "security": sec,
                "responses": {"200": ok("Me"), "401": _err("Unauthorized"), "403": _err("No API role assigned")}}},
            f"{BASE}/entities": {"get": {
                "tags": ["Entities"], "summary": "List visible entities",
                "parameters": [
                    {"name": "domain", "in": "query", "schema": {"type": "string"}},
                    {"name": "area", "in": "query", "schema": {"type": "string"}},
                    {"name": "q", "in": "query", "description": "Substring match on name/entity_id", "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 500, "maximum": 2000}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}],
                "responses": {"200": ok("EntityList"), "401": _err("Unauthorized")}}},
            f"{BASE}/entities/{{entity_id}}": {"get": {
                "tags": ["Entities"], "summary": "Get one entity", "parameters": [ent_id],
                "responses": {"200": ok("Entity"), "404": _err("Not found or not visible")}}},
            f"{BASE}/entities/{{entity_id}}/command": {"post": {
                "tags": ["Entities"], "summary": "Send a command",
                "description": "Only allowlisted commands exist (see `x-command-catalog`). Fields are strictly validated.",
                "parameters": [ent_id],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Command"}}}},
                "responses": {"200": ok("Entity"), "400": _err("Unknown command or invalid field"),
                              "403": _err("Role may not run this command"), "404": _err("Not found or not visible")}}},
            f"{BASE}/entities/{{entity_id}}/snapshot": {"get": {
                "tags": ["Entities"], "summary": "Camera still image (role action `snapshot`)", "parameters": [ent_id],
                "responses": {"200": {"description": "Image", "content": {"image/jpeg": {"schema": {"type": "string", "format": "binary"}}}},
                              "403": _err("Forbidden"), "404": _err("Not found or not a camera")}}},
            f"{BASE}/devices": {"get": {
                "tags": ["Entities"], "summary": "Devices that have at least one visible entity",
                "responses": {"200": ok("DeviceList")}}},
            f"{BASE}/areas": {"get": {
                "tags": ["Entities"], "summary": "Areas that have at least one visible entity",
                "responses": {"200": ok("AreaList")}}},
            f"{BASE}/events": {"get": {
                "tags": ["Realtime"], "summary": "Server-Sent Events stream of state changes",
                "description": ("`text/event-stream`. Events: `snapshot` (first, if `initial=1`), `state`, `removed`, "
                                "`resync` (client was too slow - re-fetch `/entities`). Administrators also get `user` events; every user gets `login` events for the sign-ins they may read "
                                "(home owner / administrator / support: everyone's; others: their own) and, when allowed to see everybody's, `login_alert` events "
                                "(kinds: failed, new_ip, support). A `: ping` comment is sent every 20 s. "
                                "Max 5 concurrent streams per user. Reverse proxies must not buffer this route."),
                "parameters": [
                    {"name": "domains", "in": "query", "description": "Comma-separated filter", "schema": {"type": "string"}},
                    {"name": "entities", "in": "query", "description": "Comma-separated entity_ids", "schema": {"type": "string"}},
                    {"name": "initial", "in": "query", "schema": {"type": "integer", "enum": [0, 1], "default": 1}}],
                "responses": {"200": {"description": "Event stream", "content": {"text/event-stream": {"schema": {"type": "string"}}}},
                              "429": _err("Too many streams")}}},
            f"{BASE}/auth/authorize": {"get": {
                "tags": ["Authentication"], "summary": "Start sign-in (browser page)", "security": [],
                "description": "Open in a browser / in-app web view. The user signs in and is redirected to the app's registered "
                               "`redirect_uri` with `code` and `state`. PKCE (`S256`) is mandatory. Unknown apps or redirect "
                               "addresses show an error page and are never redirected.",
                "parameters": [
                    {"name": "response_type", "in": "query", "required": True, "schema": {"type": "string", "enum": ["code"]}},
                    {"name": "client_id", "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "redirect_uri", "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "code_challenge", "in": "query", "required": True, "description": "base64url(SHA-256(code_verifier)), 43 chars", "schema": {"type": "string"}},
                    {"name": "code_challenge_method", "in": "query", "required": True, "schema": {"type": "string", "enum": ["S256"]}},
                    {"name": "state", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Sign-in page (HTML)"}, "302": {"description": "Redirect to the app"}}}},
            f"{BASE}/auth/token": {"post": {
                "tags": ["Authentication"], "summary": "Exchange a code or refresh token", "security": [],
                "requestBody": {"required": True, "content": {
                    "application/x-www-form-urlencoded": {"schema": {"$ref": "#/components/schemas/TokenRequest"}},
                    "application/json": {"schema": {"$ref": "#/components/schemas/TokenRequest"}}}},
                "responses": {"200": ok("TokenResponse"), "400": {"description": "invalid_grant / unsupported_grant_type"},
                              "401": {"description": "invalid_client"}, "429": {"description": "Too many failed attempts"}}}},
            f"{BASE}/auth/revoke": {"post": {
                "tags": ["Authentication"], "summary": "Sign out (revoke the token you hold)", "security": [],
                "description": "RFC 7009. Always returns 200. Revoking a refresh token ends the whole session.",
                "requestBody": {"required": True, "content": {"application/x-www-form-urlencoded": {"schema": {
                    "type": "object", "required": ["token"], "properties": {"token": {"type": "string"}}}}}},
                "responses": {"200": {"description": "OK"}}}},
            f"{BASE}/auth/tokens": {
                "get": {"tags": ["Authentication"], "summary": "List your tokens and sessions (admin role: `?all=1` for everyone)",
                        "responses": {"200": {"description": "OK"}, "401": _err("Unauthorized")}},
                "post": {"tags": ["Authentication"], "summary": "Create a long-lived token",
                         "description": "No expiry unless `expires_in_days` is given. The secret is returned once.",
                         "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewToken"}}}},
                         "responses": {"201": {"description": "Created - `token` is shown only now"}, "400": _err("Validation failed")}}},
            f"{BASE}/auth/tokens/{{token_id}}": {"delete": {
                "tags": ["Authentication"], "summary": "Revoke a token or session (own tokens; admin role: any)",
                "parameters": [{"name": "token_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Revoked"}, "404": _err("Not found")}}},
            f"{BASE}/auth/clients": {
                "get": {"tags": ["Authentication"], "summary": "Registered apps (admin role)", "responses": {"200": {"description": "OK"}, "403": _err("Admin only")}},
                "put": {"tags": ["Authentication"], "summary": "Register / update an app (admin role)",
                        "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Client"}}}},
                        "responses": {"200": {"description": "Saved"}, "400": _err("Validation failed"), "403": _err("Admin only")}}},
            f"{BASE}/auth/new-token": {"get": {
                "tags": ["Authentication"], "summary": "Browser page to create a long-lived token", "security": [],
                "responses": {"200": {"description": "HTML page"}}}},
            f"{BASE}/ws": {"get": {
                "tags": ["Realtime"], "summary": "WebSocket stream (upgrade request)", "security": [],
                "description": "Messages: server `auth_required` -> client `{type:auth, access_token}` -> `auth_ok` -> client "
                               "`{type:subscribe, domains?, entity_ids?, initial?}` -> `subscribed`, `snapshot`, then `state` / `removed` events (administrators also get `user` events: created, removed, role_changed, ...; everyone gets `login` / `login_alert` events within their sign-in-history scope) "
                               "events. Client may send `{type:ping}`. Closed with code 4004 when the token is revoked.",
                "responses": {"101": {"description": "Switching protocols"}}}},
            f"{BASE}/logins": {
                "get": {"tags": ["Sign-in history"], "summary": "Sign-in history (audit / compliance)",
                        "description": ("Every sign-in attempt on every door (portal, hub, app sign-in, token page) and every support-file download. "
                                        "Home owner, administrators and support see EVERYONE's entries (administrators included); everyone else, and any token capped "
                                        "below `manager`, sees only their own. The Tez Solutions support account appears as `Tez Solutions support`. "
                                        "Entries are hash-chained (`integrity`) and cannot be edited or deleted. No passwords, tokens or 2FA codes are stored."),
                        "parameters": [
                            {"name": "user", "in": "query", "schema": {"type": "string"}, "description": "username, display name or user id"},
                            {"name": "door", "in": "query", "schema": {"type": "string", "enum": ["portal", "hub", "link_app", "link_token", "support"]}},
                            {"name": "outcome", "in": "query", "schema": {"type": "string", "enum": ["success", "wrong_password", "wrong_2fa", "blocked", "downloaded"]}},
                            {"name": "since", "in": "query", "schema": {"type": "number"}, "description": "unix seconds"},
                            {"name": "until", "in": "query", "schema": {"type": "number"}},
                            {"name": "alerts_only", "in": "query", "schema": {"type": "boolean"}, "description": "only entries that raised a flag (new_ip, failed_burst, support, bundle)"},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
                            {"name": "before", "in": "query", "schema": {"type": "integer"}, "description": "page: pass `next_before` from the previous reply"}],
                        "responses": {"200": ok("LoginList"), "400": _err("Bad query"), "401": _err("Not signed in")}}},
            f"{BASE}/logins/summary": {
                "get": {"tags": ["Sign-in history"], "summary": "Counts for the last 24 h / 7 days (same scope rules) and your last sign-in",
                        "responses": {"200": {"description": "Summary"}}}},
            f"{BASE}/logins/settings": {
                "get": {"tags": ["Sign-in history"], "summary": "Retention and alert settings (home owner, administrator, support)",
                        "responses": {"200": ok("LoginSettings"), "403": _err("Not allowed")}},
                "put": {"tags": ["Sign-in history"], "summary": "Change retention (>= 90 days) and alerts (home owner / administrator + scope `logins:settings`)",
                        "description": "Support can read but never weaken these settings.",
                        "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LoginSettings"}}}},
                        "responses": {"200": ok("LoginSettings"), "400": _err("Invalid"), "403": _err("Not allowed / missing scope")}}},
            f"{BASE}/users": {
                "get": {"tags": ["Users"], "summary": "List users (admin role)",
                        "description": "Same list the node portal shows. The vendor support account is never listed. `assignable` = roles you may give.",
                        "responses": {"200": ok("UserList"), "403": _err("Admin only")}},
                "post": {"tags": ["Users"], "summary": "Create a user (admin role + token scopes `users:write` and `users:password`)",
                         "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserCreate"}}}},
                         "responses": {"201": {"description": "Created (returns the new id)"}, "400": _err("Validation failed / weak password"),
                                       "403": _err("Missing scope or role not assignable"), "409": _err("Username taken")}}},
            f"{BASE}/users/{{user_id}}": {
                "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "get": {"tags": ["Users"], "summary": "One user (admin role)", "responses": {"200": ok("User"), "404": _err("Unknown user")}},
                "patch": {"tags": ["Users"], "summary": "Change name, role and/or active (scope `users:write`)",
                          "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserPatch"}}}},
                          "responses": {"200": ok("User"), "400": _err("Validation failed"), "403": _err("Missing scope / cannot manage this account"),
                                        "404": _err("Unknown user")}},
                "delete": {"tags": ["Users"], "summary": "Delete a user (scope `users:write`)",
                           "responses": {"204": {"description": "Deleted"}, "403": _err("Cannot manage this account"), "404": _err("Unknown user")}}},
            f"{BASE}/users/{{user_id}}/password": {
                "parameters": [{"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "post": {"tags": ["Users"], "summary": "Reset a password (scope `users:password`)",
                         "description": "Signs the user out everywhere. The password policy of the portal applies.",
                         "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["password"],
                                                                                                         "properties": {"password": {"type": "string"}}}}}},
                         "responses": {"200": {"description": "Changed"}, "400": _err("Weak password"), "403": _err("Missing scope / cannot manage"),
                                       "404": _err("Unknown user")}}},
            f"{BASE}/admin/config": {
                "get": {"tags": ["Admin"], "summary": "Exposure + role configuration (admin role)",
                        "responses": {"200": ok("AdminConfig"), "403": _err("Admin only")}},
                "put": {"tags": ["Admin"], "summary": "Update exposure / custom roles / group roles / default role",
                        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
                        "responses": {"200": ok("AdminConfig"), "400": _err("Validation failed"), "403": _err("Admin only")}}},
            f"{BASE}/admin/audit": {"get": {
                "tags": ["Admin"], "summary": "Recent API commands and config changes (admin role)",
                "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100, "maximum": 200}}],
                "responses": {"200": {"description": "OK"}, "403": _err("Admin only")}}},
        },
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer",
                                                "description": "Sentinel Link token (OAuth2 access token or long-lived token). Hub tokens are not accepted."}},
            "schemas": {
                "Error": {"type": "object", "properties": {"error": {"type": "object", "properties": {
                    "code": {"type": "string"}, "message": {"type": "string"}}}}},
                "Info": {"type": "object", "properties": {
                    "name": {"type": "string"}, "api_version": {"type": "string"}, "integration_version": {"type": "string"},
                    "node_id": {"type": "string"}, "enabled": {"type": "boolean"},
                    "docs": {"type": "string"}, "openapi": {"type": "string"}, "realtime": {"type": "object"}}},
                "Me": {"type": "object", "properties": {
                    "user_id": {"type": "string"}, "name": {"type": "string"},
                    "role": {"type": "string"}, "is_admin": {"type": "boolean"}}},
                "Entity": {"type": "object", "properties": {
                    "entity_id": {"type": "string"}, "id": {"type": "string"}, "domain": {"type": "string"},
                    "name": {"type": "string"}, "state": {"type": "string"}, "attributes": {"type": "object"},
                    "device_id": {"type": "string", "nullable": True}, "area_id": {"type": "string", "nullable": True},
                    "last_changed": {"type": "string", "format": "date-time"},
                    "last_updated": {"type": "string", "format": "date-time"},
                    "commands": {"type": "array", "items": {"type": "string"},
                                 "description": "Commands THIS caller may run on this entity."}}},
                "EntityList": {"type": "object", "properties": {
                    "total": {"type": "integer"}, "entities": {"type": "array", "items": {"$ref": "#/components/schemas/Entity"}}}},
                "DeviceList": {"type": "object", "properties": {"devices": {"type": "array", "items": {"type": "object"}}}},
                "AreaList": {"type": "object", "properties": {"areas": {"type": "array", "items": {"type": "object"}}}},
                "Command": {"type": "object", "required": ["command"], "properties": {
                    "command": {"type": "string", "example": "turn_on"},
                    "data": {"type": "object", "example": {"brightness_pct": 60}}}},
                "User": {"type": "object", "properties": {
                    "id": {"type": "string"}, "name": {"type": "string"}, "username": {"type": "string", "nullable": True},
                    "role": {"type": "string", "description": "admin, installer, homeowner, manager, operator, viewer or user"},
                    "active": {"type": "boolean"}, "mfa": {"type": "boolean"}, "last_seen": {"type": "string", "nullable": True},
                    "removable": {"type": "boolean"}, "resettable": {"type": "boolean"}, "assignable": {"type": "boolean"}}},
                "LoginEntry": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "seq": {"type": "integer"}, "ts": {"type": "number"}, "kind": {"type": "string", "enum": ["signin", "support_bundle"]},
                    "user_id": {"type": "string", "nullable": True}, "username": {"type": "string", "nullable": True}, "name": {"type": "string"},
                    "role": {"type": "string", "nullable": True, "description": "`support` for the Tez Solutions account when you are not support yourself"},
                    "door": {"type": "string"}, "outcome": {"type": "string"}, "ip": {"type": "string", "nullable": True}, "device": {"type": "string"},
                    "flags": {"type": "array", "items": {"type": "string", "enum": ["new_ip", "failed_burst", "support", "bundle"]}}}},
                "LoginList": {"type": "object", "properties": {
                    "logins": {"type": "array", "items": {"$ref": "#/components/schemas/LoginEntry"}}, "total": {"type": "integer"},
                    "scope": {"type": "string", "enum": ["all", "own"]}, "next_before": {"type": "integer", "nullable": True},
                    "integrity": {"type": "object", "properties": {"ok": {"type": "boolean"}, "entries": {"type": "integer"}}}, "retention_days": {"type": "integer"}}},
                "LoginSettings": {"type": "object", "properties": {
                    "retention_days": {"type": "integer", "minimum": 90}, "alerts": {"type": "object", "properties": {
                        "failed": {"type": "boolean"}, "new_ip": {"type": "boolean"}, "support": {"type": "boolean"}}},
                    "notify_services": {"type": "array", "items": {"type": "string"}, "description": "extra notify services, e.g. mobile_app_phone"}}},
                "UserList": {"type": "object", "properties": {"users": {"type": "array", "items": {"$ref": "#/components/schemas/User"}},
                                                              "assignable": {"type": "array", "items": {"type": "string"}}}},
                "UserCreate": {"type": "object", "required": ["name", "username", "password"], "properties": {
                    "name": {"type": "string"}, "username": {"type": "string", "description": "3-32 chars: a-z 0-9 . _ -"},
                    "password": {"type": "string"}, "role": {"type": "string", "default": "user"}}},
                "UserPatch": {"type": "object", "properties": {"name": {"type": "string"}, "role": {"type": "string"}, "active": {"type": "boolean"}}},
                "AdminConfig": {"type": "object"},
                "TokenRequest": {"type": "object", "required": ["grant_type", "client_id"], "properties": {
                    "grant_type": {"type": "string", "enum": ["authorization_code", "refresh_token"]},
                    "client_id": {"type": "string"}, "code": {"type": "string"}, "redirect_uri": {"type": "string"},
                    "code_verifier": {"type": "string", "description": "43-128 chars, the PKCE verifier"},
                    "refresh_token": {"type": "string"}}},
                "TokenResponse": {"type": "object", "properties": {
                    "access_token": {"type": "string"}, "refresh_token": {"type": "string"}, "token_type": {"type": "string", "example": "Bearer"},
                    "expires_in": {"type": "integer", "example": 1800}, "role": {"type": "string"}, "user": {"type": "object"}}},
                "NewToken": {"type": "object", "required": ["name"], "properties": {
                    "name": {"type": "string", "example": "Kitchen wall panel"},
                    "expires_in_days": {"type": "integer", "nullable": True, "description": "Omit or null = never expires"},
                    "max_role": {"type": "string", "enum": ["viewer", "operator", "manager"], "nullable": True}}},
                "Client": {"type": "object", "required": ["client_id", "name", "redirect_uris"], "properties": {
                    "client_id": {"type": "string", "example": "com.acme.homeapp"}, "name": {"type": "string"},
                    "redirect_uris": {"type": "array", "items": {"type": "string"}, "example": ["com.acme.homeapp://callback"]}}},
            },
        },
        "x-command-catalog": _command_catalog(),
    }
    return spec


SWAGGER_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Sentinel Link API</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/api/sentinel_link/v1/static/swagger-ui.css"></head>
<body><div id="ui"></div>
<noscript>JavaScript is required. The raw spec is at <a href="%(spec)s">%(spec)s</a>.</noscript>
<script src="/api/sentinel_link/v1/static/swagger-ui-bundle.js"></script>
<script>window.ui=SwaggerUIBundle({url:"%(spec)s",dom_id:"#ui",persistAuthorization:true,tryItOutEnabled:true});</script>
</body></html>"""
