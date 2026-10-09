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
                "**Authentication** - standard OAuth2 sign-in against the node (Sentinel Hub): obtain an access token through "
                "the hub's login flow (`/auth/authorize` -> `/auth/token`) or create a long-lived "
                "access token, and send `Authorization: Bearer <token>`.\n\n"
                "**Roles** - `viewer`, `operator`, `manager`, `admin` (plus custom roles). Roles are assigned in the "
                "node's management interface (Users). Entities a role may not see are reported as `404`, "
                "never `403`, so their existence is not disclosed. `403` means the entity is visible but the "
                "command is not permitted.\n\n"
                "**Realtime** - WebSocket: connect to `/api/websocket`, authenticate, then send "
                "`{\"id\":1,\"type\":\"sentinel_link/subscribe\",\"domains\":[\"light\"],\"initial\":true}`; "
                "or Server-Sent Events: `GET /events` (see below). Both deliver only what the caller's role may read.\n\n"
                "**Internal vs external server** - the API is identical on the LAN address and the public address; "
                "switch the base URL depending on where the app is."
            ),
        },
        "servers": [{"url": server_url}] if server_url else [],
        "security": sec,
        "tags": [{"name": "Discovery"}, {"name": "Entities"}, {"name": "Realtime"}, {"name": "Admin"}],
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
                                "`resync` (client was too slow - re-fetch `/entities`). A `: ping` comment is sent every 20 s. "
                                "Max 5 concurrent streams per user. Reverse proxies must not buffer this route."),
                "parameters": [
                    {"name": "domains", "in": "query", "description": "Comma-separated filter", "schema": {"type": "string"}},
                    {"name": "entities", "in": "query", "description": "Comma-separated entity_ids", "schema": {"type": "string"}},
                    {"name": "initial", "in": "query", "schema": {"type": "integer", "enum": [0, 1], "default": 1}}],
                "responses": {"200": {"description": "Event stream", "content": {"text/event-stream": {"schema": {"type": "string"}}}},
                              "429": _err("Too many streams")}}},
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
                                                "description": "Sentinel Hub access token (OAuth2 or long-lived)."}},
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
                "AdminConfig": {"type": "object"},
            },
        },
        "x-command-catalog": _command_catalog(),
    }
    return spec


SWAGGER_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Sentinel Link API</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="ui"></div>
<noscript>JavaScript is required. The raw spec is at <a href="%(spec)s">%(spec)s</a>.</noscript>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.ui=SwaggerUIBundle({url:"%(spec)s",dom_id:"#ui",persistAuthorization:true,tryItOutEnabled:true});</script>
</body></html>"""
