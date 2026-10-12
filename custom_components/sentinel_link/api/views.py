"""REST + Server-Sent-Events views for the Sentinel Link API."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from aiohttp import web
from homeassistant.components import camera as camera_comp
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import Context, HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceNotFound
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr

from . import commands as cmds
from . import rbac
from .core import API_DATA, API_VERSION, MAX_STREAMS_PER_USER, ApiState
from .openapi import BASE, SWAGGER_HTML, build_spec

_LOGGER = logging.getLogger(__name__)
_JSON_HEADERS = {"Cache-Control": "no-store"}


def _err(status: int, code: str, message: str) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status, headers=_JSON_HEADERS)


def _api(hass: HomeAssistant) -> ApiState | None:
    st: ApiState | None = hass.data.get(API_DATA)
    return st if st is not None and st.enabled else None


def _bearer(request: web.Request) -> str | None:
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h[:7].lower() == "bearer " else None


class _Base(HomeAssistantView):
    """Link API views use Sentinel Link's OWN tokens (not hub tokens): requires_auth=False turns the hub's
    authentication off for these routes and ``_ctx`` validates the Link token instead."""

    requires_auth = False
    cors_allowed = True

    async def _ctx(self, request: web.Request):
        """Return (hass, state, user, role) or an error Response. The token record is in request['sl_token']."""
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _err(404, "api_disabled", "Sentinel Link API is disabled on this node")
        token = _bearer(request)
        auth = await st.authenticate(token) if token else None
        if auth is None:
            resp = _err(401, "unauthorized", "Missing, invalid, expired or revoked Sentinel Link token")
            resp.headers["WWW-Authenticate"] = 'Bearer realm="Sentinel Link"'
            return resp
        user, rec, role = auth
        request["sl_token"] = rec
        if role is None:
            return _err(403, "no_role", "No API role is assigned to this user")
        return hass, st, user, role


class InfoView(HomeAssistantView):
    url = f"{BASE}/info"
    name = "api:sentinel_link:info"
    requires_auth = False
    cors_allowed = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st: ApiState | None = hass.data.get(API_DATA)
        enabled = bool(st and st.enabled)
        return web.json_response({
            "name": "Sentinel Link API",
            "enabled": enabled,
            "api_version": API_VERSION,
            "integration_version": st.version if st else None,
            "node_id": st.node_id if st else None,
            "docs": f"{BASE}/docs",
            "openapi": f"{BASE}/openapi.json",
            "auth": {"type": "oauth2_pkce+bearer", "authorize": f"{BASE}/auth/authorize", "token": f"{BASE}/auth/token",
                     "revoke": f"{BASE}/auth/revoke", "tokens": f"{BASE}/auth/tokens", "new_token_page": f"{BASE}/auth/new-token"},
            "realtime": {"websocket": f"{BASE}/ws", "sse": f"{BASE}/events"},
            "discovery": {"service": "_sentinel._tcp", "port": 443},
        }, headers=_JSON_HEADERS)


class OpenApiView(HomeAssistantView):
    url = f"{BASE}/openapi.json"
    name = "api:sentinel_link:openapi"
    requires_auth = False
    cors_allowed = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st: ApiState | None = hass.data.get(API_DATA)
        if st is None or not st.enabled:
            return _err(404, "api_disabled", "Sentinel Link API is disabled on this node")
        # relative server URL: works on the LAN address, the public domain and behind the node portal alike
        return web.json_response(build_spec(st.version, "/"), headers={"Cache-Control": "no-cache"})


class DocsView(HomeAssistantView):
    url = f"{BASE}/docs"
    name = "api:sentinel_link:docs"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        if _api(hass) is None:
            return _err(404, "api_disabled", "Sentinel Link API is disabled on this node")
        return web.Response(text=SWAGGER_HTML % {"spec": f"{BASE}/openapi.json"}, content_type="text/html",
                            headers={"Cache-Control": "no-cache"})


class MeView(_Base):
    url = f"{BASE}/me"
    name = "api:sentinel_link:me"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, _st, user, role = c
        return web.json_response({"user_id": user.id, "name": user.name, "role": role,
                                  "is_admin": bool(user.is_admin or user.is_owner)}, headers=_JSON_HEADERS)


class EntitiesView(_Base):
    url = f"{BASE}/entities"
    name = "api:sentinel_link:entities"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        q = request.query
        try:
            limit = max(1, min(int(q.get("limit", 500)), 2000))
            offset = max(0, int(q.get("offset", 0)))
        except ValueError:
            return _err(400, "invalid_query", "limit/offset must be integers")
        cfg, role, states = st.visible_states(user, request['sl_token'].get('max_role'))
        out = [st.serialize(s, cfg, role) for s in states]
        if q.get("domain"):
            out = [e for e in out if e["domain"] == q["domain"]]
        if q.get("area"):
            out = [e for e in out if e["area_id"] == q["area"]]
        if q.get("q"):
            needle = q["q"].lower()
            out = [e for e in out if needle in e["entity_id"].lower() or needle in (e["name"] or "").lower()]
        out.sort(key=lambda e: e["entity_id"])
        return web.json_response({"total": len(out), "entities": out[offset:offset + limit]}, headers=_JSON_HEADERS)


class EntityView(_Base):
    url = f"{BASE}/entities/{{entity_id}}"
    name = "api:sentinel_link:entity"

    async def get(self, request: web.Request, entity_id: str) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        cfg = st.rbac()
        state = hass.states.get(entity_id)
        if state is None or not st.can(cfg, role, entity_id, rbac.READ):
            return _err(404, "not_found", "Entity not found")
        return web.json_response(st.serialize(state, cfg, role), headers=_JSON_HEADERS)


class CommandView(_Base):
    url = f"{BASE}/entities/{{entity_id}}/command"
    name = "api:sentinel_link:command"

    async def post(self, request: web.Request, entity_id: str) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        cfg = st.rbac()
        state = hass.states.get(entity_id)
        if state is None or not st.can(cfg, role, entity_id, rbac.READ):
            return _err(404, "not_found", "Entity not found")
        try:
            body = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("command"), str):
            return _err(400, "invalid_body", "Expected {\"command\": \"...\", \"data\": {...}}")
        command = body["command"]
        data = body.get("data")
        try:
            service, svc_data = cmds.validate(state.domain, command, data)
        except cmds.CommandError as exc:
            st.log(user, role, f"command:{command}", entity_id, f"rejected:{exc.code}", data)
            return _err(400, exc.code, exc.message)
        if not st.can(cfg, role, entity_id, command):
            st.log(user, role, f"command:{command}", entity_id, "denied", data)
            return _err(403, "forbidden", f"Role '{role}' may not run '{command}' on this entity")
        try:
            await hass.services.async_call(
                state.domain, service, {"entity_id": entity_id, **svc_data},
                blocking=True, context=Context(user_id=user.id),
            )
        except ServiceNotFound:
            return _err(400, "unsupported", "This entity does not support that command")
        except HomeAssistantError as exc:
            st.log(user, role, f"command:{command}", entity_id, f"error:{exc}", data)
            return _err(502, "device_error", str(exc)[:200])
        st.log(user, role, f"command:{command}", entity_id, "ok", data)
        new_state = hass.states.get(entity_id) or state
        return web.json_response(st.serialize(new_state, cfg, role), headers=_JSON_HEADERS)


class SnapshotView(_Base):
    url = f"{BASE}/entities/{{entity_id}}/snapshot"
    name = "api:sentinel_link:snapshot"

    async def get(self, request: web.Request, entity_id: str) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        cfg = st.rbac()
        if not entity_id.startswith("camera.") or hass.states.get(entity_id) is None \
                or not st.can(cfg, role, entity_id, rbac.READ):
            return _err(404, "not_found", "Camera not found")
        if not st.can(cfg, role, entity_id, cmds.SNAPSHOT_ACTION):
            return _err(403, "forbidden", "Role may not fetch camera snapshots")
        try:
            image = await camera_comp.async_get_image(hass, entity_id, timeout=10)
        except HomeAssistantError as exc:
            return _err(502, "camera_error", str(exc)[:200])
        st.log(user, role, "snapshot", entity_id, "ok")
        return web.Response(body=image.content, content_type=image.content_type, headers={"Cache-Control": "no-store"})


class DevicesView(_Base):
    url = f"{BASE}/devices"
    name = "api:sentinel_link:devices"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, _role = c
        _cfg, _r, states = st.visible_states(user, request['sl_token'].get('max_role'))
        from homeassistant.helpers import entity_registry as er

        entreg = er.async_get(hass)
        counts: dict[str, int] = {}
        for s in states:
            reg = entreg.async_get(s.entity_id)
            if reg and reg.device_id:
                counts[reg.device_id] = counts.get(reg.device_id, 0) + 1
        devreg = dr.async_get(hass)
        devices = []
        for did, n in counts.items():
            d = devreg.async_get(did)
            if d is None:
                continue
            devices.append({"id": d.id, "name": d.name_by_user or d.name, "manufacturer": d.manufacturer,
                            "model": d.model, "area_id": d.area_id, "entities": n})
        devices.sort(key=lambda d: (d["name"] or "").lower())
        return web.json_response({"devices": devices}, headers=_JSON_HEADERS)


class AreasView(_Base):
    url = f"{BASE}/areas"
    name = "api:sentinel_link:areas"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, _role = c
        _cfg, _r, states = st.visible_states(user, request['sl_token'].get('max_role'))
        counts: dict[str, int] = {}
        for s in states:
            a = st.entity_ctx(s.entity_id).area_id
            if a:
                counts[a] = counts.get(a, 0) + 1
        areareg = ar.async_get(hass)
        areas = []
        for aid, n in counts.items():
            a = areareg.async_get_area(aid)
            if a:
                areas.append({"id": a.id, "name": a.name, "entities": n})
        areas.sort(key=lambda a: a["name"].lower())
        return web.json_response({"areas": areas}, headers=_JSON_HEADERS)


class EventsView(_Base):
    """Server-Sent Events. Per-user filtered, bounded queue, keep-alive pings."""

    url = f"{BASE}/events"
    name = "api:sentinel_link:events"

    async def get(self, request: web.Request) -> web.StreamResponse:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        if st.streams_for(user.id) >= MAX_STREAMS_PER_USER:
            return _err(429, "too_many_streams", f"Max {MAX_STREAMS_PER_USER} concurrent streams per user")
        q = request.query
        domains = {d for d in q.get("domains", "").split(",") if d}
        ents = {e for e in q.get("entities", "").split(",") if e}
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=500)

        def send(msg: dict[str, Any]) -> None:
            try:
                queue.put_nowait(msg)
            except asyncio.QueueFull:
                # Slow consumer: drop the backlog, tell it to resync, then close.
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait({"type": "resync"})
                queue.put_nowait(None)

        def close() -> None:
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

        resp = web.StreamResponse(headers={
            "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no", "Connection": "keep-alive"})
        await resp.prepare(request)
        rec = request.get("sl_token") or {}
        cap = rec.get("max_role")
        sid = st.add_subscriber(user, send, close, domains, ents, token_id=rec.get("id"), cap=cap)
        try:
            if q.get("initial", "1") != "0":
                cfg, role, states = st.visible_states(user, cap)
                snap = [st.serialize(s, cfg, role) for s in states
                        if (not domains or s.domain in domains) and (not ents or s.entity_id in ents)]
                await self._write(resp, "snapshot", {"entities": snap})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    await resp.write(b": ping\n\n")
                    continue
                if msg is None:
                    break
                await self._write(resp, msg["type"], msg)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            st.remove_subscriber(sid)
        return resp

    @staticmethod
    async def _write(resp: web.StreamResponse, event: str, payload: dict[str, Any]) -> None:
        await resp.write(f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n".encode())


class AdminConfigView(_Base):
    url = f"{BASE}/admin/config"
    name = "api:sentinel_link:admin_config"

    async def _admin(self, request: web.Request):
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        if not st.rbac().is_admin_role(role):
            return _err(403, "forbidden", "Admin role required")
        return hass, st, user, role

    async def get(self, request: web.Request) -> web.Response:
        c = await self._admin(request)
        if isinstance(c, web.Response):
            return c
        return web.json_response(c[1].status(), headers=_JSON_HEADERS)

    async def put(self, request: web.Request) -> web.Response:
        c = await self._admin(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        try:
            body = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        if not isinstance(body, dict):
            return _err(400, "invalid_body", "Body must be an object")
        errs = st.apply_config(body)
        if errs:
            st.log(user, role, "config", "-", "rejected", {"errors": errs})
            return web.json_response({"error": {"code": "validation_failed", "message": "; ".join(errs)}, "errors": errs},
                                     status=400, headers=_JSON_HEADERS)
        st.log(user, role, "config", "-", "ok", {"keys": sorted(body)})
        return web.json_response(st.status(), headers=_JSON_HEADERS)


class AdminAuditView(AdminConfigView):
    url = f"{BASE}/admin/audit"
    name = "api:sentinel_link:admin_audit"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._admin(request)
        if isinstance(c, web.Response):
            return c
        try:
            limit = max(1, min(int(request.query.get("limit", 100)), 200))
        except ValueError:
            return _err(400, "invalid_query", "limit must be an integer")
        return web.json_response({"entries": list(c[1].audit)[:limit]}, headers=_JSON_HEADERS)

    async def put(self, request: web.Request) -> web.Response:  # pragma: no cover
        return _err(405, "method_not_allowed", "GET only")



# --------------------------------------------------------------------------- user management (admin role + token scopes)
def _users_api(hass: HomeAssistant):
    return (hass.data.get("hub_mgmt") or {}).get("user_api")


class _UsersBase(_Base):
    """Administrator only. Reads need the admin role; writes also need the token scope `users:write`
    (`users:password` for passwords). The rules themselves live in hub_mgmt and are shared with the node portal."""

    async def _users_ctx(self, request: web.Request, scope: str | None = None):
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        if not st.rbac().is_admin_role(role):
            return _err(403, "forbidden", "Admin role required")
        if scope and scope not in ((request.get("sl_token") or {}).get("scopes") or []):
            st.log(user, role, f"users:{scope.split(':')[1]}", request.path, "denied", {"reason": "missing scope"})
            return _err(403, "missing_scope", f"This token lacks the '{scope}' scope")
        api = _users_api(hass)
        if api is None:
            return _err(501, "unavailable", "User management is not available on this node")
        return hass, st, user, role, api

    @staticmethod
    async def _json(request: web.Request):
        try:
            b = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        return b if isinstance(b, dict) else _err(400, "invalid_body", "Body must be an object")

    @staticmethod
    async def _run(st, user, role, action: str, target: str, coro, data: dict | None = None):
        """Await a hub_mgmt user operation: audit it, turn its ApiError into the API's error shape."""
        try:
            res = await coro
        except Exception as err:  # noqa: BLE001
            if not (hasattr(err, "status") and hasattr(err, "code")):
                raise
            st.log(user, role, action, target, "denied" if err.status in (403, 404) else "error", {**(data or {}), "code": err.code})
            return _err(err.status, err.code, err.message)
        st.log(user, role, action, target, "ok", data)
        st.persist()
        return res


class UsersView(_UsersBase):
    url = f"{BASE}/users"
    name = "api:sentinel_link:users"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._users_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, _st, user, _role, api = c
        return web.json_response(await api.list(user), headers=_JSON_HEADERS)

    async def post(self, request: web.Request) -> web.Response:
        c = await self._users_ctx(request, "users:write")
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, api = c
        b = await self._json(request)
        if isinstance(b, web.Response):
            return b
        if b.get("password") and "users:password" not in ((request.get("sl_token") or {}).get("scopes") or []):
            return _err(403, "missing_scope", "Setting a password needs the 'users:password' scope")
        res = await self._run(st, user, role, "users:create", str(b.get("username")), api.create(
            user, name=b.get("name", ""), username=b.get("username", ""), password=b.get("password", ""), role=b.get("role", "user")),
            {"username": b.get("username"), "role": b.get("role", "user")})
        return res if isinstance(res, web.Response) else web.json_response(res, status=201, headers=_JSON_HEADERS)


class UserView(_UsersBase):
    url = f"{BASE}/users/{{user_id}}"
    name = "api:sentinel_link:user"

    async def get(self, request: web.Request, user_id: str) -> web.Response:
        c = await self._users_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, api = c
        try:
            return web.json_response(await api.get(user_id, user), headers=_JSON_HEADERS)
        except Exception as err:  # noqa: BLE001
            if not (hasattr(err, "status") and hasattr(err, "code")):
                raise
            return _err(err.status, err.code, err.message)

    async def patch(self, request: web.Request, user_id: str) -> web.Response:
        """Body: any of name, role, active. Everything is validated before anything is changed."""
        c = await self._users_ctx(request, "users:write")
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, api = c
        b = await self._json(request)
        if isinstance(b, web.Response):
            return b
        extra = set(b) - {"name", "role", "active"}
        if extra or not b:
            return _err(400, "validation_failed", "Send one or more of: name, role, active")
        if "active" in b and not isinstance(b["active"], bool):
            return _err(400, "validation_failed", "active must be true or false")
        uid = user_id
        try:
            await api.get(uid, user)
        except Exception as err:  # noqa: BLE001
            if not (hasattr(err, "status") and hasattr(err, "code")):
                raise
            return _err(err.status, err.code, err.message)
        for key, op in (("role", lambda: api.set_role(user, uid, b["role"])), ("name", lambda: api.rename(user, uid, b["name"])),
                        ("active", lambda: api.set_active(user, uid, b["active"]))):
            if key in b:
                res = await self._run(st, user, role, f"users:{key}", uid, op(), {key: b[key]})
                if isinstance(res, web.Response):
                    return res
        return web.json_response(await api.get(uid, user), headers=_JSON_HEADERS)

    async def delete(self, request: web.Request, user_id: str) -> web.Response:
        c = await self._users_ctx(request, "users:write")
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, api = c
        uid = user_id
        res = await self._run(st, user, role, "users:delete", uid, api.remove(user, uid))
        return res if isinstance(res, web.Response) else web.Response(status=204, headers=_JSON_HEADERS)


class UserPasswordView(_UsersBase):
    url = f"{BASE}/users/{{user_id}}/password"
    name = "api:sentinel_link:user_password"

    async def post(self, request: web.Request, user_id: str) -> web.Response:
        c = await self._users_ctx(request, "users:password")
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, api = c
        b = await self._json(request)
        if isinstance(b, web.Response):
            return b
        uid = user_id
        res = await self._run(st, user, role, "users:password", uid, api.set_password(user, uid, b.get("password", "")))
        return res if isinstance(res, web.Response) else web.json_response({"ok": True}, headers=_JSON_HEADERS)


# ---------------------------------------------------------------------------------------------------------------- sign-in history
def _hist(hass: HomeAssistant):
    return (hass.data.get("hub_mgmt") or {}).get("logins")


class _LoginsBase(_Base):
    """Sign-in history.  Everybody who can use the API may read it; WHAT they get is decided by the same rules as the portal:
    home owner, administrator and the vendor see every account's entries (administrators included), everyone else only their own.
    A token capped below `manager` also sees only its own user's entries.  Entries cannot be created, edited or deleted here."""

    async def _hist_ctx(self, request: web.Request):
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        svc = _hist(hass)
        if svc is None:
            return _err(501, "unavailable", "Sign-in history is not available on this node")
        return hass, st, user, role, svc


class LoginsView(_LoginsBase):
    url = f"{BASE}/logins"
    name = "api:sentinel_link:logins"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._hist_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, _st, user, role, svc = c
        q = request.query
        try:
            num = lambda k: float(q[k]) if k in q else None  # noqa: E731
            limit = int(q.get("limit", 100))
            before = int(q["before"]) if "before" in q else None
            since, until = num("since"), num("until")
        except ValueError:
            return _err(400, "invalid_query", "since, until, limit and before must be numbers")
        if not 1 <= limit <= 1000:
            return _err(400, "invalid_query", "limit must be 1-1000")
        for key, allowed in (("door", svc.log.DOORS), ("outcome", svc.log.OUTCOMES)):
            if key in q and q[key] not in allowed:
                return _err(400, "invalid_query", f"{key} must be one of: {', '.join(allowed)}")
        alerts_only = q.get("alerts_only", "").lower() in ("1", "true", "yes")
        res = svc.log.query(user.id, svc.role_of(user), role, user=q.get("user"), door=q.get("door"), outcome=q.get("outcome"),
                            since=since, until=until, alerts_only=alerts_only, limit=limit, before=before)
        return web.json_response(res, headers=_JSON_HEADERS)


class LoginsSummaryView(_LoginsBase):
    url = f"{BASE}/logins/summary"
    name = "api:sentinel_link:logins:summary"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._hist_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, _st, user, role, svc = c
        return web.json_response(svc.log.summary(user.id, svc.role_of(user), role), headers=_JSON_HEADERS)


class LoginsSettingsView(_LoginsBase):
    url = f"{BASE}/logins/settings"
    name = "api:sentinel_link:logins:settings"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._hist_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, _st, user, role, svc = c
        if svc.log.scope_for(svc.role_of(user), role) != "all":
            return _err(403, "forbidden", "Only the home owner, administrators and support can read these settings")
        return web.json_response({**svc.log.settings, "min_retention_days": svc.log.MIN_RETENTION_DAYS,
                                  "can_change": svc.role_of(user) in ("homeowner", "admin")}, headers=_JSON_HEADERS)

    async def put(self, request: web.Request) -> web.Response:
        c = await self._hist_ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role, svc = c
        hub_role = svc.role_of(user)
        if hub_role not in ("homeowner", "admin") or svc.log.scope_for(hub_role, role) != "all":
            return _err(403, "forbidden", "Only the home owner and the administrator can change these settings")
        if "logins:settings" not in ((request.get("sl_token") or {}).get("scopes") or []):
            st.log(user, role, "logins:settings", request.path, "denied", {"reason": "missing scope"})
            return _err(403, "missing_scope", "This token lacks the 'logins:settings' scope")
        try:
            b = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        if not isinstance(b, dict) or not b:
            return _err(400, "invalid_body", "Body must be a non-empty object")
        bad = sorted(set(b) - set(svc.log.DEFAULT_SETTINGS))
        if bad:
            return _err(400, "invalid_body", f"Unknown setting: {', '.join(bad)}")
        new, errs = svc.log.set_settings(b)
        if errs:
            return _err(400, "invalid_body", "; ".join(errs))
        svc._save()
        st.log(user, role, "logins:settings", request.path, "ok", {"keys": sorted(b)})
        st.persist()
        return web.json_response({**new, "min_retention_days": svc.log.MIN_RETENTION_DAYS, "can_change": True}, headers=_JSON_HEADERS)



# ---------------------------------------------------------------------------------------------- cloud (admin only)
def _cloud_err(e) -> web.Response:
    return _err(e.status, e.code, e.message)


class _CloudBase(_Base):
    """Administrator only; changes also need the token scope `cloud:manage`. The cloud platform itself can never reach these paths."""

    async def _cloud_ctx(self, request: web.Request, write: bool = False):
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        hass, st, user, role = c
        if not st.rbac().is_admin_role(role) or (request.get("sl_token") or {}).get("relay"):
            return _err(403, "forbidden", "Admin role required")
        if write and "cloud:manage" not in ((request.get("sl_token") or {}).get("scopes") or []):
            st.log(user, role, "cloud:manage", request.path, "denied", {"reason": "missing scope"})
            return _err(403, "missing_scope", "This token lacks the 'cloud:manage' scope")
        return hass, st, user, role

    @staticmethod
    async def _body(request: web.Request):
        try:
            b = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        return b if isinstance(b, dict) else _err(400, "invalid_body", "Body must be an object")


class CloudView(_CloudBase):
    url = f"{BASE}/cloud"
    name = "api:sentinel_link:cloud"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request)
        if isinstance(c, web.Response):
            return c
        return web.json_response(c[1].cloud.status(), headers=_JSON_HEADERS)

    async def put(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request, True)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        b = await self._body(request)
        if isinstance(b, web.Response):
            return b
        errs = st.cloud.configure(b)
        if errs:
            return _err(400, "validation_failed", "; ".join(errs))
        st.log(user, role, "cloud.configure", "cloud", "ok", {k: v for k, v in b.items() if k in ("level", "paused", "name", "endpoint")})
        st.persist()
        return web.json_response(st.cloud.status(), headers=_JSON_HEADERS)

    async def delete(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request, True)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        cid = st.cloud.cfg.get("cloud_node_id")
        await st.cloud.disconnect()
        st.log(user, role, "cloud.disconnect", str(cid), "ok")
        st.persist()
        return web.json_response(st.cloud.status(), headers=_JSON_HEADERS)


class CloudEnrollView(_CloudBase):
    url = f"{BASE}/cloud/enroll"
    name = "api:sentinel_link:cloud_enroll"

    async def post(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request, True)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        b = await self._body(request)
        if isinstance(b, web.Response):
            return b
        try:
            res = await st.cloud.enroll(user, b.get("endpoint", st.cloud.cfg.get("endpoint")), b.get("code"), b.get("level"), b.get("name"))
        except Exception as e:  # noqa: BLE001
            from .cloud import CloudError
            if not isinstance(e, CloudError):
                raise
            st.log(user, role, "cloud.enroll", str(b.get("endpoint"))[:100], "error", {"code": e.code})
            return _cloud_err(e)
        st.log(user, role, "cloud.enroll", str(res.get("endpoint")), "ok", {"cloud_node_id": res.get("cloud_node_id"), "level": res.get("level")})
        st.persist()
        return web.json_response(res, status=201, headers=_JSON_HEADERS)


class CloudDebugView(_CloudBase):
    """On-node approval for the remote support report (default 60 minutes, at most 24 hours)."""
    url = f"{BASE}/cloud/debug"
    name = "api:sentinel_link:cloud_debug"

    async def put(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request, True)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        b = await self._body(request) if request.can_read_body else {}
        if isinstance(b, web.Response):
            return b
        if not st.cloud.enrolled:
            return _err(409, "not_enrolled", "This node is not connected to a cloud platform")
        err = st.cloud.approve_debug(b.get("minutes"), user)
        if err:
            return _err(400, "validation_failed", err)
        st.log(user, role, "cloud.debug_approve", "cloud", "ok", {"minutes": b.get("minutes", 60)})
        st.persist()
        return web.json_response(st.cloud.status(), headers=_JSON_HEADERS)

    async def delete(self, request: web.Request) -> web.Response:
        c = await self._cloud_ctx(request, True)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        st.cloud.approval.revoke()
        st.log(user, role, "cloud.debug_revoke", "cloud", "ok")
        st.persist()
        return web.json_response(st.cloud.status(), headers=_JSON_HEADERS)


ALL_VIEWS = (CloudView, CloudEnrollView, CloudDebugView, LoginsView, LoginsSummaryView, LoginsSettingsView, UsersView, UserView, UserPasswordView, InfoView, OpenApiView, DocsView, MeView, EntitiesView, EntityView, CommandView, SnapshotView,
             DevicesView, AreasView, EventsView, AdminConfigView, AdminAuditView)
