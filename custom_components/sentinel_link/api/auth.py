"""Sentinel Link API authentication: OAuth2 (authorization code + PKCE), long-lived tokens, revoke, and the
Link WebSocket. Users and passwords are the hub's own accounts - there is no second user database."""
from __future__ import annotations

import asyncio
import html
import json
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import aiohttp
from aiohttp import web
from homeassistant.auth.models import Credentials
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from . import rbac
from . import tokens as tok
from .core import API_DATA, ApiState
from .openapi import BASE
from .views import _JSON_HEADERS, _Base, _api, _bearer, _err

_LOGGER = logging.getLogger(__name__)
AUTH = f"{BASE}/auth"
_PAGE_HEADERS = {
    "Cache-Control": "no-store", "Pragma": "no-cache", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' *; base-uri 'none'; frame-ancestors 'none'",
}
_TICKET_TTL = 300
MAX_BODY = 8192


# ------------------------------------------------------------------------------------------------ helpers
def _ip(request: web.Request) -> str:
    """Client address for lockout keys. Behind the node's nginx every request comes from the proxy, so nginx passes the
    real address in X-Sentinel-Client-IP; it is honoured only when the connection itself is local/private. (A spoofed
    value can only dodge the per-address limit - the per-user lockout and nginx rate limits still apply.)"""
    peer = request.remote or "?"
    fwd = request.headers.get("X-Sentinel-Client-IP", "")
    if fwd and len(fwd) <= 45 and all(c in "0123456789abcdefABCDEF.:" for c in fwd):
        try:
            import ipaddress
            if ipaddress.ip_address(peer).is_private or ipaddress.ip_address(peer).is_loopback:
                return fwd
        except ValueError:
            pass
    return peer


class _redirect(web.HTTPFound):
    """302 whose Location is EXACTLY the registered redirect URI + query (the default helper re-normalises the URL,
    e.g. adds a trailing slash to custom-scheme addresses, so the app would get back a different string)."""

    def __init__(self, uri: str, params: dict[str, str]) -> None:
        super().__init__(location="/")
        self.headers["Location"] = uri + ("&" if "?" in uri else "?") + urlencode(params)


def _json_err(status: int, error: str, desc: str) -> web.Response:
    """OAuth2-style error (RFC 6749 section 5.2)."""
    return web.json_response({"error": error, "error_description": desc}, status=status, headers=_JSON_HEADERS)


async def _form(request: web.Request) -> dict[str, str]:
    if request.content_length is not None and request.content_length > MAX_BODY:
        raise web.HTTPRequestEntityTooLarge(max_size=MAX_BODY, actual_size=request.content_length)
    ctype = request.content_type
    try:
        if ctype == "application/json":
            data = await request.json()
            return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}
        data = await request.post()
        return {k: v for k, v in data.items() if isinstance(v, str)}
    except (ValueError, web.HTTPException):
        return {}


def _page(title: str, body: str, status: int = 200) -> web.Response:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:#0b1118;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}}
.c{{width:100%;max-width:380px;background:#121a24;border:1px solid #243242;border-radius:14px;padding:26px}}h1{{font-size:19px;margin:0 0 4px}}
.s{{color:#8b9bb0;font-size:13px;margin:0 0 18px}}label{{display:block;font-size:12.5px;color:#8b9bb0;margin:12px 0 4px}}
input[type=text],input[type=password]{{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #243242;background:#0a0f16;color:#e6edf3;font:inherit}}
input:focus{{outline:2px solid #2f81f7;border-color:#2f81f7}}button{{margin-top:18px;width:100%;padding:11px;border:0;border-radius:9px;background:#2f81f7;color:#fff;font:inherit;font-weight:600;cursor:pointer}}
button.g{{background:#243242;margin-top:8px}}.e{{background:#3a1d22;border:1px solid #7a2c35;color:#ffb4bc;border-radius:9px;padding:9px 11px;font-size:13px;margin-bottom:10px}}
.t{{background:#0a0f16;border:1px solid #243242;border-radius:9px;padding:10px;word-break:break-all;font:12.5px ui-monospace,monospace;user-select:all}}
.w{{color:#e3b341;font-size:13px}}</style></head><body><div class="c">{body}</div></body></html>"""
    return web.Response(text=doc, status=status, content_type="text/html", headers=_PAGE_HEADERS)


def _login_form(app: str, hidden: dict[str, str], err: str | None = None, sub: str = "Sign in to continue") -> str:
    fields = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in hidden.items())
    e = f'<div class="e">{html.escape(err)}</div>' if err else ""
    return (f'<h1>Sentinel Hub</h1><p class="s">{html.escape(sub)}</p>{e}'
            f'<form method="post" autocomplete="on">{fields}'
            '<label for="u">Username</label><input id="u" type="text" name="username" autocomplete="username" autocapitalize="none" required autofocus>'
            '<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required>'
            f'<button type="submit">Sign in</button></form><p class="s" style="margin-top:14px">{html.escape(app)} wants to connect to this hub.</p>')


def _mfa_form(hidden: dict[str, str], err: str | None = None) -> str:
    fields = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in hidden.items())
    e = f'<div class="e">{html.escape(err)}</div>' if err else ""
    return (f'<h1>Two-step verification</h1><p class="s">Enter the code from your authenticator app.</p>{e}'
            f'<form method="post">{fields}<label for="c">Code</label>'
            '<input id="c" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>'
            '<button type="submit">Verify</button></form>')


async def check_password(hass: HomeAssistant, username: str, password: str) -> tuple[Any, str | None]:
    """Verify against the hub's own accounts. Returns (user, None) or (None, 'bad'|'inactive').
    The user's second factor is checked separately by ``mfa_modules``."""
    provider = None
    for p in hass.auth.auth_providers:
        if p.type == "homeassistant":
            provider = p
            break
    if provider is None:
        return None, "bad"
    try:
        await provider.async_validate_login(username, password)
        creds: Credentials = await provider.async_get_or_create_credentials({"username": username.strip().casefold()})
    except Exception:  # noqa: BLE001 - InvalidAuth and friends: never reveal which part was wrong
        return None, "bad"
    user = await hass.auth.async_get_user_by_credentials(creds)
    if user is None or user.system_generated:
        return None, "bad"
    if not user.is_active:
        return None, "inactive"
    return user, None


async def mfa_modules(hass: HomeAssistant, user: Any) -> dict[str, str]:
    return await hass.auth.async_get_enabled_mfa(user)


# ------------------------------------------------------------------------------------------------ OAuth: authorize
class AuthorizeView(HomeAssistantView):
    """GET renders the sign-in page, POST checks the password (+ second factor) and redirects with a code."""

    url = f"{AUTH}/authorize"
    name = "api:sentinel_link:auth:authorize"
    requires_auth = False
    cors_allowed = False

    @staticmethod
    def _params(src: Any) -> tuple[dict[str, str], str | None]:
        p = {k: str(src.get(k, "")) for k in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type")}
        if p["response_type"] != "code":
            return p, "response_type must be 'code'"
        if p["code_challenge_method"] != "S256" or not tok.valid_challenge(p["code_challenge"]):
            return p, "PKCE is required: send code_challenge (S256, base64url, 43 characters)"
        if len(p["state"]) > 500:
            return p, "state is too long"
        return p, None

    def _client(self, st: ApiState, p: dict[str, str]) -> str | None:
        c = st.book.clients.get(p["client_id"])
        if not c:
            return None
        return c["name"] if st.book.redirect_ok(p["client_id"], p["redirect_uri"]) else None

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _page("Unavailable", "<h1>Unavailable</h1><p class='s'>The Sentinel Link API is switched off on this hub.</p>", 404)
        p, err = self._params(request.query)
        # an unknown app or redirect address must NEVER redirect (open-redirect protection): show a plain error page
        name = self._client(st, p)
        if name is None:
            return _page("Unknown app", "<h1>Unknown app</h1><p class='s'>This app is not registered on this hub, or its return address does not match. Ask the hub administrator to register it.</p>", 400)
        if err:
            return self._redirect_error(p, "invalid_request", err)
        return _page("Sign in", _login_form(name, p))

    def _redirect_error(self, p: dict[str, str], error: str, desc: str) -> web.Response:
        q = {"error": error, "error_description": desc}
        if p.get("state"):
            q["state"] = p["state"]
        raise _redirect(p["redirect_uri"], q)

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _page("Unavailable", "<h1>Unavailable</h1><p class='s'>The Sentinel Link API is switched off on this hub.</p>", 404)
        f = await _form(request)
        p, err = self._params(f)
        name = self._client(st, p)
        if name is None:
            return _page("Unknown app", "<h1>Unknown app</h1><p class='s'>This app is not registered on this hub, or its return address does not match.</p>", 400)
        if err:
            return self._redirect_error(p, "invalid_request", err)
        ip = _ip(request)

        # ---- step 2: second factor
        ticket = f.get("ticket")
        if ticket:
            t = st.pending.get(ticket)
            if not t or t["exp"] < time.time() or t["client_id"] != p["client_id"] or t["challenge"] != p["code_challenge"]:
                return _page("Sign in", _login_form(name, p, "That sign-in expired. Start again."), 400)
            if st.throttle.locked(f"u:{t['user_id']}") or st.throttle.locked(f"ip:{ip}"):
                return _page("Sign in", _login_form(name, p, "Too many attempts. Try again later."), 429)
            user = await hass.auth.async_get_user(t["user_id"])
            module = hass.auth.get_auth_mfa_module(t["module"])
            ok = bool(user and module and await module.async_validate(user.id, {"code": f.get("code", "").strip()}))
            if not ok:
                st.throttle.fail(f"u:{t['user_id']}")
                st.throttle.fail(f"ip:{ip}")
                st.log(user, None, "auth:mfa", p["client_id"], "failed")
                st.persist()
                hidden = {**p, "ticket": ticket}
                return _page("Two-step verification", _mfa_form(hidden, "That code is not right."), 401)
            st.pending.pop(ticket, None)
            return self._finish(st, user, p)

        # ---- step 1: username + password
        username, password = f.get("username", "").strip(), f.get("password", "")
        ukey = f"u:{username.casefold()}"
        if st.throttle.locked(ukey) or st.throttle.locked(f"ip:{ip}"):
            return _page("Sign in", _login_form(name, p, "Too many attempts. Try again later."), 429)
        user, why = await check_password(hass, username, password)
        if user is None:
            st.throttle.fail(ukey)
            st.throttle.fail(f"ip:{ip}")
            st.log(None, None, "auth:login", p["client_id"], "failed", {"username": username[:40]})
            st.persist()
            msg = "This account is disabled." if why == "inactive" else "Wrong username or password."
            return _page("Sign in", _login_form(name, p, msg), 401)
        st.throttle.ok(ukey)
        mods = await mfa_modules(hass, user)
        if mods:
            module_id = next(iter(mods))
            tk = secrets.token_urlsafe(24)
            st.pending[tk] = {"user_id": user.id, "client_id": p["client_id"], "challenge": p["code_challenge"],
                              "module": module_id, "exp": time.time() + _TICKET_TTL}
            return _page("Two-step verification", _mfa_form({**p, "ticket": tk}))
        return self._finish(st, user, p)

    def _finish(self, st: ApiState, user: Any, p: dict[str, str]) -> web.Response:
        code = st.book.new_code(p["client_id"], p["redirect_uri"], p["code_challenge"], user.id)
        st.log(user, st.role_for(user), "auth:authorize", p["client_id"], "ok")
        st.persist()
        q = {"code": code}
        if p.get("state"):
            q["state"] = p["state"]
        raise _redirect(p["redirect_uri"], q)


# ------------------------------------------------------------------------------------------------ OAuth: token / revoke
class TokenView(HomeAssistantView):
    url = f"{AUTH}/token"
    name = "api:sentinel_link:auth:token"
    requires_auth = False
    cors_allowed = True

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _json_err(404, "api_disabled", "Sentinel Link API is disabled on this node")
        f = await _form(request)
        ip = _ip(request)
        if st.throttle.locked(f"ip:{ip}"):
            return _json_err(429, "slow_down", "Too many failed attempts. Try again later.")
        grant = f.get("grant_type")
        cid = f.get("client_id", "")
        if cid not in st.book.clients:
            st.throttle.fail(f"ip:{ip}")
            return _json_err(401, "invalid_client", "Unknown client_id")
        if grant == "authorization_code":
            rec = st.book.redeem_code(f.get("code", ""), cid, f.get("redirect_uri", ""), f.get("code_verifier", ""))
            if rec is None:
                st.throttle.fail(f"ip:{ip}")
                return _json_err(400, "invalid_grant", "The code is invalid, expired, already used or does not match the PKCE verifier")
            user = await hass.auth.async_get_user(rec["user_id"])
            if user is None or not user.is_active:
                return _json_err(400, "invalid_grant", "User is not available")
            out = st.book.issue_session(user.id, cid)
            st.log(user, st.role_for(user), "auth:token", cid, "ok", {"grant": "authorization_code"})
        elif grant == "refresh_token":
            out = st.book.refresh(f.get("refresh_token", ""), cid)
            if out is None:
                st.throttle.fail(f"ip:{ip}")
                return _json_err(400, "invalid_grant", "The refresh token is invalid or was revoked")
            user = await hass.auth.async_get_user(out["user_id"])
            if user is None or not user.is_active:
                st.close_tokens(st.book.revoke_user(out["user_id"]))
                st.persist()
                return _json_err(400, "invalid_grant", "User is not available")
        else:
            return _json_err(400, "unsupported_grant_type", "Use authorization_code or refresh_token")
        st.persist()
        body = {k: out[k] for k in ("access_token", "refresh_token", "token_type", "expires_in")}
        body["role"] = st.role_for(user)
        body["user"] = {"id": user.id, "name": user.name}
        return web.json_response(body, headers=_JSON_HEADERS)


class RevokeView(HomeAssistantView):
    """RFC 7009: always answers 200, so it cannot be used to probe for valid tokens."""

    url = f"{AUTH}/revoke"
    name = "api:sentinel_link:auth:revoke"
    requires_auth = False
    cors_allowed = True

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st: ApiState | None = hass.data.get(API_DATA)
        if st is not None and st.enabled:
            f = await _form(request)
            gone = st.book.revoke_presented(f.get("token", ""))
            if gone:
                st.close_tokens(gone)
                st.log(None, None, "auth:revoke", ",".join(gone), "ok")
                st.persist()
        return web.json_response({}, headers=_JSON_HEADERS)


# ------------------------------------------------------------------------------------------------ token management
class TokensView(_Base):
    """List / create tokens. Everyone manages their own; the admin role sees and revokes all."""

    url = f"{AUTH}/tokens"
    name = "api:sentinel_link:auth:tokens"

    async def get(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        everyone = st.rbac().is_admin_role(role) and request.query.get("all") == "1"
        rows = st.book.list(None if everyone else user.id)
        names = {u.id: u.name for u in await _hass.auth.async_get_users()}
        for r in rows:
            r["user"] = names.get(r["user_id"])
            r["current"] = r["id"] == (request.get("sl_token") or {}).get("id")
        return web.json_response({"tokens": rows, "clients": list(st.book.clients.values()) if everyone else None},
                                 headers=_JSON_HEADERS)

    async def post(self, request: web.Request) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        try:
            body = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        if not isinstance(body, dict):
            return _err(400, "invalid_body", "Body must be an object")
        # An access token from the OAuth flow can create tokens only for its own user; the role cap can't be raised.
        cap = body.get("max_role")
        own_cap = (request.get("sl_token") or {}).get("max_role")
        if own_cap and (cap is None or tok.ROLE_RANK.get(cap, 99) > tok.ROLE_RANK[own_cap]):
            cap = own_cap
        # scopes can only be passed on, never created: a token may grant at most the scopes it holds itself
        want = body.get("scopes") or []
        own_scopes = set((request.get("sl_token") or {}).get("scopes") or [])
        if not isinstance(want, list) or not set(want) <= own_scopes:
            return _err(403, "scope_escalation", "You can only grant scopes that your own token holds")
        rec, secret = st.book.create_long_lived(user.id, body.get("name", ""), expires_in_days=body.get("expires_in_days"),
                                                max_role=cap, created_by=user.id, scopes=want)
        if rec is None:
            return _err(400, "validation_failed", "; ".join(secret))  # type: ignore[arg-type]
        st.log(user, role, "auth:create_token", rec["id"], "ok", {"name": rec["name"], "max_role": rec["max_role"], "scopes": rec.get("scopes"),
                                                                   "expires": rec["expires"]})
        st.persist()
        out = st.book.public(rec)
        out["token"] = secret      # shown ONCE
        return web.json_response(out, status=201, headers=_JSON_HEADERS)


class TokenItemView(_Base):
    url = f"{AUTH}/tokens/{{token_id}}"
    name = "api:sentinel_link:auth:token_item"

    async def delete(self, request: web.Request, token_id: str) -> web.Response:
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        _hass, st, user, role = c
        rec = st.book.tokens.get(token_id)
        if rec is None or (rec["user_id"] != user.id and not st.rbac().is_admin_role(role)):
            return _err(404, "not_found", "Token not found")
        gone = st.book.revoke(token_id)
        st.close_tokens(gone)
        st.log(user, role, "auth:revoke_token", token_id, "ok", {"name": rec.get("name")})
        st.persist()
        return web.json_response({"revoked": True}, headers=_JSON_HEADERS)


class ClientsView(_Base):
    """Register / list OAuth apps (admin only)."""

    url = f"{AUTH}/clients"
    name = "api:sentinel_link:auth:clients"

    async def _need_admin(self, request: web.Request):
        c = await self._ctx(request)
        if isinstance(c, web.Response):
            return c
        if not c[1].rbac().is_admin_role(c[3]):
            return _err(403, "forbidden", "Admin role required")
        return c

    async def get(self, request: web.Request) -> web.Response:
        c = await self._need_admin(request)
        if isinstance(c, web.Response):
            return c
        return web.json_response({"clients": list(c[1].book.clients.values())}, headers=_JSON_HEADERS)

    async def put(self, request: web.Request) -> web.Response:
        c = await self._need_admin(request)
        if isinstance(c, web.Response):
            return c
        _h, st, user, role = c
        try:
            b = await request.json()
        except ValueError:
            return _err(400, "invalid_body", "Body must be JSON")
        if not isinstance(b, dict):
            return _err(400, "invalid_body", "Body must be an object")
        errs = st.book.save_client(b.get("client_id", ""), b.get("name", ""), b.get("redirect_uris"))
        if errs:
            return web.json_response({"error": {"code": "validation_failed", "message": "; ".join(errs)}, "errors": errs},
                                     status=400, headers=_JSON_HEADERS)
        st.log(user, role, "auth:client_save", b["client_id"], "ok")
        st.persist()
        return web.json_response(st.book.clients[b["client_id"]], headers=_JSON_HEADERS)


# ------------------------------------------------------------------------------------------------ "New token" page
class NewTokenView(HomeAssistantView):
    """Browser page for people (and for admins setting up a wall panel): sign in, name the token, copy it once."""

    url = f"{AUTH}/new-token"
    name = "api:sentinel_link:auth:new_token"
    requires_auth = False
    cors_allowed = False

    async def get(self, request: web.Request) -> web.Response:
        if _api(request.app["hass"]) is None:
            return _page("Unavailable", "<h1>Unavailable</h1><p class='s'>The Sentinel Link API is switched off on this hub.</p>", 404)
        return _page("New token", self._form_html())

    @staticmethod
    def _form_html(err: str | None = None) -> str:
        e = f'<div class="e">{html.escape(err)}</div>' if err else ""
        return ('<h1>Create an API token</h1><p class="s">Long-lived token for an app, panel or script. It stays valid until you revoke it.</p>' + e +
                '<form method="post"><label for="u">Username</label><input id="u" type="text" name="username" autocomplete="username" required autofocus>'
                '<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required>'
                '<label for="n">Token name</label><input id="n" type="text" name="name" maxlength="60" placeholder="e.g. Kitchen wall panel" required>'
                '<button type="submit">Create token</button></form>')

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _page("Unavailable", "<h1>Unavailable</h1>", 404)
        f = await _form(request)
        ip = _ip(request)
        username = f.get("username", "").strip()
        ukey = f"u:{username.casefold()}"
        if st.throttle.locked(ukey) or st.throttle.locked(f"ip:{ip}"):
            return _page("New token", self._form_html("Too many attempts. Try again later."), 429)
        user, why = await check_password(hass, username, f.get("password", ""))
        if user is None:
            st.throttle.fail(ukey)
            st.throttle.fail(f"ip:{ip}")
            st.log(None, None, "auth:login", "new-token", "failed", {"username": username[:40]})
            st.persist()
            return _page("New token", self._form_html("Wrong username or password."), 401)
        if await mfa_modules(hass, user):
            return _page("New token", self._form_html("This account uses two-step verification. Create the token through the API with an app session instead."), 400)
        st.throttle.ok(ukey)
        role = st.role_for(user)
        if role is None:
            return _page("New token", self._form_html("This account has no API access."), 403)
        rec, secret = st.book.create_long_lived(user.id, f.get("name", ""), created_by=user.id)
        if rec is None:
            return _page("New token", self._form_html("; ".join(secret)), 400)  # type: ignore[arg-type]
        st.log(user, role, "auth:create_token", rec["id"], "ok", {"name": rec["name"], "via": "web"})
        st.persist()
        return _page("Token created", f'<h1>Token created</h1><p class="s">Copy it now - it is shown only once.</p>'
                     f'<div class="t">{html.escape(secret)}</div>'  # type: ignore[arg-type]
                     '<p class="w">Treat it like a password. Revoke it any time from the hub administrator.</p>')


# ------------------------------------------------------------------------------------------------ Link WebSocket
class LinkWebSocketView(HomeAssistantView):
    """Realtime for apps: ``{"type":"auth","access_token":"..."}`` then ``{"type":"subscribe", ...}``.
    Everything is filtered by the caller's current role; a revoked token or removed user closes the socket."""

    url = f"{BASE}/ws"
    name = "api:sentinel_link:ws"
    requires_auth = False
    cors_allowed = False

    async def get(self, request: web.Request) -> web.StreamResponse:
        hass: HomeAssistant = request.app["hass"]
        st = _api(hass)
        if st is None:
            return _err(404, "api_disabled", "Sentinel Link API is disabled on this node")
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=16384)
        await ws.prepare(request)
        sid = None
        try:
            await ws.send_json({"type": "auth_required", "api_version": "1"})
            try:
                msg = await ws.receive_json(timeout=10)
            except (asyncio.TimeoutError, ValueError, TypeError):
                await ws.close(code=4001, message=b"auth timeout")
                return ws
            auth = await st.authenticate(msg.get("access_token", "")) if isinstance(msg, dict) and msg.get("type") == "auth" else None
            if auth is None:
                await ws.send_json({"type": "auth_invalid"})
                await ws.close(code=4003)
                return ws
            user, rec, role = auth
            if role is None:
                await ws.send_json({"type": "auth_invalid", "error": "no_role"})
                await ws.close(code=4003)
                return ws
            await ws.send_json({"type": "auth_ok", "role": role})
            cap = rec.get("max_role")
            loop = asyncio.get_running_loop()

            def send(payload: dict[str, Any]) -> None:
                if not ws.closed:
                    loop.create_task(ws.send_json(payload))

            def close() -> None:
                if not ws.closed:
                    loop.create_task(ws.close(code=4004, message=b"token revoked"))

            async for raw in ws:
                if raw.type != aiohttp.WSMsgType.TEXT:
                    break
                try:
                    m = json.loads(raw.data)
                except ValueError:
                    await ws.send_json({"type": "error", "error": "invalid_json"})
                    continue
                t = m.get("type") if isinstance(m, dict) else None
                if t == "ping":
                    await ws.send_json({"type": "pong"})
                elif t == "subscribe":
                    if sid is not None:
                        st.remove_subscriber(sid)
                    if st.streams_for(user.id) >= 5:
                        await ws.send_json({"type": "error", "error": "too_many_streams"})
                        continue
                    domains = {d for d in (m.get("domains") or []) if isinstance(d, str)}
                    ents = {e for e in (m.get("entity_ids") or []) if isinstance(e, str)}
                    sid = st.add_subscriber(user, send, close, domains, ents, token_id=rec["id"], cap=cap)
                    await ws.send_json({"type": "subscribed"})
                    if m.get("initial", True):
                        cfg, r2, states = st.visible_states(user, cap)
                        await ws.send_json({"type": "snapshot", "entities": [
                            st.serialize(s, cfg, r2) for s in states
                            if (not domains or s.domain in domains) and (not ents or s.entity_id in ents)]})
                else:
                    await ws.send_json({"type": "error", "error": "unknown_type"})
        finally:
            if sid is not None:
                st.remove_subscriber(sid)
        return ws


AUTH_VIEWS = (AuthorizeView, TokenView, RevokeView, TokensView, TokenItemView, ClientsView, NewTokenView, LinkWebSocketView)
