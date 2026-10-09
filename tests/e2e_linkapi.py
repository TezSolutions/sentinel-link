#!/usr/bin/env python3
"""E2E test for the Sentinel Link API + its own auth. usage: e2e_linkapi.py <host> <admin_user> [http|https]
(HA_UI_PASS read from ~/.bashrc, never printed). API calls go to <scheme>://<host>; hub management (users, roles) goes to the hub on :8123."""
import asyncio, base64, hashlib, json, os, re, secrets, sys, time, uuid
from urllib.parse import urlparse, parse_qs
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
SCHEME = sys.argv[3] if len(sys.argv) > 3 else "http"
txt = open(os.path.expanduser("~/.bashrc")).read()
APASS = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', txt, re.M).group(2)
TPASS = "Tmp-" + uuid.uuid4().hex[:14]
BASE = f"{SCHEME}://{HOST}"
# like a real third-party app: its own https client id (HA refuses a bare-IP https client id)
HUB = f"http://{HOST}:8123"          # management only (the hub login is deliberately NOT routed on 80/443)
CID = "com.sentinel.e2e"             # the registered OAuth app
REDIR = "com.sentinel.e2e://callback"
API = BASE + "/api/sentinel_link/v1"
R = []


def ok(name, cond, extra=""):
    R.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


async def hub_token(s, user, pw):
    """Sign in to the HUB (only used to drive management websocket commands)."""
    hc = HUB + "/"
    r = await s.post(HUB + "/auth/login_flow", json={"client_id": hc, "handler": ["homeassistant", None], "redirect_uri": hc + "?auth_callback=1"})
    fid = (await r.json())["flow_id"]
    r = await s.post(f"{HUB}/auth/login_flow/{fid}", json={"username": user, "password": pw, "client_id": hc})
    j = await r.json()
    if j.get("type") != "create_entry":
        return None
    r = await s.post(HUB + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": hc})
    return (await r.json()).get("access_token")


def pkce():
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


async def authorize(s, user, pw, challenge, state="st-1", client=CID, redirect=REDIR):
    """Run the Link OAuth sign-in page; return (code, location, status)."""
    await asyncio.sleep(0.6)
    f = {"client_id": client, "redirect_uri": redirect, "state": state, "code_challenge": challenge,
         "code_challenge_method": "S256", "response_type": "code"}
    r = await s.post(API + "/auth/authorize", data={**f, "username": user, "password": pw}, allow_redirects=False, ssl=False)
    loc = r.headers.get("Location", "")
    q = parse_qs(urlparse(loc).query)
    return (q.get("code") or [None])[0], loc, r.status


async def exchange(s, code, verifier, client=CID, redirect=REDIR):
    r = await s.post(API + "/auth/token", data={"grant_type": "authorization_code", "code": code, "client_id": client,
                                                "redirect_uri": redirect, "code_verifier": verifier}, ssl=False)
    return r.status, await r.json()


async def link_login(s, user, pw):
    """Full Link sign-in -> the token response dict (access_token, refresh_token...) or None."""
    v, ch = pkce()
    code, _loc, _st = await authorize(s, user, pw, ch)
    if not code:
        return None
    st_, j = await exchange(s, code, v)
    return j if st_ == 200 else None


async def token(s, user, pw):
    j = await link_login(s, user, pw)
    return j and j["access_token"]


class WS:
    def __init__(self, s, tok): self.s, self.tok, self.i = s, tok, 0
    async def __aenter__(self):
        self.ws = await self.s.ws_connect(HUB.replace("http", "ws") + "/api/websocket")
        await self.ws.receive_json()
        await self.ws.send_json({"type": "auth", "access_token": self.tok})
        assert (await self.ws.receive_json())["type"] == "auth_ok"
        return self
    async def __aexit__(self, *a): await self.ws.close()
    async def call(self, **m):
        self.i += 1; m["id"] = self.i
        await self.ws.send_json(m)
        while True:
            r = await self.ws.receive_json(timeout=20)
            if r.get("id") == self.i and r["type"] == "result":
                return r


import json as _j, pathlib as _p
MANIFEST_VERSION = _j.loads((_p.Path(__file__).parents[1] / 'custom_components/sentinel_link/manifest.json').read_text())['version']


async def main():
    created = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:
        hub_admin = await hub_token(s, ADMIN, APASS)
        ok("admin hub login (management)", hub_admin)
        H = lambda t: {"Authorization": "Bearer " + t}
        async with WS(s, hub_admin) as a:
            r = await a.call(type="sentinel_link/client_save", client_id=CID, name="E2E test app", redirect_uris=[REDIR])
            ok("register OAuth app", r["success"], r.get("error"))
            atok = await token(s, ADMIN, APASS)
            ok("admin Link sign-in (OAuth + PKCE)", atok)
            ok("hub token is NOT accepted by the Link API", (await s.get(API + "/me", headers=H(hub_admin), ssl=False)).status == 401)
            st = (await a.call(type="sentinel_link/status"))["result"]
            ok("status: enabled by default", st.get("enabled") is True, st.get("enabled"))
            ok("status: version", st.get("integration_version") == MANIFEST_VERSION, st.get("integration_version"))
            # remove leftovers of an earlier failed run, so a retry always starts clean
            ul0 = (await a.call(type="hub_mgmt/users_list"))["result"]
            for u in (ul0["users"] if isinstance(ul0, dict) else ul0):
                if str(u.get("username") or u.get("name") or "").startswith("e2e"):
                    await a.call(type="hub_mgmt/user_remove", user_id=u["id"])
            # temp users
            roles = {"viewer": "e2eview", "operator": "e2eoper", "manager": "e2emgr"}
            for role, uname in roles.items():
                r = await a.call(type="hub_mgmt/user_create", name=uname, username=uname, password=TPASS, role=role)
                ok(f"create {uname}", r["success"], r.get("error"))
                created.append(uname)
            nouser = "e2enone"
            r = await a.call(type="hub_mgmt/user_create", name=nouser, username=nouser, password=TPASS, role="user")
            ok("create plain user (no role)", r["success"], r.get("error")); created.append(nouser)
            # pick test entities
            ents = (await s.get(API + "/entities?limit=2000", headers=H(atok), ssl=False))
            ok("admin GET /entities 200", ents.status == 200, ents.status)
            ej = await ents.json()
            lights = [e for e in ej["entities"] if e["domain"] == "light"]
            switches = [e for e in ej["entities"] if e["domain"] == "switch"]
            locks = [e for e in ej["entities"] if e["domain"] == "lock"]
            doms = {e["domain"] for e in ej["entities"]}
            ok("admin sees entities", ej["total"] > 0, ej["total"])
            ok("hard-denied domains absent", not (doms & {"device_tracker", "person", "update", "persistent_notification"}), sorted(doms))
            ok("reboot button absent", not any(e["entity_id"].startswith("button.") and "reboot" in e["entity_id"] and "sentinel" in e["entity_id"] for e in ej["entities"]))
            # per-role
            for role, uname in roles.items():
                t = await token(s, uname, TPASS)
                ok(f"{role}: login", t)
                if not t: continue
                me = await (await s.get(API + "/me", headers=H(t), ssl=False)).json()
                ok(f"{role}: /me role", me.get("role") == role, me)
                lst = await (await s.get(API + "/entities?limit=2000", headers=H(t), ssl=False)).json()
                ok(f"{role}: sees entities", lst["total"] > 0)
                if lights:
                    lid = lights[0]["entity_id"]
                    r = await s.post(f"{API}/entities/{lid}/command", json={"command": "toggle"}, headers=H(t), ssl=False)
                    exp = 403 if role == "viewer" else 200
                    ok(f"{role}: light toggle -> {exp}", r.status == exp, f"{r.status} {await r.text()}"[:150])
                    if r.status == 200:  # toggle back
                        await s.post(f"{API}/entities/{lid}/command", json={"command": "toggle"}, headers=H(t), ssl=False)
                    r = await s.post(f"{API}/entities/{lid}/command", json={"command": "format_disk"}, headers=H(t), ssl=False)
                    ok(f"{role}: unknown command -> 400", r.status == 400, r.status)
                    r = await s.post(f"{API}/entities/{lid}/command", json={"command": "turn_on", "data": {"brightness": 9999}}, headers=H(t), ssl=False)
                    ok(f"{role}: bad field -> 400/403", r.status in (400, 403), r.status)
                if locks:
                    kid = locks[0]["entity_id"]
                    r = await s.post(f"{API}/entities/{kid}/command", json={"command": "unlock"}, headers=H(t), ssl=False)
                    ok(f"{role}: lock.unlock -> {'200/502' if role=='manager' else '403'}", (r.status in (200, 502)) if role == "manager" else r.status == 403, r.status)
                r = await s.get(API + "/entities/sensor.does_not_exist", headers=H(t), ssl=False)
                ok(f"{role}: unknown entity 404", r.status == 404)
                r = await s.get(API + "/admin/config", headers=H(t), ssl=False)
                ok(f"{role}: admin/config 403", r.status == 403, r.status)
                r = await s.put(API + "/admin/config", json={"default_role": "manager"}, headers=H(t), ssl=False)
                ok(f"{role}: admin PUT 403", r.status == 403, r.status)
            # no-role user
            t = await token(s, nouser, TPASS)
            r = await s.get(API + "/entities", headers=H(t), ssl=False)
            ok("no-role user: 403", r.status == 403, r.status)
            r = await s.get(API + "/entities")
            ok("anonymous: 401", r.status == 401, r.status)
            r = await s.get(API + "/info"); ok("info open", r.status == 200)
            spec = await (await s.get(API + "/openapi.json")).json()
            ok("openapi 3.0 with paths", spec.get("openapi", "").startswith("3.") and len(spec["paths"]) >= 10)
            r = await s.get(API + "/docs"); ok("swagger page", r.status == 200 and "swagger" in (await r.text()).lower())
            # hiding an entity applies instantly
            if lights:
                vt = await token(s, "e2eview", TPASS)
                lid = lights[0]["entity_id"]
                r = await a.call(type="sentinel_link/config_set", config={"exposure": {"exclude_entities": [lid]}})
                ok("config_set exclude", r["success"], r.get("error"))
                r = await s.get(f"{API}/entities/{lid}", headers=H(vt), ssl=False)
                ok("excluded entity -> 404 for viewer", r.status == 404, r.status)
                r = await s.get(f"{API}/entities/{lid}", headers=H(atok), ssl=False)
                ok("excluded entity -> 404 for admin too", r.status == 404, r.status)
                await a.call(type="sentinel_link/config_set", config={"exposure": {"exclude_entities": []}})
            r = await a.call(type="sentinel_link/config_set", config={"exposure": {"domains": "light"}})
            ok("invalid config rejected", not r["success"])
            # role change via Hub Mgmt applies immediately
            ul = (await a.call(type="hub_mgmt/users_list"))["result"]
            # realtime: WS subscribe + SSE; flip a switch/light as operator and watch viewer receive it
            target = [e for e in (switches + lights) if e["state"] in ("on", "off") and "toggle" in e.get("commands", [])]
            if target:
                tid = target[0]["entity_id"]
                vt = await token(s, "e2eview", TPASS); ot = await token(s, "e2eoper", TPASS)
                got_ws, got_sse = [], []
                async with s.ws_connect(API.replace("http", "ws") + "/ws", ssl=False) as lw:
                    ok("Link WS: auth_required first", (await lw.receive_json()).get("type") == "auth_required")
                    await lw.send_json({"type": "auth", "access_token": vt})
                    ok("Link WS: auth_ok with role", (await lw.receive_json()) == {"type": "auth_ok", "role": "viewer"})
                    await lw.send_json({"type": "subscribe", "initial": True})
                    async def reader():
                        while True:
                            m = await lw.receive_json()
                            got_ws.append(m)
                    rt = asyncio.create_task(reader())
                    async def sse():
                        async with s.get(API + "/events?initial=0", headers=H(vt), ssl=False) as resp:
                            ok("SSE 200 event-stream", resp.status == 200 and "event-stream" in resp.headers.get("Content-Type", ""), resp.status)
                            async for line in resp.content:
                                got_sse.append(line.decode())
                                if b"event: state" in line: return
                    st_ = asyncio.create_task(sse())
                    await asyncio.sleep(2)
                    for _ in range(2):
                        await s.post(f"{API}/entities/{tid}/command", json={"command": "toggle"}, headers=H(ot), ssl=False)
                        await asyncio.sleep(1.5)
                    try: await asyncio.wait_for(st_, 8)
                    except asyncio.TimeoutError: pass
                    rt.cancel()
                ok("WS: snapshot received", any(e.get("type") == "snapshot" and e["entities"] for e in got_ws))
                ok("WS: subscribed ack", any(e.get("type") == "subscribed" for e in got_ws))
                ok("WS: live state event for toggled entity", any(e.get("type") == "state" and e["entity"]["entity_id"] == tid for e in got_ws), len(got_ws))
                ok("SSE: live state event", any("event: state" in l for l in got_sse), got_sse[:3])
                ok("viewer commands list empty on realtime entity", all(e["entity"]["commands"] == [] or "snapshot" in e["entity"]["commands"] for e in got_ws if e.get("type") == "state"))
            # ================= Link authentication =================
            # --- OAuth edge cases
            v, ch = pkce()
            code, loc, stc = await authorize(s, ADMIN, APASS, ch)
            ok("authorize redirects to the registered app with code+state", stc == 302 and loc.startswith(REDIR + "?") and "state=st-1" in loc, loc[:80])
            st1, j1 = await exchange(s, code, v)
            ok("code -> access+refresh token", st1 == 200 and j1.get("access_token", "").startswith("sla_") and j1.get("refresh_token", "").startswith("slr_"), j1)
            st2, j2 = await exchange(s, code, v)
            ok("code is single-use", st2 == 400 and j2.get("error") == "invalid_grant", (st2, j2))
            v2, ch2 = pkce(); c2, _l, _s = await authorize(s, ADMIN, APASS, ch2)
            st3, _j = await exchange(s, c2, "x" * 50)
            ok("wrong PKCE verifier rejected", st3 == 400, st3)
            c3, _l, _s = await authorize(s, ADMIN, APASS, ch2)
            st4, _j = await exchange(s, c3, v2, redirect="com.sentinel.e2e://other")
            ok("redirect_uri mismatch rejected", st4 == 400, st4)
            # unknown app / unregistered redirect never redirect (open-redirect protection)
            _c, loc, stc = await authorize(s, ADMIN, APASS, ch, client="com.evil.app")
            ok("unknown app: error page, no redirect", stc == 400 and not loc, (stc, loc))
            _c, loc, stc = await authorize(s, ADMIN, APASS, ch, redirect="https://evil.example/cb")
            ok("unregistered redirect: error page, no redirect", stc == 400 and not loc, (stc, loc))
            r = await s.get(API + "/auth/authorize", params={"response_type": "code", "client_id": CID, "redirect_uri": REDIR,
                                                              "code_challenge_method": "plain", "code_challenge": "abc"}, allow_redirects=False, ssl=False)
            ok("PKCE is mandatory (plain refused)", r.status == 302 and "error=invalid_request" in r.headers.get("Location", ""), r.status)
            r = await s.get(API + "/auth/authorize", params={"response_type": "code", "client_id": CID, "redirect_uri": REDIR,
                                                              "code_challenge_method": "S256", "code_challenge": ch}, ssl=False)
            tx = await r.text()
            ok("sign-in page is Sentinel Hub branded, no Home Assistant", r.status == 200 and "Sentinel Hub" in tx and "home assistant" not in tx.lower())
            ok("sign-in page sends hardening headers", "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "") and r.headers.get("X-Frame-Options") == "DENY")
            c4, loc, stc = await authorize(s, ADMIN, "definitely-wrong", ch)
            ok("wrong password -> 401, no code", stc == 401 and not c4, stc)
            # --- access token works, refresh rotates, revoke kills
            at, rt_ = j1["access_token"], j1["refresh_token"]
            ok("access token works on the API", (await s.get(API + "/me", headers=H(at), ssl=False)).status == 200)
            r = await s.post(API + "/auth/token", data={"grant_type": "refresh_token", "refresh_token": rt_, "client_id": CID}, ssl=False)
            jr = await r.json()
            ok("refresh -> new tokens (rotated)", r.status == 200 and jr.get("refresh_token") and jr["refresh_token"] != rt_, jr)
            r = await s.post(API + "/auth/token", data={"grant_type": "refresh_token", "refresh_token": rt_, "client_id": "com.other"}, ssl=False)
            ok("refresh with another client_id refused", r.status in (400, 401), r.status)
            r = await s.post(API + "/auth/revoke", data={"token": jr["refresh_token"]}, ssl=False)
            ok("revoke returns 200", r.status == 200)
            ok("revoking the refresh token ends its access tokens", (await s.get(API + "/me", headers=H(jr["access_token"]), ssl=False)).status == 401)
            r = await s.post(API + "/auth/token", data={"grant_type": "refresh_token", "refresh_token": jr["refresh_token"], "client_id": CID}, ssl=False)
            ok("revoked refresh token refused", r.status == 400, r.status)
            r = await s.post(API + "/auth/revoke", data={"token": "sll_000000000000.nothingtoseehere1234567890"}, ssl=False)
            ok("revoking garbage still 200 (no probing)", r.status == 200)
            # --- long-lived tokens
            r = await s.post(API + "/auth/tokens", json={"name": "e2e panel"}, headers=H(atok), ssl=False)
            ll = await r.json()
            ok("create long-lived token (201, shown once)", r.status == 201 and ll.get("token", "").startswith("sll_") and ll.get("expires") is None, ll)
            llt = ll.get("token", "x")
            ok("long-lived token never expires by default", ll.get("expires") is None)
            ok("long-lived token works", (await s.get(API + "/me", headers=H(llt), ssl=False)).status == 200)
            lst = await (await s.get(API + "/auth/tokens", headers=H(atok), ssl=False)).json()
            ok("token list shows it without the secret", any(t["id"] == ll["id"] for t in lst["tokens"]) and llt.split(".")[1] not in json.dumps(lst))
            r = await s.post(API + "/auth/tokens", json={"name": "capped", "max_role": "viewer"}, headers=H(atok), ssl=False)
            cap = await r.json(); capt = cap.get("token", "x")
            me = await (await s.get(API + "/me", headers=H(capt), ssl=False)).json()
            ok("admin token capped to viewer acts as viewer", me.get("role") == "viewer", me)
            if lights:
                r = await s.post(f"{API}/entities/{lights[0]['entity_id']}/command", json={"command": "toggle"}, headers=H(capt), ssl=False)
                ok("capped token cannot control", r.status == 403, r.status)
                r = await s.get(API + "/admin/config", headers=H(capt), ssl=False)
                ok("capped token cannot reach admin", r.status == 403, r.status)
            r = await s.post(API + "/auth/tokens", json={"name": "bad", "max_role": "admin"}, headers=H(atok), ssl=False)
            ok("max_role=admin rejected", r.status == 400, r.status)
            r = await s.post(API + "/auth/tokens", json={"name": "x", "expires_in_days": 0}, headers=H(atok), ssl=False)
            ok("expires_in_days=0 rejected", r.status == 400, r.status)
            # --- a viewer can manage only their own tokens
            vt2 = await token(s, "e2eview", TPASS)
            r = await s.post(API + "/auth/tokens", json={"name": "viewer panel"}, headers=H(vt2), ssl=False)
            vj = await r.json()
            ok("viewer creates own token", r.status == 201, vj)
            r = await s.delete(f"{API}/auth/tokens/{ll['id']}", headers=H(vt2), ssl=False)
            ok("viewer cannot revoke someone else's token (404)", r.status == 404, r.status)
            r = await s.get(API + "/auth/clients", headers=H(vt2), ssl=False)
            ok("viewer cannot list apps (403)", r.status == 403, r.status)
            r = await s.put(API + "/auth/clients", json={"client_id": "com.x.y", "name": "x", "redirect_uris": ["com.x.y://cb"]}, headers=H(vt2), ssl=False)
            ok("viewer cannot register apps (403)", r.status == 403, r.status)
            r = await s.put(API + "/auth/clients", json={"client_id": "com.bad.app", "name": "x", "redirect_uris": ["http://evil.example/cb"]}, headers=H(atok), ssl=False)
            ok("insecure redirect rejected at registration", r.status == 400, r.status)
            # --- realtime closes when the token is revoked
            async with s.ws_connect(API.replace("http", "ws") + "/ws", ssl=False) as lw2:
                await lw2.receive_json(); await lw2.send_json({"type": "auth", "access_token": llt}); await lw2.receive_json()
                await lw2.send_json({"type": "subscribe", "initial": False}); await lw2.receive_json()
                r = await s.delete(f"{API}/auth/tokens/{ll['id']}", headers=H(atok), ssl=False)
                ok("admin revokes a token", r.status == 200, r.status)
                try:
                    m = await lw2.receive(timeout=6)
                    closed = m.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING)
                except asyncio.TimeoutError:
                    closed = False
                ok("live WebSocket is closed on revoke", closed)
            ok("revoked long-lived token refused (401)", (await s.get(API + "/me", headers=H(llt), ssl=False)).status == 401)
            # --- hub users + roles flow through live
            vt3 = (await link_login(s, "e2eoper", TPASS))["access_token"]
            ok("operator token role = operator", (await (await s.get(API + "/me", headers=H(vt3), ssl=False)).json()).get("role") == "operator")
            ul = (await a.call(type="hub_mgmt/users_list"))["result"]
            users = ul["users"] if isinstance(ul, dict) else ul
            oper = next(u for u in users if (u.get("username") or u.get("name")) == "e2eoper")
            r = await a.call(type="hub_mgmt/user_set_role", user_id=oper["id"], role="viewer")
            ok("hub role change (operator -> viewer)", r["success"], r.get("error"))
            me = await (await s.get(API + "/me", headers=H(vt3), ssl=False)).json()
            ok("role change applies to the SAME token immediately", me.get("role") == "viewer", me)
            r = await a.call(type="hub_mgmt/user_remove", user_id=oper["id"])
            ok("hub user removed", r["success"], r.get("error"))
            created = [c for c in created if c != "e2eoper"]
            ok("removed hub user's token is refused immediately", (await s.get(API + "/me", headers=H(vt3), ssl=False)).status == 401)
            # --- lockout after repeated failures (last: it locks this client's IP for 15 min, so unlock via a disable/enable cycle)
            codes = []
            for _ in range(10):
                c_, _l, st_ = await authorize(s, "e2enone", "wrong-password", ch)
                codes.append(st_)
            ok("repeated bad passwords get locked out (429)", 429 in codes, codes)
            c_, _l, st_ = await authorize(s, ADMIN, APASS, ch)
            ok("lockout also blocks a correct password", st_ == 429 and not c_, st_)
            # unlock: reloading the integration state clears the in-memory throttle
            await a.call(type="sentinel_link/set_enabled", enabled=False); await a.call(type="sentinel_link/set_enabled", enabled=True)
            # toggle off/on at runtime
            r = await a.call(type="sentinel_link/set_enabled", enabled=False)
            ok("disable live", r["success"] and r["result"]["enabled"] is False, r)
            r = await s.get(API + "/entities", headers=H(atok), ssl=False); ok("disabled -> 404", r.status == 404, r.status)
            r = await s.get(API + "/info"); ok("info reports disabled", (await r.json()).get("enabled") is False)
            r = await a.call(type="sentinel_link/set_enabled", enabled=True)
            ok("re-enable live", r["success"] and r["result"]["enabled"] is True)
            r = await s.get(API + "/entities", headers=H(atok), ssl=False); ok("enabled again -> 200", r.status == 200, r.status)
            au = (await a.call(type="sentinel_link/audit", limit=50))["result"]["entries"]
            ok("audit recorded commands", any(e["action"].startswith("command:") for e in au) and any(e["action"] == "api_enabled" for e in au), len(au))
            blob = json.dumps(au)
            ok("audit has no passwords, tokens or auth codes",
               APASS not in blob and TPASS not in blob and not re.search(r"sl[lar]_[0-9a-f]{12}[.]", blob) and (j1["refresh_token"].split(".")[1] not in blob))
            # cleanup (also drops the test app and every session/token it issued)
            r = await a.call(type="sentinel_link/client_remove", client_id=CID)
            ok("test app removed (sessions revoked)", r["success"], r.get("error"))
            ul = (await a.call(type="hub_mgmt/users_list"))["result"]
            users = ul["users"] if isinstance(ul, dict) else ul
            for u in users:
                if u.get("username") in created or u.get("name") in created:
                    r = await a.call(type="hub_mgmt/user_remove", user_id=u["id"])
                    print("cleanup", u.get("username") or u.get("name"), r["success"])
    bad = [n for n, c in R if not c]
    print(f"\n{len(R)-len(bad)}/{len(R)} passed")
    if bad: print("FAILED:", bad); sys.exit(1)

asyncio.run(main())
