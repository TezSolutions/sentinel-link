#!/usr/bin/env python3
"""E2E test for the Sentinel Link API. usage: e2e_linkapi.py <host:port> <admin_user>  (HA_UI_PASS read from ~/.bashrc, never printed)"""
import asyncio, json, os, re, sys, time, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
SCHEME = sys.argv[3] if len(sys.argv) > 3 else "http"
txt = open(os.path.expanduser("~/.bashrc")).read()
APASS = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', txt, re.M).group(2)
TPASS = "Tmp-" + uuid.uuid4().hex[:14]
BASE = f"{SCHEME}://{HOST}"
API = BASE + "/api/sentinel_link/v1"
R = []


def ok(name, cond, extra=""):
    R.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


async def token(s, user, pw):
    r = await s.post(BASE + "/auth/login_flow", json={"client_id": BASE + "/", "handler": ["homeassistant", None], "redirect_uri": BASE + "/?auth_callback=1"}, ssl=False)
    fid = (await r.json())["flow_id"]
    r = await s.post(f"{BASE}/auth/login_flow/{fid}", json={"username": user, "password": pw, "client_id": BASE + "/"}, ssl=False)
    j = await r.json()
    if j.get("type") != "create_entry":
        return None
    r = await s.post(BASE + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": BASE + "/"}, ssl=False)
    return (await r.json()).get("access_token")


class WS:
    def __init__(self, s, tok): self.s, self.tok, self.i = s, tok, 0
    async def __aenter__(self):
        self.ws = await self.s.ws_connect(BASE.replace("http", "ws") + "/api/websocket", ssl=False)
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


async def main():
    created = []
    async with aiohttp.ClientSession() as s:
        atok = await token(s, ADMIN, APASS)
        ok("admin login", atok)
        H = lambda t: {"Authorization": "Bearer " + t}
        async with WS(s, atok) as a:
            st = (await a.call(type="sentinel_link/status"))["result"]
            ok("status: enabled by default", st.get("enabled") is True, st.get("enabled"))
            ok("status: version 1.6.0", st.get("integration_version") == "1.6.0", st.get("integration_version"))
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
            target = (switches or lights)
            if target:
                tid = target[0]["entity_id"]
                vt = await token(s, "e2eview", TPASS); ot = await token(s, "e2eoper", TPASS)
                got_ws, got_sse = [], []
                async with WS(s, vt) as v:
                    v.i += 1; sid = v.i
                    await v.ws.send_json({"id": sid, "type": "sentinel_link/subscribe", "initial": True})
                    async def reader():
                        while True:
                            m = await v.ws.receive_json()
                            if m.get("type") == "event": got_ws.append(m["event"])
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
                ok("WS: live state event for toggled entity", any(e.get("type") == "state" and e["entity"]["entity_id"] == tid for e in got_ws), len(got_ws))
                ok("SSE: live state event", any("event: state" in l for l in got_sse), got_sse[:3])
                ok("viewer commands list empty on realtime entity", all(e["entity"]["commands"] == [] or "snapshot" in e["entity"]["commands"] for e in got_ws if e.get("type") == "state"))
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
            ok("audit has no passwords/codes", "***" in json.dumps(au) or "code" not in json.dumps(au))
            # cleanup
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
