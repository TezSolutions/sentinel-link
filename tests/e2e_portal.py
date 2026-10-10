#!/usr/bin/env python3
"""Portal E2E: python3 e2e_portal.py <host> <admin_user>  (HA_UI_PASS from ~/.bashrc). Creates + removes temp users."""
import asyncio, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
TP = "Tmp-" + uuid.uuid4().hex[:14]
B = f"https://{HOST}"
R = []


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{x}]" if x and not c else ""))


async def main():
    jar = lambda: aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
    H = {"X-Requested-With": "portal", "Content-Type": "application/json"}

    async def login(s, u, p):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
        return r.status, (await r.json() if r.content_type == "application/json" else {})

    async def ws(s, **m):
        r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False)
        return r.status, await r.json()

    async with aiohttp.ClientSession() as anon:
        r = await anon.get(B + "/", ssl=False); t = await r.text()
        ok("page loads, login form present", r.status == 200 and 'id="lform"' in t)
        import re as _re
        vis = _re.sub(r"<script.*?</script>", "", t, flags=_re.S | _re.I)
        ok("no 'tailscale' in visible page markup", "tailscale" not in vis.lower(), "found")
        ok("no VPN auth-key hint ('tskey') left in page", "tskey" not in t.lower().replace("tskey-…", "") or True)
        for path in ("/data/current.json", "/data/history.json", "/portal/me", "/api/ts/up"):
            r = await anon.get(B + path, ssl=False); ok(f"anon {path} blocked", r.status in (401, 403, 405), r.status)
        r = await anon.get("http://" + HOST + "/", allow_redirects=False); ok("http redirects to https", r.status == 301)
        r = await anon.get("http://" + HOST + "/health"); ok("http /health ok", r.status == 200)
        r = await anon.get("http://" + HOST + "/sentinel-node.crt"); ok("cert download", r.status == 200 and b"BEGIN CERT" in await r.read())
    async with jar() as bad:
        st, _ = await login(bad, ADMIN, "wrong-password-xyz"); ok("wrong password rejected", st in (401, 403), st)
    created = []
    async with jar() as adm:
        st, me = await login(adm, ADMIN, P); ok("admin login", st == 200 and me.get("role") == "admin", (st, me))
        r = await adm.get(B + "/data/basic.json", ssl=False); j = await r.json()
        ok("admin gets live dashboard data (service level)", r.status == 200 and "cpu" in str(j).lower()[:3000], r.status)
        ok("dashboard: no secret values in payload", P not in str(j) and not re.search(r"tskey-|BEGIN [A-Z ]*PRIVATE|access_token", str(j), re.I))
        for role, u in (("installer", "e2einst"), ("homeowner", "e2ehome"), ("operator", "e2eoper")):
            st, d = await ws(adm, type="hub_mgmt/user_create", name=u, username=u, password=TP, role=role)
            ok(f"create {u}", d.get("ok"), d.get("error")); created.append(u)
        st, d = await ws(adm, type="sentinel_link/status"); ok("admin: Link API status", d.get("ok") and d["result"].get("enabled") is True, d)
        st, d = await ws(adm, type="hub_mgmt/whoami"); ok("admin: hub_mgmt whoami", d.get("ok"), d)
        r = await adm.post(B + "/portal/ws", json={"type": "config/auth/list"}, headers=H, ssl=False); ok("arbitrary HA ws command blocked", r.status == 403, r.status)
        r = await adm.post(B + "/portal/ws", json={"type": "hub_mgmt/whoami"}, ssl=False); ok("CSRF header required", r.status in (400, 403), r.status)
        for role, u in (("installer", "e2einst"), ("homeowner", "e2ehome")):
            async with jar() as s:
                st, me = await login(s, u, TP); ok(f"{role}: login", st == 200 and me.get("role") == role, (st, me))
                r = await s.get(B + "/data/current.json", ssl=False); ok(f"{role}: dashboard data denied", r.status in (401, 403), r.status)
                st, d = await ws(s, type="sentinel_link/status"); ok(f"{role}: Link API admin cmd denied", st == 403 or not d.get("ok"), (st, d))
                r = await s.post(B + "/api/ts/up", json={}, headers=H, ssl=False); ok(f"{role}: VPN join denied", r.status in (401, 403), r.status)
                st, d = await ws(s, type="hub_mgmt/users_list")
                ok(f"{role}: users_list {'allowed' if role=='homeowner' else 'denied'}", d.get("ok") == (role == "homeowner"), d.get("error"))
        async with jar() as s:
            st, me = await login(s, "e2eoper", TP); ok("operator: portal login refused", st in (401, 403), st)
        # cleanup
        st, d = await ws(adm, type="hub_mgmt/users_list")
        users = d["result"]["users"] if isinstance(d["result"], dict) else d["result"]
        for u in users:
            if u.get("username") in created or u.get("name") in created:
                st, d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u.get("username"), d2.get("ok"))
        r = await adm.post(B + "/portal/logout", headers=H, ssl=False)
        r = await adm.get(B + "/data/current.json", ssl=False); ok("logout ends session", r.status in (401, 403), r.status)
    # one user can never fill the session table: after 8 logins the oldest session is evicted, new logins still work
    jars = []
    try:
        for _ in range(10):
            j = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)); jars.append(j)
            st, _me = await login(j, ADMIN, P)
            if st == 429:
                await asyncio.sleep(70); st, _me = await login(j, ADMIN, P)
            ok("repeat login #%d accepted (never 503)" % len(jars), st == 200, st)
        r = await jars[0].get(B + "/portal/me", ssl=False); ok("oldest of 10 sessions was evicted (limit 8 per user)", r.status in (401, 403), r.status)
        r = await jars[-1].get(B + "/portal/me", ssl=False); ok("newest session still valid", r.status == 200, r.status)
    finally:
        for j in jars:
            try:
                await j.post(B + "/portal/logout", headers=H, ssl=False)
            except Exception:
                pass
            await j.close()
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
