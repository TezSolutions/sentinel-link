"""Live check of hub_mgmt/remote_access_* over the HA websocket with throwaway users.  Never prints tokens or passwords.
Used from execute_code:  import wscheck; asyncio.run(wscheck.run(ip, admin_user_candidates, admin_pw, tamper=None))
`tamper` is an optional (async) object with .break_it()/.restore() used to prove the integrity indicator flips."""
import asyncio, json, secrets, time
import aiohttp

R = []


def ok(name, cond, extra=""):
    R.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{str(extra)[:200]}]" if extra and not cond else ""))


async def login(s, ip, user, pw):
    cid = f"http://{ip}:8123/"
    r = await s.post(f"http://{ip}:8123/auth/login_flow", json={"client_id": cid, "handler": ["homeassistant", None], "redirect_uri": cid + "?auth_callback=1"})
    fid = (await r.json())["flow_id"]
    r = await s.post(f"http://{ip}:8123/auth/login_flow/{fid}", json={"username": user, "password": pw, "client_id": cid})
    d = await r.json()
    if d.get("type") != "create_entry":
        return None
    r = await s.post(f"http://{ip}:8123/auth/token", data={"grant_type": "authorization_code", "code": d["result"], "client_id": cid})
    return (await r.json()).get("access_token")


class WS:
    def __init__(self, s, ip, tok):
        self.s, self.ip, self.tok, self.i = s, ip, tok, 0

    async def __aenter__(self):
        self.w = await self.s.ws_connect(f"ws://{self.ip}:8123/api/websocket", max_msg_size=0)
        await self.w.receive_json()
        await self.w.send_json({"type": "auth", "access_token": self.tok})
        m = await self.w.receive_json()
        assert m["type"] == "auth_ok", m
        return self

    async def __aexit__(self, *a):
        await self.w.close()

    async def call(self, **msg):
        self.i += 1
        await self.w.send_json({"id": self.i, **msg})
        while True:
            m = await asyncio.wait_for(self.w.receive_json(), 30)
            if m.get("id") == self.i:
                return m


async def run(ip, admin_users, admin_pw, tamper=None):
    pw = "Tmp-" + secrets.token_hex(8) + "-Aa1"
    names = {"homeowner": "rachomeowner", "installer": "rachinstaller", "user": "rachplain"}
    made = {}
    async with aiohttp.ClientSession() as s:
        tok = None
        for u in admin_users:
            tok = await login(s, ip, u, admin_pw)
            if tok:
                break
        ok("admin login", tok)
        if not tok:
            return R
        try:
            async with WS(s, ip, tok) as a:
                for role, uname in names.items():
                    m = await a.call(type="hub_mgmt/user_create", name="TMP " + uname, username=uname, password=pw, role=role)
                    ok(f"create temp {role}", m.get("success"), m)
                    if m.get("success"):
                        made[role] = m["result"].get("id") or m["result"].get("user_id")
                if not all(made.values()):
                    ul = (await a.call(type="hub_mgmt/users_list"))["result"]["users"]
                    for u in ul:
                        for role, uname in names.items():
                            if (u.get("username") or "").lower() == uname:
                                made[role] = u["id"]
                # admin
                m = await a.call(type="hub_mgmt/remote_access_log", limit=5)
                ok("admin: remote_access_log allowed", m.get("success") and m["result"]["integrity"]["status"] == "ok", m)
                res = m["result"] if m.get("success") else {}
                ok("admin: read-only flag, placeholder reason, support row", res.get("read_only") and all(e["reason"].startswith("Reason: not recorded") for e in res.get("entries", [])) and res.get("support_sessions", {}).get("status") == "Coming soon")
                ok("entries have IST+ISO, operator, method, source (no full IP)", res.get("entries") and all(e.get("time_ist") and e.get("time_iso") and e.get("operator") and e.get("method") for e in res["entries"]))
                import re
                full_ip = [e["source"] for e in res.get("entries", []) if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", e.get("source", ""))]
                ok("no full IPv4 in source", not full_ip, full_ip)
                m2 = await a.call(type="hub_mgmt/remote_access_summary")
                ok("admin: summary", m2.get("success") and "totals" in m2["result"], m2)
                m3 = await a.call(type="hub_mgmt/remote_access_log", limit=1000, method="sudo")
                ok("filter method=sudo", m3.get("success") and all(e["method"] == "sudo" for e in m3["result"]["entries"]))
                m4 = await a.call(type="hub_mgmt/remote_access_log", month="2026-10", limit=3)
                ok("month filter", m4.get("success") and m4["result"]["total"] >= 0)
                print("   total entries:", res.get("total"), "months:", res.get("months"))
                # role boundaries
                for role, uname in names.items():
                    t = await login(s, ip, uname, pw)
                    ok(f"{role}: login", t)
                    if not t:
                        continue
                    async with WS(s, ip, t) as u:
                        m = await u.call(type="hub_mgmt/remote_access_log")
                        s2 = await u.call(type="hub_mgmt/remote_access_summary")
                        if role == "homeowner":
                            ok("homeowner: allowed", m.get("success") and s2.get("success"), m)
                        else:
                            ok(f"{role}: DENIED (log + summary)", (not m.get("success")) and m["error"]["code"] == "unauthorized" and not s2.get("success"), m)
                # failed login recorded without password
                bad = "Wrong-" + secrets.token_hex(6)
                t = await login(s, ip, names["user"], bad)
                ok("failed login refused", t is None)
                await asyncio.sleep(1)
                ho = await login(s, ip, names["homeowner"], pw)
                async with WS(s, ip, ho) as h:
                    ll = (await h.call(type="hub_mgmt/login_list", limit=20))["result"]
                    hit = [e for e in ll["logins"] if e["username"] == names["user"] and e["outcome"] == "wrong_password"]
                    ok("failed login recorded in sign-in history (wrong_password)", hit, [e["outcome"] for e in ll["logins"]][:8])
                    ok("password not stored anywhere in entry", not any(bad in json.dumps(e) for e in ll["logins"]))
                # tamper -> integrity flips
                if tamper:
                    await tamper.break_it()
                    await asyncio.sleep(1)
                    m = await a.call(type="hub_mgmt/remote_access_log", limit=2)
                    st = m["result"]["integrity"] if m.get("success") else m
                    ok("tampered file -> integrity broken", m.get("success") and st["status"] == "broken", st)
                    await tamper.restore()
                    await asyncio.sleep(1)
                    m = await a.call(type="hub_mgmt/remote_access_log", limit=2)
                    ok("restored file -> integrity ok again", m.get("success") and m["result"]["integrity"]["status"] == "ok", m)
        finally:
            async with WS(s, ip, tok) as a:
                ul = (await a.call(type="hub_mgmt/users_list"))["result"]["users"]
                for u in ul:
                    if (u.get("username") or "").lower() in names.values():
                        m = await a.call(type="hub_mgmt/user_remove", user_id=u["id"])
                        print("removed temp user", u["username"], m.get("success"))
                ul = (await a.call(type="hub_mgmt/users_list"))["result"]["users"]
                ok("no temp users left", not [u for u in ul if (u.get("username") or "").lower() in names.values()])
    print(f"{sum(R)}/{len(R)} passed")
    return R
