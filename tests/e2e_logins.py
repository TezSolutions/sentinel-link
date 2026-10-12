#!/usr/bin/env python3
"""Sign-in history E2E (portal commands, REST /logins, native hub door, privacy rules, alerts, immutability).
usage: e2e_logins.py <host> <admin_user>      (HA_UI_PASS from env/~/.bashrc)
Only throwaway users prefixed 'e2elg' and throwaway tokens; removed in `finally`. Never touches real devices or real users.
The sign-in history itself is append-only by design, so the entries these tests create stay (they are tagged with the throwaway names)."""
import asyncio, json, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
B = f"https://{HOST}"
API = B + "/api/sentinel_link/v1"
PH = {"X-Requested-With": "portal", "Content-Type": "application/json"}
R = []


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(x)[:220]}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def login(s, u, p, extra=None):
    for _ in range(14):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=PH, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        return r.status, await r.json()
    return r.status, {}


async def pws(s, **m):
    r = await s.post(B + "/portal/ws", json=m, headers=PH, ssl=False)
    try:
        return await r.json()
    except Exception:
        return {"ok": False, "error": f"http {r.status}"}


async def native(s, u, p):
    """The hub's own sign-in on port 8123 (used by existing integrations)."""
    cid = f"http://{HOST}:8123/"
    r = await s.post(f"http://{HOST}:8123/auth/login_flow", json={"client_id": cid, "handler": ["homeassistant", None], "redirect_uri": cid + "?auth_callback=1"})
    fid = (await r.json())["flow_id"]
    r = await s.post(f"http://{HOST}:8123/auth/login_flow/{fid}", json={"username": u, "password": p, "client_id": cid})
    return (await r.json()).get("type")


class Api:
    def __init__(self, s, token):
        self.s, self.h = s, ({"Authorization": f"Bearer {token}"} if token else {})

    async def call(self, method, path, body=None):
        kw = {"headers": dict(self.h), "ssl": False}
        if body is not None:
            kw["json"] = body
        r = await self.s.request(method, API + path, **kw)
        try:
            j = await r.json(content_type=None)
        except Exception:
            j = {}
        return r.status, j


async def lst(s, **q):
    d = await pws(s, type="hub_mgmt/login_list", limit=1000, **q)
    return d.get("result") if d.get("ok") else None


async def main():
    tokens = []
    try:
        async with jar() as adm, jar() as http, jar() as hom, jar() as ins, jar() as anon, jar() as nat:
            st, me = await login(adm, ADMIN, P); ok("admin portal login", st == 200 and me.get("role") == "admin", (st, me))
            users = (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]
            for u in users:
                if (u.get("username") or "").startswith("e2elg"):
                    await pws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("pre-clean", u["username"])
            admin_id = next(u["id"] for u in users if u["username"] == ADMIN)
            created = {}
            for nm, role in (("e2elghome", "homeowner"), ("e2elginst", "installer")):
                d = await pws(adm, type="hub_mgmt/user_create", name=nm.upper(), username=nm, password=PW, role=role)
                ok(f"create {nm}", d.get("ok"), d)
                if d.get("ok"):
                    created[nm] = d["result"].get("id") or d["result"].get("user_id")

            # ---------------------------------------------------------------- every door records
            st, _ = await login(hom, "e2elghome", PW); ok("homeowner portal login", st == 200, st)
            st, _ = await login(ins, "e2elginst", PW); ok("installer portal login", st == 200, st)
            await login(anon, "e2elghome", "definitely-wrong-" + uuid.uuid4().hex[:6])
            await native(nat, "e2elg-nobody-" + uuid.uuid4().hex[:4], "x")
            ok("native hub door: right password", await native(nat, "e2elginst", PW) == "create_entry")
            ok("native hub door: wrong password", await native(nat, "e2elginst", "nope-" + uuid.uuid4().hex[:6]) == "form")
            await asyncio.sleep(1)

            full = await lst(adm)
            ok("admin sees the log (scope all)", full and full["scope"] == "all", full and full["scope"])
            rows = full["logins"] if full else []
            mine = [e for e in rows if e["username"] in ("e2elghome", "e2elginst")]
            find = lambda **k: [e for e in mine if all(e.get(a) == b for a, b in k.items())]  # noqa: E731
            ok("portal success recorded", find(username="e2elghome", door="portal", outcome="success"), mine[:3])
            ok("portal wrong password recorded", find(username="e2elghome", door="portal", outcome="wrong_password"), mine[:4])
            ok("hub door success recorded", find(username="e2elginst", door="hub", outcome="success"), mine[:5])
            ok("hub door wrong password recorded", find(username="e2elginst", door="hub", outcome="wrong_password"), mine[:6])
            ok("unknown account recorded without the typed name", any(e["outcome"] == "wrong_password" and e["username"] is None for e in rows) and not any("e2elg-nobody" in json.dumps(e) for e in rows))
            ok("entries carry address and short device", all(e.get("ip") for e in mine) and all(len(e.get("device", "")) <= 60 for e in mine), mine[:2])
            bridge = [e["ip"] for e in find(door="portal") if (e["ip"] or "").startswith("172.")]
            if bridge:   # Docker's userland proxy hides LAN/VPN source addresses from the portal; only Caddy-forwarded visitors keep theirs
                print("WARN portal sign-ins from LAN/VPN show the Docker bridge address", bridge[:1])
            ok("log chain verifies", full["integrity"]["ok"], full["integrity"])
            ok("no secrets in entries", not any(re.search(r"(?i)pass|token|secret|code", k) for e in rows for k in e) and PW not in json.dumps(rows), None)

            # ---------------------------------------------------------------- privacy rules
            h = await lst(hom); i = await lst(ins)
            ok("homeowner sees everybody", h and h["scope"] == "all" and any(e["username"] == ADMIN for e in h["logins"]), h and h["scope"])
            ok("homeowner sees the admin's sign-ins", any(e["username"] == ADMIN and e["outcome"] == "success" for e in h["logins"]))
            ok("installer sees only their own", i and i["scope"] == "own" and i["logins"] and all(e["username"] == "e2elginst" for e in i["logins"]), i and [e["username"] for e in i["logins"]][:5])
            ok("installer cannot read settings", not (await pws(ins, type="hub_mgmt/login_settings")).get("ok"))
            ok("homeowner can read settings", (await pws(hom, type="hub_mgmt/login_settings")).get("ok"))
            ok("portal-only note command refused from a browser", not (await pws(adm, type="hub_mgmt/login_note", what="support_bundle", ip="1.2.3.4")).get("ok"))
            for cmd in ("login_delete", "login_clear", "login_edit"):
                ok(f"no {cmd} command exists", not (await pws(adm, type=f"hub_mgmt/{cmd}")).get("ok"))

            # ---------------------------------------------------------------- filters, paging, summary
            f = await lst(adm, outcome="wrong_password"); ok("filter by outcome", f and f["logins"] and all(e["outcome"] == "wrong_password" for e in f["logins"]))
            f = await lst(adm, door="hub"); ok("filter by door", f and f["logins"] and all(e["door"] == "hub" for e in f["logins"]))
            f = await lst(adm, user="e2elginst"); ok("filter by person", f and f["logins"] and all(e["username"] == "e2elginst" for e in f["logins"]))
            p1 = await pws(adm, type="hub_mgmt/login_list", limit=2)
            p2 = await pws(adm, type="hub_mgmt/login_list", limit=2, before=p1["result"]["next_before"])
            ok("paging gives older, distinct entries", p2["result"]["logins"] and p2["result"]["logins"][0]["seq"] < p1["result"]["logins"][-1]["seq"])
            s = await pws(adm, type="hub_mgmt/login_summary")
            ok("summary counts", s.get("ok") and s["result"]["last_24h"]["failed"] >= 3 and s["result"]["last_24h"]["success"] >= 3, s)
            ok("bad filter refused", not (await pws(adm, type="hub_mgmt/login_list", door="nonsense")).get("ok"))

            # ---------------------------------------------------------------- the vendor is visible but masked
            d = await pws(adm, type="hub_mgmt/login_list", limit=1000, user="tez-solutions-support")
            sup = d["result"]["logins"] if d.get("ok") else []
            ok("support entries (if any) are masked", all(e["name"] == "Tez Solutions support" and e["username"] == "tez-solutions-support" and e["user_id"] is None and "support" in e["flags"] for e in sup), sup[:1])
            ordinary = any(u["username"] == "tez-admin" and u.get("role") != "superadmin" for u in users)   # tez-home has a normal user with that name
            if ordinary:
                print("SKIP vendor-name check: an ordinary user is called tez-admin on this node")
            else:
                ok("vendor's real account name never appears for the admin", "tez-admin" not in json.dumps(full) and "tez-admin" not in json.dumps(h))

            # ---------------------------------------------------------------- REST API
            async def mint(name, scopes):
                d = await pws(adm, type="sentinel_link/token_create", user_id=admin_id, name="e2elg " + name, scopes=scopes)
                if d.get("ok"):
                    tokens.append(d["result"]["id"])
                return d
            t0, ts = await mint("plain", []), await mint("settings", ["logins:settings"])
            ok("tokens minted", t0.get("ok") and ts.get("ok"), (t0, ts))
            A0, AS, ANON = Api(http, t0["result"]["token"]), Api(http, ts["result"]["token"]), Api(http, None)
            s_, j = await ANON.call("GET", "/logins"); ok("REST: no token -> 401", s_ == 401, (s_, j))
            s_, j = await A0.call("GET", "/logins?limit=500"); ok("REST: admin token reads /logins", s_ == 200 and j.get("scope") == "all" and j.get("logins"), (s_, str(j)[:150]))
            ok("REST: same entries as the portal", {e["seq"] for e in j.get("logins", [])} >= {e["seq"] for e in rows[:5]})
            ok("REST: integrity block present", j.get("integrity", {}).get("ok") is True, j.get("integrity"))
            s_, j = await A0.call("GET", "/logins?door=hub&outcome=wrong_password&user=e2elginst"); ok("REST: filters work", s_ == 200 and j["logins"] and all(e["door"] == "hub" for e in j["logins"]), (s_, j))
            s_, j = await A0.call("GET", "/logins?limit=0"); ok("REST: limit validated", s_ == 400, (s_, j))
            s_, j = await A0.call("GET", "/logins?door=zzz"); ok("REST: door validated", s_ == 400, (s_, j))
            s_, j = await A0.call("GET", "/logins?since=abc"); ok("REST: number validated", s_ == 400, (s_, j))
            s_, j = await A0.call("GET", "/logins/summary"); ok("REST: summary", s_ == 200 and "last_24h" in j, (s_, j))
            s_, j = await A0.call("GET", "/logins/settings"); ok("REST: settings readable", s_ == 200 and j.get("retention_days", 0) >= 90 and j.get("min_retention_days") == 90, (s_, j))
            for m in ("POST", "DELETE", "PATCH"):
                s_, _ = await A0.call(m, "/logins", {"x": 1}); ok(f"REST: {m} /logins not allowed", s_ in (404, 405), s_)
            s_, j = await A0.call("PUT", "/logins/settings", {"retention_days": 120}); ok("REST: change settings needs the scope", s_ == 403 and (j.get("error") or {}).get("code") == "missing_scope", (s_, j))
            orig = (await A0.call("GET", "/logins/settings"))[1]
            try:
                s_, j = await AS.call("PUT", "/logins/settings", {"retention_days": 30}); ok("REST: retention below 90 refused", s_ == 400, (s_, j))
                s_, j = await AS.call("PUT", "/logins/settings", {"nope": 1}); ok("REST: unknown setting refused", s_ == 400, (s_, j))
                s_, j = await AS.call("PUT", "/logins/settings", {"alerts": {"failed": "yes"}}); ok("REST: bad alert value refused", s_ == 400, (s_, j))
                s_, j = await AS.call("PUT", "/logins/settings", {"retention_days": 200, "alerts": {"new_ip": False}})
                ok("REST: settings change with scope", s_ == 200 and j["retention_days"] == 200 and j["alerts"]["new_ip"] is False, (s_, j))
                ok("REST: change visible in the portal", (await pws(adm, type="hub_mgmt/login_settings"))["result"]["retention_days"] == 200)
            finally:
                await AS.call("PUT", "/logins/settings", {"retention_days": orig.get("retention_days", 365), "alerts": orig.get("alerts", {}), "notify_services": orig.get("notify_services", [])})
            ok("settings restored", (await A0.call("GET", "/logins/settings"))[1].get("retention_days") == orig.get("retention_days"))
            s_, j = await Api(ins, None).call("GET", "/logins")
            spec = await (await http.get(API + "/openapi.json", ssl=False)).json()
            ok("REST: spec documents the endpoints", all(p in spec["paths"] for p in ("/api/sentinel_link/v1/logins", "/api/sentinel_link/v1/logins/summary", "/api/sentinel_link/v1/logins/settings")), list(spec["paths"])[:3])

            # ---------------------------------------------------------------- the Link sign-in page and the token page record too
            before = (await lst(adm, door="link_token"))["total"]
            r = await http.post(B + "/api/sentinel_link/v1/auth/new-token", data={"username": "e2elginst", "password": "wrong-" + uuid.uuid4().hex[:5]}, ssl=False)
            await asyncio.sleep(1)
            after = (await lst(adm, door="link_token"))["total"]
            ok("token page wrong password recorded", after == before + 1 and r.status in (200, 401, 403), (before, after, r.status))

            # ---------------------------------------------------------------- failed-attempt alert flag
            bad = "e2elg-burst"
            for _ in range(3):      # on the native door: the portal's own per-address lockout would otherwise lock this test out
                await native(nat, "e2elginst", "wrong-" + uuid.uuid4().hex[:5])
            await asyncio.sleep(1)
            fl = await lst(adm, alerts_only=True)
            ok("repeated failures raise a flag", fl and any("failed_burst" in e["flags"] and e["username"] == "e2elginst" for e in fl["logins"]), fl and fl["logins"][:2])

            # ---------------------------------------------------------------- realtime (admin token sees everybody; installer token only its own)
            ti = await pws(adm, type="sentinel_link/token_create", user_id=created.get("e2elginst"), name="e2elg inst", scopes=[])
            if ti.get("ok"):
                tokens.append(ti["result"]["id"])
            ok("installer token minted", ti.get("ok"), ti)

            async def listen(token, secs, actions):
                seen = []
                async with http.ws_connect(API.replace("https", "wss") + "/ws", ssl=False, timeout=10) as ws:
                    await ws.receive_json()
                    await ws.send_json({"type": "auth", "access_token": token})
                    await ws.receive_json()
                    await ws.send_json({"type": "subscribe", "initial": False})
                    await ws.receive_json()
                    async def rd():
                        while True:
                            seen.append(await ws.receive_json())
                    t = asyncio.create_task(rd())
                    await asyncio.sleep(0.5)
                    await actions()
                    await asyncio.sleep(secs)
                    t.cancel()
                return seen
            async def acts():
                await native(nat, "e2elghome", "wrong-" + uuid.uuid4().hex[:5])      # someone else's failed attempt
                async with jar() as fresh:
                    await login(fresh, "e2elginst", PW)                                # the installer's own sign-in (a fresh browser)
            try:
                adm_seen = await listen(t0["result"]["token"], 4, acts)
                ins_seen = await listen(ti["result"]["token"], 4, acts) if ti.get("ok") else []
            except Exception as e:  # noqa: BLE001
                adm_seen, ins_seen = [], []; print("ws error", e)
            al = [m for m in adm_seen if m.get("type") == "login"]
            ok("realtime: admin gets login events for everybody", any(m["entry"]["username"] == "e2elghome" for m in al) and any(m["entry"]["username"] == "e2elginst" for m in al), [(m.get("type"), (m.get("entry") or {}).get("username")) for m in adm_seen if m.get("type", "").startswith("login")])
            ok("realtime: failed attempt arrives as a login event with its outcome", any(m["entry"]["outcome"] == "wrong_password" for m in al))
            il = [m for m in ins_seen if m.get("type") == "login"]
            ok("realtime: installer gets only their own", il and all(m["entry"]["username"] == "e2elginst" for m in il), [m["entry"]["username"] for m in il])
            ok("realtime: installer gets no alerts about others", not [m for m in ins_seen if m.get("type") == "login_alert"], [m.get("kinds") for m in ins_seen if m.get("type") == "login_alert"])
            ok("realtime: events carry no secrets", PW not in json.dumps(adm_seen + ins_seen) and not any(re.search(r"(?i)pass|token|secret", k) for m in adm_seen + ins_seen for k in (m.get("entry") or {})), None)
    finally:
        try:
            async with jar() as adm:
                await login(adm, ADMIN, P)
                for t in tokens:
                    await pws(adm, type="sentinel_link/token_revoke", token_id=t)
                for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]:
                    if (u.get("username") or "").startswith("e2elg"):
                        await pws(adm, type="hub_mgmt/user_remove", user_id=u["id"])
                left = [u["username"] for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"] if (u.get("username") or "").startswith("e2elg")]
                ok("cleanup left no throwaway users", not left, left)
        except Exception as e:  # noqa: BLE001
            print("cleanup error", e)
    n = sum(R)
    print(f"\n{n}/{len(R)} passed")
    sys.exit(0 if n == len(R) else 1)


asyncio.run(main())
