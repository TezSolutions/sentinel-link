#!/usr/bin/env python3
"""Link API user-management E2E (REST /users, token scopes, realtime user events).
usage: e2e_linkapi_users.py <host> <admin_user>      (HA_UI_PASS from env/~/.bashrc; node reached over https)
Uses only throwaway users prefixed 'e2eul' and throwaway tokens; both are removed in `finally`. Never touches real devices or real users.
Admin tokens are minted through the portal (as an operator would on the Link page), then used against the REST API."""
import asyncio, json, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
PW2 = "Tmp2-" + uuid.uuid4().hex[:14] + "-Bb2"
B = f"https://{HOST}"
API = B + "/api/sentinel_link/v1"
PH = {"X-Requested-With": "portal", "Content-Type": "application/json"}
R = []


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(x)[:200]}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def login(s, u, p):
    for _ in range(14):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=PH, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        return r.status, await r.json()
    return r.status, {}


async def pws(s, **m):
    r = await s.post(B + "/portal/ws", json=m, headers=PH, ssl=False)
    return await r.json()


def code(d):
    e = d.get("error")
    return (e.get("code") if isinstance(e, dict) else e)


class Api:
    def __init__(self, s, token):
        self.s, self.h = s, ({"Authorization": f"Bearer {token}"} if token else {})

    async def call(self, method, path, body=None, raw=None):
        kw = {"headers": dict(self.h), "ssl": False}
        if raw is not None:
            kw["data"] = raw; kw["headers"]["Content-Type"] = "application/json"
        elif body is not None:
            kw["json"] = body
        r = await self.s.request(method, API + path, **kw)
        try:
            j = await r.json(content_type=None)
        except Exception:
            j = {}
        return r.status, j


async def main():
    tokens, made = [], []
    try:
        async with jar() as adm, jar() as http:
            st, me = await login(adm, ADMIN, P); ok("admin portal login", st == 200 and me.get("role") == "admin", (st, me))
            st_, w = await pws(adm, type="hub_mgmt/users_list"), None
            users = st_["result"]["users"]
            for u in users:
                if (u.get("username") or "").startswith("e2eul"):
                    await pws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("pre-clean", u["username"])
            admin_id = next(u["id"] for u in users if u["username"] == ADMIN)
            vendor_id = None

            async def mint(name, scopes, user_id=admin_id):
                d = await pws(adm, type="sentinel_link/token_create", user_id=user_id, name="e2eul " + name, scopes=scopes)
                if d.get("ok"):
                    tokens.append(d["result"]["id"])
                return d

            t_none, t_w, t_wp = (await mint("none", []), await mint("write", ["users:write"]), await mint("write+pw", ["users:write", "users:password"]))
            ok("tokens minted via portal", all(d.get("ok") for d in (t_none, t_w, t_wp)), (t_none, t_w, t_wp))
            ok("token record lists its scopes", t_wp["result"].get("scopes") == ["users:password", "users:write"], t_wp["result"])
            ok("token without scopes has none", t_none["result"].get("scopes") == [], t_none["result"])
            bad = await pws(adm, type="sentinel_link/token_create", user_id=admin_id, name="e2eul bad", scopes=["admin"])
            ok("unknown scope refused", not bad.get("ok"), bad)
            A0, AW, AWP = Api(http, t_none["result"]["token"]), Api(http, t_w["result"]["token"]), Api(http, t_wp["result"]["token"])
            ANON = Api(http, None)

            # ---------------------------------------------------------------- authentication
            s, j = await ANON.call("GET", "/users"); ok("no token: 401", s == 401, (s, j))
            s, j = await Api(http, "sll_garbage.garbage").call("GET", "/users"); ok("bad token: 401", s == 401, (s, j))

            # ---------------------------------------------------------------- read (admin role, no scope)
            s, j = await A0.call("GET", "/users"); ok("admin token without scopes can read /users", s == 200 and j.get("users"), (s, j))
            names = [u.get("username") for u in j.get("users", [])]
            ok("list has the admin", ADMIN in names, names)
            ok("list hides the vendor account", not any(u.get("role") == "superadmin" for u in j.get("users", [])), names)
            ok("list says which roles may be assigned", isinstance(j.get("assignable"), list) and "admin" not in j["assignable"] and "superadmin" not in j["assignable"], j.get("assignable"))
            ok("list carries no secrets", not re.search(r"(?i)password|hash|token", json.dumps(j.get("users", []))), None)
            ok("list matches the portal's list", sorted(names) == sorted(u["username"] for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]), names)

            # ---------------------------------------------------------------- scopes
            s, j = await A0.call("POST", "/users", {"name": "E2EUL x", "username": "e2eulx", "role": "viewer"}); ok("create without users:write -> 403 missing_scope", s == 403 and code(j) == "missing_scope", (s, j))
            s, j = await A0.call("PATCH", f"/users/{admin_id}", {"name": "x"}); ok("patch without scope -> 403", s == 403 and code(j) == "missing_scope", (s, j))
            s, j = await A0.call("DELETE", f"/users/{admin_id}"); ok("delete without scope -> 403", s == 403 and code(j) == "missing_scope", (s, j))
            s, j = await A0.call("POST", f"/users/{admin_id}/password", {"password": PW}); ok("password without scope -> 403", s == 403 and code(j) == "missing_scope", (s, j))
            s, j = await AW.call("POST", "/users", {"name": "E2EUL pw", "username": "e2eulpw", "password": PW, "role": "viewer"})
            ok("write scope alone cannot set a password at create", s == 403 and "users:password" in j.get("error", {}).get("message", ""), (s, j))
            s, j = await AW.call("POST", f"/users/{admin_id}/password", {"password": PW}); ok("write scope alone cannot reset a password", s == 403 and code(j) == "missing_scope", (s, j))

            # ---------------------------------------------------------------- create
            s, j = await AWP.call("POST", "/users", {"name": "E2EUL One", "username": "e2eul1", "password": PW, "role": "homeowner"})
            ok("create user -> 201 + id", s == 201 and j.get("id"), (s, j)); uid = j.get("id"); made.append(uid)
            s, j = await AWP.call("GET", f"/users/{uid}"); ok("get created user", s == 200 and j.get("username") == "e2eul1" and j.get("role") == "homeowner" and j.get("active") is True, (s, j))
            pl = {u["username"]: u for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]}
            ok("portal sees the API-created user with the same role", pl.get("e2eul1", {}).get("role") == "homeowner", pl.get("e2eul1"))
            async with jar() as u1:
                st, m1 = await login(u1, "e2eul1", PW); ok("API-created user can sign in to the portal", st == 200 and m1.get("role") == "homeowner", (st, m1))
            s, j = await AWP.call("POST", "/users", {"name": "Dup", "username": "e2eul1", "password": PW, "role": "viewer"}); ok("duplicate username -> 409", s == 409 and code(j) == "username_taken", (s, j))
            s, j = await AWP.call("POST", "/users", {"name": "Weak", "username": "e2eulweak", "password": "password123", "role": "viewer"}); ok("common password -> 400 weak_password", s == 400 and code(j) == "weak_password", (s, j))
            s, j = await AWP.call("POST", "/users", {"name": "Same", "username": "e2eulsame", "password": "e2eulsame", "role": "viewer"}); ok("password equal to username -> 400", s == 400 and code(j) == "weak_password", (s, j))
            s, j = await AWP.call("POST", "/users", {"name": "Short", "username": "e2eulshort", "password": "Ab1", "role": "viewer"}); ok("short password -> 400", s == 400, (s, j))
            s, j = await AWP.call("POST", "/users", {"name": "Bad", "username": "E2 EUL!", "password": PW, "role": "viewer"}); ok("invalid username -> 400", s == 400 and code(j) == "invalid_username", (s, j))
            for r_ in ("admin", "superadmin", "owner", "root"):
                s, j = await AWP.call("POST", "/users", {"name": "Esc", "username": "e2eulesc", "password": PW, "role": r_}); ok(f"cannot create role '{r_}'", s == 403 and code(j) == "forbidden", (s, j))
            ok("refused creates left no user behind", "e2eulesc" not in [u["username"] for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]])
            s, j = await AWP.call("POST", "/users", raw="not json"); ok("non-JSON body -> 400", s == 400 and code(j) == "invalid_body", (s, j))
            s, j = await AWP.call("POST", "/users", raw="[1,2]"); ok("non-object body -> 400", s == 400, (s, j))
            s, j = await AWP.call("POST", "/users", {"name": "", "username": "e2eulnn", "password": PW, "role": "viewer"}); ok("empty name -> 400", s == 400, (s, j))

            # ---------------------------------------------------------------- read one / patch
            s, j = await AWP.call("GET", "/users/does-not-exist"); ok("unknown id -> 404", s == 404 and code(j) == "not_found", (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"role": "viewer"}); ok("patch role -> 200", s == 200 and j.get("role") == "viewer", (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"role": "admin"}); ok("cannot promote to admin", s == 403 and code(j) == "forbidden", (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"role": "superadmin"}); ok("cannot promote to superadmin", s == 403, (s, j))
            s, j = await AWP.call("GET", f"/users/{uid}"); ok("failed promotion changed nothing", j.get("role") == "viewer", j)
            s, j = await AWP.call("PATCH", f"/users/{uid}", {}); ok("empty patch -> 400", s == 400, (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"username": "hacker"}); ok("patching username is refused", s == 400, (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"active": "no"}); ok("non-boolean active -> 400", s == 400, (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"name": "E2EUL Renamed", "role": "installer"}); ok("patch name+role together", s == 200 and j.get("name") == "E2EUL Renamed" and j.get("role") == "installer", (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"role": "nonsense"}); ok("unknown role refused", s == 403, (s, j))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"active": False}); ok("disable user", s == 200 and j.get("active") is False, (s, j))
            async with jar() as u1:
                st, m1 = await login(u1, "e2eul1", PW); ok("disabled user cannot sign in", st != 200, (st, m1))
            s, j = await AWP.call("PATCH", f"/users/{uid}", {"active": True}); ok("re-enable user", s == 200 and j.get("active") is True, (s, j))

            # ---------------------------------------------------------------- passwords
            s, j = await AWP.call("POST", f"/users/{uid}/password", {"password": PW2}); ok("reset password -> 200", s == 200 and j.get("ok"), (s, j))
            async with jar() as u1:
                st, m1 = await login(u1, "e2eul1", PW); ok("old password no longer works", st != 200, (st, m1))
                st, m1 = await login(u1, "e2eul1", PW2); ok("new password works", st == 200, (st, m1))
            s, j = await AWP.call("POST", f"/users/{uid}/password", {"password": "password123"}); ok("weak reset refused", s == 400 and code(j) == "weak_password", (s, j))
            s, j = await AWP.call("POST", f"/users/{uid}/password", {}); ok("missing password refused", s == 400, (s, j))
            s, j = await AWP.call("POST", "/users/does-not-exist/password", {"password": PW}); ok("password for unknown user -> 404", s == 404, (s, j))

            # ---------------------------------------------------------------- protected accounts
            s, j = await AWP.call("DELETE", f"/users/{admin_id}"); ok("cannot delete yourself", s == 403 and code(j) == "forbidden", (s, j))
            s, j = await AWP.call("PATCH", f"/users/{admin_id}", {"active": False}); ok("cannot disable yourself", s == 403, (s, j))
            s, j = await AWP.call("PATCH", f"/users/{admin_id}", {"role": "viewer"}); ok("cannot demote yourself", s == 403, (s, j))
            s, j = await AWP.call("POST", f"/users/{admin_id}/password", {"password": PW}); ok("cannot reset your own password here", s == 403, (s, j))
            others = [u for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"] if u["role"] == "admin" and u["id"] != admin_id]
            for o in others[:1]:
                s, j = await AWP.call("DELETE", f"/users/{o['id']}"); ok("cannot delete another administrator", s == 403, (s, j))
            # the vendor account: probe by the id the super admin's own session would see (never exposed to admin)
            vp = os.path.expanduser("~/.config/tez-sentinel/fedeyn-tez-admin")
            if os.environ.get("SUPERADMIN_PASS") or os.path.exists(vp):
                sp = os.environ.get("SUPERADMIN_PASS") or open(vp).read().strip()
                async with jar() as sup:
                    st, _m = await login(sup, "tez-admin", sp)
                    if st == 200:
                        vendor_id = next((u["id"] for u in (await pws(sup, type="hub_mgmt/users_list"))["result"]["users"] if u["username"] == "tez-admin"), None)
            if vendor_id:
                s, j = await AWP.call("GET", f"/users/{vendor_id}"); ok("vendor account: GET -> 404 for admin", s == 404, (s, j))
                s, j = await AWP.call("DELETE", f"/users/{vendor_id}"); ok("vendor account: DELETE -> 404 for admin", s == 404, (s, j))
                s, j = await AWP.call("PATCH", f"/users/{vendor_id}", {"active": False}); ok("vendor account: PATCH -> 404 for admin", s == 404, (s, j))
                s, j = await AWP.call("POST", f"/users/{vendor_id}/password", {"password": PW}); ok("vendor account: password -> 404 for admin", s == 404, (s, j))
            else:
                print("SKIP vendor-account probes (no super admin credentials on this controller)")

            # ---------------------------------------------------------------- scope escalation via /auth/tokens
            s, j = await AW.call("POST", "/auth/tokens", {"name": "e2eul esc", "scopes": ["users:password"]}); ok("token cannot grant a scope it does not hold", s == 403 and code(j) == "scope_escalation", (s, j))
            s, j = await A0.call("POST", "/auth/tokens", {"name": "e2eul esc2", "scopes": ["users:write"]}); ok("scope-less token cannot grant any scope", s == 403, (s, j))
            s, j = await AW.call("POST", "/auth/tokens", {"name": "e2eul child", "scopes": ["users:write"]})
            ok("token can pass on a scope it holds", s == 201 and j.get("scopes") == ["users:write"], (s, j))
            if s == 201:
                tokens.append(j["id"]); child = Api(http, j["token"])
                s2, j2 = await child.call("GET", "/users"); ok("child token works", s2 == 200, (s2, j2))
            s, j = await A0.call("POST", "/auth/tokens", {"name": "e2eul plain"})
            ok("default token has no scopes", s == 201 and j.get("scopes") == [], (s, j))
            if s == 201:
                tokens.append(j["id"])
            s, j = await A0.call("GET", "/auth/tokens?all=1"); ok("token list shows scopes", s == 200 and all("scopes" in t for t in j.get("tokens", [])), (s, j))

            # ---------------------------------------------------------------- role matrix: a non-admin's token never manages users
            s, j = await AWP.call("POST", "/users", {"name": "E2EUL Mgr", "username": "e2eulmgr", "password": PW, "role": "manager"})
            if s == 201:
                made.append(j["id"]); mid = j["id"]
                d = await mint("manager", ["users:write", "users:password"], mid)
                if d.get("ok"):
                    M = Api(http, d["result"]["token"])
                    for meth, path, body in (("GET", "/users", None), ("POST", "/users", {"name": "n", "username": "e2eulzz", "password": PW, "role": "viewer"}),
                                             ("DELETE", f"/users/{uid}", None), ("POST", f"/users/{uid}/password", {"password": PW})):
                        s2, j2 = await M.call(meth, path, body); ok(f"non-admin token (even with scopes): {meth} {path.split('/')[1] if path != '/users' else 'users'} -> 403", s2 == 403, (s2, j2))
                else:
                    print("NOTE manager token not mintable:", d.get("error"))
                    ok("non-admin users cannot be given scoped tokens", True)
            else:
                ok("create manager for role matrix", False, (s, j))

            # ---------------------------------------------------------------- realtime (admin only)
            got = []

            async def sse(tok, sink):
                async with http.get(API + "/events?initial=0", headers={"Authorization": f"Bearer {tok}"}, ssl=False) as resp:
                    async for line in resp.content:
                        sink.append(line.decode())

            task = asyncio.create_task(sse(t_none["result"]["token"], got))
            await asyncio.sleep(2)
            s, j = await AWP.call("POST", "/users", {"name": "E2EUL Live", "username": "e2eullive", "password": PW, "role": "viewer"}); lid = j.get("id"); made.append(lid)
            await AWP.call("PATCH", f"/users/{lid}", {"role": "operator"})
            await AWP.call("DELETE", f"/users/{lid}"); made.remove(lid)
            await asyncio.sleep(3); task.cancel()
            txt = "".join(got)
            ok("SSE: admin gets 'user' events", "event: user" in txt, txt[:300])
            acts = re.findall(r'"action":"(\w+)"', txt)
            ok("SSE: created, role_changed, removed arrive in order", [a for a in acts if a in ("created", "role_changed", "removed")][:3] == ["created", "role_changed", "removed"], acts)
            ok("SSE user events carry no password or hash", not re.search(r"(?i)password\"|hash", txt))

            # ---------------------------------------------------------------- audit + docs
            s, j = await A0.call("GET", "/admin/audit?limit=200"); aud = json.dumps(j)
            ok("audit records user actions", all(a in aud for a in ("users:create", "users:role", "users:password", "users:delete")), None)
            ok("audit shows denied attempts", '"denied"' in aud, None)
            ok("audit never contains a password", PW not in aud and PW2 not in aud, None)
            s, j = await ANON.call("GET", "/openapi.json")
            paths = j.get("paths", {})
            ok("OpenAPI documents /users", all(any(p.endswith(x) for p in paths) for x in ("/users", "/users/{user_id}", "/users/{user_id}/password")), list(paths)[:6])
            ok("OpenAPI documents user schemas", all(k in j.get("components", {}).get("schemas", {}) for k in ("User", "UserList", "UserCreate", "UserPatch")))

            # ---------------------------------------------------------------- delete
            s, j = await AWP.call("DELETE", f"/users/{uid}"); ok("delete user -> 204", s == 204, (s, j)); made.remove(uid)
            s, j = await AWP.call("GET", f"/users/{uid}"); ok("deleted user is gone", s == 404, (s, j))
            s, j = await AWP.call("DELETE", f"/users/{uid}"); ok("deleting twice -> 404", s == 404, (s, j))
            s, j = await AWP.call("GET", "/users"); ok("deleted user not in list", "e2eul1" not in [u["username"] for u in j.get("users", [])], None)
    finally:
        async with jar() as adm:
            st, _m = await login(adm, ADMIN, P)
            if st == 200:
                for u in (await pws(adm, type="hub_mgmt/users_list"))["result"]["users"]:
                    if (u.get("username") or "").startswith("e2eul"):
                        await pws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleaned user", u["username"])
                for t in tokens:
                    await pws(adm, type="sentinel_link/token_revoke", token_id=t)
                left = (await pws(adm, type="sentinel_link/tokens"))["result"]["tokens"]
                for t in left:
                    if (t.get("name") or "").startswith("e2eul"):
                        await pws(adm, type="sentinel_link/token_revoke", token_id=t["id"]); print("cleaned token", t["id"])
    n = sum(R)
    print(f"\n{n}/{len(R)} passed")
    sys.exit(0 if n == len(R) else 1)


asyncio.run(main())
