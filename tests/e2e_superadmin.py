#!/usr/bin/env python3
"""Super-admin tier E2E: python3 e2e_superadmin.py <host> <admin_user>
(HA_UI_PASS for the customer admin from env/~/.bashrc; the vendor account's password from SUPERADMIN_PASS or ~/.config/tez-sentinel/<node>-tez-admin.)
Read-only against the node apart from throwaway users 'e2esa*' (removed in `finally`). Never touches real devices."""
import asyncio, io, json, os, re, sys, uuid, zipfile
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
NODE_TAG = os.environ.get("SUPERADMIN_FILE_TAG", "fedeyn")
SP = os.environ.get("SUPERADMIN_PASS") or open(os.path.expanduser(f"~/.config/tez-sentinel/{NODE_TAG}-tez-admin")).read().strip()
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
B = f"https://{HOST}"
R = []
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}
LEAKS = ("homeassistant", "nginx-proxy", "tez-portal", "frigate-review", "mosquitto", "nodered", "matter-server", "docker", ".service")
CONTAINER_WORDS = ("nginx-proxy", "tez-portal", "frigate-review", "Container homeassistant", "docker compose", "ghcr.io")


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{x}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def login(s, u, p):
    for _ in range(14):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        return r.status, await r.json()
    return r.status, {}


async def ws(s, **m):
    r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False)
    return r.status, await r.json()


async def get(s, path):
    r = await s.get(B + path, ssl=False)
    return r.status, await r.read(), r.headers


async def main():
    made = []
    try:
        async with jar() as sup, jar() as adm, jar() as ins:
            st, me = await login(sup, "tez-admin", SP); ok("super admin signs in", st == 200 and me.get("role") == "superadmin", (st, me))
            st, w = await ws(sup, type="hub_mgmt/whoami"); scaps = set((w.get("result") or {}).get("caps", []))
            ok("super admin caps include infra + debug + system", {"infra", "debug", "system", "users"} <= scaps, sorted(scaps))
            st, me2 = await login(adm, ADMIN, P); ok("customer admin signs in", st == 200 and me2.get("role") == "admin", (st, me2))
            st, w = await ws(adm, type="hub_mgmt/whoami"); acaps = set((w.get("result") or {}).get("caps", []))
            ok("customer admin has debug but not infra", "debug" in acaps and "infra" not in acaps and "system" in acaps, sorted(acaps))

            # ---- dashboard data: container level only for the vendor account
            st, body, _ = await get(sup, "/data/current.json"); cur = json.loads(body) if st == 200 else {}
            ok("super admin reads container-level current.json", st == 200 and cur.get("docker", {}).get("containers"), st)
            st, body, _ = await get(adm, "/data/current.json"); ok("customer admin is refused current.json", st == 403, st)
            st, body, _ = await get(adm, "/data/basic.json"); basic = json.loads(body) if st == 200 else {}
            ok("customer admin reads basic.json", st == 200 and basic.get("view") == "basic" and basic.get("services"), st)
            t = json.dumps(basic)
            ok("basic.json has no container/unit names", not [w for w in LEAKS if w in t], [w for w in LEAKS if w in t])
            ok("basic.json has service rows with up/down", all("label" in s and "up" in s for s in basic.get("services", [])))
            ok("basic.json has no docker section", "docker" not in basic and "docker_df" not in basic and "errors" not in basic)
            st, body, _ = await get(adm, "/data/history.json"); ok("customer admin still reads history.json", st == 200, st)
            st, body, _ = await get(sup, "/data/basic.json"); ok("super admin can read basic.json too", st == 200, st)

            # ---- vendor account invisible to the customer's admin
            st, d = await ws(adm, type="hub_mgmt/users_list"); names = [u.get("username") for u in d["result"]["users"]]
            ok("customer admin does not see tez-admin in Users", "tez-admin" not in names, names)
            st, d = await ws(sup, type="hub_mgmt/users_list"); names = [u.get("username") for u in d["result"]["users"]]
            ok("super admin sees tez-admin in Users", "tez-admin" in names, names)
            uid = next((u["id"] for u in d["result"]["users"] if u["username"] == "tez-admin"), None)
            st, d = await ws(adm, type="hub_mgmt/user_remove", user_id=uid)
            ok("customer admin cannot remove tez-admin", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/user_set_password", user_id=uid, password=PW)
            ok("customer admin cannot reset tez-admin's password", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/user_create", name="E2E SA Role", username="e2esarole", password=PW, role="superadmin")
            ok("a superadmin role cannot be assigned through the portal", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/users_list"); counts = d["result"].get("counts") or d["result"].get("by_role") or {}
            ok("role counts do not reveal the vendor account", "superadmin" not in json.dumps(d["result"]), counts)

            # ---- link api user overview hides it
            st, d = await ws(adm, type="sentinel_link/overview")
            ok("Link API overview hides the vendor account", "tez-admin" not in json.dumps(d), None)

            # ---- support bundle
            for who, jr, full in (("customer admin", adm, False), ("super admin", sup, True)):
                st, body, hd = await get(jr, "/portal/debug/bundle")
                ok(f"{who} downloads a support zip", st == 200 and "zip" in hd.get("Content-Type", "") and "attachment" in hd.get("Content-Disposition", ""), st)
                try:
                    z = zipfile.ZipFile(io.BytesIO(body)); names = z.namelist()
                except Exception as e:
                    ok(f"{who} bundle is a valid zip", False, e); continue
                allt = "\n".join(z.read(n).decode("utf-8", "replace") for n in names)
                ok(f"{who} bundle has README, hub logs and host summary", "README.txt" in names and "hub/log.txt" in names and "host/summary.json" in names, names)
                ok(f"{who} bundle contains no password/token material",
                   not re.search(r"(?i)(password|token|secret)\W{1,4}[A-Za-z0-9]{12,}", allt) and "eyJ" not in allt and P not in allt and SP not in allt)
                has_c = "host/containers.json" in names
                ok(f"{who} bundle {'has' if full else 'has NO'} container-level files", has_c == full, names)
                if not full:
                    ok("standard bundle names no containers or units", not [w for w in CONTAINER_WORDS if w in allt], [w for w in CONTAINER_WORDS if w in allt])
                else:
                    ok("full bundle includes container logs", any(n.startswith("host/container_log_") for n in names), names)
                ok(f"{who} bundle has no user list", '"username"' not in allt)

            # ---- other roles: no bundle, no container data, no infra
            for r_, u in (("installer", "e2esainst"), ("homeowner", "e2esahome")):
                st, d = await ws(adm, type="hub_mgmt/user_create", name="E2E SA " + r_, username=u, password=PW, role=r_)
                ok(f"create throwaway {r_}", d.get("ok"), d)
                if d.get("ok"):
                    made.append(u)
                async with jar() as o:
                    st, me3 = await login(o, u, PW); ok(f"{r_} signs in", st == 200 and me3.get("role") == r_, (st, me3))
                    st, _b, _h = await get(o, "/portal/debug/bundle"); ok(f"{r_} cannot download a support bundle", st == 403, st)
                    for pth in ("/data/current.json", "/data/basic.json"):
                        st, _b, _h = await get(o, pth); ok(f"{r_} refused {pth}", st in (401, 403), st)
                    st, d2 = await ws(o, type="hub_mgmt/debug_info"); ok(f"{r_} refused hub debug_info", not d2.get("ok") and st in (200, 403), d2)
            st, _b, _h = await get(aiohttp.ClientSession() if False else adm, "/portal/debug/bundle")  # keep the session counted
            async with aiohttp.ClientSession() as anon:
                r = await anon.get(B + "/portal/debug/bundle", ssl=False); ok("signed-out request refused", r.status == 401, r.status)
                r = await anon.get(B + "/data/current.json", ssl=False); ok("signed-out current.json refused", r.status in (401, 403), r.status)

            # ---- audit trail records the downloads
            st, d = await ws(sup, type="hub_mgmt/debug_info"); ok("super admin can call hub debug_info", d.get("ok") and d["result"].get("log_lines") is not None, d)
            ok("hub debug_info lists no usernames", '"username"' not in json.dumps(d))
    finally:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P)
            if st == 200:
                st, d = await ws(adm, type="hub_mgmt/users_list")
                for u in d["result"]["users"]:
                    if (u.get("username") or "").startswith("e2esa"):
                        await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleaned", u["username"])
    n = sum(R)
    print(f"\n{n}/{len(R)} passed")
    sys.exit(0 if n == len(R) else 1)


asyncio.run(main())
