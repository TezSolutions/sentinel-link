#!/usr/bin/env python3
"""Phase 7 portal E2E (Setup checklist, handover sheet, Cameras): python3 e2e_setup.py <host> <admin_user> [--snapshot-real]
Throwaway users 'e2esetup*'. Nothing is changed on the node except those users (removed in finally). A real camera is NEVER asked for
an image unless --snapshot-real is given (a battery camera may wake up); the validation paths of the snapshot command always run."""
import asyncio, os, re, sys, uuid, aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
REAL = "--snapshot-real" in sys.argv
P = os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2)
B = f"https://{HOST}"; H = {"X-Requested-With": "portal", "Content-Type": "application/json"}
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
res = []


def ck(name, ok, extra=""):
    res.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name, str(extra)[:150])


async def main():
    made = []
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as adm:
        async def call(s, **m):
            r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False); return await r.json()

        async def A(**m):
            return await call(adm, **m)

        async def login(s, u, p):
            r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
            if r.status == 429:
                await asyncio.sleep(70); r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
            return r.status

        ck("admin signs in", await login(adm, ADMIN, P) == 200)
        try:
            # ---- checklist
            d = await A(type="hub_mgmt/setup_status"); ck("setup_status ok", d["ok"], d.get("error"))
            S = d["result"]; ids = [i["id"] for i in S["steps"]]
            ck("all ten steps present, in order", ids == ["name", "zone", "areas", "devices", "placed", "owner", "2fa", "backup", "app", "cameras"], ids)
            ck("steps carry title/detail/page", all(i["title"] and i["detail"] and i["page"] for i in S["steps"]))
            p = S["progress"]; req = [i for i in S["steps"] if not i["optional"]]
            ck("progress agrees with the steps", p["total"] == len(req) == 8 and p["done"] == sum(1 for i in req if i["done"]) and p["ready"] == (p["done"] == p["total"]), p)
            ck("'next' is the first open required step", p["next"] == next((i["id"] for i in req if not i["done"]), None), p["next"])
            # the checklist must agree with what the other pages say
            ar = await A(type="hub_mgmt/areas"); n_areas = len(ar["result"]["areas"]) if ar.get("ok") and isinstance(ar["result"], dict) and "areas" in ar["result"] else None
            if n_areas is not None:
                ck("area count equals the Areas page", [i for i in S["steps"] if i["id"] == "areas"][0]["detail"].startswith(f"{n_areas} area"), n_areas)
            bk = await A(type="hub_mgmt/backup_list"); nb = len(bk["result"]["backups"])
            ck("backup count equals the System page", [i for i in S["steps"] if i["id"] == "backup"][0]["detail"].startswith(f"{nb} backup"), nb)
            # ---- handover sheet
            for bad in ("http://x.example.com", "https://user:pw@x.example.com", "https://x.example.com/?token=abc", "javascript:alert(1)", "https://bad host.com"):
                d = await A(type="hub_mgmt/handover", url=bad); ck(f"handover refuses {bad[:34]!r}", not d["ok"] and d["error"]["code"] == "invalid", d.get("error"))
            d = await A(type="hub_mgmt/handover"); ck("handover without address has no QR", d["ok"] and d["result"]["qr_svg"] is None and d["result"]["address"] is None)
            d = await A(type="hub_mgmt/handover", url="https://demo.example.com/"); ck("handover with address", d["ok"], d.get("error"))
            R = d["result"]; txt = str(R)
            ck("address normalised + docs link + QR", R["address"] == "https://demo.example.com" and R["api_docs"].endswith("/api/sentinel_link/v1/docs") and R["qr_svg"].startswith("<svg"))
            ck("sheet lists accounts and node name", len(R["accounts"]) >= 1 and R["node"])
            ck("sheet holds no secret", not re.search(r"(?i)password\s*[=:]|bearer\s+\w{8,}|eyJ[A-Za-z0-9_-]{10,}\.|secret\s*[=:]|token\s*[=:]\s*\w", txt), txt[:80])
            ck("sheet states it has no passwords", "no passwords" in R["note"])
            # ---- cameras
            d = await A(type="hub_mgmt/camera_list"); ck("camera_list ok", d["ok"], d.get("error")); C = d["result"]
            ck("cameras have state/label/area list", all({"entity_id", "name", "label", "level", "sensors"} <= set(c) for c in C["cameras"]), len(C["cameras"]))
            ck("no 'frigate' shown in camera names", not any("frigate" in c["name"].lower() for c in C["cameras"]))
            ck("areas offered for assignment", isinstance(C["areas"], list))
            ck("live video is stated out of scope", "Still images" in C["note"])
            for bad in ("light.kitchen", "camera.", "camera.Front", "camera.x/../y", "camera.does_not_exist_zz", "../../etc/passwd"):
                d = await A(type="hub_mgmt/camera_snapshot", entity_id=bad); ck(f"snapshot refuses {bad!r}", not d["ok"] and d["error"]["code"] == "not_found", d.get("error"))
            if REAL and C["cameras"]:
                d = await A(type="hub_mgmt/camera_snapshot", entity_id=C["cameras"][0]["entity_id"])
                ck("real snapshot returns an image", d["ok"] and d["result"]["content_type"] in ("image/jpeg", "image/png") and len(d["result"]["data"]) > 200, d.get("error"))
            # ---- roles
            for role in ("installer", "homeowner"):
                u = f"e2esetup{role[:4]}"
                d = await A(type="hub_mgmt/user_create", name="E2E " + role, username=u, password=PW, role=role); ck(f"create throwaway {role}", d["ok"], d.get("error"))
                uid = d["result"].get("id") or d["result"].get("user_id")
                if not uid:
                    uid = next(x["id"] for x in (await A(type="hub_mgmt/users_list"))["result"]["users"] if x["username"] == u)
                made.append(uid)
                async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as us:
                    ck(f"{role} signs in", await login(us, u, PW) == 200)
                    d = await call(us, type="hub_mgmt/setup_status"); got = d["ok"]
                    ck(f"{role} {'can' if role == 'installer' else 'cannot'} open Setup", got == (role == "installer"), d.get("error"))
                    d = await call(us, type="hub_mgmt/handover"); ck(f"{role} {'can' if role == 'installer' else 'cannot'} open the handover sheet", d["ok"] == (role == "installer"))
                    d = await call(us, type="hub_mgmt/camera_list"); ck(f"{role} can see cameras", d["ok"], d.get("error"))
                    me = (await call(us, type="hub_mgmt/whoami"))["result"]["caps"]
                    ck(f"{role} caps: setup {'present' if role == 'installer' else 'absent'}", ("setup" in me) == (role == "installer"), me)
        finally:
            for uid in made:
                await A(type="hub_mgmt/user_remove", user_id=uid)
            left = [x["username"] for x in (await A(type="hub_mgmt/users_list"))["result"]["users"] if x["username"].startswith("e2esetup")]
            ck("throwaway users removed", not left, left)
    print(f"{sum(res)}/{len(res)} passed")
    sys.exit(0 if all(res) else 1)


asyncio.run(main())
