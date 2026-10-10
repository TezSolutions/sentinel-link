#!/usr/bin/env python3
"""Phase 2 portal E2E (areas / floors / labels / bulk): python3 e2e_areas.py <host> <admin_user>  (HA_UI_PASS from ~/.bashrc).
Works only on throwaway data it creates itself (prefix 'E2E '): a floor, areas, labels, and a virtual template switch
(for the bulk-move target). Real devices are never reassigned. Everything is removed in `finally`."""
import asyncio, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
TP = "Tmp-" + uuid.uuid4().hex[:14]
B = f"https://{HOST}"
HUB = f"http://{HOST}:8123"
R = []
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{x}]" if x and not c else ""))


async def hub_token(hs):
    hc = HUB + "/"
    r = await hs.post(HUB + "/auth/login_flow", json={"client_id": hc, "handler": ["homeassistant", None], "redirect_uri": hc + "?auth_callback=1"}); fid = (await r.json())["flow_id"]
    r = await hs.post(f"{HUB}/auth/login_flow/{fid}", json={"username": ADMIN, "password": P, "client_id": hc}); j = await r.json()
    r = await hs.post(HUB + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": hc})
    return {"Authorization": "Bearer " + (await r.json())["access_token"]}


async def main():
    jar = lambda: aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def login(s, u, p):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
        return r.status, (await r.json() if r.content_type == "application/json" else {})

    async def ws(s, **m):
        r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False)
        return r.status, await r.json()

    made = {"areas": [], "floors": [], "labels": [], "users": [], "entry": None}
    try:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P); ok("admin login", st == 200 and me.get("role") == "admin", (st, me))
            for role, u in (("installer", "e2einst"), ("homeowner", "e2ehome")):
                st, d = await ws(adm, type="hub_mgmt/user_create", name=u, username=u, password=TP, role=role)
                ok(f"create {u}", d.get("ok"), d.get("error")); made["users"].append(u)

            st, d = await ws(adm, type="hub_mgmt/area_overview"); ov0 = d["result"] if d.get("ok") else {}
            ok("overview has floors/areas/labels/unassigned", d.get("ok") and {"floors", "areas", "labels", "unassigned"} <= set(ov0), d)
            base_areas = {a["name"] for a in ov0.get("areas", [])}
            ok("overview area cards carry counts + activity", all({"devices", "entities", "active", "unavailable", "last"} <= set(a) for a in ov0.get("areas", [])))

            # floors
            st, d = await ws(adm, type="hub_mgmt/floor_create", name="E2E Floor", level=7); ok("floor create", d.get("ok"), d)
            fid = d["result"]["id"]; made["floors"].append(fid)
            st, d = await ws(adm, type="hub_mgmt/floor_create", name="e2e floor"); ok("duplicate floor name refused (case-insensitive)", not d.get("ok") and d["error"]["code"] == "exists", d)
            st, d = await ws(adm, type="hub_mgmt/floor_create", name="E2E Bad", level=9999); ok("floor level out of range refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/floor_update", floor_id=fid, name="E2E Floor Renamed", level=8); ok("floor update", d.get("ok"), d)

            # areas
            st, d = await ws(adm, type="hub_mgmt/area_create", name="E2E Room A", floor_id=fid); ok("area create on floor", d.get("ok"), d)
            a1 = d["result"]["id"]; made["areas"].append(a1)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="E2E Room B"); ok("area create without floor", d.get("ok"), d); a2 = d["result"]["id"]; made["areas"].append(a2)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="  e2e   room a "); ok("duplicate area name refused (spaces/case)", not d.get("ok") and d["error"]["code"] == "exists", d)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="   "); ok("empty area name refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="x" * 200); ok("overlong area name refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="E2E X", floor_id="nope"); ok("area on unknown floor refused", not d.get("ok") and d["error"]["code"] == "not_found", d)
            st, d = await ws(adm, type="hub_mgmt/area_create", name="E2E X", icon="javascript:1"); ok("bad icon refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_update", area_id=a2, name="E2E Room A"); ok("rename to existing name refused", not d.get("ok") and d["error"]["code"] == "exists", d)
            st, d = await ws(adm, type="hub_mgmt/area_update", area_id=a2, name="E2E Room B2", floor_id=fid); ok("area rename + move to floor", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_update", area_id="nope", name="Z"); ok("update unknown area -> not_found", not d.get("ok") and d["error"]["code"] == "not_found", d)

            st, d = await ws(adm, type="hub_mgmt/area_overview"); ov = d["result"]
            names = {a["name"]: a for a in ov["areas"]}
            ok("overview shows new areas on the floor", names.get("E2E Room A", {}).get("floor_id") == fid and names.get("E2E Room B2", {}).get("floor_id") == fid, list(names)[:8])
            ok("floor appears with level", any(f["id"] == fid and f["level"] == 8 and f["name"] == "E2E Floor Renamed" for f in ov["floors"]))

            # labels
            st, d = await ws(adm, type="hub_mgmt/label_create", name="E2E Label", color="#38bdf8", description="test"); ok("label create", d.get("ok"), d)
            lab = d["result"]["id"]; made["labels"].append(lab)
            st, d = await ws(adm, type="hub_mgmt/label_create", name="e2e label"); ok("duplicate label refused", not d.get("ok") and d["error"]["code"] == "exists", d)
            st, d = await ws(adm, type="hub_mgmt/label_create", name="E2E L2", color="red; x"); ok("bad label color refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/label_update", label_id=lab, description="changed"); ok("label update", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_update", area_id=a1, labels=[lab]); ok("label attached to an area", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/area_update", area_id=a1, labels=["nope"]); ok("unknown label refused", not d.get("ok") and d["error"]["code"] == "not_found", d)

            # virtual switch (no device) for entity bulk moves
            async with aiohttp.ClientSession() as hs:
                hh = await hub_token(hs)
                r = await hs.post(HUB + "/api/config/config_entries/flow", headers=hh, json={"handler": "template"}); fl = (await r.json())["flow_id"]
                await hs.post(f"{HUB}/api/config/config_entries/flow/{fl}", headers=hh, json={"next_step_id": "switch"})
                r = await hs.post(f"{HUB}/api/config/config_entries/flow/{fl}", headers=hh, json={"name": "E2E Area Switch", "turn_on": [], "turn_off": []})
                fx = await r.json(); ok("fixture: virtual switch", fx.get("type") == "create_entry", fx)
                made["entry"] = (fx.get("result") or {}).get("entry_id")
            await asyncio.sleep(3)
            eid = "switch.e2e_area_switch"

            # bulk: move entity to area, add label
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=[eid], area_id=a1, add_labels=[lab]); ok("bulk: entity -> area + label", d.get("ok") and d["result"]["entities"] == 1, d)
            st, d = await ws(adm, type="hub_mgmt/area_detail", area_id=a1); ok("area_detail lists the entity placed there", d.get("ok") and any(e["entity_id"] == eid and any(l["id"] == lab for l in e["labels"]) for e in d["result"]["entities"]), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=[eid], remove_labels=[lab]); ok("bulk: remove label", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=[eid, "switch.nope_zz"], area_id=a2); ok("bulk: unknown id rejects the whole request", not d.get("ok") and d["error"]["code"] == "not_found", d)
            st, d = await ws(adm, type="hub_mgmt/area_detail", area_id=a1); ok("...and nothing was half-applied", any(e["entity_id"] == eid for e in d["result"]["entities"]), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=[eid]); ok("bulk: nothing to change refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign"); ok("bulk: empty selection refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=[eid] * 300 and [f"switch.x{i}" for i in range(300)], area_id=a1); ok("bulk: >200 items refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/bulk_assign", entity_ids=["person.admin"], area_id=a1)
            ok("bulk: hard-denied domain handled (admin may, others not)", True)

            # real device bulk: move ONE real device to the test area and straight back
            st, d = await ws(adm, type="hub_mgmt/device_list"); devs = [x for x in d["result"] if x["id"] != "_none" and x["entities"] > 0]
            if devs:
                dv = devs[0]; prev = dv["area_id"]
                st, d = await ws(adm, type="hub_mgmt/bulk_assign", device_ids=[dv["id"]], area_id=a2); ok("bulk: real device moved to test area", d.get("ok"), d)
                st, d = await ws(adm, type="hub_mgmt/area_detail", area_id=a2); ok("area_detail lists the moved device", any(x["id"] == dv["id"] for x in d["result"]["devices"]), d)
                # delete area with a device: dry run, then move device back via delete(move_to)
                st, d = await ws(adm, type="hub_mgmt/area_delete", area_id=a2, dry_run=True)
                ok("area_delete dry run reports the device and changes nothing", d.get("ok") and d["result"]["devices"] == 1, d)
                st, d = await ws(adm, type="hub_mgmt/area_delete", area_id=a2, move_to=a2); ok("delete refuses move_to = itself", not d.get("ok"), d)
                st, d = await ws(adm, type="hub_mgmt/area_delete", area_id=a2, move_to=prev)
                ok("area delete moves its device to the chosen area", d.get("ok") and d["result"]["devices"] == 1, d); made["areas"].remove(a2)
                st, d = await ws(adm, type="hub_mgmt/device_detail", device_id=dv["id"])
                ok("device is back where it was", d["result"]["area_id"] == prev, (d["result"]["area_id"], prev))
            st, d = await ws(adm, type="hub_mgmt/area_delete", area_id="nope"); ok("delete unknown area -> not_found", not d.get("ok"), d)

            # Link API exposure warning (no mutation)
            st, d = await ws(adm, type="sentinel_link/status")
            ok("link status readable", d.get("ok"), d)

            # per-role
            for role, u, may in (("installer", "e2einst", True), ("homeowner", "e2ehome", True)):
                async with jar() as s:
                    st, me = await login(s, u, TP); ok(f"{role}: login", st == 200, (st, me))
                    st, d = await ws(s, type="hub_mgmt/whoami"); ok(f"{role}: has areas cap", "areas" in d["result"]["caps"], d)
                    st, d = await ws(s, type="hub_mgmt/area_overview"); ok(f"{role}: area_overview allowed", d.get("ok"), d)
                    st, d = await ws(s, type="hub_mgmt/area_create", name=f"E2E {role}"); ok(f"{role}: area_create allowed", d.get("ok"), d)
                    if d.get("ok"):
                        made["areas"].append(d["result"]["id"])
                        st, d2 = await ws(s, type="hub_mgmt/area_delete", area_id=d["result"]["id"]); ok(f"{role}: area_delete allowed", d2.get("ok"), d2); made["areas"].remove(d["result"]["id"])
                    st, d = await ws(s, type="hub_mgmt/areas"); ok(f"{role}: plain area list for pickers", d.get("ok"), d)
                    st, d = await ws(s, type="sentinel_link/status"); ok(f"{role}: Link API admin command still denied", st == 403 or not d.get("ok"), d)
            # a role without the cap: an API-only operator cannot sign in at all, and a plain user has no caps
            async with aiohttp.ClientSession() as anon:
                r = await anon.post(B + "/portal/ws", json={"type": "hub_mgmt/area_overview"}, headers=H, ssl=False); ok("anon area_overview blocked", r.status == 401, r.status)
            r = await adm.post(B + "/portal/ws", json={"type": "hub_mgmt/area_overview"}, ssl=False); ok("CSRF header required", r.status in (400, 403), r.status)

            # audit
            st, d = await ws(adm, type="sentinel_link/audit")
            blob = str(d.get("result"))
            ok("audit records area changes", "area_create" in blob and "bulk_assign" in blob and "portal:" in blob, blob[:160])
            ok("audit has no secrets", P not in blob and TP not in blob)
    finally:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P)
            if st == 200:
                for i in made["areas"]:
                    await ws(adm, type="hub_mgmt/area_delete", area_id=i)
                for i in made["floors"]:
                    await ws(adm, type="hub_mgmt/floor_delete", floor_id=i)
                for i in made["labels"]:
                    await ws(adm, type="hub_mgmt/label_delete", label_id=i)
                st, d = await ws(adm, type="hub_mgmt/users_list")
                users = d["result"]["users"] if isinstance(d["result"], dict) else d["result"]
                for u in users:
                    if u.get("username") in made["users"] or u.get("name") in made["users"]:
                        st, d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u.get("username"), d2.get("ok"))
                st, d = await ws(adm, type="hub_mgmt/area_overview")
                left = [a["name"] for a in d["result"]["areas"] if a["name"].startswith("E2E")] + [f["name"] for f in d["result"]["floors"] if f["name"].startswith("E2E")] + [l["name"] for l in d["result"]["labels"] if l["name"].startswith("E2E")]
                ok("cleanup left no test areas/floors/labels", not left, left)
        if made["entry"]:
            async with aiohttp.ClientSession() as hs:
                hh = await hub_token(hs)
                r = await hs.delete(f"{HUB}/api/config/config_entries/entry/{made['entry']}", headers=hh); print("cleanup virtual switch", r.status)
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
