#!/usr/bin/env python3
"""Phase 5 portal E2E (scenes + simple rules): python3 e2e_scenes.py <host> <admin_user>
Throwaway users 'e2es*', a virtual template switch as the only device ever operated, and a before/after check that
pre-existing scenes/automations are untouched. Everything created is removed in `finally`."""
import asyncio, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2)
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
B = f"https://{HOST}"
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}
R = []


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(x)[:300]}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def post(s, path, body=None):
    for _ in range(14):
        r = await s.post(B + path, json=body, headers=H, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        try:
            return r.status, await r.json()
        except Exception:  # noqa: BLE001
            return r.status, {}
    return r.status, {}


async def ws(s, **m):
    return (await post(s, "/portal/ws", m))[1]


def code(d):
    return (d.get("error") or {}).get("code") if isinstance(d.get("error"), dict) else d.get("error")


async def main():
    entry = None
    made_scenes, made_rules = [], []
    before = {"scenes": [], "rules": []}
    foreign_s, foreign_r = set(), set()
    try:
        async with jar() as adm:
            st, me = await post(adm, "/portal/login", {"username": ADMIN, "password": P}); ok("admin login", st == 200, (st, me))
            d = await ws(adm, type="hub_mgmt/users_list")
            for u in d["result"]["users"]:
                if (u.get("username") or "").startswith("e2es"):
                    await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"])
            for role, u in (("installer", "e2esinst"), ("homeowner", "e2eshome"), ("viewer", "e2esview")):
                d = await ws(adm, type="hub_mgmt/user_create", name="E2ES " + u, username=u, password=PW, role=role); ok(f"create {u}", d.get("ok"), d)

            before = (await ws(adm, type="hub_mgmt/scene_list"))["result"]
            foreign_s = {s["id"] for s in before["scenes"] if not s["editable"]}
            foreign_r = {r["id"] for r in before["rules"] if not r["editable"]}
            ok("existing automations are listed read-only (no spec)", all(r["spec"] is None for r in before["rules"] if r["id"] in foreign_r))
            ok("foreign scenes expose no entity details", all(s["entities"] is None for s in before["scenes"] if not s["editable"]))

            d = await ws(adm, type="hub_mgmt/integ_flow_start", domain="template"); f = d["result"]["flow_id"]
            await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=f, user_input={"next_step_id": "switch"})
            d = await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=f, user_input={"name": "E2E Scene Switch"}); ok("fixture switch created", d.get("ok") and d["result"]["type"] == "create_entry", d)
            await asyncio.sleep(3)
            ov = (await ws(adm, type="hub_mgmt/integ_overview"))["result"]
            entry = next((e["id"] for e in ov["entries"] if e["domain"] == "template" and "E2E Scene" in e["title"]), None)
            cands = (await ws(adm, type="hub_mgmt/scene_candidates"))["result"]["entities"]
            sw = next((c["entity_id"] for c in cands if c["name"] == "E2E Scene Switch"), None)
            ok("fixture switch offered as a scene candidate", sw is not None, [c["name"] for c in cands][:5])
            ok("candidates never include locks, alarms, sensors or cameras", not any(c["domain"] in ("lock", "alarm_control_panel", "sensor", "camera") for c in cands))

            await ws(adm, type="hub_mgmt/entity_control", entity_id=sw, command="turn_off"); await asyncio.sleep(1)
            d = await ws(adm, type="hub_mgmt/scene_capture", entity_ids=[sw, "lock.nope", "sensor.nope"]); ok("capture keeps the switch, skips others", d["result"]["entities"].get(sw, {}).get("state") in ("on", "off") and len(d["result"]["skipped"]) == 2, d)

            for bad, why in (({"name": "", "entities": {sw: {"state": "on"}}}, "empty name"), ({"name": "x" * 70, "entities": {sw: {"state": "on"}}}, "long name"),
                             ({"name": "A{{x}}", "entities": {sw: {"state": "on"}}}, "template chars"), ({"name": "S", "entities": {}}, "no devices"),
                             ({"name": "S", "entities": {"lock.front": {"state": "on"}}}, "a lock"), ({"name": "S", "entities": {"switch.does_not_exist": {"state": "on"}}}, "unknown device")):
                d = await ws(adm, type="hub_mgmt/scene_save", **bad); ok(f"scene_save refuses {why}", not d.get("ok") and code(d) == "invalid", d)
            d = await ws(adm, type="hub_mgmt/scene_save", name="E2E Scene A", entities={sw: {"state": "on", "service": "shell_command.x"}}); ok("scene saved (extra keys ignored)", d.get("ok") and d["result"]["id"].startswith("portal_") and d["result"]["entity_id"], d)
            sid = d["result"]["id"]; seid = d["result"]["entity_id"]; made_scenes.append(sid)
            d = await ws(adm, type="hub_mgmt/scene_save", name="e2e scene a", entities={sw: {"state": "on"}}); ok("duplicate name refused (case-insensitive)", not d.get("ok") and code(d) == "duplicate", d)
            d = await ws(adm, type="hub_mgmt/scene_save", scene_id=sid, name="E2E Scene A2", entities={sw: {"state": "on"}}); ok("scene edit keeps the id", d.get("ok") and d["result"]["id"] == sid, d)
            sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]
            mine = next((s for s in sl["scenes"] if s["id"] == sid), None)
            ok("scene listed, editable, renamed, no service key stored", mine and mine["editable"] and mine["name"] == "E2E Scene A2" and mine["count"] == 1 and "service" not in mine["entities"][sw], mine)
            for fid in list(foreign_s)[:1]:
                d = await ws(adm, type="hub_mgmt/scene_delete", scene_id=fid); ok("cannot delete a scene the portal did not create", not d.get("ok"), d)
                d = await ws(adm, type="hub_mgmt/scene_save", scene_id=fid, name="hijack", entities={sw: {"state": "on"}}); ok("cannot overwrite a foreign scene", not d.get("ok"), d)
            d = await ws(adm, type="hub_mgmt/scene_save", scene_id="portal_doesnotexist", name="Ghost", entities={sw: {"state": "on"}}); ok("editing an unknown scene refused", not d.get("ok") and code(d) in ("not_found", "forbidden"), d)
            await ws(adm, type="hub_mgmt/entity_control", entity_id=sw, command="turn_off"); await asyncio.sleep(1)
            d = await ws(adm, type="hub_mgmt/scene_activate", scene_id=sid); ok("scene activate ok", d.get("ok"), d)
            await asyncio.sleep(2)
            d = await ws(adm, type="hub_mgmt/scene_capture", entity_ids=[sw]); ok("activating the scene turned the switch on", d["result"]["entities"][sw]["state"] == "on", d)
            d = await ws(adm, type="hub_mgmt/scene_activate", scene_id="nope"); ok("activate unknown -> not_found", not d.get("ok") and code(d) == "not_found", d)

            R1 = {"name": "E2E Rule Off", "trigger": {"type": "time", "at": "03:33", "days": ["mon"]}, "actions": [{"type": "entity", "entity_id": sw, "command": "turn_off"}], "enabled": True}
            bads = [({**R1, "trigger": {"type": "template", "value_template": "{{ true }}"}}, "template trigger"), ({**R1, "trigger": {"type": "time", "at": "99:99"}}, "bad time"),
                    ({**R1, "actions": [{"type": "service", "service": "shell_command.rm"}]}, "service action"), ({**R1, "actions": [{"type": "entity", "entity_id": "lock.front_door", "command": "turn_off"}]}, "lock action"),
                    ({**R1, "actions": []}, "no actions"), ({**R1, "actions": [{"type": "scene", "scene_id": "light.x"}]}, "scene id of wrong kind"), ({**R1, "name": "{{ evil }}"}, "template name"),
                    ({**R1, "trigger": {"type": "state", "entity_id": "switch.does_not_exist", "to": "on"}}, "unknown watched device"), ({**R1, "trigger": {"type": "state", "entity_id": sw, "to": "{{ x }}"}}, "template state")]
            for body, why in bads:
                d = await ws(adm, type="hub_mgmt/rule_save", rule=body); ok(f"rule_save refuses {why}", not d.get("ok") and code(d) == "invalid", d)
            d = await ws(adm, type="hub_mgmt/rule_save", rule=R1); ok("rule saved and loaded", d.get("ok") and d["result"]["entity_id"], d)
            rid = d["result"]["id"]; made_rules.append(rid)
            d = await ws(adm, type="hub_mgmt/rule_save", rule={**R1, "name": "e2e rule off"}); ok("duplicate rule name refused", not d.get("ok") and code(d) == "duplicate", d)
            sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]; rr = next((r for r in sl["rules"] if r["id"] == rid), None)
            ok("rule listed with a readable summary and spec", rr and rr["editable"] and rr["summary"].startswith("At 03:33 (Mon)") and rr["enabled"] is True, rr)
            d = await ws(adm, type="hub_mgmt/rule_save", rule_id=rid, rule={**R1, "name": "E2E Rule Off 2", "trigger": {"type": "sun", "event": "sunset", "offset_min": -30}, "only_between": {"from": "17:00", "to": "23:00"}}); ok("rule edit ok", d.get("ok"), d)
            sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]; rr = next(r for r in sl["rules"] if r["id"] == rid)
            ok("edited summary reflects the new trigger and window", "30 min before sunset" in rr["summary"] and "17:00" in rr["summary"], rr["summary"])
            d = await ws(adm, type="hub_mgmt/rule_run", rule_id=rid); ok("rule run now ok", d.get("ok"), d)
            await asyncio.sleep(2)
            d = await ws(adm, type="hub_mgmt/scene_capture", entity_ids=[sw]); ok("the rule really switched the device off", d["result"]["entities"][sw]["state"] == "off", d)
            sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]; rr = next(r for r in sl["rules"] if r["id"] == rid); ok("last-ran time recorded", rr["last_triggered"], rr)
            d = await ws(adm, type="hub_mgmt/rule_set_enabled", rule_id=rid, enabled=False); ok("rule disabled", d.get("ok"), d)
            sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]; ok("...and shown as off", next(r for r in sl["rules"] if r["id"] == rid)["enabled"] is False)
            d = await ws(adm, type="hub_mgmt/rule_save", rule={"name": "E2E Rule Scene", "trigger": {"type": "state", "entity_id": sw, "to": "on", "for_min": 5}, "actions": [{"type": "scene", "scene_id": seid}], "enabled": False}); ok("rule using the scene saved", d.get("ok"), d)
            if d.get("ok"):
                made_rules.append(d["result"]["id"])
                d2 = await ws(adm, type="hub_mgmt/scene_delete", scene_id=sid); ok("scene in use by a rule cannot be deleted", not d2.get("ok") and code(d2) == "in_use", d2)
            for fid in list(foreign_r)[:2]:
                for t, extra in (("rule_delete", {}), ("rule_run", {}), ("rule_set_enabled", {"enabled": False})):
                    d = await ws(adm, type="hub_mgmt/" + t, rule_id=fid, **extra); ok(f"{t} refuses a rule the portal did not create", not d.get("ok") and code(d) == "not_found", d)
                d = await ws(adm, type="hub_mgmt/rule_save", rule_id=fid, rule=R1); ok("rule_save cannot overwrite a foreign automation", not d.get("ok"), d)

            async with jar() as ins, jar() as hom, jar() as vw:
                await post(ins, "/portal/login", {"username": "e2esinst", "password": PW}); await post(hom, "/portal/login", {"username": "e2eshome", "password": PW}); await post(vw, "/portal/login", {"username": "e2esview", "password": PW})
                for who, s_ in (("installer", ins), ("homeowner", hom)):
                    d = await ws(s_, type="hub_mgmt/scene_list"); ok(f"{who}: scene_list allowed", d.get("ok"), d)
                    d = await ws(s_, type="hub_mgmt/scene_activate", scene_id=sid); ok(f"{who}: can run a scene", d.get("ok"), d)
                    d = await ws(s_, type="hub_mgmt/rule_run", rule_id=rid); ok(f"{who}: can run a rule", d.get("ok"), d)
                d = await ws(hom, type="hub_mgmt/scene_save", name="E2E Home Scene", entities={sw: {"state": "off"}}); ok("homeowner: can create a scene", d.get("ok"), d)
                if d.get("ok"): made_scenes.append(d["result"]["id"])
                st_v, dv = await post(vw, "/portal/login", {"username": "e2esview", "password": PW}); ok("viewer: portal sign-in refused (no portal role)", st_v in (401, 403), (st_v, dv))
                for cmd, extra in (("scene_list", {}), ("scene_save", {"name": "V", "entities": {sw: {"state": "on"}}}), ("scene_delete", {"scene_id": sid}), ("rule_run", {"rule_id": rid}), ("rule_save", {"rule": R1})):
                    d = await ws(vw, type="hub_mgmt/" + cmd, **extra); ok(f"viewer without a session denied {cmd}", not d.get("ok"), d)
                d = await ws(adm, type="hub_mgmt/scene_list"); ok("viewer's attempts changed nothing", len([s for s in d["result"]["scenes"] if s["editable"]]) == len(made_scenes), len(made_scenes))

            blob = str((await ws(adm, type="sentinel_link/audit")).get("result"))
            ok("audit records scene and rule actions", all(k in blob for k in ("scene_save", "scene_activate", "rule_save", "rule_run")), blob[:200])
            ok("audit holds no passwords", PW not in blob and P not in blob)
    finally:
        async with jar() as adm:
            st, me = await post(adm, "/portal/login", {"username": ADMIN, "password": P})
            if st == 200:
                for r in list(made_rules):
                    d = await ws(adm, type="hub_mgmt/rule_delete", rule_id=r); print("cleanup rule", r, d.get("ok"))
                for s in list(made_scenes):
                    d = await ws(adm, type="hub_mgmt/scene_delete", scene_id=s); print("cleanup scene", s, d.get("ok"))
                sl = (await ws(adm, type="hub_mgmt/scene_list"))["result"]
                for r in sl["rules"]:
                    if r["editable"] and "E2E" in r["name"]:
                        await ws(adm, type="hub_mgmt/rule_delete", rule_id=r["id"]); print("cleanup stray rule", r["name"])
                for s in sl["scenes"]:
                    if s["editable"] and "E2E" in s["name"]:
                        await ws(adm, type="hub_mgmt/scene_delete", scene_id=s["id"]); print("cleanup stray scene", s["name"])
                if entry:
                    d = await ws(adm, type="hub_mgmt/integ_remove", entry_id=entry); print("cleanup fixture", d.get("ok"))
                d = await ws(adm, type="hub_mgmt/users_list")
                for u in d["result"]["users"]:
                    if (u.get("username") or "").startswith("e2es"):
                        d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u["username"], d2.get("ok"))
                after = (await ws(adm, type="hub_mgmt/scene_list"))["result"]
                ok("cleanup left no portal scene or rule behind", not [x for x in after["scenes"] + after["rules"] if x["editable"] and "E2E" in x["name"]])
                ok("pre-existing scenes and automations are exactly as before",
                   {s["id"] for s in after["scenes"] if not s["editable"]} == foreign_s and {r["id"] for r in after["rules"]} == {r["id"] for r in before["rules"]})
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
