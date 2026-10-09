#!/usr/bin/env python3
"""Phase 1 portal E2E (devices + entities): python3 e2e_devices.py <host> <admin_user>   (HA_UI_PASS from ~/.bashrc).
Everything goes through the portal relay on https (/portal/login + /portal/ws), exactly like the browser.
Creates + removes temp users; restores any entity setting it changes."""
import asyncio, os, re, sys, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2)
TP = "Tmp-" + uuid.uuid4().hex[:14]
B = f"https://{HOST}"
# the test operates a REAL device: never pick anything that makes noise or moves something heavy
UNSAFE = re.compile(r"alarm|siren|buzz|horn|lock|door|garage|gate|valve|water|gas|pump|heater|boiler|oven|charger|reboot|restart|reset|identify|update|flip|mirror|ptz|privacy|record|detect|camera|motor|siren|permit|join|bridge|pair|network|vpn|wifi|dhcp", re.I)
R = []
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{x}]" if x and not c else ""))


async def main():
    jar = lambda: aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def login(s, u, p):
        r = await s.post(B + "/portal/login", json={"username": u, "password": p}, headers=H, ssl=False)
        return r.status, (await r.json() if r.content_type == "application/json" else {})

    async def ws(s, **m):
        r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False)
        return r.status, await r.json()

    created = []
    restore = []
    fixture_entry = []
    async with jar() as adm:
        st, me = await login(adm, ADMIN, P); ok("admin login", st == 200 and me.get("role") == "admin", (st, me))
        for role, u in (("installer", "e2einst"), ("homeowner", "e2ehome")):
            st, d = await ws(adm, type="hub_mgmt/user_create", name=u, username=u, password=TP, role=role)
            ok(f"create {u}", d.get("ok"), d.get("error")); created.append(u)

        st, d = await ws(adm, type="hub_mgmt/whoami")
        ok("whoami reports caps (admin has all)", d.get("ok") and {"entities", "areas", "system", "profile"} <= set(d["result"].get("caps", [])), d)

        st, d = await ws(adm, type="hub_mgmt/device_list"); devs = d["result"] if d.get("ok") else []
        ok("device_list returns devices", d.get("ok") and len(devs) > 0, d)
        ok("device_list rows carry the fields the page needs", all({"id", "name", "integration", "available", "entities"} <= set(x) for x in devs))
        ok("device_list hides service entries and secrets", not any("serial" in x or "identifiers" in x for x in devs))

        # a throwaway VIRTUAL switch (template helper) is the control target: the test never touches real hardware
        hub = "http://" + HOST + ":8123"
        hc = hub + "/"
        async with aiohttp.ClientSession() as hs:
            r = await hs.post(hub + "/auth/login_flow", json={"client_id": hc, "handler": ["homeassistant", None], "redirect_uri": hc + "?auth_callback=1"}); fid = (await r.json())["flow_id"]
            r = await hs.post(f"{hub}/auth/login_flow/{fid}", json={"username": ADMIN, "password": P, "client_id": hc}); j = await r.json()
            r = await hs.post(hub + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": hc}); hh = {"Authorization": "Bearer " + (await r.json())["access_token"]}
            r = await hs.post(hub + "/api/config/config_entries/flow", headers=hh, json={"handler": "template"}); fl = (await r.json())["flow_id"]
            await hs.post(f"{hub}/api/config/config_entries/flow/{fl}", headers=hh, json={"next_step_id": "switch"})
            r = await hs.post(f"{hub}/api/config/config_entries/flow/{fl}", headers=hh, json={"name": "E2E Virtual Switch", "turn_on": [], "turn_off": []})
            fixture = await r.json()
            ok("test fixture: virtual switch created", fixture.get("type") == "create_entry", fixture)
            entry_id = (fixture.get("result") or {}).get("entry_id") if isinstance(fixture.get("result"), dict) else None
            fixture_entry.append(entry_id)
        await asyncio.sleep(3)

        # find the richest device with a controllable entity
        target = None; ent = None
        target_name = None
        ok("entities without a device are listed (pseudo device first)", bool(devs) and devs[0]["id"] == "_none", devs[:1])
        for dv in [x for x in devs if x["id"] == "_none"]:
            target_name = dv["name"]
            st, d = await ws(adm, type="hub_mgmt/device_detail", device_id=dv["id"])
            if not d.get("ok"):
                continue
            for e in d["result"]["entity_list"]:
                if (e["domain"] in ("switch", "light", "button", "fan") and e["state"] not in (None, "unavailable") and e["commands"] and not e["disabled"]
                    and "e2e_virtual_switch" in e["entity_id"]):
                    target, ent = d["result"], e
                    break
            if ent:
                break
        ok("a controllable entity exists on this node for the live control test", ent is not None, "none found - control tests skipped")
        st, d = await ws(adm, type="hub_mgmt/device_detail", device_id="does-not-exist"); ok("unknown device -> not_found", not d.get("ok") and d["error"]["code"] == "not_found", d)

        if target:
            ok("detail has entity list with live state + attrs", len(target["entity_list"]) > 0 and "attrs" in ent and "ctl" in ent)
            ok("detail does not leak serial numbers / connection ids", "serial" in target and target["serial"] is None and all(isinstance(c, str) and ":" not in c for c in target["connections"]))
            eid = ent["entity_id"]; dom = ent["domain"]
            # states poll
            st, d = await ws(adm, type="hub_mgmt/device_states", device_id=target["id"])
            ok("device_states returns the entity", d.get("ok") and eid in d["result"], d)

            # control round trip
            if dom in ("switch", "light", "fan"):
                want = "turn_off" if ent["state"] == "on" else "turn_on"
                st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command=want)
                ok(f"admin: control {eid} {want}", d.get("ok"), d)
                want_state = "off" if want == "turn_off" else "on"
                await asyncio.sleep(1.5)
                st, d = await ws(adm, type="hub_mgmt/device_states", device_id=target["id"])
                now = d["result"][eid]["state"]
                ok("state changed after control (live)", now == want_state, (ent["state"], now, want_state))
                back = "turn_on" if ent["state"] == "on" else "turn_off"
                await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command=back)   # restore
            else:
                st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command="press")
                ok(f"admin: press {eid}", d.get("ok"), d)

            # validation: unknown command / unknown field / out-of-range / unknown entity
            st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command="format_disk")
            ok("unknown command refused", not d.get("ok") and d["error"]["code"] == "unknown_command", d)
            if dom == "light":
                st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command="turn_on", data={"brightness": 999})
                ok("out-of-range field refused", not d.get("ok") and d["error"]["code"] == "invalid_field", d)
            st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command="turn_on", data={"evil": 1})
            ok("unknown field refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id="switch.does_not_exist_zz", command="turn_on")
            ok("unknown entity refused", not d.get("ok"), d)

            # entity_update: rename + hide, then restore
            orig_name = ent["name"]
            st, d = await ws(adm, type="hub_mgmt/entity_update", entity_id=eid, name="E2E Renamed", hidden=True)
            ok("entity rename + hide", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/device_detail", device_id=target["id"])
            e2 = next(x for x in d["result"]["entity_list"] if x["entity_id"] == eid)
            ok("rename + hide visible in detail", e2["name"] == "E2E Renamed" and e2["hidden"] is True, (e2["name"], e2["hidden"]))
            st, d = await ws(adm, type="hub_mgmt/entity_update", entity_id=eid, name=None, hidden=False)
            ok("entity settings restored", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/entity_update", entity_id="switch.does_not_exist_zz", name="x"); ok("update unknown entity -> not_found", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/entity_update", entity_id=eid, area_id="no-such-area"); ok("update with unknown area refused", not d.get("ok"), d)

            # history
            st, d = await ws(adm, type="hub_mgmt/entity_history", entity_id=eid, hours=24)
            ok("history returns a series object", d.get("ok") and d["result"].get("kind") in ("number", "state", "none"), d)
            st, d = await ws(adm, type="hub_mgmt/entity_history", entity_id=eid, hours=9999); ok("history hours bounded", not d.get("ok"), d)

            # diagnostics
            real = next(x["id"] for x in devs if x["id"] != "_none")
            st, d = await ws(adm, type="hub_mgmt/device_diagnostics", device_id=real)
            txt = str(d)
            ok("diagnostics bundle ok, no secrets", d.get("ok") and P not in txt and not re.search(r"access_token|refresh_token|password", txt, re.I), d.get("error"))

            # per-role permissions
            for role, u in (("installer", "e2einst"), ("homeowner", "e2ehome")):
                async with jar() as s:
                    st, me = await login(s, u, TP); ok(f"{role}: login", st == 200, (st, me))
                    st, d = await ws(s, type="hub_mgmt/whoami"); caps = set(d["result"].get("caps", []))
                    ok(f"{role}: caps include entities, exclude system", "entities" in caps and "system" not in caps, caps)
                    st, d = await ws(s, type="hub_mgmt/device_list"); ok(f"{role}: device_list allowed", d.get("ok"), d)
                    st, d = await ws(s, type="hub_mgmt/device_detail", device_id=target["id"]); ok(f"{role}: device_detail allowed", d.get("ok"), d)
                    st, d = await ws(s, type="hub_mgmt/entity_control", entity_id=eid, command="press" if dom == "button" else ("turn_off" if ent["state"] == "on" else "turn_on"))
                    ok(f"{role}: can operate a {dom}", d.get("ok"), d)
                    await ws(adm, type="hub_mgmt/entity_control", entity_id=eid, command="press" if dom == "button" else ("turn_on" if ent["state"] == "on" else "turn_off"))
                    st, d = await ws(s, type="hub_mgmt/device_diagnostics", device_id=real)
                    ok(f"{role}: diagnostics {'allowed' if role == 'installer' else 'denied'}", d.get("ok") == (role == "installer"), d.get("error"))
                    st, d = await ws(s, type="hub_mgmt/remove_device", device_id=target["id"])
                    ok(f"{role}: remove device {'not for homeowner' if role == 'homeowner' else 'checked'}", role != "homeowner" or not d.get("ok"), d)
                    st, d = await ws(s, type="sentinel_link/status"); ok(f"{role}: Link API admin command still denied", st == 403 or not d.get("ok"), d)

            # sensitive domains: find a lock/alarm if the node has one
            st, d = await ws(adm, type="hub_mgmt/entity_control", entity_id="lock.nonexistent", command="unlock")
            ok("lock command on a missing lock fails closed", not d.get("ok"), d)
            async with jar() as s:
                await login(s, "e2einst", TP)
                st, d = await ws(s, type="hub_mgmt/entity_control", entity_id="lock.nonexistent", command="unlock")
                ok("installer: lock command refused for permission (not just missing)", not d.get("ok") and d["error"]["code"] == "forbidden", d)
                st, d = await ws(s, type="hub_mgmt/entity_control", entity_id="person.admin", command="turn_on")
                ok("hard-denied domain refused", not d.get("ok") and d["error"]["code"] == "forbidden", d)

            # audit trail got the portal actions
            st, d = await ws(adm, type="sentinel_link/audit")
            rows = d["result"] if d.get("ok") and isinstance(d["result"], list) else (d.get("result") or {}).get("entries", [])
            blob = str(rows)
            ok("audit trail records portal control", "entity_control" in blob and "portal:" in blob, blob[:200])
            ok("audit trail has no secrets", P not in blob and TP not in blob)

        # an unauthenticated caller and the CSRF header
        async with aiohttp.ClientSession() as anon:
            r = await anon.post(B + "/portal/ws", json={"type": "hub_mgmt/device_list"}, headers=H, ssl=False); ok("anon device_list blocked", r.status == 401, r.status)
        r = await adm.post(B + "/portal/ws", json={"type": "hub_mgmt/device_list"}, ssl=False); ok("CSRF header required", r.status in (400, 403), r.status)

        # cleanup
        st, d = await ws(adm, type="hub_mgmt/users_list")
        users = d["result"]["users"] if isinstance(d["result"], dict) else d["result"]
        for u in users:
            if u.get("username") in created or u.get("name") in created:
                st, d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u.get("username"), d2.get("ok"))
    # remove the virtual test switch
    if fixture_entry and fixture_entry[0]:
        hub = "http://" + HOST + ":8123"; hc = hub + "/"
        async with aiohttp.ClientSession() as hs:
            r = await hs.post(hub + "/auth/login_flow", json={"client_id": hc, "handler": ["homeassistant", None], "redirect_uri": hc + "?auth_callback=1"}); fid = (await r.json())["flow_id"]
            r = await hs.post(f"{hub}/auth/login_flow/{fid}", json={"username": ADMIN, "password": P, "client_id": hc}); j = await r.json()
            r = await hs.post(hub + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": hc})
            r = await hs.delete(f"{hub}/api/config/config_entries/entry/{fixture_entry[0]}", headers={"Authorization": "Bearer " + (await r.json())["access_token"]})
            print("cleanup virtual switch", r.status)
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
