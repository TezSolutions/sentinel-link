#!/usr/bin/env python3
"""Phase 4 portal E2E (integrations + network): python3 e2e_integrations.py <host> <admin_user> [--no-net-apply]
(HA_UI_PASS from ~/.bashrc). Throwaway users prefixed 'e2ei'; the integration under test is a virtual 'template' switch
that is removed in `finally`. Network: validation + plan always run; the real apply/confirm/timer-revert round trip uses
settings EQUIVALENT to the current ones (DHCP on the wired port that already uses DHCP), so connectivity cannot be lost."""
import asyncio, os, re, sys, time, uuid
import aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
NET_APPLY = "--no-net-apply" not in sys.argv
P = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2)
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
B = f"https://{HOST}"
R = []
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{str(x)[:300]}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def post(s, path, body=None, method="POST"):
    for _ in range(14):
        r = await s.request(method, B + path, json=body, headers=H, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        try:
            return r.status, await r.json()
        except Exception:  # noqa: BLE001
            return r.status, {}
    return r.status, {}


async def login(s, u, p):
    return await post(s, "/portal/login", {"username": u, "password": p})


async def ws(s, **m):
    return await post(s, "/portal/ws", m)


def err(d):
    return (d.get("error") or {}).get("code") if isinstance(d.get("error"), dict) else d.get("error")


async def main():
    made_entry = None
    stray_flows = []
    try:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P); ok("admin login", st == 200 and me.get("role") == "admin", (st, me))
            st, d = await ws(adm, type="hub_mgmt/users_list")
            for u in d["result"]["users"]:
                if (u.get("username") or "").startswith("e2ei"):
                    await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"])
            for role, u in (("installer", "e2eiinst"), ("installer", "e2eiinst2"), ("homeowner", "e2eihome")):
                st, d = await ws(adm, type="hub_mgmt/user_create", name="E2EI " + u, username=u, password=PW, role=role); ok(f"create {u}", d.get("ok"), d)

            # ---- overview
            st, d = await ws(adm, type="hub_mgmt/integ_overview"); ov = d["result"] if d.get("ok") else {}
            ok("overview: entries/catalog/discovered/attention", d.get("ok") and {"entries", "catalog", "discovered", "attention"} <= set(ov), d)
            doms = {e["domain"] for e in ov.get("entries", [])}
            ok("overview hides product plumbing (hub_mgmt, sentinel_link, hacs, sun, go2rtc)", not ({"hub_mgmt", "sentinel_link", "hacs", "sun", "go2rtc", "backup", "analytics"} & doms), doms)
            ok("overview entries have health + permissions + counts", all({"health", "can_remove", "can_reload", "can_reconfigure", "devices", "entities", "protected"} <= set(e) for e in ov["entries"]))
            cat = {i["domain"] for g in ov["catalog"] for i in g["items"]}
            ok("catalog is curated and never offers system integrations", "template" in cat and "tuya" in cat and not ({"hub_mgmt", "sentinel_link", "hacs", "zha", "frigate", "backup"} & cat), cat)
            ok("every entry's reason is empty when healthy", all(e["reason"] is None for e in ov["entries"] if e["health"]["ok"]))
            prot = [e for e in ov["entries"] if e["protected"]]
            ok("protected entries cannot be removed", all(not e["can_remove"] for e in prot), prot[:2])
            fr = next((e for e in ov["entries"] if e["domain"] == "frigate"), None)
            if fr:
                st, d = await ws(adm, type="hub_mgmt/integ_remove", entry_id=fr["id"]); ok("admin cannot remove Frigate", not d.get("ok") and err(d) == "forbidden", d)
                st, d = await ws(adm, type="hub_mgmt/integ_remove", entry_id=fr["id"], dry_run=True); ok("...not even as a dry run", not d.get("ok"), d)
                st, d = await ws(adm, type="hub_mgmt/integ_set_disabled", entry_id=fr["id"], disabled=True); ok("cannot switch Frigate off", not d.get("ok"), d)
                st, d = await ws(adm, type="hub_mgmt/integ_flow_start", domain="frigate", entry_id=fr["id"]); ok("cannot reconfigure Frigate", not d.get("ok"), d)

            # ---- start flows: only catalog domains
            for dom in ("hub_mgmt", "sentinel_link", "hacs", "zha", "frigate", "../etc", "nope_not_real"):
                st, d = await ws(adm, type="hub_mgmt/integ_flow_start", domain=dom); ok(f"flow_start refuses '{dom}'", not d.get("ok") and err(d) == "forbidden", d)
            st, d = await ws(adm, type="hub_mgmt/integ_flow_start", domain="template", entry_id="nope"); ok("flow_start unknown entry -> not_found", not d.get("ok") and err(d) == "not_found", d)

            # ---- add a virtual switch through the generic flow (menu -> form -> create)
            st, d = await ws(adm, type="hub_mgmt/integ_flow_start", domain="template"); r1 = d.get("result", {})
            ok("template flow starts with a menu", d.get("ok") and r1.get("type") == "menu" and "switch" in (r1.get("menu_options") or []), d)
            fid = r1.get("flow_id")
            if fid: stray_flows.append(fid)
            st, d = await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=fid, user_input={"next_step_id": "switch"}); r2 = d.get("result", {})
            ok("menu choice leads to a form with fields", d.get("ok") and r2.get("type") == "form" and any(f["name"] == "name" for f in r2.get("data_schema", [])), d)
            # bounded input
            for bad, why in (({"name": "x" * 5000}, "huge value"), ({"bad key!": 1}, "bad field name"), ({"name": {"a": {"b": {"c": {"d": {"e": 1}}}}}}, "deep nesting")):
                st, d = await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=fid, user_input=bad); ok(f"flow_step refuses {why}", not d.get("ok") and err(d) == "invalid", d)
            # someone else's flow
            async with jar() as other:
                await login(other, "e2eiinst2", PW)
                st, d = await ws(other, type="hub_mgmt/integ_flow_step", flow_id=fid, user_input={"name": "hijack"}); ok("another installer cannot continue my flow", not d.get("ok") and err(d) == "forbidden", d)
                st, d = await ws(other, type="hub_mgmt/integ_flow_abort", flow_id=fid); ok("...or abort it", not d.get("ok") and err(d) == "forbidden", d)
                st, d = await ws(other, type="hub_mgmt/integ_flow_step", flow_id="bogus", user_input={}); ok("unknown flow id refused", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=fid, user_input={"name": "E2E Integ Switch"}); r3 = d.get("result", {})
            ok("form submit creates the entry (secrets not echoed)", d.get("ok") and r3.get("type") == "create_entry" and "data" not in r3 and "result" not in r3, d)
            stray_flows.clear()
            await asyncio.sleep(2)
            st, d = await ws(adm, type="hub_mgmt/integ_overview"); ent = next((e for e in d["result"]["entries"] if e["domain"] == "template" and "E2E Integ" in e["title"]), None)
            ok("new integration listed, running, with an entity", ent is not None and ent["health"]["ok"] and ent["entities"] >= 1 and ent["can_remove"], ent)
            made_entry = ent["id"] if ent else None

            # ---- operate on it
            st, d = await ws(adm, type="hub_mgmt/integ_reload", entry_id=made_entry); ok("restart works and reports state", d.get("ok") and d["result"]["state"] == "loaded", d)
            st, d = await ws(adm, type="hub_mgmt/integ_set_disabled", entry_id=made_entry, disabled=True); ok("turn off", d.get("ok"), d)
            await asyncio.sleep(2)
            st, d = await ws(adm, type="hub_mgmt/integ_overview"); e2 = next(e for e in d["result"]["entries"] if e["id"] == made_entry)
            ok("turned-off entry is marked disabled and cannot be restarted", e2["disabled"] and not e2["can_reload"], e2)
            st, d = await ws(adm, type="hub_mgmt/integ_reload", entry_id=made_entry); ok("restart refused while off", not d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/integ_set_disabled", entry_id=made_entry, disabled=False); ok("turn on", d.get("ok"), d)
            await asyncio.sleep(2)
            st, d = await ws(adm, type="hub_mgmt/integ_remove", entry_id=made_entry, dry_run=True); ok("remove dry run reports counts and changes nothing", d.get("ok") and d["result"]["entities"] >= 1, d)
            st, d = await ws(adm, type="hub_mgmt/integ_overview"); ok("...still present after the dry run", any(e["id"] == made_entry for e in d["result"]["entries"]))
            st, d = await ws(adm, type="hub_mgmt/integ_reload", entry_id="nope"); ok("reload unknown -> not_found", not d.get("ok") and err(d) == "not_found", d)

            # ---- abort path
            st, d = await ws(adm, type="hub_mgmt/integ_flow_start", domain="template"); f2 = d["result"]["flow_id"]
            st, d = await ws(adm, type="hub_mgmt/integ_flow_abort", flow_id=f2); ok("abort a flow", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/integ_flow_step", flow_id=f2, user_input={}); ok("aborted flow cannot be continued", not d.get("ok"), d)

            # ---- role matrix
            async with jar() as ins, jar() as hom:
                st, me = await login(ins, "e2eiinst", PW); ok("installer login", st == 200, (st, me))
                st, me = await login(hom, "e2eihome", PW); ok("homeowner login", st == 200, (st, me))
                st, d = await ws(ins, type="hub_mgmt/integ_overview"); ok("installer: overview allowed", d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/whoami"); ok("installer has integrations cap", "integrations" in d["result"]["caps"], d)
                st, d = await ws(hom, type="hub_mgmt/whoami"); ok("homeowner has NO integrations cap", "integrations" not in d["result"]["caps"], d)
                for cmd, extra in (("integ_overview", {}), ("integ_flow_start", {"domain": "template"}), ("integ_reload", {"entry_id": made_entry}),
                                    ("integ_remove", {"entry_id": made_entry}), ("integ_set_disabled", {"entry_id": made_entry, "disabled": True}),
                                    ("integ_flow_step", {"flow_id": "x"}), ("integ_flow_abort", {"flow_id": "x"})):
                    st, d = await ws(hom, type="hub_mgmt/" + cmd, **extra); ok(f"homeowner denied {cmd}", not d.get("ok") and err(d) == "unauthorized", d)
                st, d = await ws(ins, type="hub_mgmt/integ_set_disabled", entry_id=made_entry, disabled=True); ok("installer may switch an integration off", d.get("ok"), d)
                await ws(ins, type="hub_mgmt/integ_set_disabled", entry_id=made_entry, disabled=False)
                # network access by role
                st, d = await post(ins, "/api/net/status", None, "GET"); ok("installer: net status", st == 200 and "interfaces" in d, (st, d))
                st, d = await post(hom, "/api/net/status", None, "GET"); ok("homeowner: net status refused", st == 403, (st, d))
                st, d = await post(hom, "/api/net/apply", {"iface": "enp4s0", "mode": "dhcp"}); ok("homeowner: net apply refused", st == 403, (st, d))
                st, d = await post(ins, "/api/ts/logout", {}); ok("installer still cannot touch the VPN", st == 403, (st, d))
                st, d = await post(ins, "/api/iot/run", {"what": "zigbee", "action": "disable"}); ok("installer still cannot touch radios", st == 403, (st, d))
                st, d = await post(ins, "/api/net/hack", {}); ok("unknown /api/net path -> 404", st == 404, (st, d))
            async with aiohttp.ClientSession() as anon:
                r = await anon.get(B + "/api/net/status", ssl=False); ok("anon net status blocked", r.status == 401, r.status)
            r = await adm.post(B + "/api/net/confirm", json={}, ssl=False); ok("net POST needs the CSRF header", r.status in (400, 403), r.status)

            # ---- network: validation through the real tool
            st, d = await post(adm, "/api/net/status", None, "GET"); ns = d
            ok("net status: editable wired ports, VPN not editable", st == 200 and ns.get("editable") and any(i["editable"] and i["kind"] == "lan" for i in ns["interfaces"]) and all(not i["editable"] for i in ns["interfaces"] if i["kind"] in ("vpn", "wifi")), (st, str(d)[:200]))
            wired = next(i for i in ns["interfaces"] if i["editable"] and i["state"] == "up" and i["ipv4"])
            cur = wired["config"]
            gw = ns["gateway"]["via"]
            bads = [({"iface": "tailscale0", "mode": "dhcp"}, "VPN port"), ({"iface": "wlo1", "mode": "dhcp"}, "Wi-Fi port"), ({"iface": "../../x", "mode": "dhcp"}, "path in name"),
                    ({"iface": wired["name"], "mode": "static", "address": "999.1.1.1/24", "gateway": gw}, "bad address"),
                    ({"iface": wired["name"], "mode": "static", "address": wired["ipv4"][0], "gateway": "8.8.8.8"}, "gateway outside"),
                    ({"iface": wired["name"], "mode": "static", "address": "127.0.0.5/8", "gateway": "127.0.0.1"}, "loopback"),
                    ({"iface": wired["name"], "mode": "dhcp", "dns": ["bad"]}, "bad dns"), ({"iface": wired["name"], "mode": "dhcp", "revert_s": 3}, "timer too short"),
                    ({"iface": wired["name"], "mode": "dhcp", "revert_s": 99999}, "timer too long")]
            for body, why in bads:
                st, d = await post(adm, "/api/net/plan", body); ok(f"net plan refuses {why}", st == 200 and d.get("ok") is False and d.get("error"), (st, d))
                st, d = await post(adm, "/api/net/apply", body); ok(f"net apply refuses {why} (nothing queued)", st == 400, (st, d))
            st, d = await post(adm, "/api/net/plan", {"iface": wired["name"], "mode": "dhcp"}); ok("net plan accepts DHCP and describes it", d.get("ok") and "automatic" in d["summary"]["after"], d)
            st, d = await post(adm, "/api/net/plan", {"iface": wired["name"], "mode": "static", "address": wired["ipv4"][0], "gateway": gw})
            ok("net plan for a fixed address says the address may change", d.get("ok") and d["summary"]["after"].startswith("static"), d)
            st, d = await post(adm, "/api/net/confirm", {}); ok("confirm with nothing pending -> false, nothing happens", d.get("ok") is False, d)

            if NET_APPLY:
                if cur["mode"] != "dhcp":
                    print("SKIP net apply round trip: wired port is not on DHCP, no equivalent-settings test is possible")
                else:
                    ip0 = wired["ipv4"][0]
                    # 1) apply equivalent settings and confirm
                    st, d = await post(adm, "/api/net/apply", {"iface": wired["name"], "mode": "dhcp", "revert_s": 60}); ok("net apply (equivalent DHCP settings) queued", st == 200 and d.get("ok"), (st, d))
                    pend = None
                    for _ in range(30):
                        await asyncio.sleep(2)
                        st, ns2 = await post(adm, "/api/net/status", None, "GET")
                        if st == 200 and ns2.get("pending"):
                            pend = ns2["pending"]; break
                    ok("a pending change with a countdown appears", pend and 0 < pend["seconds_left"] <= 60, ns2 if not pend else pend)
                    ok("job reports waiting for confirmation", (ns2.get("job") or {}).get("state") == "waiting", ns2.get("job"))
                    left0 = pend["seconds_left"]
                    st, d = await post(adm, "/api/net/apply", {"iface": wired["name"], "mode": "dhcp", "dns": ["9.9.9.9"], "revert_s": 300}); await asyncio.sleep(3)
                    st, ns3 = await post(adm, "/api/net/status", None, "GET"); p3 = ns3.get("pending") or {}
                    ok("a second change while one is pending does not reset or replace the countdown", p3 and p3["seconds_left"] < left0 and p3["seconds_left"] <= 60 and "9.9.9.9" not in str(p3), (left0, p3))
                    st, d = await post(adm, "/api/net/confirm", {}); ok("confirm keeps the settings", d.get("ok") is True, d)
                    await asyncio.sleep(2)
                    st, ns4 = await post(adm, "/api/net/status", None, "GET")
                    w4 = next(i for i in ns4["interfaces"] if i["name"] == wired["name"])
                    ok("confirmed: nothing pending, same address, link up", not ns4.get("pending") and w4["ipv4"] == wired["ipv4"] and w4["state"] == "up", (ns4.get("pending"), w4["ipv4"], ip0))
                    ok("the portal itself is still reachable after the change", st == 200)
                    # 2) apply and DO NOT confirm: the timer must put the old file back
                    st, d = await post(adm, "/api/net/apply", {"iface": wired["name"], "mode": "dhcp", "dns": ["9.9.9.9"], "revert_s": 30}); ok("second apply (not to be confirmed) queued", st == 200 and d.get("ok"), (st, d))
                    seen = False
                    for _ in range(15):
                        await asyncio.sleep(2)
                        st, ns5 = await post(adm, "/api/net/status", None, "GET")
                        if ns5.get("pending"): seen = True; break
                    ok("pending change visible", seen, ns5)
                    reverted = False
                    for _ in range(40):
                        await asyncio.sleep(3)
                        st, ns6 = await post(adm, "/api/net/status", None, "GET")
                        if st == 200 and not ns6.get("pending") and (ns6.get("job") or {}).get("state") == "reverted":
                            reverted = True; break
                    ok("unconfirmed change was reverted by the safety timer", reverted, ns6.get("job"))
                    w6 = next(i for i in ns6["interfaces"] if i["name"] == wired["name"])
                    ok("after the revert the wired port is up with its address and DNS 9.9.9.9 is gone", w6["state"] == "up" and w6["ipv4"] == wired["ipv4"] and "9.9.9.9" not in (w6["config"].get("dns") or []), (w6["ipv4"], w6.get("config")))
                    # 3) manual revert restores the very first file (wildcard) as the latest backup chain allows
                    st, d = await post(adm, "/api/net/revert", {}); ok("manual revert queued", st == 200 and d.get("ok"), (st, d))
                    for _ in range(20):
                        await asyncio.sleep(2)
                        st, ns7 = await post(adm, "/api/net/status", None, "GET")
                        if (ns7.get("job") or {}).get("state") in ("reverted", "error"): break
                    ok("manual revert completed", (ns7.get("job") or {}).get("state") == "reverted", ns7.get("job"))
                    w7 = next(i for i in ns7["interfaces"] if i["name"] == wired["name"])
                    ok("...and the node kept its address", w7["ipv4"] == wired["ipv4"] and w7["state"] == "up", w7["ipv4"])

            # ---- audit
            st, d = await ws(adm, type="sentinel_link/audit"); blob = str(d.get("result"))
            ok("audit records integration actions", all(k in blob for k in ("integ_flow_start", "integ_added", "integ_reload", "integ_disable")), blob[:200])
            ok("audit has no passwords", PW not in blob and P not in blob)
    finally:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P)
            if st == 200:
                if made_entry:
                    st, d = await ws(adm, type="hub_mgmt/integ_remove", entry_id=made_entry); print("cleanup template integration", d.get("ok"))
                st, d = await ws(adm, type="hub_mgmt/integ_overview")
                for e in d["result"]["entries"]:
                    if e["domain"] == "template" and "E2E" in e["title"]:
                        await ws(adm, type="hub_mgmt/integ_remove", entry_id=e["id"]); print("cleanup stray", e["title"])
                for f in stray_flows:
                    await ws(adm, type="hub_mgmt/integ_flow_abort", flow_id=f)
                st, d = await ws(adm, type="hub_mgmt/users_list")
                for u in d["result"]["users"]:
                    if (u.get("username") or "").startswith("e2ei"):
                        st, d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u["username"], d2.get("ok"))
                st, d = await ws(adm, type="hub_mgmt/integ_overview")
                left = [e["title"] for e in d["result"]["entries"] if e["domain"] == "template" and "E2E" in e["title"]]
                ok("cleanup left no test integration", not left, left)
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
