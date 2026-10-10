#!/usr/bin/env python3
"""Phase 6 portal E2E (System: settings, backups, logs, versions, storage): python3 e2e_system.py <host> <admin_user>
Throwaway users 'e2esys*'. Settings and schedule are changed and put back in try/finally; the only backup created is deleted.
A real RESTORE is NOT run (it replaces the node's configuration); only its refusal paths are exercised."""
import asyncio, os, re, sys, uuid, aiohttp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
B = f"https://{HOST}"; H = {"X-Requested-With": "portal", "Content-Type": "application/json"}
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
res = []


def ck(name, ok, extra=""):
    res.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name, str(extra)[:140])


async def main():
    made = []
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as adm:
        async def call(s, **m):
            r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False); return r.status, await r.json()

        async def A(**m):
            st, d = await call(adm, **m); return d

        r = await adm.post(B + "/portal/login", json={"username": ADMIN, "password": P}, headers=H, ssl=False)
        ck("admin signs in", r.status == 200, r.status)
        orig = sched = None; bid = None
        try:
            # ---- info
            d = await A(type="hub_mgmt/system_info"); ck("system_info ok", d.get("ok"), d.get("error"))
            I = d["result"]; orig = dict(I["settings"])
            ck("versions present", I["versions"]["hub"] and I["versions"]["integrations"], I["versions"]["hub"])
            ck("storage numbers", I["storage"]["disk_total"] > 0 and 0 <= I["storage"]["disk_used_pct"] <= 100)
            ck("no 'Frigate' shown in versions", not any("frigate" in i["name"].lower() for i in I["versions"]["integrations"]))
            ck("no update is applied silently (note shown)", "never silently" in I["update_note"])
            # ---- settings: validation, then change + restore of the node name only
            for bad, fld in (({"name": ""}, "name"), ({"time_zone": "Mars/Base"}, "time_zone"), ({"unit_system": "furlongs"}, "unit_system"),
                             ({"latitude": 123}, "latitude"), ({"country": "India"}, "country")):
                d = await A(type="hub_mgmt/system_settings_save", values=bad); ck(f"settings rejects bad {fld}", not d["ok"] and fld in d["error"]["message"], d.get("error"))
            d = await A(type="hub_mgmt/system_settings_save", values={"name": "E2E Node Name"}); ck("settings save name", d["ok"] and d["result"]["changed"] == ["location_name"], d)
            d = await A(type="hub_mgmt/system_info"); ck("name visible after save", d["result"]["settings"]["name"] == "E2E Node Name")
            d = await A(type="hub_mgmt/system_settings_save", values={"name": orig["name"], "time_zone": orig["time_zone"], "unit_system": orig["unit_system"]})
            ck("settings put back", d["ok"], d.get("error"))
            d = await A(type="hub_mgmt/system_info"); ck("original name restored", d["result"]["settings"]["name"] == orig["name"])
            # ---- backups
            d = await A(type="hub_mgmt/backup_list"); ck("backup_list ok", d["ok"], d.get("error")); L = d["result"]
            sched = L["schedule"]; before = {b["id"] for b in L["backups"]}
            d = await A(type="hub_mgmt/backup_create", name="e2e-sys-" + uuid.uuid4().hex[:6], password="short"); ck("short backup password refused", not d["ok"])
            d = await A(type="hub_mgmt/backup_create", name="a/b"); ck("bad backup name refused", not d["ok"])
            name = "e2e-sys-" + uuid.uuid4().hex[:6]
            d = await A(type="hub_mgmt/backup_create", name=name); ck("backup created", d["ok"], d.get("error"))
            bid = d["result"]["id"]; ck("new backup listed with size", any(b["id"] == bid and b["name"] == name and (b["size"] or 0) > 10000 for b in d["result"]["backups"]))
            ck("existing backups untouched", before <= {b["id"] for b in d["result"]["backups"]})
            r = await adm.get(B + f"/portal/backup/{bid}", ssl=False); body = await r.read()
            ck("admin can download the backup", r.status == 200 and len(body) > 10000 and body[257:262] == b"ustar", f"{r.status} {len(body)}B")
            r = await adm.get(B + "/portal/backup/../../etc/passwd", ssl=False); ck("download path traversal refused", r.status in (400, 404), r.status)
            r = await adm.get(B + "/portal/backup/doesnotexist1", ssl=False); ck("unknown backup id is 404", r.status == 404, r.status)
            # schedule
            for bad in ({"recurrence": "hourly"}, {"recurrence": "daily", "time": "25:00"}, {"recurrence": "custom_days", "days": []}, {"recurrence": "daily", "copies": 0}):
                d = await A(type="hub_mgmt/backup_schedule", **bad); ck(f"schedule rejects {list(bad.values())[-1]!r}", not d["ok"])
            d = await A(type="hub_mgmt/backup_schedule", recurrence="custom_days", days=["wed", "mon"], time="03:30", copies=5)
            ck("schedule saved", d["ok"] and d["result"]["schedule"]["days"] == ["mon", "wed"] and d["result"]["schedule"]["copies"] == 5, d.get("error"))
            # restore: refusal paths only
            for kw, why in (({"confirm": "restore", "typed_name": name}, "lowercase phrase"), ({"confirm": "RESTORE", "typed_name": "wrong"}, "wrong name"),
                            ({"confirm": "", "typed_name": ""}, "empty")):
                d = await A(type="hub_mgmt/backup_restore", backup_id=bid, **kw); ck(f"restore refused: {why}", not d["ok"] and d["error"]["code"] == "confirm", d.get("error"))
            d = await A(type="hub_mgmt/backup_restore", backup_id="nope", confirm="RESTORE", typed_name="x"); ck("restore refused: unknown backup", not d["ok"] and d["error"]["code"] == "not_found")
            d = await A(type="hub_mgmt/system_restart", confirm="restart"); ck("restart refused without exact word", not d["ok"] and d["error"]["code"] == "confirm")
            st, d = await call(adm, type="hub_mgmt/backup_list"); ck("hub still up after refusals", d["ok"])
            # ---- logs
            d = await A(type="hub_mgmt/system_logs", limit=300); ck("logs returned", d["ok"] and isinstance(d["result"]["lines"], list), d.get("error"))
            lines = d["result"]["lines"]
            ck("log limit honoured", len(lines) <= 300)
            leak = [x for x in lines if re.search(r"(?i)bearer\s+[A-Za-z0-9._-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(token|password|secret)\s*[=:]\s*[^*\s]", x)]
            ck("no credential patterns in the returned log", not leak, leak[:1])
            d = await A(type="hub_mgmt/system_logs", level="ERROR", limit=100); ck("log level filter", d["ok"] and all(("WARNING" not in x[:40] and " INFO " not in x[:40]) for x in d["result"]["lines"]))
            d = await A(type="hub_mgmt/system_logs", text="zzz-no-such-text-zzz"); ck("log text filter", d["ok"] and d["result"]["lines"] == [])
            # ---- roles: nobody but admin
            roles = {}
            for role in ("homeowner", "installer"):
                u = f"e2esys{role[:4]}"
                d = await A(type="hub_mgmt/user_create", name="E2E " + role, username=u, password=PW, role=role)
                ck(f"create throwaway {role}", d["ok"], d.get("error"))
                uid = d["result"].get("id") or d["result"].get("user_id")
                if not uid:
                    us = (await A(type="hub_mgmt/users_list"))["result"]["users"]; uid = next(x["id"] for x in us if x["username"] == u)
                made.append(uid); roles[role] = u
            for role, u in roles.items():
                async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as us:
                    r = await us.post(B + "/portal/login", json={"username": u, "password": PW}, headers=H, ssl=False)
                    if r.status == 429:
                        await asyncio.sleep(70); r = await us.post(B + "/portal/login", json={"username": u, "password": PW}, headers=H, ssl=False)
                    ck(f"{role} signs in", r.status == 200, r.status)
                    denied = 0; cmds = ("system_info", "backup_list", "system_logs", "backup_create", "backup_delete", "backup_restore", "backup_schedule", "system_settings_save", "system_restart")
                    for c in cmds:
                        extra = {"backup_create": {"name": "x"}, "backup_delete": {"backup_id": bid}, "backup_restore": {"backup_id": bid, "confirm": "RESTORE", "typed_name": name},
                                 "backup_schedule": {"recurrence": "never"}, "system_settings_save": {"values": {"name": "hacked"}}, "system_restart": {"confirm": "RESTART"}}.get(c, {})
                        st, d = await call(us, type="hub_mgmt/" + c, **extra)
                        if not d.get("ok") and d.get("error", {}).get("code") == "unauthorized": denied += 1
                    ck(f"{role} denied all {len(cmds)} system commands", denied == len(cmds), denied)
                    r = await us.get(B + f"/portal/backup/{bid}", ssl=False); ck(f"{role} cannot download a backup", r.status == 403, r.status)
                    d = (await call(adm, type="hub_mgmt/system_info"))[1]
            d = await A(type="hub_mgmt/system_info"); ck("name unchanged after attempted tamper", d["result"]["settings"]["name"] == orig["name"])
            ck("safe: no restore or restart was run", True)
        finally:
            if sched:
                try:
                    await A(type="hub_mgmt/backup_schedule", recurrence=sched["recurrence"], days=sched["days"], time=sched["time"], copies=sched["copies"] or 7)
                except Exception as e:
                    print("schedule restore failed", e)
            if orig:
                await A(type="hub_mgmt/system_settings_save", values={"name": orig["name"]})
            if bid:
                d = await A(type="hub_mgmt/backup_delete", backup_id=bid); ck("test backup deleted", d.get("ok"), d.get("error"))
            for uid in made:
                await A(type="hub_mgmt/user_remove", user_id=uid)
            d = await A(type="hub_mgmt/backup_list")
            if d.get("ok"):
                ck("schedule is back as it was", d["result"]["schedule"]["recurrence"] == (sched or {}).get("recurrence"), d["result"]["schedule"])
    print(f"{sum(res)}/{len(res)} passed")
    sys.exit(0 if all(res) else 1)


asyncio.run(main())
