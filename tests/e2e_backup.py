#!/usr/bin/env python3
"""Full-backup E2E (System > Backups > Full backup): python3 e2e_backup.py <host> <admin_user>
Checks auth, validation and the download path with a throwaway homeowner. Does NOT create or delete a backup (slow, ~1 GB);
it only reads the list and downloads the first 64 KB of an existing archive if one exists."""
import asyncio, os, re, sys, uuid, aiohttp
HOST, ADMIN = sys.argv[1], sys.argv[2]
P = (os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2))
B = f"https://{HOST}"; H = {"X-Requested-With": "portal", "Content-Type": "application/json"}
res = []
def ck(n, ok, x=""): res.append(bool(ok)); print(("PASS " if ok else "FAIL ") + n, str(x)[:120])
async def main():
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as adm, aiohttp.ClientSession() as anon:
        r = await adm.post(B + "/portal/login", json={"username": ADMIN, "password": P}, headers=H, ssl=False); ck("admin signs in", r.status == 200, r.status)
        r = await anon.get(B + "/api/backup/list", ssl=False); ck("anonymous list refused", r.status == 401, r.status)
        r = await anon.get(B + "/portal/fullbackup/x.tar.gz", ssl=False); ck("anonymous download refused", r.status == 401, r.status)
        r = await adm.get(B + "/api/backup/list", ssl=False); d = await r.json()
        ck("list has archives/schedule/classifiers", r.status == 200 and all(k in d for k in ("archives", "schedule", "classifiers", "job")), list(d)[:5])
        r = await adm.post(B + "/api/backup/schedule", json={"recurrence": "daily", "time": "99:99", "copies": 3}, headers=H, ssl=False); ck("bad time rejected", r.status == 400, r.status)
        r = await adm.post(B + "/api/backup/schedule", json={"recurrence": "daily", "time": "03:30", "copies": 500}, headers=H, ssl=False); ck("bad copies rejected", r.status == 400, r.status)
        r = await adm.post(B + "/api/backup/delete", json={"name": "../../etc/passwd"}, headers=H, ssl=False); ck("delete traversal rejected", r.status == 400, r.status)
        r = await adm.post(B + "/api/backup/create", json={}, ssl=False); ck("create without CSRF header refused", r.status == 400, r.status)
        r = await adm.get(B + "/portal/fullbackup/..%2f..%2fetc%2fpasswd", ssl=False); ck("download traversal refused", r.status == 404, r.status)
        r = await adm.get(B + "/portal/fullbackup/nope-0000.tar.gz", ssl=False); ck("unknown archive 404", r.status == 404, r.status)
        if d.get("archives"):
            n = d["archives"][0]["name"]; r = await adm.get(B + "/portal/fullbackup/" + n, ssl=False); b = await r.content.read(65536)
            ck("download streams gzip", r.status == 200 and b[:2] == b"\x1f\x8b", r.status); r.close()
asyncio.run(main()); print("%d/%d passed" % (sum(res), len(res))); sys.exit(0 if all(res) else 1)
