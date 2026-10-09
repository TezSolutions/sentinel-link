#!/usr/bin/env python3
"""Phase 3 portal E2E (users, passwords, two-step sign-in, sessions): python3 e2e_users.py <host> <admin_user>
(HA_UI_PASS from ~/.bashrc; needs `pyotp` in the venv). Uses only throwaway users prefixed 'e2eu'; removed in `finally`."""
import asyncio, os, re, sys, uuid
import aiohttp
import pyotp

HOST, ADMIN = sys.argv[1], sys.argv[2]
P = re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', open(os.path.expanduser("~/.bashrc")).read(), re.M).group(2)
PW = "Tmp-" + uuid.uuid4().hex[:14] + "-Aa1"
PW2 = "Tmp2-" + uuid.uuid4().hex[:14] + "-Bb2"
B = f"https://{HOST}"
R = []
H = {"X-Requested-With": "portal", "Content-Type": "application/json"}


def ok(n, c, x=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{x}]" if x and not c else ""))


def jar():
    return aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))


async def post_retry(s, path, body):
    """nginx rate-limits sign-ins (429 html); back off instead of failing the run."""
    for _ in range(14):
        r = await s.post(B + path, json=body, headers=H, ssl=False)
        if r.status == 429 and r.content_type != "application/json":
            await asyncio.sleep(5); continue
        return r
    return r


async def login(s, u, p, code=None):
    r = await post_retry(s, "/portal/login", {"username": u, "password": p})
    j = await r.json()
    if r.status == 200 and j.get("mfa"):
        if code is None:
            return 200, j
        r = await post_retry(s, "/portal/login/mfa", {"token": j["token"], "code": code})
        j = await r.json()
    return r.status, j


async def ws(s, **m):
    r = await s.post(B + "/portal/ws", json=m, headers=H, ssl=False)
    return r.status, await r.json()


def err(d):
    return (d.get("error") or {}).get("code") if isinstance(d.get("error"), dict) else d.get("error")


async def main():
    users = ["e2euinst", "e2euhome", "e2euview", "e2euview2", "e2eumfa"]
    uid = {}
    try:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P); ok("admin login", st == 200 and me.get("role") == "admin", (st, me))
            st, d = await ws(adm, type="hub_mgmt/users_list")
            for u in d["result"]["users"]:
                if (u.get("username") or "").startswith("e2eu"):
                    await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("pre-clean", u["username"])

            # ---- password policy on create
            st, d = await ws(adm, type="hub_mgmt/user_create", name="E2EU Weak", username="e2euweak", password="password123", role="viewer")
            ok("create with a common password refused", not d.get("ok") and err(d) == "weak_password", d)
            st, d = await ws(adm, type="hub_mgmt/user_create", name="E2EU Same", username="e2eusame", password="e2eusame", role="viewer")
            ok("password equal to username refused", not d.get("ok") and err(d) == "weak_password", d)
            for role, u in (("installer", "e2euinst"), ("homeowner", "e2euhome"), ("viewer", "e2euview"), ("viewer", "e2euview2"), ("viewer", "e2eumfa")):
                st, d = await ws(adm, type="hub_mgmt/user_create", name="E2EU " + u, username=u, password=PW, role=role); ok(f"create {u}", d.get("ok"), d)
            st, d = await ws(adm, type="hub_mgmt/users_list"); L = {x["username"]: x for x in d["result"]["users"]}
            uid = {u: L[u]["id"] for u in users if u in L}
            ok("users_list carries mfa + last_seen", all("mfa" in x and "last_seen" in x for x in L.values()))
            # viewers have no portal access; give e2eumfa a portal role to exercise portal login
            await ws(adm, type="hub_mgmt/user_set_role", user_id=uid["e2eumfa"], role="viewer")

            # ---- own profile: installer
            async with jar() as ins:
                st, me = await login(ins, "e2euinst", PW); ok("installer login", st == 200, (st, me))
                st, d = await ws(ins, type="hub_mgmt/profile"); p = d["result"]
                ok("profile shows name/username/role/mfa/sessions", p["username"] == "e2euinst" and p["role"] == "installer" and p["mfa_available"] and p["mfa_enabled"] is False and p["sessions"] >= 1, p)
                st, d = await ws(ins, type="hub_mgmt/profile_update", name="E2EU Installer Renamed"); ok("rename self", d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/profile_update", name="<script>"); ok("rename with markup refused", not d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/profile_update", name="  "); ok("empty name refused", not d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/profile_password", current_password="wrong-wrong-1", new_password=PW2); ok("password change: wrong current refused", not d.get("ok") and err(d) == "wrong_password", d)
                st, d = await ws(ins, type="hub_mgmt/profile_password", current_password=PW, new_password="short"); ok("password change: too short refused", not d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/profile_password", current_password=PW, new_password=PW); ok("password change: same password refused", not d.get("ok"), d)
                # throttle: 4 wrong already counted? do remaining wrongs
                for _ in range(5):
                    st, d = await ws(ins, type="hub_mgmt/profile_password", current_password="wrong-wrong-2", new_password=PW2)
                ok("repeated wrong current password is throttled", not d.get("ok") and err(d) == "throttled", d)
                st, d = await ws(ins, type="hub_mgmt/profile_password", current_password=PW, new_password=PW2); ok("throttle also blocks the right password for now", not d.get("ok") and err(d) == "throttled", d)
                # this account is now locked for 5 min; use a second account for the happy path below
                st, d = await ws(ins, type="hub_mgmt/users_list"); ok("installer cannot list users", not d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/user_detail", user_id=uid["e2euview"]); ok("installer cannot open user_detail", not d.get("ok"), d)
                st, d = await ws(ins, type="hub_mgmt/user_set_active", user_id=uid["e2euview"], active=False); ok("installer cannot disable users", not d.get("ok"), d)

            # ---- happy path password change + other sessions signed out (user e2euview2 gets homeowner-less portal role? use homeowner acct)
            async with jar() as a, jar() as b:
                st, _ = await login(a, "e2euhome", PW); st2, _ = await login(b, "e2euhome", PW); ok("homeowner: two sessions", st == 200 and st2 == 200)
                st, d = await ws(a, type="hub_mgmt/my_sessions"); ses = d["result"]["sessions"]
                ok("my_sessions lists both, one marked current", len(ses) >= 2 and sum(1 for x in ses if x["current"]) == 1, ses)
                other = next(x for x in ses if not x["current"])
                st, d = await ws(a, type="hub_mgmt/my_session_revoke", session_id=[x for x in ses if x["current"]][0]["id"]); ok("cannot revoke current session this way", not d.get("ok"), d)
                st, d = await ws(a, type="hub_mgmt/my_session_revoke", session_id="nope"); ok("revoke unknown session -> not_found", not d.get("ok") and err(d) == "not_found", d)
                st, d = await ws(a, type="hub_mgmt/profile_password", current_password=PW, new_password=PW2)
                ok("homeowner: password changed", d.get("ok"), d)
                ok("...and reports other sessions signed out", d.get("ok") and d["result"]["signed_out"] >= 1, d)
                await asyncio.sleep(1)
                st, d = await ws(a, type="hub_mgmt/whoami"); ok("...this session still works", d.get("ok"), d)
            async with jar() as c:
                st, me = await login(c, "e2euhome", PW); ok("old password no longer works", st == 401, (st, me))
                st, me = await login(c, "e2euhome", PW2); ok("new password works", st == 200, (st, me))

            # ---- homeowner managing others
            async with jar() as hm:
                await login(hm, "e2euhome", PW2)
                st, d = await ws(hm, type="hub_mgmt/user_detail", user_id=uid["e2euview"]); ok("homeowner: viewer user_detail manageable", d.get("ok") and d["result"]["manageable"] and "sessions" in d["result"], d)
                st, d = await ws(hm, type="hub_mgmt/user_detail", user_id=uid["e2euinst"]); ok("homeowner: installer detail visible but NOT manageable", d.get("ok") and not d["result"]["manageable"] and d["result"]["sessions"] == [], d)
                st, d = await ws(hm, type="hub_mgmt/user_set_active", user_id=uid["e2euinst"], active=False); ok("homeowner cannot disable an installer", not d.get("ok") and err(d) == "forbidden", d)
                st, d = await ws(hm, type="hub_mgmt/user_rename", user_id=uid["e2euinst"], name="Hacked"); ok("homeowner cannot rename an installer", not d.get("ok"), d)
                st, d = await ws(hm, type="hub_mgmt/user_set_active", user_id=uid["e2euhome"], active=False); ok("nobody can disable themselves", not d.get("ok") and err(d) == "forbidden", d)
                st, d = await ws(hm, type="hub_mgmt/user_signout", user_id=uid["e2euhome"]); ok("no self sign-out through manage commands", not d.get("ok"), d)
                st, d = await ws(adm, type="hub_mgmt/users_list"); adm_id = next(x["id"] for x in d["result"]["users"] if x["username"] == ADMIN) if any(x["username"] == ADMIN for x in d["result"]["users"]) else None
                if adm_id:
                    st, d = await ws(hm, type="hub_mgmt/user_set_active", user_id=adm_id, active=False); ok("homeowner cannot disable an administrator", not d.get("ok"), d)
                st, d = await ws(hm, type="hub_mgmt/user_rename", user_id=uid["e2euview"], name="E2EU Viewer Renamed"); ok("homeowner renames a viewer", d.get("ok"), d)
                st, d = await ws(hm, type="hub_mgmt/user_password", user_id=uid["e2euview"], password="password123"); ok("reset to a common password refused", not d.get("ok") and err(d) == "weak_password", d)
                st, d = await ws(hm, type="hub_mgmt/user_detail", user_id="nope"); ok("unknown user -> not_found", not d.get("ok") and err(d) == "not_found", d)

            # ---- disabling signs the user out immediately (use admin to disable a homeowner-session holder)
            async with jar() as victim:
                await login(victim, "e2euhome", PW2)
                st, d = await ws(victim, type="hub_mgmt/whoami"); ok("victim session works before disable", d.get("ok"))
                st, d = await ws(adm, type="hub_mgmt/user_set_active", user_id=uid["e2euhome"], active=False); ok("admin disables homeowner", d.get("ok"), d)
                await asyncio.sleep(1.5)
                st, d = await ws(victim, type="hub_mgmt/whoami"); ok("disabled user's live session is dead", st in (401, 403) or not d.get("ok"), (st, d))
                async with jar() as c:
                    st, me = await login(c, "e2euhome", PW2); ok("disabled user cannot sign in", st != 200, (st, me))
                st, d = await ws(adm, type="hub_mgmt/user_set_active", user_id=uid["e2euhome"], active=True); ok("admin re-enables", d.get("ok"), d)
                async with jar() as c:
                    st, me = await login(c, "e2euhome", PW2); ok("re-enabled user can sign in again", st == 200, (st, me))

            # ---- two-step sign-in, full flow through the portal login
            # e2eumfa is a plain viewer (no portal access) so promote to homeowner for the portal tests
            st, d = await ws(adm, type="hub_mgmt/user_set_role", user_id=uid["e2eumfa"], role="homeowner"); ok("promote e2eumfa to homeowner (portal access)", d.get("ok"), d)
            async with jar() as m:
                st, me = await login(m, "e2eumfa", PW); ok("mfa user: password-only login works before 2FA", st == 200 and me.get("ok"), (st, me))
                st, d = await ws(m, type="hub_mgmt/mfa_start", current_password="nope-nope-1"); ok("mfa_start: wrong password refused", not d.get("ok") and err(d) == "wrong_password", d)
                st, d = await ws(m, type="hub_mgmt/mfa_confirm", code="123456"); ok("mfa_confirm without start -> expired", not d.get("ok") and err(d) == "expired", d)
                st, d = await ws(m, type="hub_mgmt/mfa_start", current_password=PW); ok("mfa_start returns secret + QR", d.get("ok") and len(d["result"]["secret"]) >= 16 and (d["result"]["qr_svg"] or "").startswith("<svg"), str(d)[:200])
                sec = d["result"]["secret"]; tot = pyotp.TOTP(sec)
                ok("QR svg has no script", "<script" not in (d["result"]["qr_svg"] or "").lower())
                st, d = await ws(m, type="hub_mgmt/mfa_confirm", code="000000" if tot.now() != "000000" else "111111"); ok("mfa_confirm: wrong code refused", not d.get("ok") and err(d) == "wrong_code", d)
                st, d = await ws(m, type="hub_mgmt/mfa_confirm", code="12ab"); ok("mfa_confirm: malformed code refused", not d.get("ok"), d)
                st, d = await ws(m, type="hub_mgmt/mfa_confirm", code=tot.now()); ok("mfa_confirm: right code turns 2-step on", d.get("ok"), d)
                st, d = await ws(m, type="hub_mgmt/profile"); ok("profile reports mfa_enabled", d["result"]["mfa_enabled"] is True, d)
                st, d = await ws(m, type="hub_mgmt/mfa_start", current_password=PW); ok("mfa_start again refused (already on)", not d.get("ok") and err(d) == "already", d)
            # sign-in now needs the code
            async with jar() as c:
                st, j = await login(c, "e2eumfa", PW); ok("login step 1 asks for a code", st == 200 and j.get("mfa") and j.get("token") and not j.get("ok"), (st, j))
                tok = j.get("token")
                st, d = await ws(c, type="hub_mgmt/whoami"); ok("no session after step 1 only", st == 401, (st, d))
                r = await post_retry(c, "/portal/login/mfa", {"token": tok, "code": "abcdef"}); ok("step 2: malformed code -> 400", r.status == 400, r.status)
                r = await post_retry(c, "/portal/login/mfa", {"token": tok, "code": "000000" if tot.now() != "000000" else "111111"}); ok("step 2: wrong code -> 401", r.status == 401, r.status)
                r = await post_retry(c, "/portal/login/mfa", {"token": "bogus", "code": tot.now()}); j = await r.json(); ok("step 2: unknown token -> 401 restart", r.status == 401 and j.get("restart"), (r.status, j))
                for _ in range(14):
                    r = await c.post(B + "/portal/login/mfa", json={"token": tok, "code": tot.now()}, ssl=False)
                    if r.status != 429:
                        break
                    await asyncio.sleep(5)
                ok("step 2 needs the CSRF header", r.status in (400, 403), r.status)
                r = await post_retry(c, "/portal/login/mfa", {"token": tok, "code": tot.now()}); j = await r.json()
                ok("step 2: right code signs in", r.status == 200 and j.get("ok") and j.get("role") == "homeowner", (r.status, j))
                st, d = await ws(c, type="hub_mgmt/whoami"); ok("session works after step 2", d.get("ok"), d)
                # a used code token cannot be replayed
                r = await post_retry(c, "/portal/login/mfa", {"token": tok, "code": tot.now()}); ok("step-2 token is single use", r.status == 401, r.status)
                # profile password change needs current pw even with 2FA; disable 2FA
                st, d = await ws(c, type="hub_mgmt/mfa_disable", current_password="nope-nope-1"); ok("mfa_disable: wrong password refused", not d.get("ok") and err(d) == "wrong_password", d)
            # admin can reset someone's 2FA
            st, d = await ws(adm, type="hub_mgmt/users_list"); ok("users_list shows mfa on", next(x for x in d["result"]["users"] if x["username"] == "e2eumfa")["mfa"] is True)
            st, d = await ws(adm, type="hub_mgmt/user_mfa_reset", user_id=uid["e2euview"]); ok("mfa_reset on a user without 2FA -> not_on", not d.get("ok") and err(d) == "not_on", d)
            st, d = await ws(adm, type="hub_mgmt/user_mfa_reset", user_id=uid["e2eumfa"]); ok("admin resets another user's 2-step", d.get("ok"), d)
            async with jar() as c:
                st, j = await login(c, "e2eumfa", PW); ok("after reset: password-only login again", st == 200 and j.get("ok") and not j.get("mfa"), (st, j))
                st, d = await ws(c, type="hub_mgmt/mfa_start", current_password=PW)
                tot2 = pyotp.TOTP(d["result"]["secret"]); await ws(c, type="hub_mgmt/mfa_confirm", code=tot2.now())
                st, d = await ws(c, type="hub_mgmt/mfa_disable", current_password=PW); ok("user turns 2-step off with password", d.get("ok"), d)
                st, d = await ws(c, type="hub_mgmt/profile"); ok("profile reports mfa off", d["result"]["mfa_enabled"] is False, d)

            # ---- admin sign-out / session revoke of another user
            async with jar() as s1:
                await login(s1, "e2eumfa", PW)
                st, d = await ws(adm, type="hub_mgmt/user_detail", user_id=uid["e2eumfa"]); ses = d["result"]["sessions"]
                ok("admin sees the user's sessions", len(ses) >= 1, d)
                newest = max(ses, key=lambda x: x["last_used"] or x["created"] or "")
                st, d = await ws(adm, type="hub_mgmt/user_session_revoke", user_id=uid["e2eumfa"], session_id=newest["id"]); ok("admin revokes one session", d.get("ok"), d)
                await asyncio.sleep(1)
                st, d = await ws(s1, type="hub_mgmt/whoami"); ok("revoked session is dead", st in (401, 403) or not d.get("ok"), (st, d))
            async with jar() as s2:
                await login(s2, "e2eumfa", PW)
                st, d = await ws(adm, type="hub_mgmt/user_signout", user_id=uid["e2eumfa"]); ok("admin signs a user out everywhere", d.get("ok"), d)
                await asyncio.sleep(1)
                st, d = await ws(s2, type="hub_mgmt/whoami"); ok("...their session is dead", st in (401, 403) or not d.get("ok"), (st, d))

            # ---- admin password reset signs the user out
            async with jar() as s3:
                await login(s3, "e2eumfa", PW)
                st, d = await ws(adm, type="hub_mgmt/user_password", user_id=uid["e2eumfa"], password=PW2); ok("admin resets password", d.get("ok"), d)
                await asyncio.sleep(1)
                st, d = await ws(s3, type="hub_mgmt/whoami"); ok("password reset signs the user out", st in (401, 403) or not d.get("ok"), (st, d))

            # ---- anon + csrf
            async with aiohttp.ClientSession() as anon:
                r = await anon.post(B + "/portal/ws", json={"type": "hub_mgmt/profile"}, headers=H, ssl=False); ok("anon profile blocked", r.status == 401, r.status)
            r = await adm.post(B + "/portal/ws", json={"type": "hub_mgmt/profile"}, ssl=False); ok("CSRF header required", r.status in (400, 403), r.status)

            # ---- audit
            st, d = await ws(adm, type="sentinel_link/audit"); blob = str(d.get("result"))
            ok("audit records account actions", all(k in blob for k in ("profile_password", "mfa_enabled", "user_disable", "user_signout")), blob[:200])
            ok("audit has no passwords/codes/secrets", PW not in blob and PW2 not in blob and P not in blob and sec not in blob)
    finally:
        async with jar() as adm:
            st, me = await login(adm, ADMIN, P)
            if st == 200:
                st, d = await ws(adm, type="hub_mgmt/users_list")
                for u in d["result"]["users"]:
                    if (u.get("username") or "").startswith("e2eu"):
                        st, d2 = await ws(adm, type="hub_mgmt/user_remove", user_id=u["id"]); print("cleanup", u["username"], d2.get("ok"))
                st, d = await ws(adm, type="hub_mgmt/users_list")
                left = [u["username"] for u in d["result"]["users"] if (u.get("username") or "").startswith("e2eu")]
                ok("cleanup left no test users", not left, left)
    print(f"\n{sum(R)}/{len(R)} passed")
    sys.exit(0 if all(R) else 1)

asyncio.run(main())
