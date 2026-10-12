#!/usr/bin/env python3
"""E2E: cloud channel (Part B) against a MOCK cloud platform.

usage: e2e_cloud.py <node> <admin-user> [http|https]

The mock runs here and is reached from the node through an SSH reverse tunnel (127.0.0.1 on the node), so nothing is opened on the node and the
node's real cloud settings are never involved.  The test skips if the node is already paired.  Safety: only a virtual entity is used,
the throwaway user is removed, the pairing is always removed again in `finally`.
"""
import asyncio, json, os, re, secrets, subprocess, sys, time, uuid
import aiohttp
from aiohttp import web
sys.path.insert(0, os.path.dirname(__file__))

HOST, ADMIN = sys.argv[1], sys.argv[2]
SCHEME = sys.argv[3] if len(sys.argv) > 3 else "http"
txt = open(os.path.expanduser("~/.bashrc")).read()
APASS = os.environ.get("HA_UI_PASS") or re.search(r'^\s*export\s+HA_UI_PASS=(["\']?)(.*?)\1\s*$', txt, re.M).group(2)
TPASS = "Tmp-" + uuid.uuid4().hex[:14]
BASE = f"{SCHEME}://{HOST}"
HUB = f"http://{HOST}:8123"
API = BASE + "/api/sentinel_link/v1"
CID, REDIR = "com.sentinel.e2ecloud", "com.sentinel.e2ecloud://callback"
R = []
_VID = uuid.uuid4().hex[:8]
VLIGHT = f"light.e2e_cloud_{_VID}"
PORT = 20000 + int(uuid.uuid4().hex[:4], 16) % 20000
EP = f"http://127.0.0.1:{PORT}"
SSH = ["ssh", "-i", os.path.expanduser("~/.ssh/id_sentinel"), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ExitOnForwardFailure=yes",
       "-o", "ConnectTimeout=10", "-N", "-R", f"127.0.0.1:{PORT}:127.0.0.1:{PORT}", f"tez-admin@{HOST}"]


def ok(name, cond, extra=""):
    R.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{str(extra)[:300]}]" if extra and not cond else ""))


# ------------------------------------------------------------------ the mock cloud platform
class Mock:
    def __init__(self):
        self.codes = {}                  # code -> dict(valid)
        self.secret = "ns_" + secrets.token_urlsafe(30)
        self.cloud_node_id = "cn_" + uuid.uuid4().hex[:10]
        self.channel_override = None
        self.ws = None
        self.frames = []                 # frames received from the node
        self.connects = 0
        self.headers = {}
        self.unenroll_auth = None
        self.waiters = {}
        self.runner = None

    async def enroll(self, req):
        b = await req.json()
        if self.codes.pop(b.get("code"), None) is None:
            return web.json_response({"error": "bad code"}, status=403)
        self.enroll_body = b
        return web.json_response({"cloud_node_id": self.cloud_node_id, "node_secret": self.secret, "heartbeat_s": 10,
                                  "channel_url": self.channel_override or f"ws://127.0.0.1:{PORT}/channel"})

    async def unenroll(self, req):
        self.unenroll_auth = req.headers.get("Authorization")
        return web.json_response({"ok": True})

    async def channel(self, req):
        self.headers = dict(req.headers)
        if req.headers.get("Authorization") != "Bearer " + self.secret:
            return web.Response(status=401)
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=4 * 1024 * 1024)
        await ws.prepare(req)
        self.ws = ws
        self.connects += 1
        async for m in ws:
            if m.type == aiohttp.WSMsgType.TEXT:
                f = json.loads(m.data)
                self.frames.append(f)
                if f.get("id") in self.waiters:
                    self.waiters[f["id"]].set_result(f)
        self.ws = None
        return ws

    async def start(self):
        app = web.Application()
        app.add_routes([web.post("/v1/nodes/enroll", self.enroll), web.post("/v1/nodes/{id}/unenroll", self.unenroll), web.get("/channel", self.channel)])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", PORT).start()

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()

    def new_code(self):
        c = "PAIR-" + secrets.token_hex(6)
        self.codes[c] = True
        return c

    async def ask(self, typ, timeout=15, **kw):
        rid = uuid.uuid4().hex[:10]
        fut = asyncio.get_running_loop().create_future()
        self.waiters[rid] = fut
        await self.ws.send_str(json.dumps({"type": typ, "id": rid, **kw}))
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self.waiters.pop(rid, None)

    async def req(self, method, path, body=None, by="mock-user"):
        f = await self.ask("request", method=method, path=path, **({"body": body} if body is not None else {}), by=by)
        return (f or {}).get("status"), (f or {}).get("body"), f

    def of(self, typ):
        return [f for f in self.frames if f.get("type") == typ]


async def until(fn, secs=20, step=0.5):
    t = time.time()
    while time.time() - t < secs:
        v = fn() if not asyncio.iscoroutinefunction(fn) else await fn()
        if v:
            return v
        await asyncio.sleep(step)
    return None


# ------------------------------------------------------------------ Link / hub helpers
import base64, hashlib
from urllib.parse import urlparse, parse_qs


def pkce():
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


async def hub_token(s, user, pw):
    hc = HUB + "/"
    r = await s.post(HUB + "/auth/login_flow", json={"client_id": hc, "handler": ["homeassistant", None], "redirect_uri": hc + "?auth_callback=1"})
    fid = (await r.json())["flow_id"]
    r = await s.post(f"{HUB}/auth/login_flow/{fid}", json={"username": user, "password": pw, "client_id": hc})
    j = await r.json()
    if j.get("type") != "create_entry":
        return None
    r = await s.post(HUB + "/auth/token", data={"grant_type": "authorization_code", "code": j["result"], "client_id": hc})
    return (await r.json()).get("access_token")


async def link_token(s, user, pw):
    await asyncio.sleep(0.6)
    v, ch = pkce()
    f = {"client_id": CID, "redirect_uri": REDIR, "state": "st-1", "code_challenge": ch, "code_challenge_method": "S256", "response_type": "code"}
    r = await s.post(API + "/auth/authorize", data={**f, "username": user, "password": pw}, allow_redirects=False, ssl=False)
    code = (parse_qs(urlparse(r.headers.get("Location", "")).query).get("code") or [None])[0]
    if not code:
        return None
    r = await s.post(API + "/auth/token", data={"grant_type": "authorization_code", "code": code, "client_id": CID, "redirect_uri": REDIR, "code_verifier": v}, ssl=False)
    return (await r.json()).get("access_token") if r.status == 200 else None


class WS:
    def __init__(self, s, tok): self.s, self.tok, self.i = s, tok, 0
    async def __aenter__(self):
        self.ws = await self.s.ws_connect(HUB.replace("http", "ws") + "/api/websocket")
        await self.ws.receive_json()
        await self.ws.send_json({"type": "auth", "access_token": self.tok})
        assert (await self.ws.receive_json())["type"] == "auth_ok"
        return self
    async def __aexit__(self, *a): await self.ws.close()
    async def call(self, **m):
        self.i += 1; m["id"] = self.i
        await self.ws.send_json(m)
        while True:
            r = await self.ws.receive_json(timeout=30)
            if r.get("id") == self.i and r["type"] == "result":
                return r


H = lambda t: {"Authorization": "Bearer " + t}


async def main():
    mock = Mock()
    await mock.start()
    tun = subprocess.Popen(SSH, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    await asyncio.sleep(3)
    if tun.poll() is not None:
        print("SKIP cloud e2e: cannot open the SSH tunnel to the node:", tun.stderr.read().decode()[:200])
        await mock.stop()
        return
    created_user = None
    hub_admin = None
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:
        try:
            hub_admin = await hub_token(s, ADMIN, APASS)
            ok("admin hub login (management)", hub_admin)
            if not hub_admin:
                return
            async with WS(s, hub_admin) as a:
                me = await a.call(type="auth/current_user")
                uid = me["result"]["id"]
                r = await a.call(type="sentinel_link/client_save", client_id=CID, name="E2E cloud test app", redirect_uris=[REDIR])
                ok("register OAuth app", r["success"], r.get("error"))
                r = await a.call(type="sentinel_link/token_create", user_id=uid, name="e2e cloud full", scopes=["cloud:manage", "users:write", "users:password"])
                ok("admin token with cloud:manage", r["success"], r.get("error"))
                T = r["result"]["token"]
                r = await a.call(type="sentinel_link/token_create", user_id=uid, name="e2e cloud read")
                ok("admin token without scopes", r["success"], r.get("error"))
                T0 = r["result"]["token"]

                # --- before pairing
                st0 = await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json()
                if st0.get("enrolled"):
                    print("SKIP cloud e2e: this node is already paired with a cloud platform; not touching it")
                    return
                r = await s.put(API + "/cloud", json={"level": "full"}, headers=H(T), ssl=False)
                ok("unpaired node refuses a level change -> 400", r.status == 400, r.status)
                r = await s.put(API + "/cloud", json={"paused": True}, headers=H(T), ssl=False)
                ok("unpaired node refuses pause -> 400", r.status == 400, r.status)
                st1 = await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json()
                ok("refused changes leave nothing stored", st1["level"] == "health" and st1["paused"] is False and st1["endpoint"] is None, st1)
                ok("not paired at start", st0["enrolled"] is False and st0["level"] == "health", st0)
                r = await s.get(API + "/cloud", ssl=False)
                ok("anonymous GET /cloud -> 401", r.status == 401, r.status)
                r = await s.get(API + "/cloud", headers=H("slr_bogus.token"), ssl=False)
                ok("bad token GET /cloud -> 401", r.status == 401, r.status)

                # throwaway non-admin user must be refused
                un = "e2ecloud" + uuid.uuid4().hex[:5]
                r = await s.post(API + "/users", json={"name": "E2E cloud viewer", "username": un, "password": TPASS, "role": "user"}, headers=H(T), ssl=False)
                if r.status == 201:
                    created_user = (await r.json()).get("id") or (await r.json()).get("user", {}).get("id")
                ok("throwaway user created", r.status == 201, r.status)
                if r.status == 201:
                    ut = await link_token(s, un, TPASS)
                    ok("throwaway user signs in", ut)
                    if ut:
                        for m, path in (("GET", "/cloud"), ("PUT", "/cloud"), ("POST", "/cloud/enroll"), ("DELETE", "/cloud"), ("PUT", "/cloud/debug")):
                            rr = await s.request(m, API + path, json={}, headers=H(ut), ssl=False)
                            ok(f"non-admin {m} {path} -> 403", rr.status == 403, rr.status)

                # --- scope and validation
                r = await s.put(API + "/cloud", json={"level": "events"}, headers=H(T0), ssl=False)
                ok("PUT without cloud:manage -> 403 missing_scope", r.status == 403 and (await r.json())["error"]["code"] == "missing_scope", r.status)
                r = await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": "ABCD-EFGH-12"}, headers=H(T0), ssl=False)
                ok("enroll without scope -> 403", r.status == 403, r.status)
                for body, label in (({"endpoint": "http://example.com", "code": "ABCD-EFGH-12"}, "plain http to a remote host"),
                                    ({"endpoint": "https://169.254.169.254", "code": "ABCD-EFGH-12"}, "link-local address"),
                                    ({"endpoint": "https://u:p@x.example.com", "code": "ABCD-EFGH-12"}, "address with a password"),
                                    ({"endpoint": EP, "code": "bad code!"}, "malformed code"),
                                    ({"endpoint": EP, "code": "ABCD-EFGH-12", "level": "root"}, "unknown level"),
                                    ({"code": "ABCD-EFGH-12"}, "missing address")):
                    r = await s.post(API + "/cloud/enroll", json=body, headers=H(T), ssl=False)
                    ok(f"enroll refused: {label} -> 400", r.status == 400, (r.status, await r.text())[:120] if r.status != 400 else "")
                r = await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": "WRONG-CODE-123"}, headers=H(T), ssl=False)
                j = await r.json()
                ok("platform rejects the code -> 400 code_rejected", r.status == 400 and j["error"]["code"] == "code_rejected", (r.status, j))
                r = await s.post(API + "/cloud/enroll", json={"endpoint": f"http://127.0.0.1:{PORT + 1}", "code": "ABCD-EFGH-12"}, headers=H(T), ssl=False)
                ok("unreachable platform -> 502", r.status == 502, r.status)
                mock.channel_override = "ws://evil.example.com/channel"
                r = await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": mock.new_code()}, headers=H(T), ssl=False)
                ok("platform sends a non-local ws:// channel -> 502, not paired", r.status == 502, r.status)
                mock.channel_override = None
                ok("still not paired after failed attempts", (await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json())["enrolled"] is False)

                # virtual entity for the data checks
                rr = await s.post(f"{HUB}/api/states/{VLIGHT}", json={"state": "off", "attributes": {"supported_color_modes": ["brightness"], "friendly_name": "E2E cloud light"}}, headers=H(hub_admin))
                ok("virtual entity created", rr.status in (200, 201), rr.status)

                # --- pair
                r = await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": mock.new_code(), "name": "E2E node"}, headers=H(T), ssl=False)
                j = await r.json()
                ok("enroll -> 201", r.status == 201, (r.status, j))
                ok("status: enrolled, level health (default)", j.get("enrolled") is True and j.get("level") == "health", j)
                ok("reply never contains the node secret", mock.secret not in json.dumps(j))
                ok("code is single use", (await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": "WRONG-CODE-123"}, headers=H(T), ssl=False)).status == 409)
                ok("node announced itself to the platform", getattr(mock, "enroll_body", {}).get("node_id") and mock.enroll_body.get("node_name") == "E2E node", getattr(mock, "enroll_body", None))
                ok("channel connected (node dialled out)", await until(lambda: mock.ws is not None, 20))
                ok("channel sent the node secret and node id", mock.headers.get("Authorization") == "Bearer " + mock.secret and mock.headers.get("X-Node-Id"))
                hello = await until(lambda: (mock.of("hello") or [None])[-1], 10)
                ok("hello frame: level health", hello and hello["level"] == "health" and hello["cloud_node_id"] == mock.cloud_node_id, hello)
                hb = await until(lambda: (mock.of("heartbeat") or [None])[-1], 15)
                ok("heartbeat received with health data", hb and "entities" in hb["status"] and hb["status"]["version"], hb)
                st = await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json()
                ok("status: connected", st["connected"] is True and st["last_error"] is None, st)
                ok("status never contains secrets", mock.secret not in json.dumps(st) and "channel_url" not in st)

                # --- level: health  (nothing but the heartbeat)
                status, body, _ = await mock.req("GET", "/info")
                ok("health: GET /info -> 403 level_too_low", status == 403 and body["error"]["code"] == "level_too_low", (status, body))
                status, body, _ = await mock.req("GET", "/entities")
                ok("health: GET /entities -> 403", status == 403, status)
                n_ev = len(mock.of("event"))
                await s.post(f"{HUB}/api/states/{VLIGHT}", json={"state": "on", "attributes": {"supported_color_modes": ["brightness"], "friendly_name": "E2E cloud light"}}, headers=H(hub_admin))
                await asyncio.sleep(3)
                ok("health: no state events are sent", len(mock.of("event")) == n_ev)

                # --- level: events (read only)
                r = await s.put(API + "/cloud", json={"level": "events"}, headers=H(T), ssl=False)
                ok("admin raises the level to events", r.status == 200 and (await r.json())["level"] == "events", r.status)
                hello = await until(lambda: [f for f in mock.of("hello") if f["level"] == "events"], 10)
                ok("platform is told the new level", hello)
                status, body, _ = await mock.req("GET", "/info")
                ok("events: GET /info 200", status == 200 and body.get("api_version") == "1", (status, body))
                status, body, _ = await mock.req("GET", "/me")
                ok("events: relay is capped to viewer", status == 200 and body.get("role") == "viewer", (status, body))
                status, body, _ = await mock.req("GET", "/entities?limit=2000")
                ok("events: GET /entities lists the virtual light", status == 200 and any(e["entity_id"] == VLIGHT for e in body["entities"]), status)
                status, body, _ = await mock.req("GET", f"/entities/{VLIGHT}")
                ok("events: GET one entity", status == 200, status)
                status, body, _ = await mock.req("GET", "/devices")
                ok("events: GET /devices 200", status == 200, status)
                status, body, _ = await mock.req("POST", f"/entities/{VLIGHT}/command", {"command": "toggle"})
                ok("events: command -> 403 level_too_low", status == 403 and body["error"]["code"] == "level_too_low", (status, body))
                for m, p in (("GET", "/users"), ("POST", "/users"), ("GET", "/logins"), ("GET", "/logins/summary"), ("PUT", "/logins/settings"), ("GET", "/admin/config"),
                             ("GET", "/admin/audit"), ("GET", "/cloud"), ("PUT", "/cloud"), ("DELETE", "/cloud"), ("PUT", "/cloud/debug"), ("POST", "/cloud/enroll"),
                             ("GET", "/auth/tokens"), ("POST", "/auth/token"), ("GET", "/events"), ("GET", "/docs")):
                    status, body, _ = await mock.req(m, p, {} if m in ("POST", "PUT") else None)
                    ok(f"events: {m} {p} is not reachable from the cloud (404)", status == 404, (status, body))
                for p in ("/entities/../users", "//users", "/entities/%2e%2e/users", "/entities?x=<script>", "/entities#a"):
                    status, body, _ = await mock.req("GET", p)
                    ok(f"events: malformed path {p!r} -> 400", status == 400, (status, body))
                status, body, _ = await mock.req("TRACE", "/info")
                ok("events: unknown method refused", status in (400, 404), status)
                n_ev = len(mock.of("event"))
                for v in ("off", "on"):
                    await s.post(f"{HUB}/api/states/{VLIGHT}", json={"state": v, "attributes": {"supported_color_modes": ["brightness"], "friendly_name": "E2E cloud light"}}, headers=H(hub_admin))
                    await asyncio.sleep(1)
                evs = await until(lambda: [f for f in mock.of("event")[n_ev:] if json.dumps(f).find(VLIGHT) >= 0], 10)
                ok("events: state changes arrive as event frames", evs, len(mock.of("event")))

                # --- level: full
                r = await s.put(API + "/cloud", json={"level": "full"}, headers=H(T), ssl=False)
                ok("admin raises the level to full", r.status == 200)
                await asyncio.sleep(1.5)
                status, body, _ = await mock.req("GET", "/me")
                ok("full: relay is capped to manager (not admin)", status == 200 and body.get("role") == "manager", (status, body))
                status, body, _ = await mock.req("POST", f"/entities/{VLIGHT}/command", {"command": "toggle"})
                ok("full: command on the virtual light -> 200", status == 200, (status, body))
                status, body, _ = await mock.req("POST", f"/entities/{VLIGHT}/command", {"command": "no_such_command"})
                ok("full: invalid command still validated by the API (400/403/404)", status in (400, 403, 404, 422), (status, body))
                status, body, _ = await mock.req("GET", "/users")
                ok("full: users still not reachable", status == 404, status)

                # --- audit
                au = await (await s.get(API + "/admin/audit?limit=200", headers=H(T0), ssl=False)).json()
                rows = au.get("audit") or au.get("entries") or au.get("items") or []
                acts = [x.get("action") for x in rows]
                ok("audit: pairing and level changes recorded", "cloud.enroll" in acts and "cloud.configure" in acts, sorted(set(a for a in acts if a and a.startswith("cloud"))))
                relay = [x for x in rows if x.get("action") == "cloud.relay"]
                ok("audit: every relayed call names the cloud user", relay and any((x.get("data") or {}).get("by") == "mock-user" for x in relay), len(relay))
                ok("audit: refused calls are recorded as denied", any(x.get("result") == "denied" for x in relay))
                ok("audit: no secrets in the audit trail", mock.secret not in json.dumps(au) and T not in json.dumps(au))

                # --- remote support report
                f = await mock.ask("debug_request", by="mock-user")
                ok("support report refused without approval", f and f["type"] == "debug_denied" and f["reason"] == "approval_required", f)
                st = await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json()
                ok("status shows the pending request", st["debug"]["requested"], st["debug"])
                for bad in ({"minutes": 0}, {"minutes": 99999}, {"minutes": "60"}):
                    rr = await s.put(API + "/cloud/debug", json=bad, headers=H(T), ssl=False)
                    ok(f"approval {bad} -> 400", rr.status == 400, rr.status)
                rr = await s.put(API + "/cloud/debug", json={"minutes": 5}, headers=H(T0), ssl=False)
                ok("approval needs the scope", rr.status == 403, rr.status)
                rr = await s.put(API + "/cloud/debug", json={"minutes": 5}, headers=H(T), ssl=False)
                ok("admin approves 5 minutes", rr.status == 200 and (await rr.json())["debug"]["approved_until"], rr.status)
                f = await mock.ask("debug_request", by="mock-user", timeout=40)
                ok("support report delivered after approval", f and f["type"] == "debug_report" and "versions" in f["report"], (f or {}).get("type"))
                blob = json.dumps(f)
                ok("report holds no secrets", mock.secret not in blob and T not in blob and APASS not in blob and "slr_" not in blob and "sll_" not in blob)
                rr = await s.delete(API + "/cloud/debug", headers=H(T), ssl=False)
                f = await mock.ask("debug_request", by="mock-user")
                ok("withdrawn approval refuses again", f and f["type"] == "debug_denied", f)

                # --- connection handling
                n = mock.connects
                await mock.ws.close()
                ok("node reconnects after the platform drops it", await until(lambda: mock.connects > n and mock.ws is not None, 30), (n, mock.connects))
                n = mock.connects
                await mock.ws.send_str(json.dumps({"type": "ack", "pad": "x" * 70000}))      # larger than the node accepts
                ok("oversized frame is refused and the node recovers", await until(lambda: mock.connects > n and mock.ws is not None, 30), (n, mock.connects))
                await mock.ws.send_str("not json at all")
                await mock.ws.send_str(json.dumps({"type": "request", "id": "x", "method": "GET", "path": "/info", "by": "a" * 500}))
                await mock.ws.send_str(json.dumps({"no": "type"}))
                await asyncio.sleep(1.5)
                status, body, _ = await mock.req("GET", "/me")
                ok("junk frames are ignored, channel still works", status == 200, status)

                r = await s.put(API + "/cloud", json={"paused": True}, headers=H(T), ssl=False)
                ok("pause", r.status == 200 and (await r.json())["paused"] is True)
                ok("pause closes the channel", await until(lambda: mock.ws is None, 15))
                await asyncio.sleep(4)
                ok("paused node stays disconnected", mock.ws is None)
                r = await s.put(API + "/cloud", json={"paused": False}, headers=H(T), ssl=False)
                ok("resume reconnects", await until(lambda: mock.ws is not None, 20))
                r = await s.put(API + "/cloud", json={"endpoint": "https://other.example.com"}, headers=H(T), ssl=False)
                ok("address cannot be changed while paired -> 400", r.status == 400, r.status)
                for bad in ({"level": "root"}, {"paused": "yes"}, {"name": ""}, {"name": "x" * 61}, {"unknown": 1}):
                    r = await s.put(API + "/cloud", json=bad, headers=H(T), ssl=False)
                    ok(f"settings {bad} -> 400", r.status == 400, r.status)

                # --- the platform removes the node
                await mock.ws.send_str(json.dumps({"type": "unenroll"}))
                async def unpaired():
                    return (await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json())["enrolled"] is False
                ok("platform-initiated removal unpairs the node", await until(unpaired, 15))

                # --- pair again, then the administrator disconnects
                r = await s.post(API + "/cloud/enroll", json={"endpoint": EP, "code": mock.new_code(), "level": "events"}, headers=H(T), ssl=False)
                ok("pair again at level events", r.status == 201 and (await r.json())["level"] == "events", r.status)
                ok("channel connected again", await until(lambda: mock.ws is not None, 20))
                r = await s.delete(API + "/cloud", headers=H(T0), ssl=False)
                ok("disconnect needs the scope", r.status == 403, r.status)
                r = await s.delete(API + "/cloud", headers=H(T), ssl=False)
                j = await r.json()
                ok("admin disconnects", r.status == 200 and j["enrolled"] is False and j["connected"] is False, j)
                ok("platform is told (with the node secret)", await until(lambda: mock.unenroll_auth == "Bearer " + mock.secret, 10), mock.unenroll_auth)
                ok("channel is closed", await until(lambda: mock.ws is None, 10))
                st = await (await s.get(API + "/cloud", headers=H(T0), ssl=False)).json()
                ok("nothing of the pairing is kept", st["enrolled"] is False and st["cloud_node_id"] is None and st["level"] == "health" and st["endpoint"] is None, st)

                # --- docs
                spec = await (await s.get(API + "/openapi.json", ssl=False)).json()
                ok("OpenAPI documents /cloud, /cloud/enroll, /cloud/debug", all(f"/api/sentinel_link/v1{p}" in spec["paths"] or p in spec["paths"] for p in ("/cloud", "/cloud/enroll", "/cloud/debug")), [p for p in spec["paths"] if "cloud" in p])
                ok("OpenAPI has the Cloud schemas", {"CloudStatus", "CloudSettings", "CloudEnroll"} <= set(spec["components"]["schemas"]))
        finally:
            # always leave the node unpaired and clean
            try:
                if hub_admin:
                    async with WS(s, hub_admin) as a:
                        await a.call(type="sentinel_link/cloud_disconnect")
                        if created_user:
                            await a.call(type="hub_mgmt/user_remove", user_id=created_user)
                        toks = ((await a.call(type="sentinel_link/tokens")).get("result") or {}).get("tokens") or []
                        for t in toks:
                            if str(t.get("name", "")).startswith("e2e cloud"):
                                await a.call(type="sentinel_link/token_revoke", token_id=t["id"])
                        await a.call(type="sentinel_link/client_remove", client_id=CID)
                    await s.delete(f"{HUB}/api/states/{VLIGHT}", headers=H(hub_admin))
            except Exception as e:  # noqa: BLE001
                print("cleanup problem:", type(e).__name__, e)
            tun.terminate()
            await mock.stop()


asyncio.run(main())
bad = [n for n, c in R if not c]
print(f"\n{len(R) - len(bad)}/{len(R)} passed")
sys.exit(1 if bad else 0)
