"""Cloud MQTT TLS tests (no HA needed): verifying context, and refusal of an untrusted server with no plaintext fallback.
Run: python -m pytest tests/test_cloud_tls.py   (needs paho-mqtt, cryptography)"""
import ast, asyncio, copy, datetime, importlib, ipaddress, logging, os, socket, ssl, sys, tempfile, threading, time, types

import pytest

pytest.importorskip("paho")
x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PKG = os.path.join(os.path.dirname(__file__), "..", "custom_components", "sentinel_link")
if not os.path.isdir(PKG):  # image copy: stack/regression -> stack/HA/config
    PKG = os.path.join(os.path.dirname(__file__), "..", "HA", "config", "custom_components", "sentinel_link")
pkg = types.ModuleType("sl_under_test"); pkg.__path__ = [PKG]; sys.modules["sl_under_test"] = pkg
cc = importlib.import_module("sl_under_test.cloud_client")
const = importlib.import_module("sl_under_test.const")


def test_defaults_are_tls():
    assert const.DEFAULT_CLOUD_PORT == 8883 and const.DEFAULT_CLOUD_TLS is True


def test_context_verifies():
    ctx = cc.make_tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def _selfsigned(d, hostname="localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)] + (
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if hostname == "localhost" else [])), False)
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


class _Server:
    """TLS server with an UNTRUSTED (self-signed) cert; records handshake failures and any plaintext bytes."""
    def __init__(self, hostname="localhost", reject_auth=False):
        d = tempfile.mkdtemp(); cp, kp = _selfsigned(d, hostname)
        self.ca = cp; self.reject_auth = reject_auth
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.ctx.load_cert_chain(cp, kp)
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(5); self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]; self.failed = 0; self.ok = 0; self.run = True
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while self.run:
            try: c, _ = self.sock.accept()
            except OSError: continue
            try:
                s = self.ctx.wrap_socket(c, server_side=True); self.ok += 1
                if self.reject_auth:
                    s.settimeout(3); s.recv(4096); s.sendall(b"\x20\x02\x00\x05")
                    time.sleep(0.1)
                s.close()
            except Exception: self.failed += 1; c.close()
    def stop(self): self.run = False; self.sock.close()


def test_untrusted_cert_is_refused_without_plaintext_fallback():
    srv = _Server()
    loop = asyncio.new_event_loop(); threading.Thread(target=loop.run_forever, daemon=True).start()
    seen = []
    async def cb(c): seen.append(c)
    client = cc.SentinelCloudClient(loop=loop, node_id="t", host="127.0.0.1", port=srv.port, username="u", password="",
                                    use_tls=True, ha_version="x", on_connection_state_change=cb)
    client.start(); time.sleep(2.0); client.disconnect(); srv.stop(); loop.call_soon_threadsafe(loop.stop)
    assert client.status_text == "disconnected: TLS error"
    assert client.is_connected is False and srv.ok == 0 and srv.failed >= 1
    assert seen and seen[0] is False


def test_validator_reports_tls_error():
    srv = _Server()
    err = cc.validate_cloud_broker("127.0.0.1", srv.port, "u", "", True, timeout=5)
    srv.stop()
    assert err and err.startswith("TLS error")


def test_trusted_certificate_wrong_hostname_is_refused(monkeypatch):
    srv = _Server(hostname="wrong.example")
    ctx = ssl.create_default_context(cafile=srv.ca)
    monkeypatch.setattr(cc, "make_tls_context", lambda: ctx)
    try:
        err = cc.validate_cloud_broker("127.0.0.1", srv.port, "fixture-user", "", True, timeout=3)
        assert err and err.startswith("TLS error")
        assert "mismatch" in err.lower() and srv.ok == 0
    finally:
        srv.stop()


def test_tls_broker_authorization_refusal_remains_failure(monkeypatch):
    srv = _Server(reject_auth=True)
    ctx = ssl.create_default_context(cafile=srv.ca)
    monkeypatch.setattr(cc, "make_tls_context", lambda: ctx)
    try:
        err = cc.validate_cloud_broker("127.0.0.1", srv.port, "fixture-user", "fixture-pass", True, timeout=3)
        assert err and "authorized" in err.lower()
        assert srv.ok == 1 and srv.failed == 0
    finally:
        srv.stop()


def _migrate(data, options):
    """Exercise the real lifecycle migration without importing Home Assistant."""
    namespace = {name: value for name, value in vars(const).items() if name.isupper()}
    namespace["_LOGGER"] = logging.getLogger(__name__)
    tree = ast.parse("from __future__ import annotations\n" + open(os.path.join(PKG, "__init__.py")).read())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_upgrade_cloud_transport")
    module = ast.Module(body=[tree.body[0], function], type_ignores=[])
    exec(compile(module, "cloud_transport_migration", "exec"), namespace)
    entry = types.SimpleNamespace(data=copy.deepcopy(data), options=copy.deepcopy(options))
    updates = []
    def update(entry, **values):
        updates.append(values)
        entry.data, entry.options = values["data"], values["options"]
    hass = types.SimpleNamespace(config_entries=types.SimpleNamespace(async_update_entry=update))
    namespace["_upgrade_cloud_transport"](hass, entry)
    namespace["_upgrade_cloud_transport"](hass, entry)
    return entry, updates


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("options", [{}, {"cloud_port": 1883}, {"cloud_tls": False}, {
    "cloud_host": "mqtt.flespi.io", "cloud_port": 1883, "cloud_tls": True}])
def test_legacy_transport_migration_preserves_identity_credentials_and_options(tls, options):
    data = {"cloud_host": "mqtt.flespi.io", "cloud_port": 1883, "cloud_tls": tls,
            "node_id": "logical-node", "cloud_username": "fixture-user", "cloud_password": "fixture-pass"}
    options = {**options, "metrics_interval": 47, "cloud_username": "fixture-option-user"}
    e, updates = _migrate(data, options)
    cfg = {**e.data, **e.options}
    assert (cfg["cloud_port"], cfg["cloud_tls"]) == (8883, True)
    assert cfg["node_id"] == "logical-node" and cfg["cloud_username"] == "fixture-option-user"
    assert cfg["cloud_password"] == "fixture-pass" and cfg["metrics_interval"] == 47
    assert len(updates) == 1  # second invocation is a no-op
    for original, migrated in [(data, e.data), (options, e.options)]:
        assert {k: v for k, v in original.items() if k not in ("cloud_port", "cloud_tls")} == {
            k: v for k, v in migrated.items() if k not in ("cloud_port", "cloud_tls")}


@pytest.mark.parametrize("data,options", [
    ({"cloud_host": "mqtt.flespi.io", "cloud_port": 8883, "cloud_tls": True}, {}),
    ({"cloud_host": "broker.example", "cloud_port": 1883, "cloud_tls": True}, {}),
    ({"cloud_host": "mqtt.flespi.io", "cloud_port": 9883, "cloud_tls": True}, {}),
    ({"cloud_host": "mqtt.flespi.io", "cloud_port": 1883, "cloud_tls": False},
     {"cloud_host": "broker.example", "cloud_port": 1883, "cloud_tls": False}),
    ({"cloud_host": "mqtt.flespi.io", "cloud_port": 1883, "cloud_tls": False},
     {"cloud_port": 9883, "cloud_tls": True}),
])
def test_correct_or_explicit_nondefault_transport_is_untouched(data, options):
    e, updates = _migrate(data, options)
    assert e.data == data and e.options == options and updates == []
