"""Cloud MQTT TLS tests (no HA needed): verifying context, and refusal of an untrusted server with no plaintext fallback.
Run: python -m pytest tests/test_cloud_tls.py   (needs paho-mqtt, cryptography)"""
import asyncio, datetime, importlib, ipaddress, os, socket, ssl, sys, tempfile, threading, time, types

import pytest

pytest.importorskip("paho")
x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PKG = os.path.join(os.path.dirname(__file__), "..", "custom_components", "sentinel_link")
pkg = types.ModuleType("sl_under_test"); pkg.__path__ = [PKG]; sys.modules["sl_under_test"] = pkg
cc = importlib.import_module("sl_under_test.cloud_client")
const = importlib.import_module("sl_under_test.const")


def test_defaults_are_tls():
    assert const.DEFAULT_CLOUD_PORT == 8883 and const.DEFAULT_CLOUD_TLS is True


def test_context_verifies():
    ctx = cc.make_tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def _selfsigned(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


class _Server:
    """TLS server with an UNTRUSTED (self-signed) cert; records handshake failures and any plaintext bytes."""
    def __init__(self):
        d = tempfile.mkdtemp(); cp, kp = _selfsigned(d)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.ctx.load_cert_chain(cp, kp)
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(5); self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]; self.failed = 0; self.ok = 0; self.run = True
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while self.run:
            try: c, _ = self.sock.accept()
            except OSError: continue
            try:
                s = self.ctx.wrap_socket(c, server_side=True); self.ok += 1; s.close()
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
