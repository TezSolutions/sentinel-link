#!/usr/bin/env python3
"""
vigi_alarm.py - Standalone control of TP-Link VIGI C340-W "Active Defence - Sound Alarm".

Logs into the camera using TP-Link's VIGI/Tapo encrypted login handshake (md5 passwdType,
encrypt_type "2": RSA-encrypted "MD5(salt:password):nonce"), obtains a session 'stok' token,
then reads/sets the sound_alarm_enabled flag via /stok=<TOKEN>/ds.

Pure stdlib + 'requests'. No browser. RSA PKCS#1 v1.5 is implemented locally so pycryptodome
is NOT required.

Usage:
    python3 vigi_alarm.py status
    python3 vigi_alarm.py enable
    python3 vigi_alarm.py disable
"""
import os
import sys
import json
import hashlib
import secrets
import base64
import urllib.parse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore

# ---------------------------------------------------------------------------
# Configuration (overridable via env vars)
# ---------------------------------------------------------------------------
VIGI_HOST = os.environ.get("VIGI_HOST", "192.168.0.107")
VIGI_USER = os.environ.get("VIGI_USER", "admin")
VIGI_PASS = os.environ.get("VIGI_PASS", "TezCam$1089")

# Hardcoded MD5 salt prefix from the firmware JS bundle:
#   Hoe = e => MD5("TPCQ75NF2Y:" + e).hex().upper()
MD5_SALT_PREFIX = "TPCQ75NF2Y:"

BASE_URL = f"https://{VIGI_HOST}"
TIMEOUT = 15


# ---------------------------------------------------------------------------
# Minimal ASN.1 / DER parsing for an RSA SubjectPublicKeyInfo
# ---------------------------------------------------------------------------
def _read_len(data, idx):
    """Read a DER length field. Returns (length, new_index)."""
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    num_bytes = first & 0x7F
    length = int.from_bytes(data[idx:idx + num_bytes], "big")
    return length, idx + num_bytes


def _read_tlv(data, idx):
    """Read a TLV. Returns (tag, value_bytes, new_index)."""
    tag = data[idx]
    idx += 1
    length, idx = _read_len(data, idx)
    value = data[idx:idx + length]
    return tag, value, idx + length


def parse_rsa_public_key(der_bytes):
    """
    Parse a DER-encoded SubjectPublicKeyInfo (X.509) RSA public key.
    Returns (n, e) as integers.
    """
    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    tag, spki, _ = _read_tlv(der_bytes, 0)
    assert tag == 0x30, "expected outer SEQUENCE"
    # algorithm AlgorithmIdentifier (SEQUENCE) - skip
    tag, _alg, idx = _read_tlv(spki, 0)
    assert tag == 0x30, "expected algorithm SEQUENCE"
    # subjectPublicKey BIT STRING
    tag, bitstr, _ = _read_tlv(spki, idx)
    assert tag == 0x03, "expected BIT STRING"
    # First byte of BIT STRING is the number of unused bits (0)
    rsa_pub_der = bitstr[1:]
    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    tag, rsaseq, _ = _read_tlv(rsa_pub_der, 0)
    assert tag == 0x30, "expected RSAPublicKey SEQUENCE"
    tag, n_bytes, idx = _read_tlv(rsaseq, 0)
    assert tag == 0x02, "expected modulus INTEGER"
    tag, e_bytes, _ = _read_tlv(rsaseq, idx)
    assert tag == 0x02, "expected exponent INTEGER"
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    return n, e


def rsa_encrypt_pkcs1v15(message_bytes, n, e):
    """
    RSAES-PKCS1-v1_5 encryption (RFC 8017, section 7.2.1).
    Returns the ciphertext bytes (length == modulus size).
    """
    k = (n.bit_length() + 7) // 8
    m_len = len(message_bytes)
    if m_len > k - 11:
        raise ValueError("message too long for RSA modulus")
    # EM = 0x00 || 0x02 || PS || 0x00 || M  ; PS = >=8 non-zero random bytes
    ps_len = k - m_len - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    em = b"\x00\x02" + bytes(ps) + b"\x00" + message_bytes
    m_int = int.from_bytes(em, "big")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(k, "big")


# ---------------------------------------------------------------------------
# Login handshake
# ---------------------------------------------------------------------------
def _md5_password(password):
    """Hoe = MD5('TPCQ75NF2Y:' + password).hex().upper()"""
    return hashlib.md5((MD5_SALT_PREFIX + password).encode("utf-8")).hexdigest().upper()


def _build_encrypted_password(md5_pwd, nonce, pubkey_der):
    """
    xoe(): message = md5_pwd + ':' + nonce, RSA-encrypt (PKCS#1 v1.5), base64.
    Retry until base64 length % 64 == 0 (matches the firmware's loop).
    """
    n, e = parse_rsa_public_key(pubkey_der)
    message = (md5_pwd + ":" + nonce).encode("utf-8")
    b64 = ""
    for _ in range(50):
        cipher = rsa_encrypt_pkcs1v15(message, n, e)
        b64 = base64.b64encode(cipher).decode("ascii")
        if len(b64) % 64 == 0:
            return b64
    return b64  # fall back to last attempt


def login(session):
    """Perform the full handshake, return the (decoded) stok token string."""
    # Step 1: anonymous "do" login to obtain nonce + RSA key + passwdType.
    step1_body = {
        "method": "do",
        "login": {"username": VIGI_USER, "password": VIGI_PASS},
    }
    r = session.post(BASE_URL + "/", json=step1_body, verify=False, timeout=TIMEOUT)
    data = r.json()
    auth = data.get("data", {})
    if "nonce" not in auth or "key" not in auth:
        # Already got a token directly? (some firmwares)
        if "stok" in data:
            return urllib.parse.unquote(data["stok"])
        raise RuntimeError(f"Unexpected step-1 response: {data}")

    encrypt_type = auth.get("encrypt_type", ["1"])
    passwd_type = auth.get("passwdType", "md5")
    nonce = auth.get("nonce", "")
    key = auth.get("key")
    key_2 = auth.get("key_2")

    # l = key_2 ?? key ; keyType "1" when key_2 used
    use_key = key_2 if key_2 else key
    key_type = "1" if key_2 else None
    pubkey_der = base64.b64decode(urllib.parse.unquote(use_key))

    # Pick highest encrypt_type (firmware sorts descending and takes [0]).
    d = sorted(encrypt_type, key=lambda x: int(x), reverse=True)[0] if encrypt_type else "1"

    if passwd_type == "md5":
        md5_pwd = _md5_password(VIGI_PASS)
    else:
        raise RuntimeError(f"Unsupported passwdType: {passwd_type}")

    enc_pwd_b64 = _build_encrypted_password(md5_pwd, nonce, pubkey_der)

    login_obj = {
        "encrypt_type": d,
        "passwdType": passwd_type,
        "password": urllib.parse.quote(enc_pwd_b64, safe=""),
        "username": VIGI_USER,
    }
    if key_type:
        login_obj["keyType"] = key_type

    step2_body = {"method": "do", "login": login_obj}
    r2 = session.post(BASE_URL + "/", json=step2_body, verify=False, timeout=TIMEOUT)
    data2 = r2.json()
    if data2.get("error_code") == 0 and "stok" in data2:
        return urllib.parse.unquote(data2["stok"])
    raise RuntimeError(f"Login failed (step 2): {data2}")


# ---------------------------------------------------------------------------
# Control API
# ---------------------------------------------------------------------------
def _ds_url(stok):
    # The stok may contain special chars like ')'; embed raw (no URL-encoding,
    # matching the firmware which uses decodeURIComponent(stok) verbatim).
    return f"{BASE_URL}/stok={stok}/ds"


def get_sound_alarm(session, stok):
    body = {"method": "get", "msg_alarm": {"name": "chn1_msg_alarm_info"}}
    r = session.post(_ds_url(stok), json=body, verify=False, timeout=TIMEOUT)
    data = r.json()
    if data.get("error_code") != 0:
        raise RuntimeError(f"get failed: {data}")
    info = data.get("msg_alarm", {}).get("chn1_msg_alarm_info", {})
    # Some firmwares wrap it in a list.
    if isinstance(info, list):
        info = info[0] if info else {}
    return info.get("sound_alarm_enabled")


def set_sound_alarm(session, stok, state):
    assert state in ("on", "off")
    body = {
        "method": "set",
        "msg_alarm": {"chn1_msg_alarm_info": {"sound_alarm_enabled": state}},
    }
    r = session.post(_ds_url(stok), json=body, verify=False, timeout=TIMEOUT)
    data = r.json()
    if data.get("error_code") != 0:
        raise RuntimeError(f"set failed: {data}")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("status", "enable", "disable"):
        print("Usage: python3 vigi_alarm.py {status|enable|disable}", file=sys.stderr)
        sys.exit(2)

    action = sys.argv[1]
    session = requests.Session()

    try:
        stok = login(session)
    except Exception as exc:
        print(f"ERROR: login failed: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        if action == "status":
            state = get_sound_alarm(session, stok)
            print(f"sound_alarm_enabled: {state}")
        elif action == "enable":
            set_sound_alarm(session, stok, "on")
            state = get_sound_alarm(session, stok)
            print(f"Sound Alarm ENABLED. sound_alarm_enabled: {state}")
        elif action == "disable":
            set_sound_alarm(session, stok, "off")
            state = get_sound_alarm(session, stok)
            print(f"Sound Alarm DISABLED. sound_alarm_enabled: {state}")
    except Exception as exc:
        print(f"ERROR: {action} failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
