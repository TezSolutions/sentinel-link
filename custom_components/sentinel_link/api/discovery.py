"""LAN discovery (mDNS/DNS-SD) for the Sentinel Link API.

The helpers at the top are pure (no hub imports) so they can be unit-tested; the coroutines at the
bottom import the hub's shared zeroconf lazily. Registration is best effort and never raises.
"""
from __future__ import annotations

import logging
import re
import socket
from typing import Any

_LOGGER = logging.getLogger(__name__)

SERVICE_TYPE = "_sentinel._tcp.local."
SERVICE_TYPE_SHORT = "_sentinel._tcp"
PORT = 443
API_PATH = "/api/sentinel_link/v1"
PREFIX = "sentinel-"
MAX_ID_LEN = 20
TXT_KEYS = ("api", "ver", "id", "proto")
BANNED_WORDS = ("home assistant", "homeassistant", "frigate")
_DATA_KEY = "sentinel_link_api_discovery"


def node_id_from_hostname(hostname: str | None) -> str:
    """'sentinel-fedeyn' -> 'fedeyn'; no prefix -> whole name; lower-case, [a-z0-9-], max 20 chars."""
    h = (hostname or "").strip().lower().split(".")[0]
    if h.startswith(PREFIX) and len(h) > len(PREFIX):
        h = h[len(PREFIX):]
    h = re.sub(r"[^a-z0-9-]", "", h).strip("-")[:MAX_ID_LEN].strip("-")
    return h or "node"


def instance_name(node_id: str) -> str:
    return f"Sentinel {node_id}"


def service_name(node_id: str) -> str:
    return f"{instance_name(node_id)}.{SERVICE_TYPE}"


def server_name(hostname: str | None) -> str:
    h = re.sub(r"[^a-z0-9-]", "", (hostname or "").strip().lower().split(".")[0]).strip("-")[:63]
    return f"{h or 'sentinel'}.local."


def build_txt(node_id: str, version: str) -> dict[str, str]:
    return {"api": API_PATH, "ver": str(version), "id": node_id, "proto": "https"}


def validate_txt(txt: dict[str, str]) -> list[str]:
    """Return a list of problems (empty = fine)."""
    problems: list[str] = []
    if set(txt) != set(TXT_KEYS):
        problems.append(f"keys must be exactly {TXT_KEYS}")
    for k, v in txt.items():
        if not isinstance(v, str):
            problems.append(f"{k}: not a string")
            continue
        if len(k) + len(v) + 1 > 255:
            problems.append(f"{k}: too long")
        low = v.lower()
        for w in BANNED_WORDS:
            if w in low:
                problems.append(f"{k}: banned word {w!r}")
        if re.search(r"token|secret|password", k.lower() + low):
            problems.append(f"{k}: looks like a secret")
    return problems


async def async_register(hass: Any, version: str, hostname: str | None = None) -> bool:
    """Advertise the API on the LAN. Returns True when registered. Never raises."""
    try:
        if hass.data.get(_DATA_KEY):
            return True
        from homeassistant.components import network, zeroconf
        from zeroconf.asyncio import AsyncServiceInfo

        host = hostname if hostname is not None else socket.gethostname()
        nid = node_id_from_hostname(host)
        txt = build_txt(nid, version)
        bad = validate_txt(txt)
        if bad:
            _LOGGER.warning("Sentinel Link discovery not advertised: %s", "; ".join(bad))
            return False
        addrs = await network.async_get_announce_addresses(hass)
        info = AsyncServiceInfo(SERVICE_TYPE, service_name(nid), server=server_name(host),
                                parsed_addresses=addrs, port=PORT, properties=txt)
        aiozc = await zeroconf.async_get_async_instance(hass)
        await aiozc.async_register_service(info, allow_name_change=True)
        hass.data[_DATA_KEY] = (aiozc, info)
        _LOGGER.info("Sentinel Link discovery advertised as %s on port %s", instance_name(nid), PORT)
        return True
    except Exception as exc:  # noqa: BLE001 - discovery must never stop the API
        _LOGGER.warning("Sentinel Link discovery could not be advertised: %s", exc)
        return False


async def async_unregister(hass: Any) -> None:
    """Withdraw the advertisement (no-op when not registered). Never raises."""
    rec = hass.data.pop(_DATA_KEY, None)
    if not rec:
        return
    aiozc, info = rec
    try:
        await aiozc.async_unregister_service(info)
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("Sentinel Link discovery could not be withdrawn: %s", exc)
