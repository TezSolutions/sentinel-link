"""Pure helpers for the portal integrations commands (no hub-core imports, unit-tested)."""
from __future__ import annotations

import re
from typing import Any

# Curated catalog: only these can be added from the portal. (domain, title, group, blurb)
CATALOG: tuple[tuple[str, str, str, str], ...] = (
    ("matter", "Matter", "Smart home protocols", "Matter and Thread devices."),
    ("mqtt", "MQTT", "Smart home protocols", "Devices that talk MQTT (Zigbee2MQTT, sensors, bridges)."),
    ("zwave_js", "Z-Wave", "Smart home protocols", "Z-Wave controller."),
    ("homekit_controller", "HomeKit devices", "Smart home protocols", "Pair HomeKit accessories."),
    ("esphome", "ESPHome", "Smart home protocols", "ESP32/ESP8266 devices running ESPHome."),
    ("tuya", "Tuya", "Lights, plugs and sensors", "Tuya / Smart Life cloud account."),
    ("tplink", "TP-Link Kasa / Tapo", "Lights, plugs and sensors", "TP-Link smart plugs, bulbs and cameras."),
    ("shelly", "Shelly", "Lights, plugs and sensors", "Shelly relays and sensors."),
    ("hue", "Philips Hue", "Lights, plugs and sensors", "Hue Bridge."),
    ("wled", "WLED", "Lights, plugs and sensors", "WLED LED controllers."),
    ("nanoleaf", "Nanoleaf", "Lights, plugs and sensors", "Nanoleaf panels."),
    ("lifx", "LIFX", "Lights, plugs and sensors", "LIFX bulbs on the local network."),
    ("tradfri", "IKEA TRÅDFRI", "Lights, plugs and sensors", "IKEA gateway."),
    ("sonos", "Sonos", "Media and voice", "Sonos speakers."),
    ("cast", "Google Cast", "Media and voice", "Chromecast and Cast speakers."),
    ("roku", "Roku", "Media and voice", "Roku players and TVs."),
    ("webostv", "LG webOS TV", "Media and voice", "LG TVs."),
    ("samsungtv", "Samsung TV", "Media and voice", "Samsung Smart TVs."),
    ("yamaha_musiccast", "Yamaha MusicCast", "Media and voice", "Yamaha receivers."),
    ("denonavr", "Denon / Marantz AVR", "Media and voice", "Network receivers."),
    ("kodi", "Kodi", "Media and voice", "Kodi media centre."),
    ("wyoming", "Voice services (Wyoming)", "Media and voice", "Speech-to-text and text-to-speech services."),
    ("onvif", "ONVIF camera", "Cameras and security", "Network cameras that speak ONVIF."),
    ("reolink", "Reolink", "Cameras and security", "Reolink cameras and NVRs."),
    ("hikvision", "Hikvision", "Cameras and security", "Hikvision cameras and NVRs."),
    ("ezviz", "EZVIZ", "Cameras and security", "EZVIZ cameras."),
    ("generic", "Generic camera", "Cameras and security", "Any camera with an RTSP or snapshot URL."),
    ("unifi", "UniFi Network", "Network and power", "UniFi controller."),
    ("pi_hole", "Pi-hole", "Network and power", "Pi-hole DNS filter statistics."),
    ("adguard", "AdGuard Home", "Network and power", "AdGuard Home."),
    ("nut", "UPS (NUT)", "Network and power", "Network UPS Tools."),
    ("apcupsd", "APC UPS", "Network and power", "APC UPS daemon."),
    ("ping", "Ping (presence)", "Network and power", "Device presence by ping."),
    ("openweathermap", "OpenWeatherMap", "Services", "Weather from OpenWeatherMap."),
    ("template", "Virtual device (template)", "Helpers", "Build a virtual sensor or switch from a template."),
    ("group", "Group", "Helpers", "Combine several lights, switches or sensors into one."),
    ("utility_meter", "Utility meter", "Helpers", "Daily / monthly energy or water totals."),
)
CATALOG_BY_DOMAIN = {c[0]: c for c in CATALOG}
DISPLAY_NAMES = {"frigate": "AINVR"}

# Never removable, reloadable or reconfigurable from the portal (the product itself depends on them)
PROTECTED = frozenset({"hub_mgmt", "sentinel_link", "tez_sentinel", "backup", "go2rtc", "analytics", "sun", "ingress",
                       "hacs", "browser_mod", "home_intercom", "frigate", "mqtt", "matter", "zha"})
# Built-in plumbing that is not a "device integration" and is not worth showing in the list
HIDDEN_DOMAINS = frozenset({"sun", "go2rtc", "backup", "analytics", "ingress", "met", "radio_browser", "google_translate",
                            "shopping_list", "ibeacon", "bluetooth", "hub_mgmt", "sentinel_link", "browser_mod", "hacs", "home_intercom"})
# These may be reloaded (restart the integration) but not removed
RELOADABLE_PROTECTED = frozenset({"mqtt", "matter", "zha", "frigate"})

HEALTH_BAD = {"setup_error": "Setup failed", "migration_error": "Needs migration", "failed_unload": "Could not stop",
              "setup_retry": "Not reachable, retrying", "not_loaded": "Not running"}
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_SECRET_RE = re.compile(
    r"""(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization|credential)s?["']?(\s*[=:]\s*|\s+)["']?"""
    r"""(?:(?:bearer|basic)\s+)?[^\s,;&"'}]+""")
_URL_CRED_RE = re.compile(r"(?i)(\w+://)[^/\s:@]+:[^/\s@]+@")
_HOST_ID = re.compile(r"[A-Za-z0-9._~-]{16,}")


def clean_reason(text: Any, limit: int = 240) -> str | None:
    """Error text from an integration, with anything that looks like a credential removed."""
    if not text:
        return None
    t = str(text).replace("\n", " ").strip()
    t = _URL_CRED_RE.sub(r"\1***@", t)
    t = _BEARER_RE.sub(lambda m: m.group(1) + " ***", t)
    t = _SECRET_RE.sub(lambda m: m.group(1) + "=***", t)
    return t[:limit]


def health(state: str, reauth: bool) -> dict[str, Any]:
    if reauth:
        return {"level": "warn", "label": "Sign in again", "ok": False}
    if state == "loaded":
        return {"level": "ok", "label": "Running", "ok": True}
    if state in ("setup_in_progress", "unload_in_progress"):
        return {"level": "info", "label": "Starting", "ok": False}
    return {"level": "bad", "label": HEALTH_BAD.get(state, state.replace("_", " ").capitalize()), "ok": False}


def can_remove(domain: str) -> bool:
    return domain not in PROTECTED


def can_reload(domain: str) -> bool:
    return domain not in PROTECTED or domain in RELOADABLE_PROTECTED


def can_reconfigure(domain: str, supports: bool) -> bool:
    return bool(supports) and domain not in PROTECTED


def catalog_view(loaded_domains: dict[str, int]) -> list[dict[str, Any]]:
    groups: dict[str, list] = {}
    for dom, title, grp, blurb in CATALOG:
        groups.setdefault(grp, []).append({"domain": dom, "title": title, "blurb": blurb, "added": loaded_domains.get(dom, 0)})
    order = ["Smart home protocols", "Lights, plugs and sensors", "Media and voice", "Cameras and security", "Network and power", "Services", "Helpers"]
    return [{"group": g, "items": groups[g]} for g in order if g in groups]


def clean_user_input(v: Any, depth: int = 0) -> Any:
    """Bound what a client may send into a config flow: plain JSON values, limited size and depth."""
    if depth > 4:
        raise ValueError("Too deeply nested")
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        if len(v) > 4000:
            raise ValueError("Value too long")
        return v
    if isinstance(v, list):
        if len(v) > 200:
            raise ValueError("List too long")
        return [clean_user_input(x, depth + 1) for x in v]
    if isinstance(v, dict):
        if len(v) > 60:
            raise ValueError("Too many fields")
        out = {}
        for k, x in v.items():
            if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", k):
                raise ValueError("Bad field name")
            out[k] = clean_user_input(x, depth + 1)
        return out
    raise ValueError("Unsupported value")


def entry_view(domain: str, title: str, state: str, reason: Any, reauth: bool, devices: int, entities: int,
               supports_reconfigure: bool, entry_id: str, source: str, disabled: bool) -> dict[str, Any]:
    h = health(state, reauth)
    return {
        "id": entry_id, "domain": domain, "name": DISPLAY_NAMES.get(domain) or (CATALOG_BY_DOMAIN.get(domain) or (domain, domain.replace("_", " ").title()))[1],
        "title": (title or "")[:80], "state": state, "health": h, "reason": clean_reason(reason) if not h["ok"] else None,
        "devices": devices, "entities": entities, "source": source, "disabled": disabled,
        "can_remove": can_remove(domain), "can_reload": can_reload(domain) and not disabled,
        "can_reconfigure": can_reconfigure(domain, supports_reconfigure) and not disabled, "protected": domain in PROTECTED,
    }
