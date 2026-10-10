"""Pure helpers for the commissioning checklist, the handover sheet and the camera page. No hub-core imports, unit-tested."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

DEFAULT_NAMES = {"", "home", "sentinel", "my home", "homeassistant", "home assistant"}
CAMERA_ID = re.compile(r"^camera\.[a-z0-9_]{1,80}$")
MOTION_CLASSES = ("motion", "occupancy", "moving", "presence", "person")


def steps(f: dict[str, Any]) -> list[dict[str, Any]]:
    """Commissioning checklist from plain facts about the node. Every step says what to do and which page does it."""
    name = str(f.get("name") or "").strip()
    tz = str(f.get("time_zone") or "")
    no2fa = [str(x) for x in f.get("staff_without_2fa") or []]
    s: list[dict[str, Any]] = []

    def add(sid, title, done, detail, page, optional=False):
        s.append({"id": sid, "title": title, "done": bool(done), "detail": detail, "page": page, "optional": optional})

    add("name", "Name the node", name.lower() not in DEFAULT_NAMES, name or "No name yet", "system")
    add("zone", "Set the time zone", tz not in ("", "UTC", "Etc/UTC"), tz or "Not set", "system")
    add("areas", "Create the rooms (areas)", int(f.get("areas", 0)) >= 1, f"{int(f.get('areas', 0))} area(s)", "areas")
    add("devices", "Add the devices", int(f.get("devices", 0)) >= 1, f"{int(f.get('devices', 0))} device(s)", "integrations")
    add("placed", "Put every device in a room", int(f.get("devices", 0)) >= 1 and int(f.get("unplaced", 0)) == 0,
        f"{int(f.get('unplaced', 0))} device(s) without a room" if f.get("unplaced") else "All placed", "devices")
    add("owner", "Create the homeowner account", int(f.get("homeowners", 0)) >= 1, f"{int(f.get('homeowners', 0))} homeowner(s)", "users")
    add("2fa", "Turn on two-step sign-in for staff", not no2fa, ("Missing for: " + ", ".join(no2fa[:5])) if no2fa else "Everyone has it", "users")
    add("backup", "Create a first backup and a schedule", int(f.get("backups", 0)) >= 1 and f.get("backup_schedule", "never") != "never",
        f"{int(f.get('backups', 0))} backup(s), schedule: {f.get('backup_schedule', 'never')}", "system")
    add("app", "Connect the first app (Link API)", bool(f.get("link_enabled")) and int(f.get("link_clients", 0)) + int(f.get("link_tokens", 0)) >= 1,
        "Link API is off" if not f.get("link_enabled") else f"{int(f.get('link_clients', 0))} app(s), {int(f.get('link_tokens', 0))} token(s)", "link", optional=True)
    add("cameras", "Check the cameras", int(f.get("cameras", 0)) >= 1, f"{int(f.get('cameras', 0))} camera(s)", "cameras", optional=True)
    return s


def progress(items: list[dict[str, Any]]) -> dict[str, Any]:
    req = [i for i in items if not i["optional"]]
    done = sum(1 for i in req if i["done"])
    return {"done": done, "total": len(req), "ready": done == len(req),
            "next": next((i["id"] for i in items if not i["done"] and not i["optional"]), None)}


def valid_public_url(v: Any) -> str | None:
    """The address printed as a QR code on the handover sheet: https only, no credentials, no query."""
    s = str(v or "").strip()
    if not s or len(s) > 200:
        return None
    p = urlsplit(s)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        return None
    if not re.fullmatch(r"[A-Za-z0-9.-]+", p.hostname):
        return None
    return f"https://{p.hostname}" + (f":{p.port}" if p.port else "") + (p.path.rstrip("/") if p.path not in ("", "/") else "")


def is_camera_id(v: Any) -> bool:
    return isinstance(v, str) and bool(CAMERA_ID.match(v))


def related_sensors(camera_device_id: str | None, sensors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Motion-type binary sensors of the same device, newest-first order kept as given."""
    if not camera_device_id:
        return []
    return [x for x in sensors if x.get("device_id") == camera_device_id and x.get("device_class") in MOTION_CLASSES]


def camera_state_text(state: str | None) -> tuple[str, str]:
    """(label, level) for the camera tile."""
    st = (state or "").lower()
    if st in ("idle", "streaming", "recording"):
        return ("Online" if st != "recording" else "Recording"), "ok"
    if st in ("unavailable", "unknown", ""):
        return "Not reachable", "bad"
    return st.capitalize(), "warn"
