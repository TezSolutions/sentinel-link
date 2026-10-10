"""Hub Mgmt phase 6: System pages for the node portal (admin only, capability `system`).

Settings (name, time zone, units, location), backups (create, list, schedule, delete, restore with double confirmation and an
automatic pre-restore backup), versions, hub log viewer with redaction, storage, and hub restart. Backups use the hub's own
backup manager; nothing here shells out. Passwords for encrypted backups are never stored or logged.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api

from . import system_util as su
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_sys = _cap("system", "Only administrators can change system settings")
AGENT = "backup.local"
_LOG_TAIL_BYTES = 3 * 1024 * 1024


def _mgr(hass):
    from homeassistant.components.backup.const import DATA_MANAGER
    return hass.data.get(DATA_MANAGER)


def _tz_ok(z: str) -> bool:
    from homeassistant.util import dt as dt_util
    return dt_util.get_time_zone(z) is not None


def _dir_size(path: str) -> int:
    tot = 0
    try:
        for root, _d, files in os.walk(path):
            for f in files:
                try:
                    tot += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass
    return tot


def _storage(hass) -> dict[str, Any]:
    import shutil
    cfg = hass.config.config_dir
    du = shutil.disk_usage(cfg)
    db = 0
    for n in ("home-assistant_v2.db", "home-assistant_v2.db-wal"):
        try:
            db += os.path.getsize(os.path.join(cfg, n))
        except OSError:
            pass
    return {"disk_total": du.total, "disk_used": du.used, "disk_free": du.free, "disk_used_pct": round(100 * du.used / du.total),
            "database": db, "backups": _dir_size(os.path.join(cfg, "backups")), "config": _dir_size(cfg)}


# ---------- info + settings ----------
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/system_info"})
@websocket_api.async_response
@_sys
async def ws_system_info(hass, connection, msg):
    from homeassistant.const import __version__ as core_version
    from homeassistant.loader import async_get_custom_components
    from . import _read_host_stats
    c = hass.config
    stats = await hass.async_add_executor_job(_read_host_stats)
    store = await hass.async_add_executor_job(_storage, hass)
    custom = await async_get_custom_components(hass)
    loaded = {e.domain for e in hass.config_entries.async_entries()}
    from .integ_util import DISPLAY_NAMES
    integ = sorted(({"domain": d, "name": DISPLAY_NAMES.get(d, i.name), "version": str(i.version or "")}
                    for d, i in custom.items() if d in loaded or d in ("hub_mgmt", "sentinel_link")), key=lambda x: x["domain"])
    connection.send_result(msg["id"], {
        "settings": {"name": c.location_name, "time_zone": c.time_zone, "unit_system": "metric" if c.units is not None and getattr(c.units, "is_metric", True) else "us_customary",
                     "latitude": c.latitude, "longitude": c.longitude, "elevation": c.elevation, "country": c.country or ""},
        "versions": {"hub": core_version, "os": stats.get("os_version", ""), "integrations": integ},
        "uptime_s": stats.get("uptime_s"), "storage": store, "time_zones_hint": "Asia/Kolkata, Europe/London, America/New_York ...",
        "update_note": ("Updates are applied by the Sentinel installer, never silently. Create a backup first (Backups tab); if "
                        "something goes wrong, restore that backup."),
    })


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/system_settings_save", vol.Required("values"): dict})
@websocket_api.async_response
@_sys
async def ws_settings_save(hass, connection, msg):
    clean, err = su.validate_settings(msg["values"], _tz_ok)
    if err:
        connection.send_error(msg["id"], "invalid", "; ".join(f"{k}: {v}" for k, v in err.items()))
        return
    if not clean:
        connection.send_result(msg["id"], {"changed": []})
        return
    await hass.config.async_update(**clean)
    _audit(hass, connection.user, "system_settings", ",".join(sorted(clean)), "ok")
    connection.send_result(msg["id"], {"changed": sorted(clean)})


# ---------- backups ----------
def _backup_view(b) -> dict[str, Any]:
    ag = b.agents.get(AGENT)
    return {"id": b.backup_id, "name": b.name, "date": b.date, "size": getattr(ag, "size", None),
            "size_text": su.fmt_size(getattr(ag, "size", None)), "automatic": bool(b.with_automatic_settings),
            "protected": bool(getattr(ag, "protected", False)), "database": b.database_included, "version": b.homeassistant_version}


async def _list(hass) -> list[dict[str, Any]]:
    mgr = _mgr(hass)
    backups, _errs = await mgr.async_get_backups()
    out = [_backup_view(b) for b in backups.values() if AGENT in b.agents]
    out.sort(key=lambda x: x["date"], reverse=True)
    return out


def _sched_view(mgr) -> dict[str, Any]:
    d = mgr.config.data
    return {"recurrence": d.schedule.recurrence.value, "days": [x.value for x in d.schedule.days],
            "time": d.schedule.time.strftime("%H:%M") if d.schedule.time else None,
            "copies": d.retention.copies, "next": d.schedule.next_automatic_backup.isoformat() if d.schedule.next_automatic_backup else None,
            "last": d.last_completed_automatic_backup.isoformat() if d.last_completed_automatic_backup else None}


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/backup_list"})
@websocket_api.async_response
@_sys
async def ws_backup_list(hass, connection, msg):
    mgr = _mgr(hass)
    if mgr is None:
        connection.send_error(msg["id"], "unavailable", "Backups are not available on this node")
        return
    connection.send_result(msg["id"], {"backups": await _list(hass), "schedule": _sched_view(mgr), "state": mgr.state.value,
                                       "storage": await hass.async_add_executor_job(_storage, hass)})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/backup_create", vol.Required("name"): str,
                                  vol.Optional("password"): vol.Any(str, None)})
@websocket_api.async_response
@_sys
async def ws_backup_create(hass, connection, msg):
    mgr = _mgr(hass)
    name = su.valid_backup_name(msg["name"])
    if mgr is None or not name:
        connection.send_error(msg["id"], "invalid", "Enter a name for the backup" if mgr else "Backups are not available")
        return
    pw = msg.get("password") or None
    if pw is not None and len(pw) < 8:
        connection.send_error(msg["id"], "invalid", "Backup password needs at least 8 characters")
        return
    before = {b["id"] for b in await _list(hass)}
    try:
        await mgr.async_create_backup(agent_ids=[AGENT], include_addons=None, include_all_addons=False, include_database=True,
                                           include_folders=None, include_homeassistant=True, name=name, password=pw)
    except Exception as e:  # noqa: BLE001
        from .integ_util import clean_reason
        _audit(hass, connection.user, "backup_create", name, "error")
        connection.send_error(msg["id"], "failed", clean_reason(e) or "Backup failed")
        return
    _audit(hass, connection.user, "backup_create", name, "ok")
    now = await _list(hass)
    fresh = [b["id"] for b in now if b["id"] not in before]
    connection.send_result(msg["id"], {"id": fresh[0] if fresh else None, "backups": now})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/backup_delete", vol.Required("backup_id"): str})
@websocket_api.async_response
@_sys
async def ws_backup_delete(hass, connection, msg):
    mgr = _mgr(hass)
    ids = {b["id"] for b in await _list(hass)} if mgr else set()
    if msg["backup_id"] not in ids:
        connection.send_error(msg["id"], "not_found", "That backup does not exist")
        return
    await mgr.async_delete_backup(msg["backup_id"], agent_ids=[AGENT])
    _audit(hass, connection.user, "backup_delete", msg["backup_id"], "ok")
    connection.send_result(msg["id"], {"backups": await _list(hass)})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/backup_schedule", vol.Required("recurrence"): str,
                                  vol.Optional("days"): list, vol.Optional("time"): vol.Any(str, None), vol.Optional("copies"): int})
@websocket_api.async_response
@_sys
async def ws_backup_schedule(hass, connection, msg):
    mgr = _mgr(hass)
    clean, e = su.validate_schedule({k: v for k, v in msg.items() if k in ("recurrence", "days", "time", "copies")})
    if mgr is None or e:
        connection.send_error(msg["id"], "invalid", e or "Backups are not available")
        return
    import datetime as dt
    from homeassistant.components.backup.config import Day, ScheduleRecurrence
    tm = dt.time.fromisoformat(clean["time"]) if clean["time"] else None
    mgr.config.update(
        automatic_backups_configured=clean["recurrence"] != "never",
        create_backup={"agent_ids": [AGENT], "include_database": True, "include_all_addons": False, "name": None, "password": None},
        retention={"copies": clean["copies"], "days": None},
        schedule={"recurrence": ScheduleRecurrence(clean["recurrence"]), "days": [Day(x) for x in clean["days"]], "time": tm})
    _audit(hass, connection.user, "backup_schedule", clean["recurrence"], "ok")
    connection.send_result(msg["id"], {"schedule": _sched_view(mgr)})


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/backup_restore", vol.Required("backup_id"): str,
                                  vol.Required("confirm"): str, vol.Required("typed_name"): str, vol.Optional("password"): vol.Any(str, None)})
@websocket_api.async_response
@_sys
async def ws_backup_restore(hass, connection, msg):
    mgr = _mgr(hass)
    found = next((b for b in await _list(hass) if b["id"] == msg["backup_id"]), None) if mgr else None
    if not found:
        connection.send_error(msg["id"], "not_found", "That backup does not exist")
        return
    bad = su.restore_allowed(msg["confirm"], msg["typed_name"], found["name"])
    if bad:
        connection.send_error(msg["id"], "confirm", bad)
        return
    if found["protected"] and not msg.get("password"):
        connection.send_error(msg["id"], "password", "This backup is password protected: enter its password")
        return
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime())
    try:  # safety net first: if the restore goes wrong, this is the way back
        await mgr.async_create_backup(agent_ids=[AGENT], include_addons=None, include_all_addons=False, include_database=True,
                                      include_folders=None, include_homeassistant=True, name=f"Before restore {stamp}", password=None)
    except Exception:  # noqa: BLE001
        _audit(hass, connection.user, "backup_restore", found["id"], "pre-backup failed")
        connection.send_error(msg["id"], "failed", "Could not create the safety backup, so nothing was restored")
        return
    _audit(hass, connection.user, "backup_restore", found["id"], "started")
    connection.send_result(msg["id"], {"ok": True, "note": "The hub is restoring and will restart. This page reconnects by itself."})
    try:
        await mgr.async_restore_backup(msg["backup_id"], agent_id=AGENT, password=msg.get("password") or None, restore_addons=None,
                                       restore_database=True, restore_folders=None, restore_homeassistant=True)
    except Exception:  # noqa: BLE001
        _LOGGER.exception("restore failed")


# ---------- logs ----------
def _read_tail(path: str, nbytes: int) -> list[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = data.splitlines()
    return lines[1:] if size > nbytes and lines else lines


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/system_logs", vol.Optional("level"): vol.Any(str, None),
                                  vol.Optional("text"): vol.Any(str, None), vol.Optional("limit"): int})
@websocket_api.async_response
@_sys
async def ws_logs(hass, connection, msg):
    lines = await hass.async_add_executor_job(_read_tail, hass.config.path("home-assistant.log"), _LOG_TAIL_BYTES)
    out = su.select_log(lines, msg.get("level"), msg.get("text"), msg.get("limit") or 500)
    connection.send_result(msg["id"], {"lines": out, "total_read": len(lines)})


# ---------- restart ----------
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/system_restart", vol.Required("confirm"): str})
@websocket_api.async_response
@_sys
async def ws_restart(hass, connection, msg):
    if msg["confirm"].strip() != "RESTART":
        connection.send_error(msg["id"], "confirm", "Type RESTART to confirm")
        return
    _audit(hass, connection.user, "system_restart", "hub", "ok")
    connection.send_result(msg["id"], {"ok": True})
    await asyncio.sleep(1)
    await hass.services.async_call("homeassistant", "restart", blocking=False)


COMMANDS = (ws_system_info, ws_settings_save, ws_backup_list, ws_backup_create, ws_backup_delete, ws_backup_schedule,
            ws_backup_restore, ws_logs, ws_restart)
