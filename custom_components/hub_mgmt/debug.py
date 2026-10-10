"""Hub Mgmt: support-bundle data for the node portal (capability `debug`: administrators and the vendor account).

The portal adds the host part (service status, resources; container level only for the vendor account) and zips everything.
Nothing secret goes in: log lines pass through the same redaction as the Logs tab, users are counted not listed, no tokens.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.helpers import (area_registry as ar, device_registry as dr, entity_registry as er, issue_registry as ir)

from . import system_util as su
from .entities import _audit, _cap

_LOGGER = logging.getLogger(__name__)
_debug = _cap("debug", "Only administrators can download the support bundle")
LOG_LINES = 1500


def _tail(path: str, nbytes: int = 1_500_000) -> list[str]:
    try:
        import os
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - nbytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
        return lines[1:] if size > nbytes and lines else lines
    except OSError:
        return []


async def _versions(hass) -> dict[str, Any]:
    from homeassistant.const import __version__ as core
    from homeassistant.loader import async_get_integration
    out = {}
    for domain in ("hub_mgmt", "sentinel_link"):
        try:
            out[domain] = str((await async_get_integration(hass, domain)).version or "")
        except Exception:  # noqa: BLE001
            out[domain] = ""
    return {"hub": core, "components": out}


async def collect(hass) -> dict[str, Any]:
    from . import _read_host_stats, _role
    from .integ_util import DISPLAY_NAMES
    ereg, dreg = er.async_get(hass), dr.async_get(hass)
    states = hass.states.async_all()
    by_domain = Counter(s.domain for s in states)
    bad = sorted(s.entity_id for s in states if s.state in ("unavailable", "unknown"))
    entries = [{"integration": DISPLAY_NAMES.get(e.domain, e.title or e.domain), "domain": e.domain, "state": str(e.state.value if hasattr(e.state, "value") else e.state),
                "reason": su.redact(str(e.reason or ""))[:200]} for e in hass.config_entries.async_entries()]
    issues = [{"id": i.issue_id, "domain": i.domain, "severity": str(i.severity)} for i in ir.async_get(hass).issues.values() if not i.dismissed_version]
    roles = Counter(_role(hass, u) for u in await hass.auth.async_get_users() if u.is_active and not u.system_generated)
    roles.pop("superadmin", None)  # the vendor account is not counted for the customer
    backups, sched = 0, "never"
    try:
        from homeassistant.components.backup.const import DATA_MANAGER
        mgr = hass.data.get(DATA_MANAGER)
        if mgr is not None:
            b, _e = await mgr.async_get_backups()
            backups, sched = len(b), mgr.config.data.schedule.recurrence.value
    except Exception:  # noqa: BLE001
        _LOGGER.debug("backup info unavailable", exc_info=True)
    host = {}
    try:
        host = await hass.async_add_executor_job(_read_host_stats)
    except Exception:  # noqa: BLE001
        pass
    log = su.select_log(await hass.async_add_executor_job(_tail, hass.config.path("home-assistant.log")), None, None, LOG_LINES)
    return {
        "node": hass.config.location_name, "time_zone": hass.config.time_zone, "versions": await _versions(hass), "host": host,
        "counts": {"devices": len(dreg.devices), "entities": len(ereg.entities), "areas": len(ar.async_get(hass).areas), "users_by_role": dict(roles),
                   "states_by_domain": dict(by_domain.most_common(25))},
        "integrations": sorted(entries, key=lambda x: x["integration"].lower()),
        "unavailable_entities": {"count": len(bad), "first": bad[:60]},
        "issues": issues, "backups": {"count": backups, "schedule": sched},
        "log_lines": log, "log_note": f"last {len(log)} lines of the hub log, secrets removed",
    }


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/debug_info"})
@websocket_api.async_response
@_debug
async def ws_debug_info(hass, connection, msg):
    _audit(hass, connection.user, "debug_bundle", "support", "ok")
    connection.send_result(msg["id"], await collect(hass))


COMMANDS = (ws_debug_info,)
