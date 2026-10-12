"""Hub Mgmt: whitelisted backend for the installer panel.

Non-admin installer users cannot call HA's admin-only websocket commands, so
this integration exposes ONLY the specific actions the installer page needs and
authorises each call itself (admin or a user listed in `allowed_users`).
"""
from __future__ import annotations

import inspect
import json
import logging
import re
import time
from collections import deque
from functools import wraps
from pathlib import Path
from typing import Any

import voluptuous as vol
try:  # HA >= 2026.9
    from probatio import to_field_list
except ImportError:  # older HA
    import voluptuous_serialize

    def to_field_list(schema, custom_serializer=None):
        return voluptuous_serialize.convert(schema, custom_serializer=custom_serializer)

from homeassistant import data_entry_flow
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.providers import homeassistant as auth_ha
from homeassistant.components import frontend, mqtt, panel_custom, websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import (
    area_registry as ar,
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
)
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType

from . import logins as logins_cmds
from . import user_api, areas, debug, entities, integrations, scenes, setup, system, training, user_util, users

DOMAIN = "hub_mgmt"
CONF_ALLOWED = "allowed_users"
CONF_MANAGERS = "homeowners"
CONF_TRAINERS = "trainers"
CONF_SUPERADMINS = "superadmins"   # vendor accounts (Tez Solutions); only root can add one, by editing configuration.yaml
Z2M_BASE = "zigbee2mqtt"
PANEL_URL = "hub-mgmt"
_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.Schema({vol.Optional(CONF_ALLOWED, default=[]): [cv.string],
                vol.Optional(CONF_MANAGERS, default=[]): [cv.string],
                vol.Optional(CONF_TRAINERS, default=[]): [cv.string],
                vol.Optional(CONF_SUPERADMINS, default=[]): [cv.string]})},
    extra=vol.ALLOW_EXTRA,
)

# Flows an installer may drive (discovered integrations only, never user-initiated
# flows for arbitrary handlers).
HIDDEN_SOURCES = {"user", "reconfigure"}


def _iter_devices(dreg):
    """Device entries on any HA version (older: iterating yields IDs; 2026.9+: entries)."""
    out = []
    for d in dreg.devices:
        out.append(dreg.async_get(d) if isinstance(d, str) else d)
    return [d for d in out if d is not None]


# Roles. "admin" is derived from HA (owner/administrator group) and is never
# stored. Every other role is stored in .storage/hub_mgmt (user_roles) and is the
# single source of truth shared with the external API (it reads hass.data[DOMAIN]
# ["user_roles"] live, so panel changes apply there immediately).
#   installer : Device Mgmt (pairing, devices, discovered)
#   homeowner : Users tab (add/remove/reset, assign manager/operator/viewer)
#   manager / operator / viewer : API-only access levels, no panel tabs
#   user      : plain HA user, no stored role (no API access)
STORED_ROLES = ("installer", "homeowner", "manager", "operator", "viewer")
# Portal capability matrix (approved 2026-10-10). Every portal command re-checks its cap server-side.
#   entities = entity settings + control, areas = areas/floors/labels, integrations = add/reconfigure + network,
#   scenes = scenes and simple rules, system = settings/backup/updates/logs/break-glass, profile = own account + 2FA
#   logins = sign-in history (homeowner/admin/vendor: everybody's; others: their own)
#   debug = download the support bundle (service-level, no container names); infra = container-level detail + full bundle (superadmin only)
_ADMIN_CAPS = {"devices", "users", "entities", "areas", "integrations", "scenes", "system", "setup", "debug", "profile", "logins"}
CAPS = {
    "superadmin": _ADMIN_CAPS | {"infra"},
    "admin": set(_ADMIN_CAPS),
    "installer": {"devices", "entities", "areas", "integrations", "scenes", "setup", "profile", "logins"},
    "homeowner": {"users", "entities", "areas", "scenes", "profile", "logins"},
}
ADMIN_ROLES = ("admin", "superadmin")
# which target roles a caller may assign / remove / reset ("user" = no role)
MANAGEABLE = {
    "superadmin": {"user", *STORED_ROLES},
    "admin": {"user", *STORED_ROLES},
    "homeowner": {"user", "manager", "operator", "viewer"},
}


def _role(hass, user) -> str:
    if user.is_owner or user.is_admin:
        # the vendor account is an HA administrator that is ALSO listed under hub_mgmt: superadmins (root-edited config only)
        return "superadmin" if user.id in hass.data[DOMAIN].get("superadmins", ()) else "admin"
    return hass.data[DOMAIN]["user_roles"].get(user.id, "user")


def _has_cap(hass, user, cap: str) -> bool:
    return cap in CAPS.get(_role(hass, user), ())


def _is_installer(hass, user) -> bool:
    """Admins and installers (device management)."""
    return _has_cap(hass, user, "devices")


def _is_manager(hass, user) -> bool:
    """Admins and homeowners (user management)."""
    return _has_cap(hass, user, "users")


def _manageable_roles(hass, caller) -> set[str]:
    return MANAGEABLE.get(_role(hass, caller), set())


async def _save(hass) -> None:
    st = hass.data[DOMAIN]
    await st["store"].async_save(
        {"ignored": sorted(st["ignored"]), "user_roles": st["user_roles"], "seeded": True}
    )


def _guard(check, message):
    """Build a decorator that authorises a ws command with `check(hass, user)`."""

    def deco(fn):
        def _ok(hass, connection, msg) -> bool:
            if check(hass, connection.user):
                return True
            connection.send_error(msg["id"], "unauthorized", message)
            return False

        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def awrapper(hass, connection, msg):
                if _ok(hass, connection, msg):
                    await fn(hass, connection, msg)

            return awrapper

        @wraps(fn)
        def wrapper(hass, connection, msg):
            if _ok(hass, connection, msg):
                return fn(hass, connection, msg)

        return wrapper

    return deco


_authorized = _guard(_is_installer, "Not an installer user")
_manager_only = _guard(_is_manager, "Not a homeowner")


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    conf = config.get(DOMAIN, {})
    state: dict[str, Any] = {
        "allowed": conf.get(CONF_ALLOWED, []),
        "managers": conf.get(CONF_MANAGERS, []),
        "trainers": conf.get(CONF_TRAINERS, []),
        "superadmins": list(conf.get(CONF_SUPERADMINS, [])),
        "bridge_state": "unknown",
        "permit_join_end": None,  # epoch seconds
        "events": deque(maxlen=30),
    }
    store = Store(hass, 1, DOMAIN)
    state["store"] = store
    saved = await store.async_load() or {}
    state["ignored"] = set(saved.get("ignored", []))
    roles = {k: v for k, v in (saved.get("user_roles") or {}).items() if v in STORED_ROLES}
    if not saved.get("seeded"):
        # One-time import of the legacy configuration.yaml lists
        for uid in state["managers"]:
            roles.setdefault(uid, "homeowner")
        for uid in state["allowed"]:
            roles.setdefault(uid, "installer")
    state["user_roles"] = roles
    hass.data[DOMAIN] = state
    from .user_api import UserApi
    state["user_api"] = UserApi(hass)   # called in-process by the Link API (/users); same rules as the portal
    from .login_service import LoginService, install_flow_hook
    logins = LoginService(hass)
    logins.node = hass.config.location_name or ""
    await logins.async_load()
    from . import debug as _debug_mod
    state["support"] = {"collect": _debug_mod.collect, "host": _read_host_stats}     # used by the Link API cloud channel (approved support report, health)
    state["logins"] = logins            # sign-in history; recorded by the portal, the Link API sign-in pages and the hub's own sign-in flow
    install_flow_hook(hass, logins)
    async def _flush_logins(_event) -> None:
        await logins.async_flush()

    hass.bus.async_listen_once("homeassistant_stop", _flush_logins)
    if not saved.get("seeded"):
        await _save(hass)

    async def _on_state(msg):
        state["bridge_state"] = (msg.payload or "").strip().strip('"')
        try:
            state["bridge_state"] = json.loads(msg.payload).get("state", state["bridge_state"])
        except (ValueError, AttributeError):
            pass

    async def _on_info(msg):
        try:
            info = json.loads(msg.payload)
        except ValueError:
            return
        end = info.get("permit_join_end")
        state["permit_join_end"] = (end / 1000) if end else None
        state["coordinator"] = info.get("coordinator")
        state["z2m_version"] = info.get("version")

    async def _on_event(msg):
        try:
            ev = json.loads(msg.payload)
        except ValueError:
            return
        if ev.get("type") in ("device_joined", "device_interview", "device_announce", "device_leave"):
            data = ev.get("data", {})
            state["events"].appendleft(
                {
                    "t": int(time.time()),
                    "type": ev["type"],
                    "name": data.get("friendly_name") or data.get("ieee_address"),
                    "status": data.get("status"),
                    "supported": data.get("supported"),
                    "model": (data.get("definition") or {}).get("model"),
                }
            )

    async def _subscribe(_=None):
        await mqtt.async_subscribe(hass, f"{Z2M_BASE}/bridge/state", _on_state)
        await mqtt.async_subscribe(hass, f"{Z2M_BASE}/bridge/info", _on_info)
        await mqtt.async_subscribe(hass, f"{Z2M_BASE}/bridge/event", _on_event)

    hass.async_create_task(_subscribe())

    for cmd in (ws_status, ws_zigbee_permit, ws_devices, ws_update_device,
                ws_matter_commission, ws_flows, ws_flow_configure, ws_flow_abort, ws_areas,
                ws_set_ignored, ws_remove_device, ws_whoami, ws_hub_stats, ws_network,
                ws_users_list, ws_user_create, ws_user_remove,
                ws_user_password, ws_user_set_role):
        websocket_api.async_register_command(hass, cmd)
    for cmd in (*training.COMMANDS, *entities.COMMANDS, *areas.COMMANDS, *users.COMMANDS, *integrations.COMMANDS, *scenes.COMMANDS, *system.COMMANDS, *setup.COMMANDS, *debug.COMMANDS, *logins_cmds.COMMANDS):
        websocket_api.async_register_command(hass, cmd)

    frontend_dir = Path(__file__).parent / "frontend"
    await hass.http.async_register_static_paths(
        [StaticPathConfig("/hub_mgmt_static", str(frontend_dir), cache_headers=False)]
    )
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name="hub-mgmt-panel",
        frontend_url_path=PANEL_URL,
        sidebar_title="Hub Mgmt",
        sidebar_icon="mdi:router-wireless",
        module_url="/hub_mgmt_static/hub-mgmt-panel.js?v=20",
        embed_iframe=False,
        require_admin=False,
    )
    return True


# ---------- status / zigbee ----------
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/status"})
@_authorized
def ws_status(hass, connection, msg):
    s = hass.data[DOMAIN]
    end = s["permit_join_end"]
    remaining = max(0, int(end - time.time())) if end else 0
    matter_loaded = bool(hass.config_entries.async_loaded_entries("matter"))
    zha_loaded = bool(hass.config_entries.async_loaded_entries("zha"))
    zend = s.get("zha_permit_end")
    if zha_loaded:
        remaining = max(remaining, int(zend - time.time()) if zend else 0)
    bridge = s["bridge_state"]
    if zha_loaded and bridge != "online":
        bridge = "online"
    connection.send_result(
        msg["id"],
        {
            "zigbee_backend": "zha" if zha_loaded else "z2m",
            "bridge_state": bridge,
            "permit_join_remaining": remaining,
            "coordinator": s.get("coordinator"),
            "z2m_version": s.get("z2m_version"),
            "events": list(s["events"]),
            "matter_ready": matter_loaded,
        },
    )


@websocket_api.websocket_command(
    {vol.Required("type"): "hub_mgmt/zigbee_permit", vol.Required("time"): vol.All(int, vol.Range(min=0, max=254))}
)
@websocket_api.async_response
@_authorized
async def ws_zigbee_permit(hass, connection, msg):
    st = hass.data[DOMAIN]
    if hass.config_entries.async_loaded_entries("zha"):
        try:
            if msg["time"] > 0:
                await hass.services.async_call("zha", "permit", {"duration": msg["time"]}, blocking=True)
                st["zha_permit_end"] = time.time() + msg["time"]
            else:
                await hass.services.async_call("zha", "permit", {"duration": 0}, blocking=True)
                st["zha_permit_end"] = None
        except Exception as err:  # noqa: BLE001
            connection.send_error(msg["id"], "permit_failed", str(err))
            return
    else:
        await mqtt.async_publish(
            hass, f"{Z2M_BASE}/bridge/request/permit_join", json.dumps({"time": msg["time"]})
        )
    connection.send_result(msg["id"], {"ok": True})



# ---------- devices ----------
def _protocol(identifiers, domains) -> str:
    for d in identifiers:
        if d in ("mqtt", "zha"):
            return "zigbee"
        if d == "matter":
            return "matter"
    return ",".join(sorted(domains)) or "other"


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/devices"})
@_authorized
def ws_devices(hass, connection, msg):
    dreg, ereg, areg = dr.async_get(hass), er.async_get(hass), ar.async_get(hass)
    out = []
    for dev in _iter_devices(dreg):
        if dev.entry_type == dr.DeviceEntryType.SERVICE:
            continue
        ids = {i[0] for i in dev.identifiers}
        ents = er.async_entries_for_device(ereg, dev.id)
        domains = {e.platform for e in ents}
        if not (ids & {"mqtt", "matter", "zha"}) and not domains - {"sun"}:
            continue
        battery = lqi = None
        unavailable = bool(ents)
        for e in ents:
            st = hass.states.get(e.entity_id)
            if not st:
                continue
            if st.state not in ("unavailable",):
                unavailable = False
            if e.original_device_class == "battery" and st.state.replace(".", "", 1).isdigit():
                battery = float(st.state)
            if e.entity_id.endswith("_linkquality") and st.state.isdigit():
                lqi = int(st.state)
        name = dev.name_by_user or dev.name
        area = areg.async_get_area(dev.area_id) if dev.area_id else None
        out.append(
            {
                "id": dev.id,
                "name": name,
                "default_name": dev.name,
                "manufacturer": dev.manufacturer,
                "model": dev.model,
                "protocol": _protocol(ids, domains),
                "area_id": dev.area_id,
                "area": area.name if area else None,
                "battery": battery,
                "linkquality": lqi,
                "available": not unavailable,
                "entities": len(ents),
                "new": dev.area_id is None,
                "ignored": dev.id in hass.data[DOMAIN]["ignored"],
                "removable": _removable_kind(dev) is not None,
            }
        )
    out.sort(key=lambda d: (not d["new"], (d["name"] or "").lower()))
    connection.send_result(msg["id"], out)


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/areas"})
@_guard(lambda hass, user: _has_cap(hass, user, "devices") or _has_cap(hass, user, "entities") or _has_cap(hass, user, "areas"), "Not allowed")
def ws_areas(hass, connection, msg):
    connection.send_result(
        msg["id"], [{"id": a.id, "name": a.name} for a in ar.async_get(hass).areas.values()]
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/update_device",
        vol.Required("device_id"): str,
        vol.Optional("name"): vol.All(str, vol.Length(min=1, max=80)),
        vol.Optional("area_id"): vol.Any(str, None),
    }
)
@_authorized
def ws_update_device(hass, connection, msg):
    dreg = dr.async_get(hass)
    dev = dreg.async_get(msg["device_id"])
    if dev is None:
        connection.send_error(msg["id"], "not_found", "Unknown device")
        return
    if dev.entry_type == dr.DeviceEntryType.SERVICE:
        connection.send_error(msg["id"], "forbidden", "Service entries cannot be edited here")
        return
    kwargs = {}
    if "name" in msg:
        kwargs["name_by_user"] = msg["name"]
    if "area_id" in msg:
        kwargs["area_id"] = msg["area_id"]
    dreg.async_update_device(msg["device_id"], **kwargs)
    connection.send_result(msg["id"], {"ok": True})


# ---------- matter ----------
@websocket_api.websocket_command(
    {vol.Required("type"): "hub_mgmt/matter_commission", vol.Required("code"): vol.All(str, vol.Length(min=4, max=64))}
)
@websocket_api.async_response
@_authorized
async def ws_matter_commission(hass, connection, msg):
    from homeassistant.components.matter.helpers import get_matter

    try:
        await get_matter(hass).matter_client.commission_with_code(msg["code"], network_only=True)
    except Exception as err:  # noqa: BLE001 - surface any matter error text
        connection.send_error(msg["id"], "commission_failed", str(err))
        return
    connection.send_result(msg["id"], {"ok": True})



# ---------- discovered integrations (config flows) ----------
def _flow_summary(flow) -> dict[str, Any]:
    ctx = flow["context"]
    return {
        "flow_id": flow["flow_id"],
        "handler": flow["handler"],
        "source": ctx.get("source"),
        "title": ctx.get("title_placeholders", {}).get("name") or flow["handler"],
    }


def _prepare(result) -> dict[str, Any]:
    r = dict(result)
    if r["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY:
        r = {k: v for k, v in r.items() if k not in ("data", "context", "result")}
    elif "data_schema" in r:
        schema = r["data_schema"]
        r["data_schema"] = [] if schema is None else to_field_list(schema, custom_serializer=cv.custom_serializer)
    r.pop("context", None)
    r["type"] = str(getattr(r["type"], "value", r["type"]))
    return json.loads(json.dumps(r, default=str))


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/flows"})
@_authorized
def ws_flows(hass, connection, msg):
    flows = [
        _flow_summary(f)
        for f in hass.config_entries.flow.async_progress()
        if f["context"].get("source") not in HIDDEN_SOURCES
    ]
    connection.send_result(msg["id"], flows)


def _is_discovered(hass, flow_id) -> bool:
    for f in hass.config_entries.flow.async_progress():
        if f["flow_id"] == flow_id:
            return f["context"].get("source") not in HIDDEN_SOURCES
    return False


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/flow_configure",
        vol.Required("flow_id"): str,
        vol.Optional("user_input"): vol.Any(dict, None),
    }
)
@websocket_api.async_response
@_authorized
async def ws_flow_configure(hass, connection, msg):
    if not _is_discovered(hass, msg["flow_id"]):
        connection.send_error(msg["id"], "forbidden", "Not a discovered flow")
        return
    try:
        result = await hass.config_entries.flow.async_configure(msg["flow_id"], msg.get("user_input"))
    except data_entry_flow.UnknownFlow:
        connection.send_error(msg["id"], "not_found", "Flow no longer exists")
        return
    except Exception as err:  # noqa: BLE001
        connection.send_error(msg["id"], "flow_error", str(err))
        return
    connection.send_result(msg["id"], _prepare(result))



@websocket_api.websocket_command(
    {vol.Required("type"): "hub_mgmt/flow_abort", vol.Required("flow_id"): str}
)
@_authorized
def ws_flow_abort(hass, connection, msg):
    if not _is_discovered(hass, msg["flow_id"]):
        connection.send_error(msg["id"], "forbidden", "Not a discovered flow")
        return
    hass.config_entries.flow.async_abort(msg["flow_id"])
    connection.send_result(msg["id"], {"ok": True})


# ---------- ignore / remove ----------
def _removable_kind(dev):
    """Return ('zigbee', ieee) / ('matter', None) for removable devices, else None."""
    for dom, ident in dev.identifiers:
        if dom == "zha" and ident.count(":") >= 7:
            return ("zha", ident)
        if dom == "mqtt" and ident.startswith("zigbee2mqtt_0x"):
            return ("zigbee", ident.split("_", 1)[1])
        if dom == "matter" and ident.startswith("deviceid_") and not dev.via_device_id:
            return ("matter", None)
    return None


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/set_ignored",
        vol.Required("device_id"): str,
        vol.Required("ignored"): bool,
    }
)
@websocket_api.async_response
@_authorized
async def ws_set_ignored(hass, connection, msg):
    st = hass.data[DOMAIN]
    if dr.async_get(hass).async_get(msg["device_id"]) is None:
        connection.send_error(msg["id"], "not_found", "Unknown device")
        return
    (st["ignored"].add if msg["ignored"] else st["ignored"].discard)(msg["device_id"])
    await _save(hass)
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/remove_device",
        vol.Required("device_id"): str,
        vol.Optional("force", default=False): bool,
    }
)
@websocket_api.async_response
@_authorized
async def ws_remove_device(hass, connection, msg):
    """Remove a Zigbee (via Z2M) or Matter device from its network and HA."""
    dreg = dr.async_get(hass)
    dev = dreg.async_get(msg["device_id"])
    kind = _removable_kind(dev) if dev else None
    if kind is None:
        connection.send_error(msg["id"], "forbidden", "This device can only be ignored, not removed here")
        return
    what, ieee = kind
    try:
        if what == "zha":
            await hass.services.async_call("zha", "remove", {"ieee": ieee}, blocking=True)
        elif what == "zigbee":
            await mqtt.async_publish(
                hass,
                f"{Z2M_BASE}/bridge/request/device/remove",
                json.dumps({"id": ieee, "force": msg["force"]}),
            )
        else:
            from homeassistant.components.matter.helpers import get_matter, get_node_from_device_entry

            node = get_node_from_device_entry(hass, dev)
            if node is not None:
                await get_matter(hass).matter_client.remove_node(node.node_id)
            dreg.async_remove_device(dev.id)
    except Exception as err:  # noqa: BLE001
        connection.send_error(msg["id"], "remove_failed", str(err))
        return
    st = hass.data[DOMAIN]
    st["ignored"].discard(msg["device_id"])
    await _save(hass)
    _LOGGER.info("Installer %s removed %s device %s", connection.user.name, what, dev.name)
    connection.send_result(msg["id"], {"ok": True})


# ---------- who am I / hub stats (any logged-in user) ----------
@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/whoami"})
@callback
def ws_whoami(hass, connection, msg):
    """Tell the panel which tabs to show. UI hint only; every action re-checks."""
    connection.send_result(
        msg["id"],
        {
            "name": connection.user.name,
            "role": _role(hass, connection.user),
            "installer": _is_installer(hass, connection.user),
            "manager": _is_manager(hass, connection.user),
            "assignable": sorted(_manageable_roles(hass, connection.user) - {"user"}),
            "trainer": training._is_trainer(hass, connection.user),
            "caps": sorted(CAPS.get(_role(hass, connection.user), ())),
        },
    )


def _read_host_stats() -> dict[str, Any]:
    import shutil

    out: dict[str, Any] = {}
    try:
        out["uptime_s"] = int(float(Path("/proc/uptime").read_text().split()[0]))
        out["load1"] = float(Path("/proc/loadavg").read_text().split()[0])
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0])
        if mem.get("MemTotal"):
            out["mem_used_pct"] = round(100 * (1 - mem["MemAvailable"] / mem["MemTotal"]))
            out["mem_total_mb"] = mem["MemTotal"] // 1024
        try:  # host /etc/os-release, bind-mounted read-only into the HA container
            for line in Path("/etc/host-os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    out["os_version"] = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        du = shutil.disk_usage("/config")
        out["disk_used_pct"] = round(100 * du.used / du.total)
        out["disk_free_gb"] = round(du.free / 1e9, 1)
    except Exception:  # noqa: BLE001 - stats are best effort
        _LOGGER.debug("host stats unavailable", exc_info=True)
    return out


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/hub_stats"})
@websocket_api.async_response
async def ws_hub_stats(hass, connection, msg):
    """Basic, non-sensitive hub health for every logged-in user."""
    from homeassistant.const import __version__ as ha_version

    s = hass.data[DOMAIN]
    stats = await hass.async_add_executor_job(_read_host_stats)
    dreg = dr.async_get(hass)
    zig = mat = 0
    for dev in _iter_devices(dreg):
        kind = _removable_kind(dev)
        if kind and kind[0] == "zigbee":
            zig += 1
        elif kind and kind[0] == "matter":
            mat += 1
    stats.update(
        {
            "name": hass.config.location_name,
            "ha_version": ha_version,
            "zigbee_state": s["bridge_state"],
            "matter_ready": bool(hass.config_entries.async_loaded_entries("matter")),
            "zigbee_devices": zig,
            "matter_devices": mat,
            "entities": len(hass.states.async_all()),
            "unavailable": sum(1 for st in hass.states.async_all() if st.state == "unavailable"),
        }
    )
    connection.send_result(msg["id"], stats)


# ---------- network details (installers and admins) ----------
TS_SOCK = "/var/run/tailscale/tailscaled.sock"
_PUBIP: dict[str, Any] = {"ip": None, "ts": 0.0}


async def _public_ip(hass) -> str | None:
    """Public IPv4, cached 10 min; None when offline."""
    if _PUBIP["ts"] and time.time() - _PUBIP["ts"] < 600:
        return _PUBIP["ip"]
    from homeassistant.helpers.aiohttp_client import async_get_clientsession

    ip = None
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            async with async_get_clientsession(hass).get(url, timeout=5) as r:
                txt = (await r.text()).strip()
                if r.status == 200 and re.fullmatch(r"[0-9.]{7,15}", txt):
                    ip = txt
                    break
        except Exception:  # noqa: BLE001
            continue
    _PUBIP.update(ip=ip, ts=time.time())
    return ip


async def _tailscale_status() -> dict[str, Any]:
    """Tailscale LocalAPI over the bind-mounted socket; state 'unavailable' without it."""
    import aiohttp

    if not Path(TS_SOCK).exists():
        return {"state": "unavailable"}
    try:
        conn = aiohttp.UnixConnector(path=TS_SOCK)
        async with aiohttp.ClientSession(connector=conn) as sess:
            async with sess.get(
                "http://local-tailscaled.sock/localapi/v0/status",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                d = await r.json()
    except Exception:  # noqa: BLE001
        return {"state": "unavailable"}
    me = d.get("Self") or {}
    ips = me.get("TailscaleIPs") or []
    return {
        "state": d.get("BackendState"),
        "hostname": me.get("HostName"),
        "dns": (me.get("DNSName") or "").rstrip("."),
        "ipv4": next((i for i in ips if ":" not in i), None),
        "ipv6": next((i for i in ips if ":" in i), None),
        "tailnet": (d.get("CurrentTailnet") or {}).get("Name"),
        "online": me.get("Online"),
        "peers": len(d.get("Peer") or {}),
    }


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/network"})
@websocket_api.async_response
@_authorized
async def ws_network(hass, connection, msg):
    """Local, public and Tailscale addresses for quick access."""
    from homeassistant.components import network as ha_network

    local = []
    try:
        for ad in await ha_network.async_get_adapters(hass):
            name = ad.get("name", "")
            if name == "lo" or name.startswith(("docker", "br-", "veth", "tailscale")):
                continue
            for ip4 in ad.get("ipv4", []):
                local.append({"iface": name, "ip": ip4["address"]})
    except Exception:  # noqa: BLE001
        _LOGGER.debug("adapters unavailable", exc_info=True)
    connection.send_result(
        msg["id"],
        {
            "local": local,
            "public": await _public_ip(hass),
            "tailscale": await _tailscale_status(),
        },
    )


# ---------- user management (homeowners and admins) ----------
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")


def _ha_username(user) -> str | None:
    for cred in user.credentials:
        if cred.auth_provider_type == "homeassistant":
            return cred.data.get("username")
    return None


def _removable_user(hass, user, caller) -> bool:
    """Target's role must be in the caller's manageable set; never self/admin/system."""
    return (
        not user.system_generated
        and user.id != caller.id
        and _role(hass, user) in _manageable_roles(hass, caller)
    )


async def _mfa_flag(hass, user) -> bool:
    mod = hass.auth.get_auth_mfa_module("totp")
    return bool(mod and await mod.async_is_user_setup(user.id))


async def user_row(hass, u, caller) -> dict | None:
    """One user as the portal and the Link API show it, or None if `caller` may not see it
    (system users; the vendor account is hidden from everyone but the vendor)."""
    if u.system_generated:
        return None
    if _role(hass, u) == "superadmin" and _role(hass, caller) != "superadmin":
        return None
    removable = _removable_user(hass, u, caller)
    return {
        "id": u.id,
        "name": u.name,
        "username": _ha_username(u),
        "active": u.is_active,
        "mfa": await _mfa_flag(hass, u),
        "last_seen": user_util.newest(t.last_used_at for t in u.refresh_tokens.values() if t.token_type == "normal"),
        "role": _role(hass, u),
        "removable": removable,
        "resettable": removable and bool(_ha_username(u)),
        "assignable": removable,
    }


@websocket_api.websocket_command({vol.Required("type"): "hub_mgmt/users_list"})
@websocket_api.async_response
@_manager_only
async def ws_users_list(hass, connection, msg):
    users = []
    all_users = await hass.auth.async_get_users()
    live = {u.id for u in all_users}
    st = hass.data[DOMAIN]
    stale = [k for k in st["user_roles"] if k not in live]
    if stale:  # users deleted elsewhere (HA settings) drop their role here
        for k in stale:
            st["user_roles"].pop(k, None)
        await _save(hass)
    for u in all_users:
        row = await user_row(hass, u, connection.user)
        if row is not None:
            users.append(row)
    order = ("superadmin", "admin", "installer", "homeowner", "manager", "operator", "viewer", "user")
    users.sort(key=lambda x: (order.index(x["role"]) if x["role"] in order else 99, (x["name"] or "").lower()))
    connection.send_result(msg["id"], {"users": users, "assignable": sorted(_manageable_roles(hass, connection.user) - {"user"})})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/user_create",
        vol.Required("name"): vol.All(str, vol.Strip, vol.Length(min=1, max=60)),
        vol.Required("username"): vol.All(str, vol.Strip, vol.Lower),
        vol.Required("password"): vol.All(str, vol.Length(min=8, max=128)),
        vol.Optional("role", default="user"): vol.In(("user", *STORED_ROLES)),
    }
)
@websocket_api.async_response
@_manager_only
async def ws_user_create(hass, connection, msg):
    """Create a NON-ADMIN user with a local login (rules in user_api.py, shared with the Link API)."""
    try:
        res = await hass.data[DOMAIN]["user_api"].create(connection.user, name=msg["name"], username=msg["username"], password=msg["password"], role=msg["role"])
    except user_api.ApiError as err:
        connection.send_error(msg["id"], err.code, err.message)
        return
    connection.send_result(msg["id"], res)


@websocket_api.websocket_command(
    {vol.Required("type"): "hub_mgmt/user_remove", vol.Required("user_id"): str}
)
@websocket_api.async_response
@_manager_only
async def ws_user_remove(hass, connection, msg):
    try:
        await hass.data[DOMAIN]["user_api"].remove(connection.user, msg["user_id"])
    except user_api.ApiError as err:
        connection.send_error(msg["id"], err.code, err.message)
        return
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/user_password",
        vol.Required("user_id"): str,
        vol.Required("password"): vol.All(str, vol.Length(min=8, max=128)),
    }
)
@websocket_api.async_response
@_manager_only
async def ws_user_password(hass, connection, msg):
    """Reset the password of an account the caller manages."""
    try:
        await hass.data[DOMAIN]["user_api"].set_password(connection.user, msg["user_id"], msg["password"])
    except user_api.ApiError as err:
        connection.send_error(msg["id"], err.code, err.message)
        return
    connection.send_result(msg["id"], {"ok": True})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hub_mgmt/user_set_role",
        vol.Required("user_id"): str,
        vol.Required("role"): vol.In(("user", *STORED_ROLES)),
    }
)
@websocket_api.async_response
@_manager_only
async def ws_user_set_role(hass, connection, msg):
    """Change a user's role (current and new role must be in the caller's manageable set)."""
    try:
        await hass.data[DOMAIN]["user_api"].set_role(connection.user, msg["user_id"], msg["role"])
    except user_api.ApiError as err:
        connection.send_error(msg["id"], err.code, err.message)
        return
    connection.send_result(msg["id"], {"ok": True})