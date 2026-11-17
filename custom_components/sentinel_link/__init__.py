"""Sentinel Link integration — entry point."""
from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback
from homeassistant.helpers.event import async_track_point_in_utc_time, async_track_time_interval
from homeassistant.util import dt as dt_util

from .cloud_client import SentinelCloudClient
from .const import (
    CONF_AVAILABILITY_BEACON,
    CONF_CLOUD_HOST,
    CONF_CLOUD_PASSWORD,
    CONF_CLOUD_PORT,
    CONF_CLOUD_TLS,
    DEFAULT_CLOUD_HOST,
    DEFAULT_CLOUD_PORT,
    LEGACY_CLOUD_PORT,
    CONF_CLOUD_USERNAME,
    CONF_METRICS_INTERVAL,
    CONF_NODE_ID,
    CONF_NOTIFICATION_FORWARD,
    CONF_REBOOT_ENABLED,
    CONF_REBOOT_TIME,
    CONF_REBOOT_WEEKDAY,
    CONF_SCRIPT_CONTROL,
    CONF_SCRIPTS,
    CONF_SYSTEM_METRICS,
    DATA_CLOUD_CLIENT,
    DATA_COORDINATOR,
    DATA_MQTT_LOCAL,
    DATA_UNSUB_HEARTBEAT,
    DATA_UNSUB_NOTIFY,
    DATA_UNSUB_REBOOT,
    DEFAULT_METRICS_INTERVAL,
    DEFAULT_NOTIFICATION_FORWARD,
    DEFAULT_REBOOT_ENABLED,
    DEFAULT_REBOOT_TIME,
    DEFAULT_REBOOT_WEEKDAY,
    DOMAIN,
    HEARTBEAT_INTERVAL,
    PLATFORMS,
    SERVICE_REBOOT_NOW,
    SERVICE_RELOAD,
    SERVICE_RUN_SCRIPT,
)
from .api.setup import async_setup_api, async_unload_api
from .coordinator import SentinelCoordinator
from .reboot_schedule import describe_schedule, next_reboot_local, parse_reboot_time, parse_weekday
from .mqtt_local import SentinelMqttLocal

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reboot helpers
# ---------------------------------------------------------------------------


def _sync_reboot() -> None:
    """Reboot the HOST device (not just the HA container).

    On sentinel nodes the HA container is privileged, runs as root, and has
    the host's ``/run/dbus`` mounted. We call the host's ``systemd-logind``
    over D-Bus to reboot the actual host. The ``sudo``/plain ``reboot``
    paths are fallbacks for other deployments.
    """
    _LOGGER.warning("Sentinel Link: executing HOST reboot")
    # 1. Preferred: systemd-logind over the mounted host dbus
    try:
        rc = subprocess.run(
            [
                "dbus-send", "--system", "--print-reply",
                "--dest=org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager.Reboot",
                "boolean:true",
            ],
            timeout=15,
            capture_output=True,
            text=True,
        )
        _LOGGER.warning(
            "Sentinel Link: logind reboot issued (rc=%s)", rc.returncode
        )
        return
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("Sentinel Link: dbus reboot failed: %s", exc)

    # 2. Fallback: sudo /sbin/reboot (needs passwordless sudo)
    try:
        subprocess.run(
            ["sudo", "/sbin/reboot"],
            timeout=10,
            capture_output=True,
            text=True,
        )
        return
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        _LOGGER.error("Sentinel Link: sudo reboot failed: %s", exc)

    # 3. Last resort: plain /sbin/reboot
    try:
        subprocess.run(
            ["/sbin/reboot"],
            timeout=10,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001
        _LOGGER.error("Sentinel Link: plain reboot failed: %s", exc)


async def _async_execute_reboot(
    hass: HomeAssistant,
    cloud_client: Any,
    node_id: str,
) -> None:
    """Publish offline status, then reboot the device."""
    # Publish offline status before going down
    try:
        cloud_client.publish_availability("offline")
        cloud_client.publish_notification(
            "Sentinel Reboot",
            f"Scheduled reboot for node {node_id} — going down now.",
        )
    except Exception:
        pass
    # Short delay to let MQTT messages flush
    await hass.async_add_executor_job(lambda: __import__("time").sleep(1))
    await hass.async_add_executor_job(_sync_reboot)


def _calculate_next_reboot(
    reboot_time_str: str, reboot_weekday: str | None = DEFAULT_REBOOT_WEEKDAY
) -> datetime:
    """Next UTC datetime for the HH:MM reboot, daily or on one weekday.

    *reboot_time_str* and the weekday are evaluated in the HA-configured
    local time zone (see ``reboot_schedule.next_reboot_local``).
    """
    local = next_reboot_local(
        dt_util.utcnow(), dt_util.get_default_time_zone(), reboot_time_str, reboot_weekday
    )
    return dt_util.as_utc(local)


@callback
def _schedule_reboot(
    hass: HomeAssistant,
    reboot_time_str: str,
    reboot_weekday: str | None,
    cloud_client: Any,
    node_id: str,
) -> Any:
    """Schedule the next daily/weekly reboot and return the unsub callback.

    Uses ``async_track_point_in_utc_time`` — fires once. The callback
    re-schedules itself for the next slot (tomorrow, or the same weekday next
    week) so a single missed reboot retries at the next slot.
    """
    label = describe_schedule(reboot_weekday)

    async def _reboot_callback(now: datetime) -> None:
        """Fire the reboot and reschedule for the next slot."""
        _LOGGER.warning(
            "Sentinel Link: scheduled %s reboot triggered at %s",
            label,
            dt_util.as_local(now).strftime("%a %H:%M:%S"),
        )
        await _async_execute_reboot(hass, cloud_client, node_id)

        # If we're still running (reboot failed or is deferred), schedule next slot
        next_dt = _calculate_next_reboot(reboot_time_str, reboot_weekday)
        # But only if the integration is still loaded
        if hass.is_running:
            new_unsub = async_track_point_in_utc_time(
                hass, _reboot_callback, next_dt
            )
            # Store the new unsub in all active entries
            for entry_id, runtime in list(hass.data.get(DOMAIN, {}).items()):
                if isinstance(runtime, dict):
                    old = runtime.get(DATA_UNSUB_REBOOT)
                    if old:
                        old()
                    runtime[DATA_UNSUB_REBOOT] = new_unsub

    next_dt = _calculate_next_reboot(reboot_time_str, reboot_weekday)
    _LOGGER.info(
        "Sentinel Link: next %s reboot scheduled at %s (local %s)",
        label,
        next_dt.isoformat(),
        dt_util.as_local(next_dt).strftime("%a %Y-%m-%d %H:%M:%S"),
    )
    return async_track_point_in_utc_time(hass, _reboot_callback, next_dt)


def _read_version() -> str:
    import json
    import pathlib

    return json.loads((pathlib.Path(__file__).parent / "manifest.json").read_text())["version"]


# ---------------------------------------------------------------------------
# Entry lifecycle
# ---------------------------------------------------------------------------


def _upgrade_cloud_transport(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Repair legacy Tez broker port 1883 (with or without TLS) to 8883 + TLS.

    Idempotent and applied to both ``data`` and ``options`` (the options flow stores a merged
    copy, and options override data). Only the default Tez broker host is touched; a customer's own
    broker, or an explicit non-default choice, is left as-is. Runs before the update listener is
    registered, so persisting the change does not trigger a reload. No version bump on purpose:
    an older Sentinel Link still reads the new keys, so a rollback is safe.
    """
    # Options may override only port/TLS or host. Decide using the effective
    # config, not each mapping separately, to preserve custom broker choices.
    effective = {**entry.data, **entry.options}
    if (
        effective.get(CONF_CLOUD_HOST) != DEFAULT_CLOUD_HOST
        or str(effective.get(CONF_CLOUD_PORT, LEGACY_CLOUD_PORT)) != str(LEGACY_CLOUD_PORT)
    ):
        return
    new_data, new_opts = dict(entry.data), dict(entry.options)
    for key, value in ((CONF_CLOUD_PORT, DEFAULT_CLOUD_PORT), (CONF_CLOUD_TLS, True)):
        new_data[key] = value
        if key in new_opts:
            new_opts[key] = value
    if new_data != dict(entry.data) or new_opts != dict(entry.options):
        _LOGGER.warning(
            "Sentinel Link: repairing the Tez cloud connection from port 1883 to TLS (8883)"
        )
        hass.config_entries.async_update_entry(entry, data=new_data, options=new_opts)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sentinel Link from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    _upgrade_cloud_transport(hass, entry)

    # Merge data + options (options override data)
    cfg: dict[str, Any] = dict(entry.data)
    cfg.update(entry.options)

    node_id: str = cfg.get(CONF_NODE_ID, "tez-home")

    # ------------------------------------------------------------------
    # 1. Create and start cloud MQTT client
    # ------------------------------------------------------------------
    ha_version = "2026.6.3"
    try:
        from homeassistant.const import __version__ as _HA_VER  # type: ignore[attr-defined]
        ha_version = _HA_VER
    except Exception:  # noqa: BLE001
        pass

    async def _on_cloud_connection_change(connected: bool) -> None:
        """Callback invoked from the cloud MQTT thread when connection state changes."""
        runtime = hass.data[DOMAIN].get(entry.entry_id, {})
        avail_sensor = runtime.get("availability_sensor")
        if avail_sensor is not None:
            avail_sensor.set_connected(connected)

    cloud_client = SentinelCloudClient(
        loop=hass.loop,
        node_id=node_id,
        host=cfg[CONF_CLOUD_HOST],
        port=cfg[CONF_CLOUD_PORT],
        username=cfg.get(CONF_CLOUD_USERNAME, ""),
        password=cfg.get(CONF_CLOUD_PASSWORD, ""),
        use_tls=cfg.get(CONF_CLOUD_TLS, False),
        ha_version=ha_version,
        on_connection_state_change=_on_cloud_connection_change,
    )
    # Start in background thread
    try:
        await hass.async_add_executor_job(cloud_client.start)
    except Exception as exc:
        _LOGGER.error(
            "Sentinel Link: cloud client start failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # 2. Create DataUpdateCoordinator
    # ------------------------------------------------------------------
    coordinator = SentinelCoordinator(hass, entry.entry_id, cfg)
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as exc:
        _LOGGER.error(
            "Sentinel Link: coordinator first refresh failed: %s",
            exc,
            exc_info=True,
        )

    # ------------------------------------------------------------------
    # 3. Local MQTT helper (kept for potential future use — no discovery)
    # ------------------------------------------------------------------
    mqtt_local = SentinelMqttLocal(hass, node_id)

    # ------------------------------------------------------------------
    # 4. Store runtime objects
    # ------------------------------------------------------------------
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_COORDINATOR: coordinator,
        DATA_CLOUD_CLIENT: cloud_client,
        DATA_MQTT_LOCAL: mqtt_local,
        "availability_sensor": None,  # filled in by binary_sensor platform
    }

    # ------------------------------------------------------------------
    # 5. Heartbeat periodic task
    # ------------------------------------------------------------------
    @callback
    def _send_heartbeat(_now: Any = None) -> None:
        cloud_client.publish_heartbeat()

    unsub_heartbeat = async_track_time_interval(
        hass,
        _send_heartbeat,
        timedelta(seconds=HEARTBEAT_INTERVAL),
    )
    hass.data[DOMAIN][entry.entry_id][DATA_UNSUB_HEARTBEAT] = unsub_heartbeat

    # ------------------------------------------------------------------
    # 6. Forward persistent_notification events to cloud
    # ------------------------------------------------------------------
    unsub_notify: Any = None
    if cfg.get(CONF_NOTIFICATION_FORWARD, DEFAULT_NOTIFICATION_FORWARD):
        @callback
        def _on_persistent_notification(event: Event) -> None:
            title = event.data.get("title", "HA Notification")
            message = event.data.get("message", "")
            cloud_client.publish_notification(title, message)

        unsub_notify = hass.bus.async_listen(
            "persistent_notifications_updated", _on_persistent_notification
        )
    hass.data[DOMAIN][entry.entry_id][DATA_UNSUB_NOTIFY] = unsub_notify

    # ------------------------------------------------------------------
    # 7. Register services
    # ------------------------------------------------------------------
    async def _handle_run_script(call: ServiceCall) -> None:
        script_id: str = call.data["script_id"]
        action: str = call.data["action"]
        scripts = cfg.get(CONF_SCRIPTS, [])
        target = next(
            (s for s in scripts if s.get("script_id") == script_id), None
        )
        if target is None:
            _LOGGER.error("Sentinel Link: run_script — unknown script_id %r", script_id)
            return
        state = await coordinator.async_run_script_command(target, action)
        await coordinator.async_request_refresh()

    async def _handle_reload(call: ServiceCall) -> None:
        await hass.config_entries.async_reload(entry.entry_id)

    if not hass.services.has_service(DOMAIN, SERVICE_RUN_SCRIPT):
        hass.services.async_register(
            DOMAIN,
            SERVICE_RUN_SCRIPT,
            _handle_run_script,
        )
    if not hass.services.has_service(DOMAIN, SERVICE_RELOAD):
        hass.services.async_register(DOMAIN, SERVICE_RELOAD, _handle_reload)

    # ------------------------------------------------------------------
    # 7b. Register reboot_now service
    # ------------------------------------------------------------------
    async def _handle_reboot_now(call: ServiceCall) -> None:
        """Immediately reboot the device."""
        _LOGGER.warning("Sentinel Link: reboot_now service called — executing reboot")
        hass.async_create_task(_async_execute_reboot(hass, cloud_client, node_id))

    if not hass.services.has_service(DOMAIN, SERVICE_REBOOT_NOW):
        hass.services.async_register(DOMAIN, SERVICE_REBOOT_NOW, _handle_reboot_now)

    # ------------------------------------------------------------------
    # 7c. Schedule daily/weekly reboot if enabled
    # ------------------------------------------------------------------
    reboot_enabled: bool = cfg.get(CONF_REBOOT_ENABLED, DEFAULT_REBOOT_ENABLED)
    unsub_reboot: Any = None

    if reboot_enabled:
        reboot_time_str: str = cfg.get(CONF_REBOOT_TIME, DEFAULT_REBOOT_TIME)
        reboot_weekday: str = cfg.get(CONF_REBOOT_WEEKDAY, DEFAULT_REBOOT_WEEKDAY)
        try:
            parse_reboot_time(reboot_time_str)
            parse_weekday(reboot_weekday)
        except ValueError as exc:
            # Never fall back to a different (e.g. daily) schedule on bad input.
            _LOGGER.error("Sentinel Link: scheduled reboot NOT set: %s", exc)
        else:
            unsub_reboot = _schedule_reboot(
                hass, reboot_time_str, reboot_weekday, cloud_client, node_id
            )
            _LOGGER.info(
                "Sentinel Link: %s reboot scheduled at %s",
                describe_schedule(reboot_weekday),
                reboot_time_str,
            )
    hass.data[DOMAIN][entry.entry_id][DATA_UNSUB_REBOOT] = unsub_reboot

    # ------------------------------------------------------------------
    # 8. Forward setup to all platforms
    # ------------------------------------------------------------------
    await hass.config_entries.async_forward_entry_setups(
        entry, [Platform.SWITCH, Platform.SENSOR, Platform.BUTTON, Platform.BINARY_SENSOR]
    )

    # Sync cloud-connected state to the binary_sensor (avoids race where
    # cloud connects before the sensor platform is set up)
    runtime = hass.data[DOMAIN].get(entry.entry_id, {})
    avail_sensor = runtime.get("availability_sensor")
    if avail_sensor is not None and cloud_client.is_connected:
        avail_sensor.set_connected(True)

    # ------------------------------------------------------------------
    # 8b. Sentinel Link API v1 (REST + realtime + RBAC); on by default
    # ------------------------------------------------------------------
    try:
        manifest_version = await hass.async_add_executor_job(_read_version)
        await async_setup_api(hass, entry, cfg, node_id, manifest_version)
    except Exception as exc:  # noqa: BLE001 - the API must never break the core integration
        _LOGGER.error("Sentinel Link: API setup failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # 9. Graceful shutdown on HA stop
    # ------------------------------------------------------------------
    @callback
    def _on_ha_stop(_event: Event) -> None:
        cloud_client.publish_availability("offline")
        cloud_client.disconnect()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_ha_stop)
    )

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(_async_update_options))

    _LOGGER.info("Sentinel Link: setup complete for node %s", node_id)
    return True


async def _async_update_options(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Handle options update — reload entry (unless only the API toggle changed)."""
    from .api.core import API_DATA

    st = hass.data.get(API_DATA)
    if st is not None and st.skip_reload:
        st.skip_reload = False
        return
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Unload platforms first
    unload_ok = await hass.config_entries.async_unload_platforms(
        entry,
        [Platform.SWITCH, Platform.SENSOR, Platform.BUTTON, Platform.BINARY_SENSOR],
    )

    if unload_ok:
        await async_unload_api(hass)
        runtime = hass.data[DOMAIN].pop(entry.entry_id, {})

        # Cancel reboot timer
        unsub_reboot = runtime.get(DATA_UNSUB_REBOOT)
        if unsub_reboot is not None:
            unsub_reboot()

        # Cancel heartbeat
        unsub_hb = runtime.get(DATA_UNSUB_HEARTBEAT)
        if unsub_hb is not None:
            unsub_hb()

        # Cancel notification listener
        unsub_notify = runtime.get(DATA_UNSUB_NOTIFY)
        if unsub_notify is not None:
            unsub_notify()

        # Unsubscribe local MQTT
        mqtt_local: SentinelMqttLocal | None = runtime.get(DATA_MQTT_LOCAL)
        if mqtt_local is not None:
            mqtt_local.unsubscribe_all()

        # Disconnect cloud client
        cloud_client: SentinelCloudClient | None = runtime.get(DATA_CLOUD_CLIENT)
        if cloud_client is not None:
            await hass.async_add_executor_job(cloud_client.disconnect)

        # Remove services if no entries remain
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_RUN_SCRIPT)
            hass.services.async_remove(DOMAIN, SERVICE_RELOAD)

    return unload_ok
