"""Sentinel Link integration — entry point."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback
from homeassistant.helpers.event import async_track_time_interval

from datetime import timedelta

from .cloud_client import SentinelCloudClient
from .const import (
    CONF_AVAILABILITY_BEACON,
    CONF_CLOUD_HOST,
    CONF_CLOUD_PASSWORD,
    CONF_CLOUD_PORT,
    CONF_CLOUD_TLS,
    CONF_CLOUD_USERNAME,
    CONF_METRICS_INTERVAL,
    CONF_NODE_ID,
    CONF_NOTIFICATION_FORWARD,
    CONF_SCRIPT_CONTROL,
    CONF_SCRIPTS,
    CONF_SYSTEM_METRICS,
    DATA_CLOUD_CLIENT,
    DATA_COORDINATOR,
    DATA_MQTT_LOCAL,
    DATA_UNSUB_HEARTBEAT,
    DATA_UNSUB_NOTIFY,
    DEFAULT_METRICS_INTERVAL,
    DEFAULT_NOTIFICATION_FORWARD,
    DOMAIN,
    HEARTBEAT_INTERVAL,
    PLATFORMS,
    SERVICE_RELOAD,
    SERVICE_RUN_SCRIPT,
)
from .coordinator import SentinelCoordinator
from .mqtt_local import SentinelMqttLocal

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sentinel Link from a config entry."""
    hass.data.setdefault(DOMAIN, {})

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
    await hass.async_add_executor_job(cloud_client.start)

    # ------------------------------------------------------------------
    # 2. Create DataUpdateCoordinator
    # ------------------------------------------------------------------
    coordinator = SentinelCoordinator(hass, entry.entry_id, cfg)
    await coordinator.async_config_entry_first_refresh()

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
    # 8. Forward setup to all platforms
    # ------------------------------------------------------------------
    await hass.config_entries.async_forward_entry_setups(
        entry, [Platform.SWITCH, Platform.SENSOR, Platform.BUTTON, Platform.BINARY_SENSOR]
    )

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
    """Handle options update — reload entry."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Unload platforms first
    unload_ok = await hass.config_entries.async_unload_platforms(
        entry,
        [Platform.SWITCH, Platform.SENSOR, Platform.BUTTON, Platform.BINARY_SENSOR],
    )

    if unload_ok:
        runtime = hass.data[DOMAIN].pop(entry.entry_id, {})

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
