"""Local MQTT helpers for Sentinel Link.

Uses HA's built-in MQTT integration (hass.components.mqtt) exclusively.
Responsible for:
  - Publishing MQTT Discovery payloads (retained) so HA creates entities
  - Publishing script state to the local state topic
  - Subscribing to the /set command topic for switch control
  - Removing Discovery entries when scripts are removed
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from homeassistant.core import HomeAssistant

from .const import (
    DOMAIN,
    TOPIC_LOCAL_DISCOVERY,
    TOPIC_LOCAL_SET,
    TOPIC_LOCAL_STATE,
    SCRIPT_TYPE_SWITCH,
    SCRIPT_TYPE_BUTTON,
    SCRIPT_TYPE_SENSOR,
    CONF_SCRIPT_NAME,
    CONF_SCRIPT_ID,
    CONF_SCRIPT_TYPE,
    CONF_MANUFACTURER,
    CONF_MODEL,
    CONF_AREA,
    MANUFACTURER,
)

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)

CommandCallback = Callable[[str, Any], Awaitable[None] | None]


class SentinelMqttLocal:
    """Thin wrapper around HA's built-in MQTT integration."""

    def __init__(self, hass: HomeAssistant, node_id: str) -> None:
        self._hass = hass
        self._node_id = node_id
        # Maps script_id -> unsubscribe callable
        self._unsubs: dict[str, Callable[[], None]] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def publish_discovery(self, script_entry: dict[str, Any]) -> None:
        """Publish an MQTT Discovery config payload for a script entity."""
        script_id: str = script_entry[CONF_SCRIPT_ID]
        script_name: str = script_entry[CONF_SCRIPT_NAME]
        script_type: str = script_entry.get(CONF_SCRIPT_TYPE, SCRIPT_TYPE_SWITCH)
        manufacturer: str = script_entry.get(CONF_MANUFACTURER, MANUFACTURER)
        model: str = script_entry.get(CONF_MODEL, "Sentinel Script")

        state_topic = TOPIC_LOCAL_STATE.format(
            node_id=self._node_id, script_id=script_id
        )
        command_topic = TOPIC_LOCAL_SET.format(
            node_id=self._node_id, script_id=script_id
        )
        unique_id = f"{DOMAIN}_{self._node_id}_{script_id}"
        device_info = {
            "identifiers": [unique_id],
            "name": script_name,
            "manufacturer": manufacturer,
            "model": model,
            "via_device": f"{DOMAIN}_{self._node_id}",
        }

        if script_type == SCRIPT_TYPE_SWITCH:
            component = "switch"
            payload: dict[str, Any] = {
                "name": script_name,
                "unique_id": unique_id,
                "state_topic": state_topic,
                "command_topic": command_topic,
                "payload_on": "on",
                "payload_off": "off",
                "state_on": "on",
                "state_off": "off",
                "retain": False,
                "qos": 0,
                "device": device_info,
                "availability_topic": state_topic,
                "availability_template": "{{ 'online' if value != '' else 'offline' }}",
            }
        elif script_type == SCRIPT_TYPE_BUTTON:
            component = "button"
            payload = {
                "name": script_name,
                "unique_id": unique_id,
                "command_topic": command_topic,
                "payload_press": "enable",
                "retain": False,
                "qos": 0,
                "device": device_info,
            }
        elif script_type == SCRIPT_TYPE_SENSOR:
            component = "sensor"
            payload = {
                "name": script_name,
                "unique_id": unique_id,
                "state_topic": state_topic,
                "retain": False,
                "qos": 0,
                "device": device_info,
            }
        else:
            _LOGGER.warning(
                "Sentinel Link: unknown script_type %r for %s — skipping discovery",
                script_type,
                script_id,
            )
            return

        discovery_topic = TOPIC_LOCAL_DISCOVERY.format(
            component=component,
            node_id=self._node_id,
            script_id=script_id,
        )
        discovery_payload = json.dumps(payload)

        _LOGGER.debug(
            "Sentinel Link: publishing discovery for %s on %s",
            script_id,
            discovery_topic,
        )
        await self._hass.components.mqtt.async_publish(
            self._hass,
            discovery_topic,
            discovery_payload,
            qos=0,
            retain=True,
        )

    async def remove_discovery(self, script_entry: dict[str, Any]) -> None:
        """Remove an entity from MQTT Discovery by publishing an empty retained payload."""
        script_id: str = script_entry[CONF_SCRIPT_ID]
        script_type: str = script_entry.get(CONF_SCRIPT_TYPE, SCRIPT_TYPE_SWITCH)

        component_map = {
            SCRIPT_TYPE_SWITCH: "switch",
            SCRIPT_TYPE_BUTTON: "button",
            SCRIPT_TYPE_SENSOR: "sensor",
        }
        component = component_map.get(script_type, "switch")
        discovery_topic = TOPIC_LOCAL_DISCOVERY.format(
            component=component,
            node_id=self._node_id,
            script_id=script_id,
        )
        await self._hass.components.mqtt.async_publish(
            self._hass,
            discovery_topic,
            "",
            qos=0,
            retain=True,
        )
        _LOGGER.debug(
            "Sentinel Link: removed discovery for %s", script_id
        )

    # ------------------------------------------------------------------
    # State publishing
    # ------------------------------------------------------------------

    async def publish_state(self, script_id: str, state: str) -> None:
        """Publish a script's state to the local state topic."""
        topic = TOPIC_LOCAL_STATE.format(
            node_id=self._node_id, script_id=script_id
        )
        await self._hass.components.mqtt.async_publish(
            self._hass,
            topic,
            state,
            qos=0,
            retain=False,
        )

    # ------------------------------------------------------------------
    # Command subscription
    # ------------------------------------------------------------------

    async def subscribe_commands(
        self, script_id: str, callback: CommandCallback
    ) -> None:
        """Subscribe to the /set command topic for a script."""
        topic = TOPIC_LOCAL_SET.format(
            node_id=self._node_id, script_id=script_id
        )

        async def _message_received(msg: Any) -> None:
            payload = msg.payload
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="replace")
            _LOGGER.debug(
                "Sentinel Link: received command %r for script %s",
                payload,
                script_id,
            )
            await callback(script_id, payload)

        unsub = await self._hass.components.mqtt.async_subscribe(
            self._hass,
            topic,
            _message_received,
            qos=0,
        )
        # Store previous unsub if re-subscribing
        if script_id in self._unsubs:
            self._unsubs[script_id]()
        self._unsubs[script_id] = unsub
        _LOGGER.debug("Sentinel Link: subscribed to command topic %s", topic)

    def unsubscribe_commands(self, script_id: str) -> None:
        """Unsubscribe from a script's command topic."""
        unsub = self._unsubs.pop(script_id, None)
        if unsub is not None:
            unsub()

    def unsubscribe_all(self) -> None:
        """Unsubscribe from all command topics."""
        for script_id, unsub in list(self._unsubs.items()):
            try:
                unsub()
            except Exception:  # noqa: BLE001
                pass
        self._unsubs.clear()
