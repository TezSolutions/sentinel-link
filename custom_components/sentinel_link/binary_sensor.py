"""Binary sensor platform for Sentinel Link.

Provides SentinelAvailabilitySensor which mirrors the cloud broker
connection state (True = connected, False = disconnected).

The availability_sensor is updated via a callback from SentinelCloudClient
running in a background thread; the update is safely dispatched back to the
HA event loop via hass.loop.call_soon_threadsafe.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DATA_CLOUD_CLIENT,
    DOMAIN,
    MANUFACTURER,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the availability binary sensor."""
    runtime: dict[str, Any] = hass.data[DOMAIN][entry.entry_id]

    cfg: dict[str, Any] = dict(entry.data)
    cfg.update(entry.options)
    node_id: str = cfg.get("node_id", "sentinel")

    sensor = SentinelAvailabilitySensor(hass, node_id, entry.entry_id)

    # Register sensor so __init__.py can call set_connected()
    runtime["availability_sensor"] = sensor

    # The cloud client starts before platforms are set up, so its on_connect
    # callback fires before this sensor exists and the state is missed.
    # Sync the current connection state now to close that race window.
    cloud_client = runtime.get(DATA_CLOUD_CLIENT)
    if cloud_client is not None and cloud_client.is_connected:
        sensor._connected = True  # noqa: SLF001

    async_add_entities([sensor])


class SentinelAvailabilitySensor(BinarySensorEntity):
    """Binary sensor that is ON when the cloud broker is connected."""

    def __init__(
        self,
        hass: HomeAssistant,
        node_id: str,
        entry_id: str,
    ) -> None:
        self.hass = hass
        self._node_id = node_id
        self._entry_id = entry_id
        self._connected: bool = False

        self.entity_description = BinarySensorEntityDescription(
            key="cloud_connected",
            name="Sentinel Cloud Connected",
            device_class=BinarySensorDeviceClass.CONNECTIVITY,
            icon="mdi:cloud-check-outline",
        )

    # ------------------------------------------------------------------
    # Entity identity
    # ------------------------------------------------------------------

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_cloud_availability"

    @property
    def name(self) -> str:
        return f"Sentinel Cloud Connected ({self._node_id})"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._entry_id}_system")},
            name=f"Sentinel Node ({self._node_id})",
            manufacturer=MANUFACTURER,
            model="Sentinel Link Gateway",
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def is_on(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # External update (called from cloud_client callback → HA event loop)
    # ------------------------------------------------------------------

    def set_connected(self, connected: bool) -> None:
        """Update connection state and push to HA.

        This method is called via ``run_coroutine_threadsafe`` from the cloud
        client's background thread, so it runs in the HA event loop.
        """
        if self._connected != connected:
            self._connected = connected
            self.async_write_ha_state()
            _LOGGER.debug(
                "Sentinel Link: availability sensor → %s",
                "connected" if connected else "disconnected",
            )
