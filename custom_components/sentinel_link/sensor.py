"""Sensor platform for Sentinel Link.

Provides:
  - SentinelStatusSensor  : for scripts of type "sensor" — shows parsed stdout
  - SentinelCpuSensor     : CPU usage %
  - SentinelRamSensor     : RAM usage %
  - SentinelHddSensor     : Disk usage % (one per configured mount)
  - SentinelUptimeSensor  : Uptime since last boot (human-readable)
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_AREA,
    CONF_DISK_MOUNTS,
    CONF_ENABLED,
    CONF_MANUFACTURER,
    CONF_MODEL,
    CONF_SCRIPT_ID,
    CONF_SCRIPT_NAME,
    CONF_SCRIPT_TYPE,
    CONF_SCRIPTS,
    CONF_SYSTEM_METRICS,
    DATA_COORDINATOR,
    DEFAULT_DISK_MOUNTS,
    DOMAIN,
    MANUFACTURER,
    SCRIPT_TYPE_SENSOR,
)
from .coordinator import SentinelCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor entities from a config entry."""
    runtime: dict[str, Any] = hass.data[DOMAIN][entry.entry_id]
    coordinator: SentinelCoordinator = runtime[DATA_COORDINATOR]

    cfg: dict[str, Any] = dict(entry.data)
    cfg.update(entry.options)

    entities: list[SensorEntity] = []

    # -- Script status sensors
    for script_entry in cfg.get(CONF_SCRIPTS, []):
        if not script_entry.get(CONF_ENABLED, True):
            continue
        if script_entry.get(CONF_SCRIPT_TYPE) != SCRIPT_TYPE_SENSOR:
            continue
        entities.append(
            SentinelStatusSensor(coordinator, script_entry, entry.entry_id)
        )

    # -- System metric sensors
    if cfg.get(CONF_SYSTEM_METRICS, True):
        node_id = cfg.get("node_id", "sentinel")
        entities.append(SentinelCpuSensor(coordinator, node_id, entry.entry_id))
        entities.append(SentinelRamSensor(coordinator, node_id, entry.entry_id))
        entities.append(SentinelUptimeSensor(coordinator, node_id, entry.entry_id))

        mounts_str: str = cfg.get(CONF_DISK_MOUNTS, DEFAULT_DISK_MOUNTS)
        for mount in [m.strip() for m in mounts_str.split(",") if m.strip()]:
            entities.append(
                SentinelHddSensor(coordinator, node_id, mount, entry.entry_id)
            )
        # Temperature sensors — one entity per discovered sensor (cpu, nvme, ambient)
        # We pre-register the three expected labels; entities that have no data stay unknown
        for label in ("cpu", "nvme", "ambient"):
            entities.append(
                SentinelTempSensor(coordinator, node_id, label, entry.entry_id)
            )

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Script status sensor
# ---------------------------------------------------------------------------

class SentinelStatusSensor(CoordinatorEntity[SentinelCoordinator], SensorEntity):
    """Sensor entity that displays the parsed output of a status script."""

    def __init__(
        self,
        coordinator: SentinelCoordinator,
        script_entry: dict[str, Any],
        entry_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._script_id: str = script_entry[CONF_SCRIPT_ID]
        self._script_name: str = script_entry.get(CONF_SCRIPT_NAME, self._script_id)
        self._manufacturer: str = script_entry.get(CONF_MANUFACTURER, MANUFACTURER)
        self._model: str = script_entry.get(CONF_MODEL, "Sentinel Script")
        self._area: str = script_entry.get(CONF_AREA, "")
        self._entry_id = entry_id

        self.entity_description = SensorEntityDescription(
            key=self._script_id,
            name=self._script_name,
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_{self._script_id}_sensor"

    @property
    def name(self) -> str:
        return self._script_name

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data is None:
            return None
        scripts: dict[str, str] = self.coordinator.data.get("scripts", {})
        return scripts.get(self._script_id)

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, f"{self._entry_id}_{self._script_id}")},
            name=self._script_name,
            manufacturer=self._manufacturer,
            model=self._model,
        )
        if self._area:
            info["suggested_area"] = self._area
        return info

    @property
    def available(self) -> bool:
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
        )


# ---------------------------------------------------------------------------
# System metric sensors (CPU / RAM / HDD)
# ---------------------------------------------------------------------------

class _SystemSensorBase(CoordinatorEntity[SentinelCoordinator], SensorEntity):
    """Base for CPU / RAM / HDD sensors."""

    def __init__(
        self,
        coordinator: SentinelCoordinator,
        node_id: str,
        entry_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._node_id = node_id
        self._entry_id = entry_id

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self._entry_id}_system")},
            name=f"Sentinel Node ({self._node_id})",
            manufacturer=MANUFACTURER,
            model="Sentinel Link Gateway",
        )

    @property
    def available(self) -> bool:
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
        )


class SentinelCpuSensor(_SystemSensorBase):
    """CPU usage sensor."""

    def __init__(
        self, coordinator: SentinelCoordinator, node_id: str, entry_id: str
    ) -> None:
        super().__init__(coordinator, node_id, entry_id)
        self.entity_description = SensorEntityDescription(
            key="cpu",
            name="CPU Usage",
            native_unit_of_measurement=PERCENTAGE,
            state_class=SensorStateClass.MEASUREMENT,
            device_class=None,
            icon="mdi:cpu-64-bit",
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_cpu"

    @property
    def name(self) -> str:
        return "Sentinel CPU Usage"

    @property
    def native_value(self) -> float | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get("cpu")


class SentinelRamSensor(_SystemSensorBase):
    """RAM usage sensor."""

    def __init__(
        self, coordinator: SentinelCoordinator, node_id: str, entry_id: str
    ) -> None:
        super().__init__(coordinator, node_id, entry_id)
        self.entity_description = SensorEntityDescription(
            key="ram",
            name="RAM Usage",
            native_unit_of_measurement=PERCENTAGE,
            state_class=SensorStateClass.MEASUREMENT,
            icon="mdi:memory",
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_ram"

    @property
    def name(self) -> str:
        return "Sentinel RAM Usage"

    @property
    def native_value(self) -> float | None:
        if self.coordinator.data is None:
            return None
        ram = self.coordinator.data.get("ram", {})
        return ram.get("percent")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        ram = self.coordinator.data.get("ram", {})
        return {
            "used_mb": ram.get("used_mb"),
            "total_mb": ram.get("total_mb"),
        }


class SentinelHddSensor(_SystemSensorBase):
    """Disk usage sensor for a single mount point."""

    def __init__(
        self,
        coordinator: SentinelCoordinator,
        node_id: str,
        mount: str,
        entry_id: str,
    ) -> None:
        super().__init__(coordinator, node_id, entry_id)
        self._mount = mount
        safe_mount = mount.replace("/", "_").strip("_") or "root"
        self.entity_description = SensorEntityDescription(
            key=f"hdd_{safe_mount}",
            name=f"Disk {mount}",
            native_unit_of_measurement=PERCENTAGE,
            state_class=SensorStateClass.MEASUREMENT,
            icon="mdi:harddisk",
        )

    @property
    def unique_id(self) -> str:
        safe_mount = self._mount.replace("/", "_").strip("_") or "root"
        return f"{DOMAIN}_{self._entry_id}_hdd_{safe_mount}"

    @property
    def name(self) -> str:
        return f"Sentinel Disk {self._mount}"

    @property
    def native_value(self) -> float | None:
        if self.coordinator.data is None:
            return None
        hdd_list: list[dict[str, Any]] = self.coordinator.data.get("hdd", [])
        for hdd in hdd_list:
            if hdd.get("mount") == self._mount:
                return hdd.get("percent")
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        hdd_list: list[dict[str, Any]] = self.coordinator.data.get("hdd", [])
        for hdd in hdd_list:
            if hdd.get("mount") == self._mount:
                return {
                    "mount": self._mount,
                    "used_gb": hdd.get("used_gb"),
                    "total_gb": hdd.get("total_gb"),
                }
        return {"mount": self._mount}


# ---------------------------------------------------------------------------
# Temperature sensors  (cpu package, nvme, ambient/acpitz)
# ---------------------------------------------------------------------------

class SentinelTempSensor(_SystemSensorBase):
    """Temperature sensor entity for one thermal sensor (cpu / nvme / ambient)."""

    _LABEL_META: dict[str, tuple[str, str]] = {
        "cpu":     ("CPU Temperature",     "mdi:thermometer"),
        "nvme":    ("NVMe Temperature",    "mdi:harddisk"),
        "ambient": ("Ambient Temperature", "mdi:thermometer-lines"),
    }

    def __init__(
        self,
        coordinator: SentinelCoordinator,
        node_id: str,
        label: str,
        entry_id: str,
    ) -> None:
        super().__init__(coordinator, node_id, entry_id)
        self._label = label
        friendly_name, icon = self._LABEL_META.get(
            label, (f"{label} Temperature", "mdi:thermometer")
        )
        self.entity_description = SensorEntityDescription(
            key=f"temp_{label}",
            name=friendly_name,
            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
            device_class=SensorDeviceClass.TEMPERATURE,
            state_class=SensorStateClass.MEASUREMENT,
            icon=icon,
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_temp_{self._label}"

    @property
    def native_value(self) -> float | None:
        temp_list: list[dict[str, Any]] = self.coordinator.data.get("temp", [])
        for entry in temp_list:
            if entry.get("label") == self._label:
                return entry.get("current")
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        temp_list: list[dict[str, Any]] = self.coordinator.data.get("temp", [])
        for entry in temp_list:
            if entry.get("label") == self._label:
                return {
                    "high": entry.get("high"),
                    "critical": entry.get("critical"),
                    "label": self._label,
                }


# ---------------------------------------------------------------------------
# Uptime sensor
# ---------------------------------------------------------------------------

class SentinelUptimeSensor(_SystemSensorBase):
    """Uptime sensor — shows time since last boot in human-readable format."""

    def __init__(
        self, coordinator: SentinelCoordinator, node_id: str, entry_id: str
    ) -> None:
        super().__init__(coordinator, node_id, entry_id)
        self.entity_description = SensorEntityDescription(
            key="uptime",
            name="Uptime",
            icon="mdi:clock-start",
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_uptime"

    @property
    def name(self) -> str:
        return "Sentinel Uptime"

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get("uptime")
