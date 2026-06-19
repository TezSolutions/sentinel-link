"""Switch platform for Sentinel Link — script-controlled switches."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_AREA,
    CONF_COMMAND,
    CONF_ENABLED,
    CONF_MANUFACTURER,
    CONF_MODEL,
    CONF_OFF_ARG,
    CONF_ON_ARG,
    CONF_SCRIPT_ID,
    CONF_SCRIPT_NAME,
    CONF_SCRIPT_TYPE,
    CONF_SCRIPTS,
    DATA_COORDINATOR,
    DEFAULT_OFF_ARG,
    DEFAULT_ON_ARG,
    DOMAIN,
    MANUFACTURER,
    SCRIPT_TYPE_SWITCH,
)
from .coordinator import SentinelCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities from a config entry."""
    runtime: dict[str, Any] = hass.data[DOMAIN][entry.entry_id]
    coordinator: SentinelCoordinator = runtime[DATA_COORDINATOR]

    cfg: dict[str, Any] = dict(entry.data)
    cfg.update(entry.options)

    scripts = cfg.get(CONF_SCRIPTS, [])
    entities: list[SentinelScriptSwitch] = []

    for script_entry in scripts:
        if not script_entry.get(CONF_ENABLED, True):
            continue
        if script_entry.get(CONF_SCRIPT_TYPE) != SCRIPT_TYPE_SWITCH:
            continue
        entities.append(
            SentinelScriptSwitch(coordinator, script_entry, entry.entry_id)
        )

    async_add_entities(entities)


class SentinelScriptSwitch(CoordinatorEntity[SentinelCoordinator], SwitchEntity):
    """A switch entity backed by an external script."""

    def __init__(
        self,
        coordinator: SentinelCoordinator,
        script_entry: dict[str, Any],
        entry_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._script_entry = script_entry
        self._entry_id = entry_id

        self._script_id: str = script_entry[CONF_SCRIPT_ID]
        self._command: str = script_entry.get(CONF_COMMAND, "")
        self._on_arg: str = script_entry.get(CONF_ON_ARG, DEFAULT_ON_ARG)
        self._off_arg: str = script_entry.get(CONF_OFF_ARG, DEFAULT_OFF_ARG)
        self._name: str = script_entry.get(CONF_SCRIPT_NAME, self._script_id)
        self._manufacturer: str = script_entry.get(CONF_MANUFACTURER, MANUFACTURER)
        self._model: str = script_entry.get(CONF_MODEL, "Sentinel Script")
        self._area: str = script_entry.get(CONF_AREA, "")

        self.entity_description = SwitchEntityDescription(
            key=self._script_id,
            name=self._name,
        )

    # ------------------------------------------------------------------
    # Entity identity
    # ------------------------------------------------------------------

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_{self._script_id}_switch"

    @property
    def name(self) -> str:
        return self._name

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, f"{self._entry_id}_{self._script_id}")},
            name=self._name,
            manufacturer=self._manufacturer,
            model=self._model,
        )
        if self._area:
            info["suggested_area"] = self._area
        return info

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        scripts: dict[str, str] = self.coordinator.data.get("scripts", {})
        raw = scripts.get(self._script_id, "unknown")
        return raw.lower() in ("on", "enabled", "active", "1", "true")

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on by running the on_arg script command."""
        await self.coordinator.async_run_script_command(
            self._script_entry, self._on_arg
        )
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off by running the off_arg script command."""
        await self.coordinator.async_run_script_command(
            self._script_entry, self._off_arg
        )
        await self.coordinator.async_request_refresh()

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
        )
