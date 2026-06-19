"""Button platform for Sentinel Link — fire-and-forget script buttons."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_AREA,
    CONF_COMMAND,
    CONF_ENABLED,
    CONF_MANUFACTURER,
    CONF_MODEL,
    CONF_ON_ARG,
    CONF_SCRIPT_ID,
    CONF_SCRIPT_NAME,
    CONF_SCRIPT_TYPE,
    CONF_SCRIPTS,
    DATA_COORDINATOR,
    DEFAULT_ON_ARG,
    DOMAIN,
    MANUFACTURER,
    SCRIPT_TYPE_BUTTON,
)
from .coordinator import SentinelCoordinator
from .script_runner import parse_status, run_script

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities from a config entry."""
    runtime: dict[str, Any] = hass.data[DOMAIN][entry.entry_id]
    coordinator: SentinelCoordinator = runtime[DATA_COORDINATOR]

    cfg: dict[str, Any] = dict(entry.data)
    cfg.update(entry.options)

    entities: list[SentinelScriptButton] = []
    for script_entry in cfg.get(CONF_SCRIPTS, []):
        if not script_entry.get(CONF_ENABLED, True):
            continue
        if script_entry.get(CONF_SCRIPT_TYPE) != SCRIPT_TYPE_BUTTON:
            continue
        entities.append(
            SentinelScriptButton(hass, coordinator, script_entry, entry.entry_id)
        )

    async_add_entities(entities)


class SentinelScriptButton(ButtonEntity):
    """A button entity that executes a script command when pressed."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: SentinelCoordinator,
        script_entry: dict[str, Any],
        entry_id: str,
    ) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._script_entry = script_entry
        self._entry_id = entry_id

        self._script_id: str = script_entry[CONF_SCRIPT_ID]
        self._name: str = script_entry.get(CONF_SCRIPT_NAME, self._script_id)
        self._command: str = script_entry.get(CONF_COMMAND, "")
        self._on_arg: str = script_entry.get(CONF_ON_ARG, DEFAULT_ON_ARG)
        self._manufacturer: str = script_entry.get(CONF_MANUFACTURER, MANUFACTURER)
        self._model: str = script_entry.get(CONF_MODEL, "Sentinel Script")
        self._area: str = script_entry.get(CONF_AREA, "")

        self.entity_description = ButtonEntityDescription(
            key=self._script_id,
            name=self._name,
            icon="mdi:play-circle-outline",
        )

    # ------------------------------------------------------------------
    # Entity identity
    # ------------------------------------------------------------------

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry_id}_{self._script_id}_button"

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
    # Press action
    # ------------------------------------------------------------------

    async def async_press(self) -> None:
        """Execute the script's on_arg command — no state tracking."""
        _LOGGER.debug(
            "Sentinel Link: button pressed — running %s %s",
            self._command,
            self._on_arg,
        )

        def _run() -> tuple[int, str, str]:
            return run_script(self._command, self._on_arg)

        rc, stdout, stderr = await self.hass.async_add_executor_job(_run)
        if rc != 0:
            _LOGGER.warning(
                "Sentinel Link: button %s returned non-zero exit code %d. stderr: %s",
                self._script_id,
                rc,
                stderr.strip(),
            )
        else:
            _LOGGER.debug(
                "Sentinel Link: button %s executed successfully. stdout: %s",
                self._script_id,
                stdout.strip(),
            )
        # Request a coordinator refresh so any related sensors update
        await self._coordinator.async_request_refresh()
