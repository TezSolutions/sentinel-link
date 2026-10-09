"""Wire the Sentinel Link API into the hub core (register once, toggle live)."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.components import websocket_api

from .core import API_DATA, ApiState
from .tokens import Throttle as tok_throttle
from .auth import AUTH_VIEWS
from .views import ALL_VIEWS
from .websocket import ALL_COMMANDS

_LOGGER = logging.getLogger(__name__)
_REGISTERED = "sentinel_link_api_registered"
CONF_API_ENABLED = "api_enabled"
DEFAULT_API_ENABLED = True


async def async_setup_api(hass: HomeAssistant, entry: ConfigEntry, cfg: dict[str, Any], node_id: str, version: str) -> ApiState:
    """Create the API state; HTTP views / WS commands are registered once per HA run."""
    enabled = bool(cfg.get(CONF_API_ENABLED, DEFAULT_API_ENABLED))
    old: ApiState | None = hass.data.get(API_DATA)
    if old is not None:
        old.async_stop()
    st = ApiState(hass, entry.entry_id, enabled, node_id, version)
    await st.async_load()
    hass.data[API_DATA] = st
    st.async_start()
    if not hass.data.get(_REGISTERED):
        for view in (*ALL_VIEWS, *AUTH_VIEWS):
            hass.http.register_view(view)
        for command in ALL_COMMANDS:
            websocket_api.async_register_command(hass, command)
        hass.data[_REGISTERED] = True
    _LOGGER.warning("Sentinel Link API v1 %s (/api/sentinel_link/v1/docs)", "ENABLED" if enabled else "disabled")
    return st


async def async_unload_api(hass: HomeAssistant) -> None:
    st: ApiState | None = hass.data.pop(API_DATA, None)
    if st is not None:
        st.async_stop()
        await st.store.async_save(st._data_to_save())  # flush pending audit/config


async def async_set_enabled(hass: HomeAssistant, enabled: bool) -> None:
    """Flip the API live and persist the option WITHOUT reloading the integration."""
    st: ApiState | None = hass.data.get(API_DATA)
    if st is None:
        return
    st.enabled = enabled
    st.throttle = tok_throttle()      # switching the API off/on also clears sign-in lockouts and half-finished sign-ins
    st.pending.clear()
    if not enabled:
        for sub in list(st.subscribers.values()):
            try:
                sub["close"]()
            except Exception:  # noqa: BLE001
                pass
        st.subscribers.clear()
    entry = hass.config_entries.async_get_entry(st.entry_id)
    if entry is not None:
        st.skip_reload = True
        hass.config_entries.async_update_entry(entry, options={**entry.options, CONF_API_ENABLED: enabled})
