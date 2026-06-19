"""Notification service for Sentinel Link.

Registers as a HA notification platform so automations can call:
  service: notify.sentinel_link
  data:
    title: "Alert"
    message: "Motion detected"

The message is forwarded to the Flespi cloud broker via SentinelCloudClient.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.notify import (
    ATTR_TITLE,
    ATTR_TITLE_DEFAULT,
    BaseNotificationService,
)
from homeassistant.core import HomeAssistant

from .const import DATA_CLOUD_CLIENT, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_get_service(
    hass: HomeAssistant,
    config: dict[str, Any],
    discovery_info: dict[str, Any] | None = None,
) -> "SentinelNotifyService | None":
    """Return the notification service for this integration.

    Called by HA when the platform is loaded.  We iterate over all active
    Sentinel Link config entries to find a cloud client.
    """
    if DOMAIN not in hass.data:
        return None

    # Return a service bound to all active entry cloud clients
    return SentinelNotifyService(hass)


class SentinelNotifyService(BaseNotificationService):
    """Send HA notifications to the Flespi cloud broker."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    def send_message(self, message: str = "", **kwargs: Any) -> None:
        """Forward notification to all active Sentinel Link cloud clients.

        ``BaseNotificationService.send_message`` is the synchronous entry
        point called by HA's notify component.  We schedule the async work
        using ``hass.async_create_task`` to stay non-blocking.
        """
        title: str = kwargs.get(ATTR_TITLE, ATTR_TITLE_DEFAULT)
        self.hass.loop.call_soon_threadsafe(
            self._publish_to_all_clients, title, message
        )

    def _publish_to_all_clients(self, title: str, message: str) -> None:
        """Publish to all active cloud clients (runs on HA event loop)."""
        domain_data: dict[str, Any] = self.hass.data.get(DOMAIN, {})
        for entry_id, runtime in domain_data.items():
            if not isinstance(runtime, dict):
                continue
            cloud_client = runtime.get(DATA_CLOUD_CLIENT)
            if cloud_client is None:
                continue
            try:
                cloud_client.publish_notification(title, message)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug(
                    "Sentinel Link: notify forward to entry %s failed: %s",
                    entry_id,
                    exc,
                )
