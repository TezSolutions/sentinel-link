"""Config flow for Sentinel Link integration."""
from __future__ import annotations

import socket
import threading
from typing import Any

import voluptuous as vol
from paho.mqtt.enums import CallbackAPIVersion
import paho.mqtt.client as mqtt

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .const import (
    BUNDLED_VIGI_ALARM,
    CONF_AREA,
    CONF_AVAILABILITY_BEACON,
    CONF_CLOUD_HOST,
    CONF_CLOUD_PASSWORD,
    CONF_CLOUD_PORT,
    CONF_CLOUD_TLS,
    CONF_CLOUD_USERNAME,
    CONF_COMMAND,
    CONF_DISK_MOUNTS,
    CONF_ENABLED,
    CONF_LOCAL_HOST,
    CONF_LOCAL_PASSWORD,
    CONF_LOCAL_PORT,
    CONF_LOCAL_TLS,
    CONF_LOCAL_USERNAME,
    CONF_MANUFACTURER,
    CONF_METRICS_INTERVAL,
    CONF_MODEL,
    CONF_NODE_ID,
    CONF_NOTIFICATION_FORWARD,
    CONF_OFF_ARG,
    CONF_ON_ARG,
    CONF_PARSE_RULE,
    CONF_POLL_INTERVAL,
    CONF_SCRIPT_CONTROL,
    CONF_SCRIPT_ID,
    CONF_SCRIPT_NAME,
    CONF_SCRIPT_TYPE,
    CONF_SCRIPTS,
    CONF_STATUS_ARG,
    CONF_SYSTEM_METRICS,
    DEFAULT_AVAILABILITY_BEACON,
    DEFAULT_CLOUD_HOST,
    DEFAULT_CLOUD_PASSWORD,
    DEFAULT_CLOUD_PORT,
    DEFAULT_CLOUD_TLS,
    DEFAULT_CLOUD_USERNAME,
    DEFAULT_DISK_MOUNTS,
    DEFAULT_LOCAL_HOST,
    DEFAULT_LOCAL_PASSWORD,
    DEFAULT_LOCAL_PORT,
    DEFAULT_LOCAL_TLS,
    DEFAULT_LOCAL_USERNAME,
    DEFAULT_METRICS_INTERVAL,
    DEFAULT_NOTIFICATION_FORWARD,
    DEFAULT_OFF_ARG,
    DEFAULT_ON_ARG,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SCRIPT_CONTROL,
    DEFAULT_STATUS_ARG,
    DEFAULT_SYSTEM_METRICS,
    DOMAIN,
    SCRIPT_TYPES,
    SCRIPT_TYPE_SWITCH,
)

_TIMEOUT = 10  # seconds for broker validation


# ---------------------------------------------------------------------------
# Synchronous broker validation (runs in executor)
# ---------------------------------------------------------------------------

def _test_mqtt_connection(
    host: str,
    port: int,
    username: str,
    password: str,
    use_tls: bool,
) -> str | None:
    """Return None on success, or an error key string on failure."""
    result: list[str | None] = [None]
    connected = threading.Event()

    def on_connect(client, userdata, connect_flags, reason_code, properties):
        is_ok = reason_code == 0 or (
            hasattr(reason_code, "is_failure") and not reason_code.is_failure()
        )
        if not is_ok:
            result[0] = "cannot_connect"
        connected.set()

    client_id = f"sentinel_link_cfgtest_{socket.gethostname()}"
    client = mqtt.Client(
        callback_api_version=CallbackAPIVersion.VERSION2,
        client_id=client_id,
        clean_session=True,
    )
    if username:
        client.username_pw_set(username, password or None)
    if use_tls:
        try:
            client.tls_set()
        except Exception:  # noqa: BLE001
            return "tls_error"
    client.on_connect = on_connect
    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()
        ok = connected.wait(timeout=_TIMEOUT)
        if not ok:
            result[0] = "timeout"
    except Exception:  # noqa: BLE001
        result[0] = "cannot_connect"
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return result[0]


# ---------------------------------------------------------------------------
# Main Config Flow
# ---------------------------------------------------------------------------

class SentinelLinkConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Three-step config flow for Sentinel Link."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Step 1: Local broker
    # ------------------------------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        return await self.async_step_local_broker(user_input)

    async def async_step_local_broker(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            error = await self.hass.async_add_executor_job(
                _test_mqtt_connection,
                user_input[CONF_LOCAL_HOST],
                user_input[CONF_LOCAL_PORT],
                user_input[CONF_LOCAL_USERNAME],
                user_input[CONF_LOCAL_PASSWORD],
                user_input[CONF_LOCAL_TLS],
            )
            if error:
                errors["base"] = error
            else:
                self._data.update(user_input)
                return await self.async_step_cloud_broker()

        schema = vol.Schema(
            {
                vol.Required(CONF_LOCAL_HOST, default=DEFAULT_LOCAL_HOST): str,
                vol.Required(CONF_LOCAL_PORT, default=DEFAULT_LOCAL_PORT): vol.Coerce(int),
                vol.Optional(CONF_LOCAL_USERNAME, default=DEFAULT_LOCAL_USERNAME): str,
                vol.Optional(CONF_LOCAL_PASSWORD, default=DEFAULT_LOCAL_PASSWORD): str,
                vol.Optional(CONF_LOCAL_TLS, default=DEFAULT_LOCAL_TLS): bool,
            }
        )
        return self.async_show_form(
            step_id="local_broker",
            data_schema=schema,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Step 2: Cloud broker
    # ------------------------------------------------------------------

    async def async_step_cloud_broker(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            error = await self.hass.async_add_executor_job(
                _test_mqtt_connection,
                user_input[CONF_CLOUD_HOST],
                user_input[CONF_CLOUD_PORT],
                user_input[CONF_CLOUD_USERNAME],
                user_input[CONF_CLOUD_PASSWORD],
                user_input[CONF_CLOUD_TLS],
            )
            if error:
                errors["base"] = error
            else:
                self._data.update(user_input)
                return await self.async_step_features()

        default_node = socket.gethostname()
        schema = vol.Schema(
            {
                vol.Required(CONF_CLOUD_HOST, default=DEFAULT_CLOUD_HOST): str,
                vol.Required(CONF_CLOUD_PORT, default=DEFAULT_CLOUD_PORT): vol.Coerce(int),
                vol.Optional(CONF_CLOUD_USERNAME, default=DEFAULT_CLOUD_USERNAME): str,
                vol.Optional(CONF_CLOUD_PASSWORD, default=DEFAULT_CLOUD_PASSWORD): str,
                vol.Optional(CONF_CLOUD_TLS, default=DEFAULT_CLOUD_TLS): bool,
                vol.Required(CONF_NODE_ID, default=default_node): str,
            }
        )
        return self.async_show_form(
            step_id="cloud_broker",
            data_schema=schema,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Step 3: Features
    # ------------------------------------------------------------------

    async def async_step_features(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            self._data.update(user_input)
            # Initialise empty scripts list
            self._data.setdefault(CONF_SCRIPTS, [])
            return self.async_create_entry(
                title=f"Sentinel Link ({self._data.get(CONF_NODE_ID, 'node')})",
                data=self._data,
            )

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_AVAILABILITY_BEACON, default=DEFAULT_AVAILABILITY_BEACON
                ): bool,
                vol.Optional(
                    CONF_SYSTEM_METRICS, default=DEFAULT_SYSTEM_METRICS
                ): bool,
                vol.Optional(
                    CONF_NOTIFICATION_FORWARD, default=DEFAULT_NOTIFICATION_FORWARD
                ): bool,
                vol.Optional(
                    CONF_SCRIPT_CONTROL, default=DEFAULT_SCRIPT_CONTROL
                ): bool,
                vol.Optional(
                    CONF_METRICS_INTERVAL, default=DEFAULT_METRICS_INTERVAL
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                vol.Optional(CONF_DISK_MOUNTS, default=DEFAULT_DISK_MOUNTS): str,
            }
        )
        return self.async_show_form(step_id="features", data_schema=schema)


# ---------------------------------------------------------------------------
# Options Flow
# ---------------------------------------------------------------------------

class SentinelLinkOptionsFlow(config_entries.OptionsFlow):
    """Options flow: manage scripts + feature toggles."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry
        # Working copy of options / data merged
        self._options: dict[str, Any] = dict(config_entry.data)
        self._options.update(config_entry.options)
        # Index of the script being edited (None = new)
        self._editing_index: int | None = None

    # ------------------------------------------------------------------
    # Main menu
    # ------------------------------------------------------------------

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show current scripts and global controls."""
        if user_input is not None:
            action = user_input.get("action", "save")
            if action == "add_script":
                self._editing_index = None
                return await self.async_step_script_edit()
            if action.startswith("edit_"):
                idx = int(action.split("_", 1)[1])
                self._editing_index = idx
                return await self.async_step_script_edit()
            if action.startswith("remove_"):
                idx = int(action.split("_", 1)[1])
                scripts: list[dict] = list(
                    self._options.get(CONF_SCRIPTS, [])
                )
                scripts.pop(idx)
                self._options[CONF_SCRIPTS] = scripts
                return await self.async_step_init()
            if action.startswith("toggle_"):
                idx = int(action.split("_", 1)[1])
                scripts = list(self._options.get(CONF_SCRIPTS, []))
                scripts[idx][CONF_ENABLED] = not scripts[idx].get(CONF_ENABLED, True)
                self._options[CONF_SCRIPTS] = scripts
                return await self.async_step_init()

            # Save global features
            self._options.update(
                {
                    CONF_AVAILABILITY_BEACON: user_input.get(
                        CONF_AVAILABILITY_BEACON,
                        self._options.get(CONF_AVAILABILITY_BEACON, DEFAULT_AVAILABILITY_BEACON),
                    ),
                    CONF_SYSTEM_METRICS: user_input.get(
                        CONF_SYSTEM_METRICS,
                        self._options.get(CONF_SYSTEM_METRICS, DEFAULT_SYSTEM_METRICS),
                    ),
                    CONF_NOTIFICATION_FORWARD: user_input.get(
                        CONF_NOTIFICATION_FORWARD,
                        self._options.get(CONF_NOTIFICATION_FORWARD, DEFAULT_NOTIFICATION_FORWARD),
                    ),
                    CONF_SCRIPT_CONTROL: user_input.get(
                        CONF_SCRIPT_CONTROL,
                        self._options.get(CONF_SCRIPT_CONTROL, DEFAULT_SCRIPT_CONTROL),
                    ),
                    CONF_METRICS_INTERVAL: user_input.get(
                        CONF_METRICS_INTERVAL,
                        self._options.get(CONF_METRICS_INTERVAL, DEFAULT_METRICS_INTERVAL),
                    ),
                    CONF_DISK_MOUNTS: user_input.get(
                        CONF_DISK_MOUNTS,
                        self._options.get(CONF_DISK_MOUNTS, DEFAULT_DISK_MOUNTS),
                    ),
                }
            )
            return self.async_create_entry(title="", data=self._options)

        scripts: list[dict] = self._options.get(CONF_SCRIPTS, [])
        # Build description with script list
        scripts_summary = (
            "\n".join(
                f"{i}: {s.get(CONF_SCRIPT_NAME, s.get(CONF_SCRIPT_ID, '?'))} "
                f"[{s.get(CONF_SCRIPT_TYPE, '?')}] "
                f"{'✓' if s.get(CONF_ENABLED, True) else '✗'}"
                for i, s in enumerate(scripts)
            )
            or "No scripts configured."
        )

        # Action choices
        action_choices = ["save", "add_script"]
        for i in range(len(scripts)):
            action_choices.append(f"edit_{i}")
            action_choices.append(f"toggle_{i}")
            action_choices.append(f"remove_{i}")

        schema = vol.Schema(
            {
                vol.Optional(
                    "action", default="save"
                ): vol.In(action_choices),
                vol.Optional(
                    CONF_AVAILABILITY_BEACON,
                    default=self._options.get(
                        CONF_AVAILABILITY_BEACON, DEFAULT_AVAILABILITY_BEACON
                    ),
                ): bool,
                vol.Optional(
                    CONF_SYSTEM_METRICS,
                    default=self._options.get(CONF_SYSTEM_METRICS, DEFAULT_SYSTEM_METRICS),
                ): bool,
                vol.Optional(
                    CONF_NOTIFICATION_FORWARD,
                    default=self._options.get(
                        CONF_NOTIFICATION_FORWARD, DEFAULT_NOTIFICATION_FORWARD
                    ),
                ): bool,
                vol.Optional(
                    CONF_SCRIPT_CONTROL,
                    default=self._options.get(CONF_SCRIPT_CONTROL, DEFAULT_SCRIPT_CONTROL),
                ): bool,
                vol.Optional(
                    CONF_METRICS_INTERVAL,
                    default=self._options.get(CONF_METRICS_INTERVAL, DEFAULT_METRICS_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                vol.Optional(
                    CONF_DISK_MOUNTS,
                    default=self._options.get(CONF_DISK_MOUNTS, DEFAULT_DISK_MOUNTS),
                ): str,
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            description_placeholders={"scripts_list": scripts_summary},
        )

    # ------------------------------------------------------------------
    # Script add / edit sub-form
    # ------------------------------------------------------------------

    async def async_step_script_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        scripts: list[dict] = list(self._options.get(CONF_SCRIPTS, []))

        # Load existing values if editing
        existing: dict[str, Any] = {}
        if self._editing_index is not None and self._editing_index < len(scripts):
            existing = scripts[self._editing_index]

        if user_input is not None:
            # Basic validation
            script_id: str = user_input.get(CONF_SCRIPT_ID, "").strip()
            if not script_id:
                errors[CONF_SCRIPT_ID] = "script_id_required"
            elif not script_id.replace("_", "").replace("-", "").isalnum():
                errors[CONF_SCRIPT_ID] = "script_id_invalid"
            elif self._editing_index is None and any(
                s.get(CONF_SCRIPT_ID) == script_id for s in scripts
            ):
                errors[CONF_SCRIPT_ID] = "script_id_duplicate"

            if not errors:
                entry = {
                    CONF_SCRIPT_NAME: user_input.get(CONF_SCRIPT_NAME, script_id),
                    CONF_SCRIPT_ID: script_id,
                    CONF_SCRIPT_TYPE: user_input.get(CONF_SCRIPT_TYPE, SCRIPT_TYPE_SWITCH),
                    CONF_COMMAND: user_input.get(CONF_COMMAND, BUNDLED_VIGI_ALARM),
                    CONF_STATUS_ARG: user_input.get(CONF_STATUS_ARG, DEFAULT_STATUS_ARG),
                    CONF_ON_ARG: user_input.get(CONF_ON_ARG, DEFAULT_ON_ARG),
                    CONF_OFF_ARG: user_input.get(CONF_OFF_ARG, DEFAULT_OFF_ARG),
                    CONF_PARSE_RULE: user_input.get(CONF_PARSE_RULE, "exitcode"),
                    CONF_POLL_INTERVAL: user_input.get(
                        CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
                    ),
                    CONF_AREA: user_input.get(CONF_AREA, ""),
                    CONF_MANUFACTURER: user_input.get(CONF_MANUFACTURER, "TezSolutions"),
                    CONF_MODEL: user_input.get(CONF_MODEL, "Sentinel Script"),
                    CONF_ENABLED: True,
                }
                if self._editing_index is not None:
                    scripts[self._editing_index] = entry
                else:
                    scripts.append(entry)
                self._options[CONF_SCRIPTS] = scripts
                return await self.async_step_init()

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCRIPT_NAME,
                    default=existing.get(CONF_SCRIPT_NAME, ""),
                ): str,
                vol.Required(
                    CONF_SCRIPT_ID,
                    default=existing.get(CONF_SCRIPT_ID, ""),
                ): str,
                vol.Required(
                    CONF_SCRIPT_TYPE,
                    default=existing.get(CONF_SCRIPT_TYPE, SCRIPT_TYPE_SWITCH),
                ): vol.In(SCRIPT_TYPES),
                vol.Required(
                    CONF_COMMAND,
                    default=existing.get(CONF_COMMAND, BUNDLED_VIGI_ALARM),
                ): str,
                vol.Optional(
                    CONF_STATUS_ARG,
                    default=existing.get(CONF_STATUS_ARG, DEFAULT_STATUS_ARG),
                ): str,
                vol.Optional(
                    CONF_ON_ARG,
                    default=existing.get(CONF_ON_ARG, DEFAULT_ON_ARG),
                ): str,
                vol.Optional(
                    CONF_OFF_ARG,
                    default=existing.get(CONF_OFF_ARG, DEFAULT_OFF_ARG),
                ): str,
                vol.Required(
                    CONF_PARSE_RULE,
                    default=existing.get(CONF_PARSE_RULE, "exitcode"),
                ): str,
                vol.Optional(
                    CONF_POLL_INTERVAL,
                    default=existing.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                vol.Optional(
                    CONF_AREA, default=existing.get(CONF_AREA, "")
                ): str,
                vol.Optional(
                    CONF_MANUFACTURER,
                    default=existing.get(CONF_MANUFACTURER, "TezSolutions"),
                ): str,
                vol.Optional(
                    CONF_MODEL,
                    default=existing.get(CONF_MODEL, "Sentinel Script"),
                ): str,
            }
        )
        return self.async_show_form(
            step_id="script_edit",
            data_schema=schema,
            errors=errors,
        )


# ---------------------------------------------------------------------------
# Register OptionsFlow
# ---------------------------------------------------------------------------

@config_entries.HANDLERS.register(DOMAIN)
class _SentinelLinkConfigFlowRegistrar(SentinelLinkConfigFlow):
    """Alias that also attaches the OptionsFlow handler."""

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> SentinelLinkOptionsFlow:
        return SentinelLinkOptionsFlow(config_entry)
