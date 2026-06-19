"""Cloud MQTT client for Sentinel Link (Flespi / any broker).

Runs paho-mqtt in its own daemon thread with loop_forever().
All publish calls are thread-safe.
All HA interactions use call_soon_threadsafe / run_coroutine_threadsafe.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from typing import TYPE_CHECKING, Any

from paho.mqtt.enums import CallbackAPIVersion
import paho.mqtt.client as mqtt

from .const import (
    TOPIC_CLOUD_CPU,
    TOPIC_CLOUD_HDD,
    TOPIC_CLOUD_HEARTBEAT,
    TOPIC_CLOUD_NOTIFY,
    TOPIC_CLOUD_RAM,
    TOPIC_CLOUD_STATUS,
    TOPIC_CLOUD_TEMP,
)

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)

# How long to wait (seconds) for the paho client to acknowledge disconnect
_DISCONNECT_TIMEOUT = 5


class SentinelCloudClient:
    """Manages the persistent paho-mqtt connection to the cloud/Flespi broker."""

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        node_id: str,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool,
        ha_version: str,
        on_connection_state_change: Any | None = None,
    ) -> None:
        self._loop = loop
        self._node_id = node_id
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._ha_version = ha_version
        self._on_connection_state_change = on_connection_state_change  # async callable

        self._connected = False
        self._shutdown = threading.Event()
        self._thread: threading.Thread | None = None

        # Build topic strings
        self._topic_status = TOPIC_CLOUD_STATUS.format(node_id=node_id)
        self._topic_heartbeat = TOPIC_CLOUD_HEARTBEAT.format(node_id=node_id)
        self._topic_cpu = TOPIC_CLOUD_CPU.format(node_id=node_id)
        self._topic_ram = TOPIC_CLOUD_RAM.format(node_id=node_id)
        self._topic_hdd = TOPIC_CLOUD_HDD.format(node_id=node_id)
        self._topic_temp = TOPIC_CLOUD_TEMP.format(node_id=node_id)
        self._topic_notify = TOPIC_CLOUD_NOTIFY.format(node_id=node_id)

        self._client = self._build_client()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_client(self) -> mqtt.Client:
        client_id = f"sentinel_link_{self._node_id}_{int(time.time())}"
        client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=client_id,
            clean_session=True,
        )

        # Credentials
        # NOTE: Flespi requires password="" (empty string), not None.
        # "self._password or None" wrongly converts "" → None → auth failure.
        if self._username:
            client.username_pw_set(
                self._username,
                self._password if self._password is not None else "",
            )

        # TLS
        if self._use_tls:
            client.tls_set()

        # LWT
        client.will_set(
            self._topic_status,
            payload="offline",
            qos=1,
            retain=True,
        )

        # Callbacks (paho v2 style)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_log = self._on_log

        return client

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        connect_flags: Any,
        reason_code: Any,
        properties: Any,
    ) -> None:
        if reason_code == 0 or (hasattr(reason_code, "is_failure") and not reason_code.is_failure):
            _LOGGER.info(
                "Sentinel Link: connected to cloud broker %s:%s",
                self._host,
                self._port,
            )
            self._connected = True
            # Publish online status
            client.publish(self._topic_status, payload="online", qos=1, retain=True)
            # Notify HA
            if self._on_connection_state_change:
                asyncio.run_coroutine_threadsafe(
                    self._on_connection_state_change(True), self._loop
                )
        else:
            _LOGGER.warning(
                "Sentinel Link: cloud broker connect failed: %s", reason_code
            )
            self._connected = False
            if self._on_connection_state_change:
                asyncio.run_coroutine_threadsafe(
                    self._on_connection_state_change(False), self._loop
                )

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        disconnect_flags: Any,
        reason_code: Any,
        properties: Any,
    ) -> None:
        self._connected = False
        if self._shutdown.is_set():
            _LOGGER.debug("Sentinel Link: cloud broker disconnected (clean shutdown)")
        else:
            _LOGGER.warning(
                "Sentinel Link: cloud broker unexpectedly disconnected: %s. "
                "paho will attempt reconnect.",
                reason_code,
            )
        if self._on_connection_state_change:
            asyncio.run_coroutine_threadsafe(
                self._on_connection_state_change(False), self._loop
            )

    def _on_log(
        self, client: mqtt.Client, userdata: Any, level: int, buf: str
    ) -> None:
        _LOGGER.debug("paho[cloud]: %s", buf)

    def _run(self) -> None:
        """Thread target — connects with exponential backoff, then loop_forever.

        Uses manual reconnect loop instead of loop_forever(retry_first_connection=True)
        so we can apply exponential backoff and stop hammering the broker (which
        causes Flespi to rate-limit / temporarily ban the token).
        """
        _LOGGER.debug("Sentinel Link: cloud MQTT thread starting")
        delay = 5  # initial reconnect delay seconds
        max_delay = 300  # cap at 5 minutes

        while not self._shutdown.is_set():
            try:
                # Rebuild client on every attempt — paho internal state becomes
                # inconsistent after loop_forever() returns on disconnect, causing
                # auth failures on subsequent reconnects with the same client object.
                self._client = self._build_client()
                _LOGGER.debug(
                    "Sentinel Link: attempting cloud broker connect %s:%s",
                    self._host,
                    self._port,
                )
                self._client.connect(self._host, self._port, keepalive=60)
                # loop_forever blocks until disconnect; disable built-in retry
                # so our outer while-loop owns the reconnect schedule
                self._client.loop_forever(retry_first_connection=False)
                # If we reach here the socket closed cleanly (or disconnect() called)
                if self._shutdown.is_set():
                    break
                # Unexpected disconnect — apply backoff then reset delay on success
                _LOGGER.debug(
                    "Sentinel Link: cloud loop_forever returned, retrying in %ds", delay
                )
                self._shutdown.wait(delay)
                delay = min(delay * 2, max_delay)
            except OSError as exc:
                # Network unreachable, DNS failure, etc.
                _LOGGER.warning(
                    "Sentinel Link: cloud broker connection error: %s. Retry in %ds.",
                    exc,
                    delay,
                )
                self._shutdown.wait(delay)
                delay = min(delay * 2, max_delay)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.error(
                    "Sentinel Link: cloud MQTT thread unexpected error: %s. Retry in %ds.",
                    exc,
                    delay,
                )
                self._shutdown.wait(delay)
                delay = min(delay * 2, max_delay)
            else:
                # Successful loop — reset backoff
                delay = 5

    # ------------------------------------------------------------------
    # Public API — all thread-safe, can be called from HA event loop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background MQTT thread."""
        self._thread = threading.Thread(
            target=self._run,
            name=f"sentinel_link_cloud_{self._node_id}",
            daemon=True,
        )
        self._thread.start()
        _LOGGER.debug("Sentinel Link: cloud MQTT thread started")

    def disconnect(self) -> None:
        """Gracefully shut down the cloud MQTT connection."""
        _LOGGER.debug("Sentinel Link: disconnecting from cloud broker")
        self._shutdown.set()
        try:
            # Publish offline before disconnecting
            if self._connected:
                self._client.publish(
                    self._topic_status, payload="offline", qos=1, retain=True
                )
        except Exception:  # noqa: BLE001
            pass
        try:
            self._client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=_DISCONNECT_TIMEOUT)

    @property
    def is_connected(self) -> bool:
        """Return True when the cloud broker connection is active."""
        return self._connected

    def publish_heartbeat(self) -> None:
        """Publish a heartbeat payload to the cloud broker."""
        if not self._connected:
            return
        try:
            uptime_s = int(time.monotonic())
            payload = json.dumps(
                {
                    "ts": int(time.time()),
                    "uptime_s": uptime_s,
                    "ha_version": self._ha_version,
                    "node_id": self._node_id,
                }
            )
            self._client.publish(self._topic_heartbeat, payload=payload, qos=0)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Sentinel Link: heartbeat publish failed: %s", exc)

    def publish_system_metrics(self, data: dict[str, Any]) -> None:
        """Publish CPU / RAM / HDD metrics to the cloud broker."""
        if not self._connected:
            return
        try:
            cpu = data.get("cpu")
            if cpu is not None:
                self._client.publish(
                    self._topic_cpu,
                    payload=json.dumps({"value": cpu, "unit": "%", "ts": int(time.time())}),
                    qos=0,
                )

            ram = data.get("ram")
            if ram is not None:
                self._client.publish(
                    self._topic_ram,
                    payload=json.dumps(
                        {
                            "percent": ram.get("percent"),
                            "used_mb": ram.get("used_mb"),
                            "total_mb": ram.get("total_mb"),
                            "ts": int(time.time()),
                        }
                    ),
                    qos=0,
                )

            hdd_list = data.get("hdd", [])
            for hdd in hdd_list:
                self._client.publish(
                    self._topic_hdd,
                    payload=json.dumps(
                        {
                            "mount": hdd.get("mount"),
                            "percent": hdd.get("percent"),
                            "used_gb": hdd.get("used_gb"),
                            "total_gb": hdd.get("total_gb"),
                            "ts": int(time.time()),
                        }
                    ),
                    qos=0,
                )

            temp_list = data.get("temp", [])
            if temp_list:
                self._client.publish(
                    self._topic_temp,
                    payload=json.dumps(
                        {
                            "sensors": temp_list,
                            "ts": int(time.time()),
                        }
                    ),
                    qos=0,
                )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Sentinel Link: system metrics publish failed: %s", exc)

    def publish_notification(self, title: str, message: str) -> None:
        """Forward a HA notification to the cloud broker."""
        if not self._connected:
            _LOGGER.debug(
                "Sentinel Link: skipping notification publish — not connected"
            )
            return
        try:
            payload = json.dumps(
                {
                    "title": title,
                    "message": message,
                    "ts": int(time.time()),
                    "node_id": self._node_id,
                }
            )
            self._client.publish(self._topic_notify, payload=payload, qos=1)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Sentinel Link: notification publish failed: %s", exc)

    def publish_availability(self, state: str) -> None:
        """Publish ``online`` or ``offline`` to the status topic."""
        if not self._connected and state != "offline":
            return
        try:
            self._client.publish(
                self._topic_status, payload=state, qos=1, retain=True
            )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Sentinel Link: availability publish failed: %s", exc)


# ---------------------------------------------------------------------------
# Synchronous connection validator (called from config flow via executor)
# ---------------------------------------------------------------------------

def validate_cloud_broker(
    host: str,
    port: int,
    username: str,
    password: str,
    use_tls: bool,
    timeout: int = 10,
) -> str | None:
    """Attempt a synchronous connection to the cloud broker.

    Returns ``None`` on success, or an error string on failure.
    """
    result: list[str | None] = [None]
    connected_event = threading.Event()

    def on_connect(client, userdata, connect_flags, reason_code, properties):
        if reason_code == 0 or (
            hasattr(reason_code, "is_failure") and not reason_code.is_failure()
        ):
            connected_event.set()
        else:
            result[0] = str(reason_code)
            connected_event.set()

    client = mqtt.Client(
        callback_api_version=CallbackAPIVersion.VERSION2,
        client_id=f"sentinel_link_test_{socket.gethostname()}",
        clean_session=True,
    )
    if username:
        client.username_pw_set(username, password or None)
    if use_tls:
        client.tls_set()
    client.on_connect = on_connect

    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()
        if not connected_event.wait(timeout=timeout):
            result[0] = "timeout"
    except Exception as exc:  # noqa: BLE001
        result[0] = str(exc)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return result[0]
