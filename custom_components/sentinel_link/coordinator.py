"""DataUpdateCoordinator for Sentinel Link.

Polls:
  - Each enabled script's status command (via executor to avoid blocking the loop)
  - psutil metrics: CPU, RAM, HDD mounts

After each successful update the cloud client receives the fresh metrics.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import psutil

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_COMMAND,
    CONF_DISK_MOUNTS,
    CONF_ENABLED,
    CONF_OFF_ARG,
    CONF_ON_ARG,
    CONF_PARSE_RULE,
    CONF_POLL_INTERVAL,
    CONF_SCRIPT_ID,
    CONF_SCRIPTS,
    CONF_STATUS_ARG,
    CONF_SYSTEM_METRICS,
    DATA_CLOUD_CLIENT,
    DEFAULT_DISK_MOUNTS,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)
from .script_runner import parse_status, run_script

if TYPE_CHECKING:
    from .cloud_client import SentinelCloudClient

_LOGGER = logging.getLogger(__name__)


class SentinelCoordinator(DataUpdateCoordinator):
    """Central coordinator — drives all periodic work for one config entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        options: dict[str, Any],
    ) -> None:
        self._entry_id = entry_id
        self._options = options

        poll_interval: int = options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry_id}",
            update_interval=timedelta(seconds=poll_interval),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _cloud_client(self) -> "SentinelCloudClient | None":
        try:
            return self.hass.data[DOMAIN][self._entry_id].get(DATA_CLOUD_CLIENT)
        except (KeyError, AttributeError):
            return None

    def _get_scripts(self) -> list[dict[str, Any]]:
        """Return the list of enabled script entries from options."""
        scripts: list[dict[str, Any]] = self._options.get(CONF_SCRIPTS, [])
        return [s for s in scripts if s.get(CONF_ENABLED, True)]

    # ------------------------------------------------------------------
    # Script polling
    # ------------------------------------------------------------------

    def _poll_script(self, script_entry: dict[str, Any]) -> tuple[str, str]:
        """Synchronous — run a script's status command and parse output.

        Returns ``(script_id, parsed_state)``.
        """
        script_id: str = script_entry[CONF_SCRIPT_ID]
        command: str = script_entry.get(CONF_COMMAND, "")
        status_arg: str = script_entry.get(CONF_STATUS_ARG, "status")
        parse_rule: str = script_entry.get(CONF_PARSE_RULE, "exitcode")

        try:
            rc, stdout, stderr = run_script(command, status_arg)
            state = parse_status(stdout, stderr, rc, parse_rule)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning(
                "Sentinel Link: error polling script %s: %s", script_id, exc
            )
            state = "unknown"

        return script_id, state

    # ------------------------------------------------------------------
    # System metrics
    # ------------------------------------------------------------------

    def _collect_metrics(self) -> dict[str, Any]:
        """Synchronous psutil calls — must be run via executor."""
        try:
            cpu = psutil.cpu_percent(interval=1)
        except Exception:  # noqa: BLE001
            cpu = 0.0

        try:
            mem = psutil.virtual_memory()
            ram: dict[str, Any] = {
                "percent": mem.percent,
                "used_mb": round(mem.used / 1024 / 1024, 1),
                "total_mb": round(mem.total / 1024 / 1024, 1),
            }
        except Exception:  # noqa: BLE001
            ram = {"percent": 0.0, "used_mb": 0.0, "total_mb": 0.0}

        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        # Convert to human-readable format
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

        raw_mounts: str = self._options.get(CONF_DISK_MOUNTS, DEFAULT_DISK_MOUNTS)
        mount_list = [m.strip() for m in raw_mounts.split(",") if m.strip()]
        hdd: list[dict[str, Any]] = []
        for mount in mount_list:
            try:
                usage = psutil.disk_usage(mount)
                hdd.append(
                    {
                        "mount": mount,
                        "percent": usage.percent,
                        "used_gb": round(usage.used / 1024 / 1024 / 1024, 2),
                        "total_gb": round(usage.total / 1024 / 1024 / 1024, 2),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug(
                    "Sentinel Link: could not read disk usage for %s: %s", mount, exc
                )

        # Temperature sensors — architecture-flexible collection.
        # Different platforms expose different psutil thermal keys:
        #   x86 Intel : coretemp (CPU package), nvme, acpitz (ACPI ambient)
        #   RPi 4/5   : cpu_thermal (SoC), rp1_adc (RP1 southbridge, RPi5)
        #   RK aarch64: soc_thermal / gpu_thermal
        #   Jetson    : cpu-thermal / gpu-thermal / tj-thermal / cv*-thermal
        #               / soc*-thermal (hyphenated)
        # Thermal-zone naming varies (dashes vs underscores), so keys are
        # normalized before matching. Keys not present on the host are
        # skipped; unknown keys fall back to the generic handler at the end
        # so nothing is silently dropped.
        temp: list[dict[str, Any]] = []
        try:
            raw_temps = psutil.sensors_temperatures()
            # Normalize keys: lower() + dashes→underscores so "cpu-thermal"
            # (Jetson) and "cpu_thermal" (RPi) collapse to one canonical key.
            # Multi-zone clusters (cv0/cv1/cv2, soc0/soc1/soc2) are folded
            # into a single base key, keeping the hottest entry — for a
            # health metric the peak of the cluster is what matters.
            all_temps: dict[str, list[Any]] = {}
            for raw_key, entries in raw_temps.items():
                base = raw_key.strip().lower().replace("-", "_").replace(" ", "_")
                base = re.sub(r"^(cv|soc)\d+_thermal$", r"\1_thermal", base)
                bucket = all_temps.setdefault(base, [])
                bucket.extend(entries)
            # Keep only the hottest entry per bucket to avoid duplicates.
            all_temps = {
                k: [max(v, key=lambda e: e.current)] for k, v in all_temps.items()
            }

            # Canonical key → (friendly label, preferred entry match substring).
            # Order matters: the first claim of a label wins, so the most
            # critical zone for each label is listed first.
            wanted: dict[str, tuple[str, str]] = {
                "tj_thermal":  ("cpu",     ""),         # junction temp (hottest die point)
                "coretemp":    ("cpu",     "package"),  # x86 CPU die (Package id 0)
                "cpu_thermal": ("cpu",     ""),         # RPi SoC / Jetson CPU
                "soc_thermal": ("cpu",     ""),         # generic aarch64 SoC
                "nvme":        ("nvme",    ""),         # NVMe SSD composite
                "acpitz":      ("ambient", ""),         # ACPI ambient / motherboard
                "rp1_adc":     ("rp1",     ""),         # RPi5 RP1 southbridge
                "gpu_thermal": ("gpu",     ""),         # aarch64 / Jetson GPU
                "cv_thermal":  ("cv",      ""),         # Jetson CV accelerator cluster
            }

            seen_labels: set[str] = set()

            def _add(entries: list[Any], label: str, match: str) -> None:
                if not entries or label in seen_labels:
                    return
                entry = next(
                    (e for e in entries if match and match in (e.label or "").lower()),
                    entries[0],
                )
                temp.append(
                    {
                        "label": label,
                        "current": round(entry.current, 1),
                        "high": round(entry.high, 1) if entry.high else None,
                        "critical": round(entry.critical, 1) if entry.critical else None,
                    }
                )
                seen_labels.add(label)

            for sensor_key, (label, match) in wanted.items():
                _add(all_temps.get(sensor_key, []), label, match)

            # Generic fallback: publish any remaining thermal zones under
            # their raw sensor key so new/arch-specific hardware still shows up.
            for sensor_key, entries in all_temps.items():
                if sensor_key in wanted:
                    continue
                for idx, entry in enumerate(entries):
                    raw = (entry.label or "").strip().lower().replace(" ", "_").replace("-", "_")
                    if not raw:
                        raw = sensor_key if len(entries) == 1 else f"{sensor_key}_{idx}"
                    label = raw
                    if label in seen_labels:
                        continue
                    temp.append(
                        {
                            "label": label,
                            "current": round(entry.current, 1),
                            "high": round(entry.high, 1) if entry.high else None,
                            "critical": round(entry.critical, 1) if entry.critical else None,
                        }
                    )
                    seen_labels.add(label)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Sentinel Link: could not read temperatures: %s", exc)

        return {"cpu": cpu, "ram": ram, "hdd": hdd, "temp": temp, "uptime": uptime_str}

    # ------------------------------------------------------------------
    # DataUpdateCoordinator overrides
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch all data — scripts + system metrics."""
        scripts: dict[str, str] = {}
        for script_entry in self._get_scripts():
            sid, state = await self.hass.async_add_executor_job(
                self._poll_script, script_entry
            )
            scripts[sid] = state

        # System metrics
        want_metrics: bool = self._options.get(CONF_SYSTEM_METRICS, True)
        metrics: dict[str, Any] = {"cpu": 0.0, "ram": {}, "hdd": []}
        if want_metrics:
            try:
                metrics = await self.hass.async_add_executor_job(self._collect_metrics)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning(
                    "Sentinel Link: system metrics collection failed: %s", exc
                )

        combined: dict[str, Any] = {
            "scripts": scripts,
            **metrics,
        }

        # Forward to cloud client (non-blocking — cloud client is thread-safe)
        cloud = self._cloud_client
        if cloud is not None and want_metrics:
            try:
                cloud.publish_system_metrics(metrics)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug(
                    "Sentinel Link: cloud metrics forward failed: %s", exc
                )

        return combined

    # ------------------------------------------------------------------
    # Convenience methods called from entities
    # ------------------------------------------------------------------

    async def async_run_script_command(
        self, script_entry: dict[str, Any], arg: str
    ) -> str:
        """Run a script with the given argument and return parsed state.

        Wraps ``run_script`` + ``parse_status`` in the executor.
        """
        command: str = script_entry.get(CONF_COMMAND, "")
        parse_rule: str = script_entry.get(CONF_PARSE_RULE, "exitcode")

        def _run() -> str:
            rc, stdout, stderr = run_script(command, arg)
            return parse_status(stdout, stderr, rc, parse_rule)

        return await self.hass.async_add_executor_job(_run)

    def update_options(self, new_options: dict[str, Any]) -> None:
        """Update the cached options (called after OptionsFlow saves)."""
        self._options = new_options
        new_interval = new_options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL)
        self.update_interval = timedelta(seconds=new_interval)
