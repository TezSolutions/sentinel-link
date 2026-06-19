# Sentinel Link

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/TezSolutions/sentinel-link.svg)](https://github.com/TezSolutions/sentinel-link/releases)

A Home Assistant custom integration that bridges external scripts into HA entities and forwards availability, system metrics, and notifications to a cloud MQTT broker (Flespi).

## Features

- **Script control** — expose any shell/Python script as a HA switch, button, or sensor via a 3-verb contract (`status` / `enable` / `disable`)
- **MQTT Discovery** — entities auto-register on the local Mosquitto broker; no HA YAML needed
- **Cloud availability beacon** — LWT publishes `online`/`offline` to Flespi so every node is remotely observable
- **System metrics** — CPU, RAM, HDD, and temperature (CPU package, NVMe, ambient) published every 30s
- **Notification forwarding** — HA notifications relayed to the cloud broker
- **Bundled scripts** — ships with `vigi_alarm.py` (TP-Link VIGI camera sound alarm control)

## Installation via HACS

1. In Home Assistant → HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/TezSolutions/sentinel-link` (category: Integration)
3. Install **Sentinel Link**
4. Restart Home Assistant
5. Settings → Integrations → Add Integration → **Sentinel Link**

## Configuration

The wizard has three steps:

1. **Local MQTT broker** — your per-node Mosquitto (default: `localhost:1883`, `nodered/NodeRED#123`)
2. **Sentinel Cloud broker** — Flespi token + host (`mqtt.flespi.io:1883`)
3. **Feature toggles** — availability beacon, system metrics, notification forwarding, script control

Scripts are added via the **Options Flow** (gear icon on the integration card) — no restart required.

## Script Contract

Any script added to the registry must implement three verbs:

```sh
<script> status   # stdout: parseable state, exit 0
<script> enable   # turns the thing on, exit 0
<script> disable  # turns the thing off, exit 0
```

### Bundled Scripts

| Script | Description |
|---|---|
| `vigi_alarm.py` | TP-Link VIGI C340-W camera sound alarm (enable/disable/status) |

## Cloud MQTT Topics

All published under `sentinel-link/<node_id>/`:

| Topic | Payload | Notes |
|---|---|---|
| `status` | `online` / `offline` | LWT retained |
| `heartbeat` | `{ts, uptime_s, ha_version, node_id}` | Every 60s |
| `system/cpu` | `{value, unit, ts}` | Every 30s |
| `system/ram` | `{percent, used_mb, total_mb, ts}` | Every 30s |
| `system/hdd` | `{mount, percent, used_gb, total_gb, ts}` | Every 30s |
| `system/temp` | `{sensors: [{label, current, high, critical}], ts}` | Every 30s |
| `notify` | `{title, message, ts, node_id}` | On HA notification |

## Part of TezSentinel

This integration is part of the [TezSentinel](https://github.com/TezSolutions/TezSentinel) smart home surveillance platform by [TezSolutions](https://tezsolutions.in).
