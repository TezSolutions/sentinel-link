"""Constants for the Sentinel Link integration."""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Core identity
# ---------------------------------------------------------------------------
DOMAIN = "sentinel_link"
PLATFORMS = ["switch", "sensor", "button", "binary_sensor"]

# ---------------------------------------------------------------------------
# Config-entry keys (top-level)
# ---------------------------------------------------------------------------
CONF_LOCAL_HOST = "local_host"
CONF_LOCAL_PORT = "local_port"
CONF_LOCAL_USERNAME = "local_username"
CONF_LOCAL_PASSWORD = "local_password"
CONF_LOCAL_TLS = "local_tls"

CONF_CLOUD_HOST = "cloud_host"
CONF_CLOUD_PORT = "cloud_port"
CONF_CLOUD_USERNAME = "cloud_username"
CONF_CLOUD_PASSWORD = "cloud_password"
CONF_CLOUD_TLS = "cloud_tls"

CONF_NODE_ID = "node_id"

# Features flags
CONF_AVAILABILITY_BEACON = "availability_beacon"
CONF_SYSTEM_METRICS = "system_metrics"
CONF_NOTIFICATION_FORWARD = "notification_forward"
CONF_SCRIPT_CONTROL = "script_control"
CONF_METRICS_INTERVAL = "metrics_interval"
CONF_DISK_MOUNTS = "disk_mounts"

# Script entry keys
CONF_SCRIPT_NAME = "script_name"
CONF_SCRIPT_ID = "script_id"
CONF_SCRIPT_TYPE = "script_type"
CONF_COMMAND = "command"
CONF_STATUS_ARG = "status_arg"
CONF_ON_ARG = "on_arg"
CONF_OFF_ARG = "off_arg"
CONF_PARSE_RULE = "parse_rule"
CONF_POLL_INTERVAL = "poll_interval"
CONF_AREA = "area"
CONF_MANUFACTURER = "manufacturer"
CONF_MODEL = "model"
CONF_ENABLED = "enabled"

# Scripts list key inside options
CONF_SCRIPTS = "scripts"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_LOCAL_HOST = "localhost"
DEFAULT_LOCAL_PORT = 1883
DEFAULT_LOCAL_USERNAME = "nodered"
DEFAULT_LOCAL_PASSWORD = "NodeRED#123"
DEFAULT_LOCAL_TLS = False

DEFAULT_CLOUD_HOST = "mqtt.flespi.io"
DEFAULT_CLOUD_PORT = 1883
DEFAULT_CLOUD_USERNAME = (
    "ruRjRlgZ6mCVTXQfNK3csHJJGX7L7y3iCaK0HjiffPxOR4m6T29hyBI9EldGezCr"
)
DEFAULT_CLOUD_PASSWORD = ""
DEFAULT_CLOUD_TLS = False

DEFAULT_AVAILABILITY_BEACON = True
DEFAULT_SYSTEM_METRICS = True
DEFAULT_NOTIFICATION_FORWARD = True
DEFAULT_SCRIPT_CONTROL = True
DEFAULT_METRICS_INTERVAL = 30  # seconds
DEFAULT_DISK_MOUNTS = "/"

DEFAULT_STATUS_ARG = "status"
DEFAULT_ON_ARG = "enable"
DEFAULT_OFF_ARG = "disable"
DEFAULT_POLL_INTERVAL = 30  # seconds

# ---------------------------------------------------------------------------
# Script types
# ---------------------------------------------------------------------------
SCRIPT_TYPE_SWITCH = "switch"
SCRIPT_TYPE_BUTTON = "button"
SCRIPT_TYPE_SENSOR = "sensor"
SCRIPT_TYPES = [SCRIPT_TYPE_SWITCH, SCRIPT_TYPE_BUTTON, SCRIPT_TYPE_SENSOR]

# Parse rule prefixes
PARSE_RULE_REGEX = "regex:"
PARSE_RULE_JSONPATH = "jsonpath:"
PARSE_RULE_EXITCODE = "exitcode"
PARSE_RULE_STDOUT = "stdout"

# Bundled script identifier
BUNDLED_VIGI_ALARM = "bundled:vigi_alarm"

# ---------------------------------------------------------------------------
# LOCAL MQTT topic templates  (uses HA built-in MQTT integration)
# ---------------------------------------------------------------------------
TOPIC_LOCAL_STATE = "sentinel_link/{node_id}/script/{script_id}/state"
TOPIC_LOCAL_SET = "sentinel_link/{node_id}/script/{script_id}/set"
TOPIC_LOCAL_DISCOVERY = "homeassistant/{component}/{node_id}_{script_id}/config"

# ---------------------------------------------------------------------------
# CLOUD MQTT topic templates  (uses private paho connection to Flespi)
# Token ACL: sentinel-link/# — all cloud topics MUST use this prefix
# ---------------------------------------------------------------------------
TOPIC_CLOUD_STATUS = "sentinel-link/{node_id}/status"
TOPIC_CLOUD_HEARTBEAT = "sentinel-link/{node_id}/heartbeat"
TOPIC_CLOUD_CPU = "sentinel-link/{node_id}/system/cpu"
TOPIC_CLOUD_RAM = "sentinel-link/{node_id}/system/ram"
TOPIC_CLOUD_HDD = "sentinel-link/{node_id}/system/hdd"
TOPIC_CLOUD_TEMP = "sentinel-link/{node_id}/system/temp"
TOPIC_CLOUD_NOTIFY = "sentinel-link/{node_id}/notify"

# ---------------------------------------------------------------------------
# Runtime data keys  (hass.data[DOMAIN][entry_id])
# ---------------------------------------------------------------------------
DATA_COORDINATOR = "coordinator"
DATA_CLOUD_CLIENT = "cloud_client"
DATA_MQTT_LOCAL = "mqtt_local"
DATA_UNSUB_HEARTBEAT = "unsub_heartbeat"
DATA_UNSUB_NOTIFY = "unsub_notify"

# ---------------------------------------------------------------------------
# HA service names
# ---------------------------------------------------------------------------
SERVICE_RUN_SCRIPT = "run_script"
SERVICE_RELOAD = "reload"

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL = 60  # seconds
MANUFACTURER = "TezSolutions"
