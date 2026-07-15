"""Simple constants for the alert system.

Intentionally not a configuration framework -- there is exactly one
place each of these is used from by default, so a plain module
constant is enough. Edit these directly (or pass overrides to
AlertEngine/FileAlertTransport/read_recent_alerts) if you need
different values.
"""
import os

from core.paths import _env_path

# Minimum fused_severity that generates an alert. HIGH and CRITICAL
# always alert regardless of this setting; LOW and NORMAL never do.
# Set to "MEDIUM" to also alert on MEDIUM.
ALERT_THRESHOLD = "HIGH"

# Append-only JSON Lines file both the live analyzer (writer) and the
# Streamlit dashboard (reader) treat as the single alert history store.
ALERT_LOG_PATH = _env_path("ALERT_LOG_PATH", "alerts.log")

# Cap on how many recent alerts the dashboard reads/holds in memory at
# once, regardless of how large alerts.log grows.
MAX_ALERT_HISTORY = 200
