"""File alert transport: append-only JSON Lines to alerts.log.

This is the durable side of the alert system -- the Streamlit dashboard
(a separate OS process from the live analyzer) reads alert history back
out of this file rather than through any in-memory channel, since
there is no shared memory between those two processes. See
core.alerting.history.read_recent_alerts.

Deliberately raises on failure rather than swallowing it -- AlertEngine
is the layer responsible for catching transport errors so one failing
transport can't take down detection or the other transports.
"""
from __future__ import annotations

import json

from core.alerting.config import ALERT_LOG_PATH
from core.alerting.transports.base import AlertTransport
from core.models import Alert


class FileAlertTransport(AlertTransport):
    def __init__(self, path: str = ALERT_LOG_PATH):
        self.path = path

    def send(self, alert: Alert) -> None:
        line = json.dumps(alert.to_dict())
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
