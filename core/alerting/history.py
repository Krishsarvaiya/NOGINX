"""Lightweight alert history reader.

No database: alerts.log (JSON Lines, append-only, written by
FileAlertTransport) is the single source of truth for alert history.
This is how the Streamlit dashboard -- a separate OS process from the
live analyzer, with no shared memory -- sees alerts at all.

Reads only the most recent `limit` entries so memory stays bounded
regardless of how large alerts.log grows. Malformed lines are skipped
(logged, not raised) so one corrupted line can't break the whole read.
"""
from __future__ import annotations

import json
import logging
import os
from collections import deque

from core.alerting.config import ALERT_LOG_PATH, MAX_ALERT_HISTORY

logger = logging.getLogger(__name__)


def read_recent_alerts(path: str = ALERT_LOG_PATH, limit: int = MAX_ALERT_HISTORY) -> list:
    """Return up to the last `limit` alerts from alerts.log, oldest first."""
    if not os.path.exists(path):
        return []

    recent_lines = deque(maxlen=limit)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                recent_lines.append(line)

    alerts = []
    for line in recent_lines:
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("skipping malformed alerts.log line")
    return alerts
