"""Console alert transport.

Uses a dedicated, non-propagating logger (rather than print()) so
output works whether or not the hosting process has configured global
logging -- this transport's whole job is to be visible on stdout, so it
can't depend on some other part of the app having called
logging.basicConfig() first.
"""
from __future__ import annotations

import logging
import sys

from core.alerting.transports.base import AlertTransport
from core.models import Alert

_logger = logging.getLogger("core.alerting.console")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


class ConsoleAlertTransport(AlertTransport):
    def send(self, alert: Alert) -> None:
        message = (
            f"[{alert.severity}]\n"
            f"IP: {alert.source_ip}\n"
            f"Threat: {alert.threat_type}\n"
            f"Score: {alert.fused_score:.1f}\n"
            f"Timestamp: {alert.timestamp.isoformat()}"
        )
        _logger.info(message)
