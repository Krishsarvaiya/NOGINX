"""Transport interface. AlertEngine depends only on this -- adding a
new transport (Slack, email, a webhook, PagerDuty, Teams) never
requires touching AlertEngine or anything in core/detection/.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Alert


class AlertTransport(ABC):
    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver one alert. May raise -- AlertEngine is responsible
        for catching and logging transport failures so one broken
        transport can never stop detection or take down the others."""
        raise NotImplementedError
