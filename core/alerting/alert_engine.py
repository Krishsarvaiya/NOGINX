"""AlertEngine: the single notification layer for the project.

Takes a ThreatAssessment (produced by StreamingPipeline, unmodified),
decides whether it clears the alert threshold, builds an Alert, and
dispatches it to every configured transport. Contains no transport-
specific logic itself -- transports are plain AlertTransport
implementations passed in at construction time.

Alert generation rule: fused_severity is compared against a single
severity-rank threshold (ALERT_THRESHOLD, default "HIGH"):
    CRITICAL, HIGH  -> always alert (both rank at or above the default
                       threshold; CRITICAL needs no special-casing to
                       be "immediate" since everything here runs
                       synchronously the moment a session is evaluated)
    MEDIUM          -> alerts only if ALERT_THRESHOLD is lowered to
                       "MEDIUM" -- this is the "configurable threshold"
    LOW, NORMAL     -> never alert
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from core.alerting.config import ALERT_THRESHOLD
from core.alerting.transports.base import AlertTransport
from core.models import Alert, ThreatAssessment

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Highest count wins; list order only breaks exact ties, so it's ordered
# most-to-least severe (added categories first, matching classifier.py's
# priority -- see core/features/feature_extractor.py for what each count
# key means).
_THREAT_TYPE_LABELS = (
    ("command_injection_count", "Command Injection"),
    ("injection_count", "SQL/Web Injection Attack"),
    ("xss_count", "Cross-Site Scripting (XSS)"),
    ("directory_traversal_count", "Directory Traversal"),
    ("sensitive_file_count", "Sensitive File Access"),
    ("brute_force_count", "Brute Force Attack"),
    ("dos_count", "DoS Pattern"),
    ("scan_count", "Reconnaissance Scan"),
    ("access_denial_count", "Access Denial"),
)


def _dominant_threat_type(features: dict) -> str:
    """Best-effort human label for the alert -- picks the highest-count
    attack category in the session's features, falling back to a
    generic label when only the ML/error-rate signal (not a specific
    rule category) drove the assessment."""
    best_label = "Anomalous Behavior"
    best_count = 0
    for key, label in _THREAT_TYPE_LABELS:
        count = features.get(key, 0)
        if count > best_count:
            best_count = count
            best_label = label
    return best_label


class AlertEngine:
    def __init__(
        self,
        transports: list[AlertTransport],
        min_severity: str = ALERT_THRESHOLD,
    ):
        self._transports = transports
        self._min_rank = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["HIGH"])

    def process(self, assessment: ThreatAssessment) -> Optional[Alert]:
        """Evaluate one ThreatAssessment. Returns the Alert if one was
        generated, else None. Never raises -- a transport failure is
        logged and the remaining transports still run.
        """
        if SEVERITY_RANK.get(assessment.fused_severity, 0) < self._min_rank:
            return None

        alert = self._build_alert(assessment)
        logger.info(
            "alert generated id=%s severity=%s ip=%s score=%.1f",
            alert.id,
            alert.severity,
            alert.source_ip,
            alert.fused_score,
        )

        for transport in self._transports:
            try:
                transport.send(alert)
            except Exception:
                logger.exception(
                    "alert transport %s failed for alert id=%s",
                    type(transport).__name__,
                    alert.id,
                )

        return alert

    @staticmethod
    def _build_alert(assessment: ThreatAssessment) -> Alert:
        duration = (assessment.window_end - assessment.window_start).total_seconds()
        return Alert(
            id=str(uuid.uuid4()),
            # Alert-generation time -- what alerts.log stores and the
            # dashboard displays (unchanged semantics: still "when this was
            # flagged", not the original request time). Only .isoformat()'d
            # downstream, never re-parsed, so the timezone-aware replacement
            # for the deprecated datetime.utcnow() is safe here.
            timestamp=datetime.now(timezone.utc),
            session_key=assessment.session_key,
            source_ip=assessment.source_ip,
            severity=assessment.fused_severity,
            threat_type=_dominant_threat_type(assessment.features),
            fused_score=assessment.fused_score,
            rule_score=assessment.rule_anomaly_score,
            ml_score=assessment.ml_anomaly_score,
            explanation=assessment.explanation,
            model_version=assessment.ml_model_version,
            session_duration=duration,
            record_count=assessment.record_count,
            decision_source=assessment.decision_source,
        )
