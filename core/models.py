"""Shared data structures for the log analysis / threat detection pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class LogRecord:
    """A single parsed log line/row."""

    timestamp: datetime
    source_ip: str
    user_agent: Optional[str]
    method: str
    url: str
    status_code: int
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """A rolling session: one or more LogRecords from the same client.

    Stays open while records keep arriving within the builder's idle
    timeout; closes only after that much silence (never on a fixed
    tumbling window).
    """

    session_id: str
    session_key: str
    source_ip: str
    user_agent: Optional[str]
    started_at: datetime
    last_activity: datetime
    records: list[LogRecord] = field(default_factory=list)
    closed_at: Optional[datetime] = None

    @property
    def is_closed(self) -> bool:
        return self.closed_at is not None


@dataclass
class SessionResult:
    """Rule-evaluated output for one completed session.

    This is the structured result StreamingPipeline (and, later, the
    offline pipeline) produce instead of a raw feature dict. Phase 4
    extends this same shape with ML fields (ml_anomaly_score,
    ml_is_anomaly, fused_score, fused_severity) rather than replacing it,
    so anything already consuming rule_anomaly_score/rule_severity keeps
    working unchanged once fusion is added.
    """

    session_id: str
    session_key: str
    source_ip: str
    user_agent: Optional[str]
    window_start: datetime
    window_end: datetime
    record_count: int
    features: dict[str, float]
    rule_anomaly_score: float
    rule_severity: str
    evaluated_at: datetime

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "session_key": self.session_key,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "record_count": self.record_count,
            "features": self.features,
            "rule_anomaly_score": round(self.rule_anomaly_score, 2),
            "rule_severity": self.rule_severity,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


@dataclass
class ThreatAssessment(SessionResult):
    """The single output of the detection pipeline: a SessionResult
    (rule-based) extended with the Isolation Forest's contribution and
    the fused verdict. Extends rather than replaces SessionResult, so
    any code written against rule_anomaly_score/rule_severity keeps
    working unchanged.

    ml_anomaly_score/ml_is_anomaly/ml_model_version are None-ish
    defaults (0.0/False/None) when no trained model is loaded -- fusion
    degrades to rules-only in that case (see core.detection.fusion).
    """

    ml_anomaly_score: float = 0.0
    ml_is_anomaly: bool = False
    ml_model_version: Optional[str] = None
    fused_score: float = 0.0
    fused_severity: str = "NORMAL"
    critical_override: bool = False
    explanation: str = ""
    # Which of the decision engine's four paths produced fused_score/
    # fused_severity: RULE_OVERRIDE, ML_OVERRIDE, CONSENSUS, or FUSION
    # (see core.detection.decision_engine). Defaults to "FUSION" so any
    # code still constructing a ThreatAssessment without this field
    # (e.g. older test fixtures) is consistent with fuse_scores() being
    # the pre-decision-engine, unconditional behavior.
    decision_source: str = "FUSION"

    def to_dict(self) -> dict:
        base = super().to_dict()
        base.update(
            {
                "ml_anomaly_score": round(self.ml_anomaly_score, 2),
                "ml_is_anomaly": self.ml_is_anomaly,
                "ml_model_version": self.ml_model_version,
                "fused_score": round(self.fused_score, 2),
                "fused_severity": self.fused_severity,
                "critical_override": self.critical_override,
                "explanation": self.explanation,
                "decision_source": self.decision_source,
            }
        )
        return base


@dataclass
class Alert:
    """A single notification-worthy event, derived from a ThreatAssessment
    once AlertEngine decides it clears the severity threshold.

    Deliberately flat and small -- this is what gets serialized to
    alerts.log and shown on the dashboard, not an internal working
    structure, so it carries only what a human reading an alert needs.
    """

    id: str
    timestamp: datetime
    session_key: str
    source_ip: str
    severity: str
    threat_type: str
    fused_score: float
    rule_score: float
    ml_score: float
    explanation: str
    model_version: Optional[str]
    session_duration: float
    record_count: int
    # Which decision-engine path produced severity/fused_score for this
    # alert: RULE_OVERRIDE, ML_OVERRIDE, CONSENSUS, or FUSION. See
    # core.detection.decision_engine.
    decision_source: str = "FUSION"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "session_key": self.session_key,
            "source_ip": self.source_ip,
            "severity": self.severity,
            "threat_type": self.threat_type,
            "fused_score": round(self.fused_score, 2),
            "rule_score": round(self.rule_score, 2),
            "ml_score": round(self.ml_score, 2),
            "explanation": self.explanation,
            "model_version": self.model_version,
            "session_duration": round(self.session_duration, 2),
            "record_count": self.record_count,
            "decision_source": self.decision_source,
        }
