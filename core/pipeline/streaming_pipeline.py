"""Synchronous streaming detection pipeline.

Buffers incoming LogRecords and evaluates completed sessions (rolling
session close + feature extraction + rule-based scoring + Isolation
Forest scoring + fusion) whenever either trigger fires: 50 records
ingested, or 30 seconds elapsed -- whichever comes first -- plus an
idle-session sweep on every tick so a session still closes and gets
evaluated even if its source goes silent and never sends another
request.

The Isolation Forest model is only ever *loaded* here (via
IsolationForestDetector.load_latest()), never trained -- training is a
separate, offline-only step (scripts/train_isolation_forest.py). If no
model has been trained yet, fusion degrades gracefully to rules-only.

Contains no asyncio or I/O: callers (e.g. src/live_analyzer.py) own
transport, scheduling, and broadcasting. This keeps the pipeline plain
and synchronous, testable with ordinary datetime objects, and reusable
from a future offline entrypoint without any adaptation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from core.detection.decision_engine import DecisionStats, apply_critical_indicator_boost, build_decision_explanation, decide
from core.detection.fusion import DEFAULT_ML_WEIGHT, DEFAULT_RULE_WEIGHT
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.detection.rule_scoring import calculate_anomaly_score, classify_threat_level
from core.features.feature_extractor import extract_session_features
from core.models import LogRecord, Session, ThreatAssessment
from core.sessions.session_builder import RollingSessionBuilder

DEFAULT_BATCH_SIZE = 50
DEFAULT_BATCH_INTERVAL = timedelta(seconds=30)
DEFAULT_IDLE_TIMEOUT = timedelta(minutes=5)


class StreamingPipeline:
    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_interval: timedelta = DEFAULT_BATCH_INTERVAL,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        detector: Optional[IsolationForestDetector] = None,
        auto_load_model: bool = True,
        rule_weight: float = DEFAULT_RULE_WEIGHT,
        ml_weight: float = DEFAULT_ML_WEIGHT,
    ):
        self._builder = RollingSessionBuilder(idle_timeout=idle_timeout)
        self._batch_size = batch_size
        self._batch_interval = batch_interval
        self._buffered = 0
        self._last_flush: Optional[datetime] = None
        self._pending_closed: list[Session] = []
        self._rule_weight = rule_weight
        self._ml_weight = ml_weight
        # Evaluation-only counters (how many sessions were decided through
        # each of the four paths) -- does not affect scoring, see
        # core.detection.decision_engine.DecisionStats.
        self.decision_stats = DecisionStats()

        if detector is not None:
            self._detector = detector
        elif auto_load_model:
            self._detector = IsolationForestDetector.load_latest()
        else:
            self._detector = None

    def ingest(self, record: LogRecord) -> list[ThreatAssessment]:
        """Feed one record (uses record.timestamp as the session clock,
        same event-time semantics the offline replay uses).

        Any session this record's arrival closes (because a new record
        for the same key showed up after the previous one had gone idle)
        is held in the pending buffer, *not* evaluated immediately --
        evaluation only happens when the batch-size or time trigger
        actually fires. Returns the evaluated results if this record
        pushed the buffer to batch_size, else an empty list.
        """
        now = record.timestamp
        if self._last_flush is None:
            self._last_flush = now

        self._pending_closed.extend(self._builder.add_record(record, now=now))
        self._buffered += 1

        if self._buffered >= self._batch_size:
            return self._flush(now)
        return []

    def tick(self, now: datetime) -> list[ThreatAssessment]:
        """Call periodically with the wall clock. Catches the 30-second
        time-based trigger and closes any session that has gone idle --
        necessary because add_record() only closes a stale session when
        a *new* record for the same key arrives, which never happens for
        a source that simply stops sending requests.
        """
        if self._last_flush is None or (now - self._last_flush) < self._batch_interval:
            return []
        return self._flush(now)

    def flush_remaining(self) -> list[ThreatAssessment]:
        """Force-close every still-open session and evaluate everything
        still pending (shutdown)."""
        self._pending_closed.extend(self._builder.flush_all())
        results = [self._evaluate(session) for session in self._pending_closed]
        self._pending_closed = []
        self._buffered = 0
        return results

    def _flush(self, now: datetime) -> list[ThreatAssessment]:
        self._pending_closed.extend(self._builder.sweep(now))
        results = [self._evaluate(session) for session in self._pending_closed]

        # A session that is still actively receiving records (e.g. a
        # sustained burst/attack from one IP) never shows up in
        # sweep()'s or add_record()'s closures, since both only report
        # sessions that have gone *idle*. Without this, a session that
        # never goes quiet would never be evaluated at all -- no
        # ThreatAssessment, no alert -- until idle_timeout finally
        # elapses, which defeats live/near-real-time detection. Evaluate
        # a snapshot of open sessions too, without closing them, so they
        # keep accumulating under the same session_id across flushes.
        # Note: a long-lived session above the alert threshold will be
        # re-evaluated (and may re-alert) on every subsequent flush until
        # it actually closes -- there is no alert dedup/cooldown yet
        # (tracked as a known limitation since Phase 5).
        results.extend(self._evaluate(session) for session in self._builder.open_sessions())

        self._pending_closed = []
        self._buffered = 0
        self._last_flush = now
        return results

    def _evaluate(self, session: Session) -> ThreatAssessment:
        features = extract_session_features(session)
        # Rule engine's own output -- untouched, and this is exactly what
        # gets reported as rule_anomaly_score/"Rule Score" below. The
        # decision engine below may compare an internally-boosted COPY
        # of this value against its thresholds (see
        # apply_critical_indicator_boost), but the value calculated here
        # is never overwritten.
        rule_score = calculate_anomaly_score(features)
        rule_severity = classify_threat_level(rule_score)

        ml_score: Optional[float] = None
        ml_is_anomaly = False
        ml_version: Optional[str] = None
        if self._detector is not None:
            ml_score, ml_is_anomaly = self._detector.score(features)
            ml_version = self._detector.version

        # Decision engine (core.detection.decision_engine): checks Rule
        # Override -> ML Override -> Consensus -> Fusion, in that order,
        # instead of always blending both scores -- see that module's
        # docstring for the full rationale. Critical indicators (exact,
        # high-confidence request patterns like /etc/passwd, DROP TABLE,
        # xp_cmdshell) boost the rule score BEFORE this decision, without
        # bypassing it -- the boosted value still has to clear whichever
        # threshold applies.
        effective_rule_score = apply_critical_indicator_boost(
            rule_score, [record.url for record in session.records]
        )
        final_score, final_severity, decision_source, critical_override = decide(
            rule_severity, effective_rule_score, ml_score, self._rule_weight, self._ml_weight,
            stats=self.decision_stats,
        )
        explanation = build_decision_explanation(
            rule_severity, effective_rule_score, rule_score, ml_score, ml_is_anomaly,
            final_score, final_severity, decision_source, critical_override,
        )

        return ThreatAssessment(
            session_id=session.session_id,
            session_key=session.session_key,
            source_ip=session.source_ip,
            user_agent=session.user_agent,
            window_start=session.started_at,
            window_end=session.closed_at or session.last_activity,
            record_count=len(session.records),
            features=features,
            rule_anomaly_score=rule_score,
            rule_severity=rule_severity,
            # Detection-time metadata only -- never read back for session/
            # scoring arithmetic (only .isoformat()'d for output), so the
            # non-deprecated, timezone-aware replacement is safe here.
            evaluated_at=datetime.now(timezone.utc),
            ml_anomaly_score=ml_score if ml_score is not None else 0.0,
            ml_is_anomaly=ml_is_anomaly,
            ml_model_version=ml_version,
            fused_score=final_score,
            fused_severity=final_severity,
            critical_override=critical_override,
            explanation=explanation,
            decision_source=decision_source,
        )
