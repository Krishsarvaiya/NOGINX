"""Decision engine: chooses the final score/severity for a session.

Replaces "always blend rule and ML scores" with a proper decision
process. Score fusion (core.detection.fusion.fuse_scores) is powerful
but has one structural weakness: it ALWAYS blends both signals, so a
detector that is extremely confident can still be diluted by the other
detector's lower confidence (e.g. a rule score of 95 blended 60/40 with
an ML score of 10 produces only 61, understating how certain the rule
engine actually was). This module fixes that by checking, in order,
whether either detector (or both together) is already confident enough
to stand on its own -- only falling through to blended fusion when
neither is.

Decision order (see decide() for the implementation; each step returns
immediately once satisfied, and always in this order)
------------------------------------------------------------------------
1. RULE_OVERRIDE  -- rule_score >= RULE_OVERRIDE_THRESHOLD.
                     The rule engine is themselves already certain,
                     independent of what the model thinks -- use the
                     rule score directly, unblended.
2. ML_OVERRIDE    -- ml_score >= ML_OVERRIDE_THRESHOLD (checked only if
                     RULE_OVERRIDE did not already fire). The model
                     detected something the keyword-based rule engine
                     structurally cannot see (e.g. pure volumetric/
                     timing anomalies) -- use the ML score directly.
3. CONSENSUS      -- both rule_score and ml_score >= CONSENSUS_THRESHOLD
                     (neither alone cleared its own, higher, override
                     bar, but both independently agree something is
                     wrong). Use the higher of the two -- two moderately
                     confident, independent detectors agreeing is
                     stronger evidence than either alone, so don't let
                     the lower one drag the score down the way blended
                     fusion would.
4. FUSION         -- none of the above. Falls through to the existing,
                     UNCHANGED core.detection.fusion.fuse_scores() --
                     the original weighted-blend behavior is preserved
                     exactly for every session that isn't confidently
                     resolved by 1-3.

Every path sets `decision_source` to one of the DECISION_* constants
below so callers (StreamingPipeline, AlertEngine, the dashboard) can
show which path produced the final verdict -- this was previously
invisible; fusion gave no indication of *how* a score was reached.

Critical indicators (see apply_critical_indicator_boost)
------------------------------------------------------------------------
A small, fixed set of very high-confidence request patterns (path
traversal to /etc/passwd or /etc/shadow, .env/.git/config disclosure,
private key exfiltration, and unambiguous SQL/command injection
payloads) add a configurable bonus to the rule score BEFORE it enters
the decision order above. This does not bypass the decision engine or
the rule engine itself (core.detection.rule_scoring.calculate_anomaly_score
is untouched, and its return value is reported as-is via
rule_anomaly_score/"Rule Score") -- it only adjusts the value the
decision engine itself compares against RULE_OVERRIDE_THRESHOLD, CONSENSUS_THRESHOLD,
etc., so a session containing one of these indicators still has to
clear the same thresholds as everything else, just from a higher
starting point.

All thresholds are named module-level constants (no inline magic
numbers) so they can be tuned or overridden by callers without editing
this file's logic.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from typing import Optional

from core.detection.fusion import build_explanation, fuse_scores
from core.detection.rule_scoring import classify_threat_level
from core.paths import _env_path

# --- Decision source labels --------------------------------------------
DECISION_RULE_OVERRIDE = "RULE_OVERRIDE"
DECISION_ML_OVERRIDE = "ML_OVERRIDE"
DECISION_CONSENSUS = "CONSENSUS"
DECISION_FUSION = "FUSION"

# Where DecisionStats.save()/load() persist counts by default, so a
# separate process (the Streamlit dashboard) can read them -- mirrors
# the alerts.log bridge pattern (live_analyzer.py and the dashboard are
# separate OS processes with no shared memory).
DECISION_STATS_PATH = _env_path("DECISION_STATS_PATH", "decision_stats.json")


class DecisionStats:
    """Evaluation-only counters: how many sessions were decided through
    each of the four paths. Purely observational -- nothing here reads
    from or feeds back into decide()'s scoring; recording a count is a
    side effect, never a factor in a decision.
    """

    def __init__(self):
        self._counts = Counter({DECISION_RULE_OVERRIDE: 0, DECISION_ML_OVERRIDE: 0, DECISION_CONSENSUS: 0, DECISION_FUSION: 0})

    def record(self, decision_source: str) -> None:
        self._counts[decision_source] += 1

    def snapshot(self) -> dict:
        """Returns a plain dict, e.g. {"RULE_OVERRIDE": 12, "ML_OVERRIDE": 3, "CONSENSUS": 8, "FUSION": 145}."""
        return dict(self._counts)

    def save(self, path: str = DECISION_STATS_PATH) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f)

    @classmethod
    def load(cls, path: str = DECISION_STATS_PATH) -> dict:
        """Reads a snapshot dict written by save(), or all-zero counts
        if the file doesn't exist yet (e.g. no sessions evaluated since
        live_analyzer.py started). Used by the dashboard, which runs in
        a separate process from whatever calls record()/save()."""
        if not os.path.exists(path):
            return {DECISION_RULE_OVERRIDE: 0, DECISION_ML_OVERRIDE: 0, DECISION_CONSENSUS: 0, DECISION_FUSION: 0}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

# --- Configurable thresholds (0-100 scale, same scale as rule/ML scores) --
# RULE_OVERRIDE_THRESHOLD / ML_OVERRIDE_THRESHOLD: calibrated (Part 1 of
# the calibration pass) to sit exactly AT the CRITICAL cutoff
# (core.detection.rule_scoring.classify_threat_level's 80), not above
# it. Rationale: the project already treats >=80 as CRITICAL on its
# own terms -- once either detector independently reaches that bar,
# blending in the other detector's possibly much lower confidence adds
# no value and can only ever pull the score down. Acting immediately at
# the same line the system already calls CRITICAL is more consistent
# than requiring an extra margin above it. Previously 85.0/85.0 (a
# margin above 80); lowered to 80.0/80.0 -- Consensus (below) and
# Fusion still cover every score that doesn't independently reach
# CRITICAL.
RULE_OVERRIDE_THRESHOLD = 80.0
ML_OVERRIDE_THRESHOLD = 80.0
# CONSENSUS_THRESHOLD: set at the HIGH cutoff (60) -- lower than the
# override thresholds, since consensus draws its strength from TWO
# independent detectors agreeing, not from either one being extreme.
# Unchanged by the Part 1 calibration.
CONSENSUS_THRESHOLD = 60.0

# --- Critical indicators ------------------------------------------------
# High-confidence request substrings, checked case-insensitively against
# a session's own URLs. Intentionally a small, hand-picked list of
# patterns that are essentially never benign (unlike the much broader
# keyword lists in core.detection.classifier, which trade some false-
# positive risk for recall) -- this boost is deliberately conservative.
CRITICAL_INDICATORS = (
    "/etc/passwd",
    "/etc/shadow",
    ".env",
    ".git/config",
    "id_rsa",
    "drop table",
    "union select",
    "xp_cmdshell",
    "whoami",
    "powershell",
    "cmd.exe",
)
CRITICAL_INDICATOR_BONUS = 15.0  # additive; final value still capped at 100


def _matches_critical_indicator(url: str) -> bool:
    lowered = url.lower()
    return any(indicator in lowered for indicator in CRITICAL_INDICATORS)


def apply_critical_indicator_boost(rule_score: float, urls: list) -> float:
    """Returns rule_score, or rule_score + CRITICAL_INDICATOR_BONUS
    (capped at 100) if any of `urls` contains a critical indicator.

    Does not modify the rule engine's own output (calculate_anomaly_score
    is not called from here and is not touched) -- this is a decision-
    layer adjustment applied to a copy of that score, used only for the
    threshold comparisons in decide() below.
    """
    if any(_matches_critical_indicator(url) for url in urls):
        return min(rule_score + CRITICAL_INDICATOR_BONUS, 100.0)
    return rule_score


def decide(
    rule_severity: str,
    rule_score: float,
    ml_anomaly_score: Optional[float],
    rule_weight: float,
    ml_weight: float,
    rule_override_threshold: float = RULE_OVERRIDE_THRESHOLD,
    ml_override_threshold: float = ML_OVERRIDE_THRESHOLD,
    consensus_threshold: float = CONSENSUS_THRESHOLD,
    stats: Optional[DecisionStats] = None,
) -> tuple:
    """Runs the 4-step decision order and returns
    (final_score, final_severity, decision_source, critical_override).

    `rule_score` should already include any critical-indicator boost
    (see apply_critical_indicator_boost) -- this function only decides
    which detector's score to trust, it doesn't compute the boost.

    `stats`, if given, has its matching counter incremented -- purely a
    side effect for evaluation (see DecisionStats), never read back
    into the decision itself. Optional and defaults to None so existing
    callers/tests are unaffected.
    """
    # 1. RULE_OVERRIDE -- rule engine alone is already certain.
    if rule_score >= rule_override_threshold:
        final_score = rule_score
        final_severity = classify_threat_level(final_score)
        if stats is not None:
            stats.record(DECISION_RULE_OVERRIDE)
        return final_score, final_severity, DECISION_RULE_OVERRIDE, rule_severity == "CRITICAL"

    # 2. ML_OVERRIDE -- model alone is already certain (only meaningful
    # when a model is actually loaded; ml_anomaly_score is None otherwise).
    if ml_anomaly_score is not None and ml_anomaly_score >= ml_override_threshold:
        final_score = ml_anomaly_score
        final_severity = classify_threat_level(final_score)
        if stats is not None:
            stats.record(DECISION_ML_OVERRIDE)
        return final_score, final_severity, DECISION_ML_OVERRIDE, rule_severity == "CRITICAL"

    # 3. CONSENSUS -- neither alone is extreme, but both independently
    # agree at a lower (but still meaningful) bar.
    if (
        ml_anomaly_score is not None
        and rule_score >= consensus_threshold
        and ml_anomaly_score >= consensus_threshold
    ):
        final_score = max(rule_score, ml_anomaly_score)
        final_severity = classify_threat_level(final_score)
        if stats is not None:
            stats.record(DECISION_CONSENSUS)
        return final_score, final_severity, DECISION_CONSENSUS, rule_severity == "CRITICAL"

    # 4. FUSION -- fall through to the existing, unmodified blend.
    fused_score, fused_severity, critical_override = fuse_scores(
        rule_severity, rule_score, ml_anomaly_score, rule_weight, ml_weight
    )
    if stats is not None:
        stats.record(DECISION_FUSION)
    return fused_score, fused_severity, DECISION_FUSION, critical_override


def build_decision_explanation(
    rule_severity: str,
    rule_score: float,
    original_rule_score: float,
    ml_anomaly_score: Optional[float],
    ml_is_anomaly: bool,
    final_score: float,
    final_severity: str,
    decision_source: str,
    critical_override: bool,
) -> str:
    """Extends the existing, unmodified build_explanation() with the
    decision source and (when applied) the critical-indicator boost --
    added as a prefix/suffix around the untouched base explanation
    rather than changing that function's own output.
    """
    parts = []
    if rule_score != original_rule_score:
        parts.append(
            f"critical_indicator_boost=+{rule_score - original_rule_score:.1f} "
            f"(raw rule_score={original_rule_score:.1f} -> effective={rule_score:.1f})"
        )
    parts.append(
        build_explanation(
            rule_severity, rule_score, ml_anomaly_score, ml_is_anomaly,
            final_score, final_severity, critical_override,
        )
    )
    parts.append(f"decision_source={decision_source}")
    return "; ".join(parts)
