"""Threat score fusion: combines rule-based severity with the Isolation
Forest anomaly score into one explainable final verdict.

Algorithm
---------
1. If no ML model is available, fused_score = rule_score (rules-only
   degrade path -- fusion never blocks on an absent/incompatible model).
   Otherwise:
       fused_score = rule_weight * rule_score + ml_weight * ml_anomaly_score
   Defaults: rule_weight=0.6, ml_weight=0.4.
2. fused_severity = classify_threat_level(fused_score), reusing the same
   80/60/40/20 thresholds as the rule-only path.
3. Critical rule override: if rule_severity is already CRITICAL, the ML
   score can only ever help *explain* the assessment, never downgrade
   it -- fused_severity is forced to CRITICAL regardless of fused_score,
   and critical_override=True is set so this is visible in the output
   rather than a silent override.

Rule score input (changed this phase)
--------------------------------------
fuse_scores() now takes the session's actual continuous rule_score
(0-100, from calculate_anomaly_score()) instead of re-deriving a score
from rule_severity via a fixed NORMAL/LOW/MEDIUM/HIGH/CRITICAL bucket
lookup. The bucket approach discarded real information: a rule_score of
61 and a rule_score of 100 both rounded up to the same "HIGH -> 75"
bucket value, so two sessions with very different rule confidence fed
identical numbers into the fusion weighting. Passing the real number
through means fusion reflects the rule engine's actual confidence
gradation, not just which of 5 buckets it landed in -- consistent with
Phase 4's move away from coarse, saturating rule scoring.

RULE_SEVERITY_SCORE is kept (unused internally now) purely for backward
compatibility with scripts that import it directly (e.g.
scripts/phase7_dataset_and_ml_analysis.py).

Known trade-off: with the default 0.6/0.4 weights, a maximal ML score
(100) with zero rule signal caps fused_score at 40 (MEDIUM) -- ML alone
cannot reach HIGH/CRITICAL. This favors precision/explainability over
raw ML sensitivity and is a config knob (rule_weight/ml_weight), not a
hard limit.
"""
from __future__ import annotations

from typing import Optional

from core.detection.rule_scoring import classify_threat_level

RULE_SEVERITY_SCORE = {
    "NORMAL": 0,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}

DEFAULT_RULE_WEIGHT = 0.6
DEFAULT_ML_WEIGHT = 0.4


def fuse_scores(
    rule_severity: str,
    rule_score: float,
    ml_anomaly_score: Optional[float],
    rule_weight: float = DEFAULT_RULE_WEIGHT,
    ml_weight: float = DEFAULT_ML_WEIGHT,
) -> tuple:
    """Returns (fused_score, fused_severity, critical_override)."""
    if ml_anomaly_score is None:
        fused_score = float(rule_score)
    else:
        fused_score = rule_weight * rule_score + ml_weight * ml_anomaly_score

    fused_severity = classify_threat_level(fused_score)

    critical_override = rule_severity == "CRITICAL"
    if critical_override:
        fused_severity = "CRITICAL"

    return fused_score, fused_severity, critical_override


def build_explanation(
    rule_severity: str,
    rule_score: float,
    ml_anomaly_score: Optional[float],
    ml_is_anomaly: bool,
    fused_score: float,
    fused_severity: str,
    critical_override: bool,
) -> str:
    parts = [f"rule_severity={rule_severity} (rule_score={rule_score:.1f})"]
    if ml_anomaly_score is None:
        parts.append("ml_anomaly_score=unavailable (no trained model loaded)")
    else:
        parts.append(f"ml_anomaly_score={ml_anomaly_score:.1f} (is_anomaly={ml_is_anomaly})")
    parts.append(f"fused_score={fused_score:.1f} -> {fused_severity}")
    if critical_override:
        parts.append("critical_override=True (rule_severity was CRITICAL; cannot be downgraded by ML)")
    return "; ".join(parts)
