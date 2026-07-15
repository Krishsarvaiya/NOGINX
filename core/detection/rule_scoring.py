"""Session-level rule-based anomaly scoring.

Operates on any dict-like/Series object exposing the feature
extractor's keys (core.features.feature_extractor.FEATURE_NAMES) --
works identically for a pandas row (offline) or a plain dict (live), so
both share this one implementation.

This is rule-based severity only. An Isolation Forest anomaly score is
computed alongside this (core/detection/isolation_forest_detector.py)
and the two are fused (core/detection/fusion.py) -- this function does
not see or affect the ML score.

Scoring rationale (rewritten this phase; see docs/DETECTION_IMPROVEMENTS_REPORT.md
for the full before/after and worked examples)
------------------------------------------------------------------------
Two designs were tried before this one:

1. The ORIGINAL design normalized each count-based signal with
   `min(count / N, 1.0)` -- a hard linear ramp that hits its ceiling at
   a small, fixed count (5 or 10) and then goes completely flat. Two
   sessions with 10 and 200 injection attempts scored identically once
   both crossed that ceiling ("early saturation").

2. A first rewrite this phase replaced every `min(x/N, 1)` with a
   smoother saturating curve `x/(x+k)` but kept the *same overall
   shape*: a weighted AVERAGE across every category, divided by the sum
   of every weight. That shape has a structural problem once there are
   many categories (this phase added several): a single strongly-firing
   category (e.g. 3 clear SQL injection hits) can only ever contribute
   its own weight's share of the *whole* sum, so the other dozen
   near-zero categories permanently drag the average down. Verified
   empirically -- a realistic 3-payload SQL injection session scored
   ~18/100 under that design despite being an obvious attack.

This version instead takes the MAX across attack categories as the
score's primary driver, then adds a smaller bonus from corroborating,
category-agnostic signals:

    score = min(100, best_matching_category_score + supporting_bonus)

This means the single most-triggered attack category can, by itself,
push a session into HIGH/CRITICAL -- exactly what "a single clear SQL
injection hit should count for something" and "recon should reach HIGH"
require -- while still scaling up smoothly with volume (`x/(x+k)` inside
each category, so 200 hits still outscores 20) and still rewarding
sessions that show *multiple* corroborating signals (encoded payloads,
bursty timing, high average classifier confidence, elevated error rate,
URL diversity) over otherwise-identical ones that don't.

Per-category ceiling (`_CEILINGS`) reflects relative real-world
severity: command injection (RCE-adjacent) > SQL injection > XSS /
directory traversal > sensitive-file access ~ brute force >
reconnaissance > DoS > access-denial noise. Per-category `k` (half-max
point) reflects how many occurrences make a category dangerous:
small k (2-3) for attack types that are dangerous even in isolation,
larger k (8-10) for signals that are only meaningful in volume
(reconnaissance scanning, repeated access-denial probing).
"""
from __future__ import annotations


def _saturating(count: float, k: float) -> float:
    """Maps count in [0, inf) to [0, 1), approaching 1 as count grows.

    x=0 -> 0.0; x=k -> 0.5; x=3k -> 0.75; never reaches exactly 1.0, so
    larger counts always score at least marginally higher than smaller
    ones -- no hard ceiling.
    """
    count = max(count, 0.0)
    return count / (count + k)


# (feature key, half-max point k, category ceiling) -- ceiling is the
# max score (out of 100) this category alone can contribute to the
# primary/MAX term before the corroborating-signal bonus is added.
_CATEGORY_SPEC = (
    ("command_injection_count", 2, 95),
    ("injection_count", 3, 90),
    ("xss_count", 3, 85),
    ("directory_traversal_count", 3, 85),
    ("sensitive_file_count", 3, 80),
    # brute_force is handled separately below (its ceiling contribution
    # is additionally scaled by failed_login_ratio)
    ("scan_count", 10, 75),
    ("dos_count", 3, 70),
    ("access_denial_count", 8, 55),
)
_BRUTE_FORCE_K = 8
_BRUTE_FORCE_CEILING = 85

# Corroborating, category-agnostic signals. None of these alone should
# read as an attack -- they nudge the score up when they co-occur with
# (or hint at) suspicious behavior a specific keyword list didn't catch.
_BONUS_WEIGHTS = {
    "evasion": 8,     # encoded_payload_count + suspicious_query_count
    "burst": 8,       # burst_score
    "rate": 6,        # request_rate
    "error_rate": 8,  # status_error_count / total requests, as a percentage
    "diversity": 6,   # unique_urls
    "confidence": 6,  # avg_confidence (already 0-1)
}
_K_EVASION = 5
_K_BURST = 5
_K_RATE = 2
_K_ERROR_RATE = 25  # error_rate is already a 0-100 percentage


def calculate_anomaly_score(row) -> float:
    """Calculate comprehensive anomaly score (0-100 scale)."""
    brute_force_signal = (
        _saturating(row["brute_force_count"], _BRUTE_FORCE_K)
        * (0.5 + 0.5 * row["failed_login_ratio"])
        * _BRUTE_FORCE_CEILING
    )
    category_signals = [brute_force_signal] + [
        _saturating(row[key], k) * ceiling for key, k, ceiling in _CATEGORY_SPEC
    ]
    primary_score = max(category_signals)

    total_requests = row["status_200_count"] + row["status_error_count"]
    error_rate_pct = (row["status_error_count"] / total_requests * 100) if total_requests > 0 else 0

    bonus = (
        _saturating(row["encoded_payload_count"] + row["suspicious_query_count"], _K_EVASION) * _BONUS_WEIGHTS["evasion"]
        + _saturating(row["burst_score"], _K_BURST) * _BONUS_WEIGHTS["burst"]
        + _saturating(row["request_rate"], _K_RATE) * _BONUS_WEIGHTS["rate"]
        + _saturating(error_rate_pct, _K_ERROR_RATE) * _BONUS_WEIGHTS["error_rate"]
        + _saturating(row["unique_urls"], 10) * _BONUS_WEIGHTS["diversity"]
        + row["avg_confidence"] * _BONUS_WEIGHTS["confidence"]
    )

    return min(primary_score + bonus, 100)


def classify_threat_level(score):
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    elif score >= 20:
        return 'LOW'
    else:
        return 'NORMAL'
