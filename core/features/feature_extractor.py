"""Extracts a fixed-shape feature dict from a completed Session.

Extends the original 12-column schema (record_count, unique_urls,
unique_methods, status counts, per-threat-type counts, avg_confidence)
with 12 additional features (see FEATURE_NAMES) that give the rule
engine and the Isolation Forest signal the original schema couldn't
express at all: per-status-code granularity (403 vs 404), request
timing/burstiness, payload diversity, and evasion indicators (residual
encoding, generic suspicious characters). All existing keys keep their
exact prior meaning and computation -- this is purely additive.

Adding to FEATURE_NAMES changes the Isolation Forest's input vector
shape, which is why core.detection.isolation_forest_detector.load_latest()
checks metadata["feature_names"] against the current tuple and refuses
to load a model trained against a different one (falling back to
rules-only) -- a schema change here requires retraining
(scripts/train_isolation_forest.py), not a code change there.
"""
from __future__ import annotations

import re
from collections import Counter

from core.models import Session

BRUTE_FORCE = "Brute Force Attack"
RECON_SCAN = "Reconnaissance Scan"
INJECTION = "SQL/Web Injection Attack"
XSS = "Cross-Site Scripting (XSS)"
COMMAND_INJECTION = "Command Injection"
DIRECTORY_TRAVERSAL = "Directory Traversal"
SENSITIVE_FILE = "Sensitive File Access"
DOS = "DoS Pattern"
ACCESS_DENIAL = "Access Denial"
NORMAL = "Normal Connection"

ERROR_STATUSES = {401, 403, 404, 500}

# Generic "this looks hand-crafted, not a browser" characters -- a
# lower-confidence, category-agnostic signal distinct from the specific
# attack-pattern counts above, meant to catch payloads that don't match
# any named keyword list (see suspicious_query_count below).
_SUSPICIOUS_QUERY_CHARS = re.compile(r"""['"<>;`|]|\$\(""")

# Canonical, order-sensitive feature schema. This is the single source of
# truth both the offline session_df columns and the Isolation Forest's
# training/inference vectors are built from -- extract_session_features()
# always returns exactly these keys, and features_to_vector() always
# reads them back in this exact order, so a model trained against one
# version of this tuple can be detected as stale if the tuple ever
# changes (see validate_feature_schema()).
FEATURE_NAMES = (
    "record_count",
    "unique_urls",
    "unique_methods",
    "status_200_count",
    "status_error_count",
    "brute_force_count",
    "scan_count",
    "injection_count",
    "dos_count",
    "access_denial_count",
    "normal_count",
    "avg_confidence",
    # -- added for richer attack-category and behavioral signal --
    "xss_count",
    "command_injection_count",
    "directory_traversal_count",
    "sensitive_file_count",
    "status_403_count",
    "status_404_count",
    "failed_login_ratio",
    "request_rate",
    "burst_score",
    "unique_query_strings",
    "encoded_payload_count",
    "suspicious_query_count",
)


def validate_feature_schema(features: dict) -> None:
    """Raise if `features` doesn't carry every key FEATURE_NAMES requires.

    Called at both training time (each row fit on) and inference time
    (each session scored) so a schema drift fails loudly instead of
    silently scoring against misaligned columns.
    """
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise ValueError(f"feature dict is missing required keys: {missing}")


def features_to_vector(features: dict) -> list:
    """Validate and vectorize a feature dict in canonical FEATURE_NAMES order."""
    validate_feature_schema(features)
    return [float(features[name]) for name in FEATURE_NAMES]


def _query_string(url: str) -> str:
    """Everything after the first '?' in a path, or '' if none."""
    idx = url.find("?")
    return url[idx + 1:] if idx != -1 else ""


def _burst_score(timestamps: list) -> int:
    """Max number of records observed within any 1-second window.

    Distinct from request_rate (the session's *average* rate): a
    session can have a low average rate but one intense burst (e.g. a
    fast automated scan followed by an idle gap), which average rate
    alone would understate.
    """
    if len(timestamps) < 2:
        return len(timestamps)
    ordered = sorted(timestamps)
    best = 1
    left = 0
    for right in range(len(ordered)):
        while (ordered[right] - ordered[left]).total_seconds() > 1.0:
            left += 1
        best = max(best, right - left + 1)
    return best


def extract_session_features(session: Session) -> dict:
    records = session.records
    threat_type_counts = Counter(r.extra.get("threat_type") for r in records)
    confidences = [r.extra.get("confidence") for r in records if r.extra.get("confidence") is not None]

    login_records = [r for r in records if "login" in r.url.lower()]
    failed_login_records = [r for r in login_records if r.status_code in (401, 403)]

    query_strings = [_query_string(r.url) for r in records]
    non_empty_queries = [q for q in query_strings if q]

    duration_seconds = max((session.last_activity - session.started_at).total_seconds(), 1.0)

    return {
        "record_count": len(records),
        "unique_urls": len({r.url for r in records}),
        "unique_methods": len({r.method for r in records}),
        "status_200_count": sum(1 for r in records if r.status_code == 200),
        "status_error_count": sum(1 for r in records if r.status_code in ERROR_STATUSES),
        "brute_force_count": threat_type_counts.get(BRUTE_FORCE, 0),
        "scan_count": threat_type_counts.get(RECON_SCAN, 0),
        "injection_count": threat_type_counts.get(INJECTION, 0),
        "dos_count": threat_type_counts.get(DOS, 0),
        "access_denial_count": threat_type_counts.get(ACCESS_DENIAL, 0),
        "normal_count": threat_type_counts.get(NORMAL, 0),
        "avg_confidence": (sum(confidences) / len(confidences)) if confidences else 0.5,
        "xss_count": threat_type_counts.get(XSS, 0),
        "command_injection_count": threat_type_counts.get(COMMAND_INJECTION, 0),
        "directory_traversal_count": threat_type_counts.get(DIRECTORY_TRAVERSAL, 0),
        "sensitive_file_count": threat_type_counts.get(SENSITIVE_FILE, 0),
        "status_403_count": sum(1 for r in records if r.status_code == 403),
        "status_404_count": sum(1 for r in records if r.status_code == 404),
        "failed_login_ratio": (len(failed_login_records) / len(login_records)) if login_records else 0.0,
        "request_rate": len(records) / duration_seconds,
        "burst_score": _burst_score([r.timestamp for r in records]),
        "unique_query_strings": len(set(non_empty_queries)),
        "encoded_payload_count": sum(1 for r in records if r.extra.get("is_encoded")),
        "suspicious_query_count": sum(1 for q in query_strings if q and _SUSPICIOUS_QUERY_CHARS.search(q)),
    }
