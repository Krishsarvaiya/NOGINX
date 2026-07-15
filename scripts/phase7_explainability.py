#!/usr/bin/env python3
"""Phase 7, Part 7: explainability for the Isolation Forest.

sklearn's IsolationForest has no feature_importances_ (unlike supervised
tree ensembles) and there are no ground-truth labels to score against,
so standard supervised permutation_importance doesn't directly apply.
Instead this computes an unsupervised permutation importance: for each
feature, shuffle its values across all real sessions, re-score with the
same loaded model, and measure how much the anomaly scores change
(mean absolute score delta + Spearman rank correlation vs. the
unpermuted scores). A feature the model relies on heavily will show a
large score change and low rank correlation when shuffled; an
unimportant feature will barely move the scores.

SHAP was considered but not used: it requires an additional dependency
not already in requirements.txt for a technique that, for an
IsolationForest, still reduces to the same path-length-based signal
permutation importance already exposes here -- not worth the added
dependency for this phase's purpose (per "no new algorithms/dependencies
unless required").

Output: evaluation/feature_permutation_importance.csv
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from core.detection.classifier import classify_threat_type
from core.features.feature_extractor import FEATURE_NAMES, features_to_vector
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.parsing.log_parser import parse_weblog_row
from core.paths import TESTING_BENCHMARK_PATH
from core.pipeline.streaming_pipeline import StreamingPipeline

EVAL_DIR = "evaluation"
os.makedirs(EVAL_DIR, exist_ok=True)


def load_results():
    df = pd.read_csv(TESTING_BENCHMARK_PATH, on_bad_lines="skip")
    df.columns = [str(c).strip() for c in df.columns]
    if "Staus" in df.columns and "Status" not in df.columns:
        df.rename(columns={"Staus": "Status"}, inplace=True)
    records = []
    for row in df.to_dict("records"):
        threat_type, confidence = classify_threat_type(row)
        row["threat_type"] = threat_type
        row["confidence"] = confidence
        rec = parse_weblog_row(row)
        if rec is not None:
            records.append(rec)
    records.sort(key=lambda r: r.timestamp)

    pipeline = StreamingPipeline()
    results = []
    for rec in records:
        results.extend(pipeline.ingest(rec))
    results.extend(pipeline.flush_remaining())
    return results


def main():
    print("[*] Loading sessions and trained model...")
    results = load_results()
    detector = IsolationForestDetector.load_latest()

    X = np.array([features_to_vector(r.features) for r in results])
    X_scaled = detector.scaler.transform(X)
    baseline_raw = -detector.model.decision_function(X_scaled)

    rng = np.random.RandomState(42)
    n_repeats = 10
    rows = []
    for i, name in enumerate(FEATURE_NAMES):
        deltas = []
        correlations = []
        for _ in range(n_repeats):
            X_permuted = X_scaled.copy()
            permuted_col = rng.permutation(X_permuted[:, i])
            X_permuted[:, i] = permuted_col
            permuted_raw = -detector.model.decision_function(X_permuted)
            deltas.append(np.mean(np.abs(permuted_raw - baseline_raw)))
            corr, _ = spearmanr(baseline_raw, permuted_raw)
            correlations.append(corr)
        rows.append({
            "feature": name,
            "mean_abs_score_change": float(np.mean(deltas)),
            "std_abs_score_change": float(np.std(deltas)),
            "mean_rank_correlation_after_shuffle": float(np.mean(correlations)),
        })

    df = pd.DataFrame(rows).sort_values("mean_abs_score_change", ascending=False)
    df["importance_rank"] = range(1, len(df) + 1)
    df.to_csv(os.path.join(EVAL_DIR, "feature_permutation_importance.csv"), index=False)

    print("\n=== Permutation importance (higher mean_abs_score_change = more influential) ===")
    print(df.to_string(index=False))
    print(f"\n[OK] Written to {os.path.join(EVAL_DIR, 'feature_permutation_importance.csv')}")


if __name__ == "__main__":
    main()
