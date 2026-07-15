#!/usr/bin/env python3
"""Offline trainer for the Isolation Forest anomaly detector.

Reuses the exact same parsing / classification / rolling-session-building
code the live analyzer and THREAT_DETECTION_PIPELINE.py use, so the
sessions trained on are identical in shape to what live inference will
see. Trains ONLY on data/training/normal_training_logs.csv by default
(see core/paths.py and docs/DATASET_GUIDE.md) -- never on live traffic.
Run this whenever that file changes meaningfully -- it never runs
automatically, and live inference (StreamingPipeline) only ever *loads*
whatever this last produced.

Usage:
    python scripts/train_isolation_forest.py
    python scripts/train_isolation_forest.py --csv data/training/normal_training_logs.csv --contamination 0.05
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from core.detection.classifier import classify_threat_type
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.features.feature_extractor import extract_session_features
from core.parsing.log_parser import parse_weblog_row
from core.paths import TRAINING_DATA_PATH
from core.sessions.session_builder import RollingSessionBuilder


def build_session_features(csv_path: str) -> list:
    """Replays a historical CSV through the shared parse -> classify ->
    rolling-session pipeline and returns one feature dict per completed
    session -- the same feature dicts THREAT_DETECTION_PIPELINE.py builds
    session_df from."""
    df = pd.read_csv(csv_path, on_bad_lines="skip")
    df.columns = [str(c).strip() for c in df.columns]
    if "Staus" in df.columns and "Status" not in df.columns:
        df.rename(columns={"Staus": "Status"}, inplace=True)

    records = []
    for row in df.to_dict("records"):
        threat_type, confidence = classify_threat_type(row)
        row["threat_type"] = threat_type
        row["confidence"] = confidence
        record = parse_weblog_row(row)
        if record is not None:
            records.append(record)
    records.sort(key=lambda r: r.timestamp)

    builder = RollingSessionBuilder()
    closed = []
    for record in records:
        closed.extend(builder.add_record(record, now=record.timestamp))
    closed.extend(builder.flush_all())

    return [extract_session_features(session) for session in closed]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default=TRAINING_DATA_PATH)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    print(f"[*] Building session features from {args.csv} ...")
    feature_rows = build_session_features(args.csv)
    print(f"[OK] {len(feature_rows)} sessions available for training")

    detector = IsolationForestDetector(contamination=args.contamination)
    detector.fit(feature_rows)
    version = detector.save()

    print(f"[OK] Trained Isolation Forest on {detector.n_sessions_trained} sessions")
    print(f"[OK] Saved model version: {version}")
    print(f"[OK] Raw score range: {detector.score_min:.4f} to {detector.score_max:.4f}")


if __name__ == "__main__":
    main()
