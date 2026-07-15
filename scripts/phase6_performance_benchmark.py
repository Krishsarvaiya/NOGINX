#!/usr/bin/env python3
"""Phase 6 performance benchmark.

Measures the existing pipeline's per-stage latency and end-to-end
throughput. No new detection logic -- every stage timed here is an
existing, already-shipped function from core/. Uses real weblog.csv
data plus the already-trained model from Phase 4.

Output: docs/assets/phase6_performance.json
"""
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import psutil

from core.alerting.alert_engine import AlertEngine
from core.alerting.transports.file_transport import FileAlertTransport
from core.detection.classifier import classify_threat_type
from core.detection.fusion import fuse_scores
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.detection.rule_scoring import calculate_anomaly_score, classify_threat_level
from core.features.feature_extractor import extract_session_features
from core.parsing.log_parser import parse_weblog_row
from core.paths import TESTING_BENCHMARK_PATH
from core.pipeline.streaming_pipeline import StreamingPipeline
from core.sessions.session_builder import RollingSessionBuilder
from scripts.train_isolation_forest import build_session_features

ASSETS_DIR = os.path.join("docs", "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)
CSV_PATH = TESTING_BENCHMARK_PATH
SCRATCH_ALERT_LOG = os.path.join(ASSETS_DIR, "_bench_alerts.log")


def load_records():
    df = pd.read_csv(CSV_PATH, on_bad_lines="skip")
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
    return records


def build_sessions(records):
    builder = RollingSessionBuilder()
    closed = []
    for rec in records:
        closed.extend(builder.add_record(rec, now=rec.timestamp))
    closed.extend(builder.flush_all())
    return closed


def time_it(fn, n=1):
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n


def main():
    process = psutil.Process(os.getpid())
    report = {"generated_at": datetime.utcnow().isoformat(), "cpu_count": psutil.cpu_count()}

    print("[*] Loading records...")
    records = load_records()
    sessions = build_sessions(records)
    sample_features = [extract_session_features(s) for s in sessions[:200]]
    sample_session = sessions[0]

    # --- Training time ---
    print("[*] Timing training...")
    feature_rows = build_session_features(CSV_PATH)
    t0 = time.perf_counter()
    detector = IsolationForestDetector(contamination=0.05)
    detector.fit(feature_rows)
    training_time = time.perf_counter() - t0
    version = detector.save()
    report["training_time_seconds"] = training_time
    report["training_sessions"] = len(feature_rows)

    # --- Model loading time ---
    print("[*] Timing model load...")
    load_times = []
    for _ in range(10):
        t0 = time.perf_counter()
        IsolationForestDetector.load_latest()
        load_times.append(time.perf_counter() - t0)
    report["model_load_time_seconds_avg"] = sum(load_times) / len(load_times)

    loaded_detector = IsolationForestDetector.load_latest()

    # --- Per-stage micro-benchmarks (averaged over 500 calls) ---
    print("[*] Timing pipeline stages...")
    N = 500
    report["feature_extraction_latency_ms"] = time_it(lambda: extract_session_features(sample_session), N) * 1000

    feat = sample_features[0]
    report["rule_engine_latency_ms"] = time_it(lambda: calculate_anomaly_score(feat), N) * 1000

    report["isolation_forest_latency_ms"] = time_it(lambda: loaded_detector.score(feat), N) * 1000

    rule_score = calculate_anomaly_score(feat)
    rule_severity = classify_threat_level(rule_score)
    ml_score, _ = loaded_detector.score(feat)
    report["fusion_latency_ms"] = time_it(lambda: fuse_scores(rule_severity, rule_score, ml_score), N) * 1000

    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)
    alert_engine = AlertEngine([FileAlertTransport(path=SCRATCH_ALERT_LOG)], min_severity="LOW")
    from core.models import ThreatAssessment

    def make_assessment():
        return ThreatAssessment(
            session_id="bench", session_key="1.1.1.1", source_ip="1.1.1.1", user_agent=None,
            window_start=sample_session.started_at, window_end=sample_session.last_activity,
            record_count=10, features=feat, rule_anomaly_score=70.0, rule_severity="HIGH",
            evaluated_at=datetime.utcnow(), ml_anomaly_score=80.0, ml_is_anomaly=True,
            ml_model_version=version, fused_score=75.0, fused_severity="HIGH",
            critical_override=False, explanation="bench",
        )

    report["alert_latency_ms"] = time_it(lambda: alert_engine.process(make_assessment()), N) * 1000
    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)

    # --- End-to-end streaming throughput + resource usage ---
    print("[*] Timing full streaming replay for throughput + resource usage...")
    process.cpu_percent(interval=None)  # prime the internal counter
    mem_before = process.memory_info().rss / (1024 * 1024)

    pipeline = StreamingPipeline()
    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)
    alert_engine = AlertEngine([FileAlertTransport(path=SCRATCH_ALERT_LOG)], min_severity="HIGH")

    t0 = time.perf_counter()
    n_alerts = 0
    n_sessions = 0
    for rec in records:
        for result in pipeline.ingest(rec):
            n_sessions += 1
            if alert_engine.process(result):
                n_alerts += 1
    for result in pipeline.flush_remaining():
        n_sessions += 1
        if alert_engine.process(result):
            n_alerts += 1
    elapsed = time.perf_counter() - t0

    cpu_percent = process.cpu_percent(interval=None)
    mem_after = process.memory_info().rss / (1024 * 1024)

    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)

    report["streaming"] = {
        "records": len(records),
        "sessions": n_sessions,
        "alerts": n_alerts,
        "elapsed_seconds": elapsed,
        "records_per_sec": len(records) / elapsed,
        "sessions_per_sec": n_sessions / elapsed,
        "alerts_per_sec": n_alerts / elapsed if n_alerts else 0.0,
        "cpu_percent_during_run": cpu_percent,
        "memory_mb_before": mem_before,
        "memory_mb_after": mem_after,
        "memory_delta_mb": mem_after - mem_before,
    }

    with open(os.path.join(ASSETS_DIR, "phase6_performance.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n=== PERFORMANCE SUMMARY ===")
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
