#!/usr/bin/env python3
"""Phase 6 stress test at 10k / 50k / 100k synthetic records.

Generates synthetic traffic in the same shape Project_Files/log_generator.py
already produces (IP, Time, URL, Status) -- reused pattern, not a new
generator design -- into a scratch CSV (never the real
Project_Files/weblog.csv, so the Phase 2-5 regression baseline of 1,881
sessions from the real fixture is never touched). Replays each scale
through the existing, unmodified pipeline and measures latency,
throughput, and memory.

Output: docs/assets/phase6_stress_test.json
"""
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil

from core.alerting.alert_engine import AlertEngine
from core.alerting.transports.file_transport import FileAlertTransport
from core.detection.classifier import classify_threat_type
from core.parsing.log_parser import parse_weblog_row
from core.pipeline.streaming_pipeline import StreamingPipeline

ASSETS_DIR = os.path.join("docs", "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)
SCRATCH_ALERT_LOG = os.path.join(ASSETS_DIR, "_stress_alerts.log")

IPS = [f"10.{a}.{b}.{c}" for a in range(1, 6) for b in range(1, 6) for c in range(1, 5)]  # 100 synthetic IPs
ENDPOINTS = ["/index.html", "/login.php", "/admin/config", "/api/data", "/profile.php?user=x",
             "/js/app.js", "/logout.php", "/search?q=' union select", "/wp-login.php", "/home.php"]
METHODS = ["GET", "POST"]
STATUSES = [200, 200, 200, 200, 301, 302, 401, 403, 404, 500]


def generate_rows(n, seed=42):
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 0, 0, 0)
    rows = []
    t = start
    for _ in range(n):
        t = t + timedelta(seconds=rng.uniform(0, 3))
        ip = rng.choice(IPS)
        method = rng.choice(METHODS)
        endpoint = rng.choice(ENDPOINTS)
        status = rng.choice(STATUSES)
        rows.append((ip, t, f"{method} {endpoint} HTTP/1.1", status))
    return rows


def rows_to_records(rows):
    records = []
    for ip, t, url, status in rows:
        row = {"IP": ip, "Time": t.strftime("[%d/%b/%Y:%H:%M:%S"), "URL": url, "Status": status}
        threat_type, confidence = classify_threat_type(row)
        row["threat_type"] = threat_type
        row["confidence"] = confidence
        rec = parse_weblog_row(row)
        if rec is not None:
            records.append(rec)
    return records


def run_scale(n):
    process = psutil.Process(os.getpid())
    rows = generate_rows(n)
    records = rows_to_records(rows)
    records.sort(key=lambda r: r.timestamp)

    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)

    pipeline = StreamingPipeline()
    alert_engine = AlertEngine([FileAlertTransport(path=SCRATCH_ALERT_LOG)], min_severity="HIGH")

    process.cpu_percent(interval=None)
    mem_before = process.memory_info().rss / (1024 * 1024)

    t0 = time.perf_counter()
    n_sessions = 0
    n_alerts = 0
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

    return {
        "records": n,
        "parsed_records": len(records),
        "sessions": n_sessions,
        "alerts": n_alerts,
        "elapsed_seconds": elapsed,
        "records_per_sec": len(records) / elapsed,
        "sessions_per_sec": n_sessions / elapsed if n_sessions else 0.0,
        "ms_per_record": elapsed / len(records) * 1000,
        "cpu_percent": cpu_percent,
        "memory_mb_before": mem_before,
        "memory_mb_after": mem_after,
        "memory_delta_mb": mem_after - mem_before,
    }


def main():
    report = {"generated_at": datetime.utcnow().isoformat(), "scales": {}}
    for n in (10_000, 50_000, 100_000):
        print(f"[*] Stress testing at {n:,} records...")
        result = run_scale(n)
        report["scales"][str(n)] = result
        print(f"    -> {result['elapsed_seconds']:.2f}s | {result['records_per_sec']:.1f} rec/s | "
              f"{result['sessions']} sessions | {result['alerts']} alerts | "
              f"mem delta {result['memory_delta_mb']:.1f} MB")

    with open(os.path.join(ASSETS_DIR, "phase6_stress_test.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n[OK] Written to docs/assets/phase6_stress_test.json")


if __name__ == "__main__":
    main()
