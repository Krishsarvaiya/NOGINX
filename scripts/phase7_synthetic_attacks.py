#!/usr/bin/env python3
"""Phase 7, Part 5: synthetic attack scenario evaluation.

Constructs one realistic synthetic session per scenario and feeds it
through the real, unmodified pipeline (classify_threat_type ->
parse_weblog_row -> RollingSessionBuilder -> extract_session_features ->
calculate_anomaly_score/classify_threat_level -> IsolationForestDetector
-> fuse_scores -> AlertEngine). No detection logic is added, changed, or
special-cased for these scenarios -- whatever the existing system
produces is what gets reported, including its blind spots.

Output: evaluation/synthetic_attack_results.csv
"""
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from core.alerting.alert_engine import AlertEngine, _dominant_threat_type
from core.alerting.transports.file_transport import FileAlertTransport
from core.detection.classifier import classify_threat_type
from core.detection.decision_engine import (
    apply_critical_indicator_boost,
    build_decision_explanation,
    decide,
)
from core.detection.fusion import DEFAULT_ML_WEIGHT, DEFAULT_RULE_WEIGHT
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.detection.rule_scoring import calculate_anomaly_score, classify_threat_level
from core.features.feature_extractor import extract_session_features
from core.parsing.log_parser import parse_weblog_row
from core.sessions.session_builder import RollingSessionBuilder

EVAL_DIR = "evaluation"
os.makedirs(EVAL_DIR, exist_ok=True)
SCRATCH_ALERT_LOG = os.path.join(EVAL_DIR, "_synthetic_alerts.log")


def build_rows(ip, url_status_pairs, start, interval_seconds, method="GET"):
    rows = []
    t = start
    for url, status in url_status_pairs:
        rows.append({"IP": ip, "Time": t.strftime("[%d/%b/%Y:%H:%M:%S"),
                     "URL": f"{method} {url} HTTP/1.1", "Status": status})
        t += timedelta(seconds=interval_seconds)
    return rows


def scenario_normal_browsing():
    pages = ["/index.html", "/home.php", "/profile.php?user=alice", "/js/app.js",
             "/about.html", "/products.php?id=12", "/contact.html", "/css/style.css",
             "/logout.php", "/login.php"]
    return build_rows("172.16.0.10", [(p, 200) for p in pages], datetime(2026, 3, 1, 9, 0, 0), 20)


def scenario_brute_force():
    pairs = [("/login.php", 401)] * 45 + [("/login.php", 200)]
    return build_rows("172.16.0.20", pairs, datetime(2026, 3, 1, 9, 0, 0), 1.5, method="POST")


def scenario_sql_injection():
    payloads = [
        "/product.php?id=1' OR '1'='1", "/search?q=' UNION SELECT username,password FROM users--",
        "/product.php?id=1;--", "/login.php?user=admin'--&pass=x",
        "/search?q=1' UNION SELECT NULL,NULL,NULL--", "/product.php?id=-1' UNION SELECT 1,2,3--",
        "/report.php?id=1 OR 1=1", "/search?q=%27%20union%20select",
    ] * 2
    return build_rows("172.16.0.30", [(p, 200) for p in payloads], datetime(2026, 3, 1, 9, 0, 0), 4)


def scenario_xss():
    payloads = [
        "/comment.php?msg=<script>alert(1)</script>", "/search?q=<svg/onload=alert(1)>",
        "/profile.php?bio=<img src=x onerror=alert(1)>", "/comment.php?msg=javascript:alert(document.cookie)",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/feedback.php?text=<script src=//evil.js></script>",
    ] * 3
    return build_rows("172.16.0.40", [(p, 200) for p in payloads], datetime(2026, 3, 1, 9, 0, 0), 5)


def scenario_directory_enumeration():
    paths = ["/admin", "/.git/config", "/.env", "/backup.zip", "/wp-admin", "/phpmyadmin",
             "/config.php", "/.htaccess", "/server-status", "/admin/login", "/administrator",
             "/db_backup.sql", "/.git/HEAD", "/wp-login.php", "/manager/html", "/.aws/credentials",
             "/config.old", "/admin.php", "/cpanel", "/.ssh/id_rsa"]
    statuses = [404] * 17 + [200, 200, 403]
    return build_rows("172.16.0.50", list(zip(paths, statuses)), datetime(2026, 3, 1, 9, 0, 0), 0.8)


def scenario_reconnaissance_scan():
    paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/admin", "/login",
             "/config", "/.git", "/.env", "/wp-login.php", "/manager/html", "/phpMyAdmin",
             "/server-info", "/admin/config", "/login.php", "/.git/config"]
    statuses = [404, 200, 404, 404, 200, 404, 404, 404, 404, 403, 404, 403, 200, 404, 404]
    return build_rows("172.16.0.60", list(zip(paths, statuses)), datetime(2026, 3, 1, 9, 0, 0), 1.2)


def scenario_dos_volumetric():
    # Deliberately all-200 responses at very high volume/rate -- tests
    # whether the rule engine's status-code-only DoS category (which
    # only fires on 5xx) misses a pure-volume flood, and whether the ML
    # model's raw record_count feature catches it instead.
    pairs = [("/", 200)] * 800
    return build_rows("172.16.0.70", pairs, datetime(2026, 3, 1, 9, 0, 0), 0.05)


def scenario_credential_stuffing():
    users = [f"user{i}" for i in range(40)]
    pairs = [(f"/login.php?user={u}", 401) for u in users]
    return build_rows("172.16.0.80", pairs, datetime(2026, 3, 1, 9, 0, 0), 3.0, method="POST")


SCENARIOS = {
    "Normal Browsing": scenario_normal_browsing,
    "Brute Force": scenario_brute_force,
    "SQL Injection": scenario_sql_injection,
    "XSS": scenario_xss,
    "Directory Enumeration": scenario_directory_enumeration,
    "Reconnaissance Scan": scenario_reconnaissance_scan,
    "DoS (volumetric)": scenario_dos_volumetric,
    "Credential Stuffing": scenario_credential_stuffing,
}


def run_scenario(name, row_builder, detector, alert_engine):
    raw_rows = row_builder()
    records = []
    classified_counts = Counter()
    for row in raw_rows:
        threat_type, confidence = classify_threat_type(row)
        classified_counts[threat_type] += 1
        row["threat_type"] = threat_type
        row["confidence"] = confidence
        rec = parse_weblog_row(row)
        if rec is not None:
            records.append(rec)
    records.sort(key=lambda r: r.timestamp)

    builder = RollingSessionBuilder()
    closed = []
    for rec in records:
        closed.extend(builder.add_record(rec, now=rec.timestamp))
    closed.extend(builder.flush_all())
    assert len(closed) == 1, f"{name}: expected 1 session, got {len(closed)} (records not within idle timeout of each other)"
    session = closed[0]

    features = extract_session_features(session)
    rule_score = calculate_anomaly_score(features)
    rule_severity = classify_threat_level(rule_score)

    if detector is not None:
        ml_score, ml_is_anomaly = detector.score(features)
    else:
        ml_score, ml_is_anomaly = None, False

    effective_rule_score = apply_critical_indicator_boost(
        rule_score, [record.url for record in session.records]
    )
    fused_score, fused_severity, decision_source, critical_override = decide(
        rule_severity,
        effective_rule_score,
        ml_score,
        DEFAULT_RULE_WEIGHT,
        DEFAULT_ML_WEIGHT,
    )
    explanation = build_decision_explanation(
        rule_severity,
        effective_rule_score,
        rule_score,
        ml_score,
        ml_is_anomaly,
        fused_score,
        fused_severity,
        decision_source,
        critical_override,
    )

    from core.models import ThreatAssessment
    assessment = ThreatAssessment(
        session_id=session.session_id, session_key=session.session_key, source_ip=session.source_ip,
        user_agent=session.user_agent, window_start=session.started_at, window_end=session.closed_at,
        record_count=len(session.records), features=features,
        rule_anomaly_score=rule_score, rule_severity=rule_severity,
        evaluated_at=datetime.now(timezone.utc),
        ml_anomaly_score=ml_score or 0.0, ml_is_anomaly=ml_is_anomaly,
        ml_model_version=detector.version if detector else None,
        fused_score=fused_score, fused_severity=fused_severity, critical_override=critical_override,
        explanation=explanation, decision_source=decision_source,
    )
    alert = alert_engine.process(assessment)

    return {
        "scenario": name,
        "record_count": len(records),
        "session_duration_s": round((session.closed_at - session.started_at).total_seconds(), 1),
        "rule_score": round(rule_score, 2),
        "rule_severity": rule_severity,
        "ml_score": round(ml_score, 2) if ml_score is not None else None,
        "ml_is_anomaly": ml_is_anomaly,
        "fused_score": round(fused_score, 2),
        "fused_severity": fused_severity,
        "alert_generated": alert is not None,
        "rule_classified_categories": dict(classified_counts),
        "dominant_threat_type": _dominant_threat_type(features),
        "explanation": explanation,
    }


def main():
    detector = IsolationForestDetector.load_latest()
    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)
    alert_engine = AlertEngine([FileAlertTransport(path=SCRATCH_ALERT_LOG)], min_severity="HIGH")

    results = []
    for name, builder in SCENARIOS.items():
        print(f"[*] Running scenario: {name}")
        result = run_scenario(name, builder, detector, alert_engine)
        results.append(result)
        print(f"    rule={result['rule_severity']}({result['rule_score']}) "
              f"ml={result['ml_score']} fused={result['fused_severity']}({result['fused_score']}) "
              f"alert={result['alert_generated']}")
        print(f"    rule classified as: {result['rule_classified_categories']}")

    if os.path.exists(SCRATCH_ALERT_LOG):
        os.remove(SCRATCH_ALERT_LOG)

    df = pd.DataFrame(results)
    df.to_csv(os.path.join(EVAL_DIR, "synthetic_attack_results.csv"), index=False)
    print(f"\n[OK] Written to {os.path.join(EVAL_DIR, 'synthetic_attack_results.csv')}")


if __name__ == "__main__":
    main()
