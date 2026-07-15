#!/usr/bin/env python3
"""Phase 6 ML evaluation report generator.

Read-only analysis script: reuses the existing, already-tested core/
pipeline (parser, classifier, RollingSessionBuilder, feature extractor,
rule scoring, IsolationForestDetector, fusion) exactly as
THREAT_DETECTION_PIPELINE.py and src/live_analyzer.py already do --
no new detection logic, no new algorithms. It only computes reporting
statistics and renders visualizations on top of what the pipeline
already produces.

Outputs:
    docs/assets/*.png                      visualizations
    docs/assets/top_20_by_ml_score.csv      ranked anomaly tables
    docs/assets/top_20_by_fused_score.csv
    docs/assets/phase6_ml_evaluation.json   every numeric result, so the
                                            written report can be checked
                                            against real numbers rather
                                            than transcribed by hand
"""
import json
import os
import sys
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import plotly.graph_objects as go

from core.alerting.alert_engine import _dominant_threat_type
from core.detection.classifier import classify_threat_type
from core.features.feature_extractor import FEATURE_NAMES
from core.parsing.log_parser import parse_weblog_row
from core.paths import TESTING_BENCHMARK_PATH
from core.persistence.model_store import ModelStore
from core.pipeline.streaming_pipeline import StreamingPipeline

ASSETS_DIR = os.path.join("docs", "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

SEVERITY_ORDER = ["NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def load_records(csv_path):
    df = pd.read_csv(csv_path, on_bad_lines="skip")
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
    return records, len(df)


def run_pipeline(records):
    pipeline = StreamingPipeline()
    results = []
    for rec in records:
        results.extend(pipeline.ingest(rec))
    results.extend(pipeline.flush_remaining())
    return results, pipeline


def dataset_summary(records, raw_row_count, results):
    durations = [(r.window_end - r.window_start).total_seconds() for r in results]
    sizes = [r.record_count for r in results]
    return {
        "total_log_records": raw_row_count,
        "parsed_records": len(records),
        "total_sessions": len(results),
        "avg_session_size": float(np.mean(sizes)),
        "median_session_size": float(np.median(sizes)),
        "longest_session_seconds": float(np.max(durations)),
        "shortest_session_seconds": float(np.min(durations)),
        "median_session_duration_seconds": float(np.median(durations)),
    }


def feature_analysis(results):
    feature_df = pd.DataFrame([r.features for r in results])[list(FEATURE_NAMES)]
    stats = {}
    for col in FEATURE_NAMES:
        series = feature_df[col]
        q1, q3 = series.quantile(0.25), series.quantile(0.75)
        iqr = q3 - q1
        outliers = series[(series < q1 - 1.5 * iqr) | (series > q3 + 1.5 * iqr)]
        stats[col] = {
            "mean": float(series.mean()),
            "median": float(series.median()),
            "std": float(series.std()),
            "min": float(series.min()),
            "max": float(series.max()),
            "outlier_count": int(len(outliers)),
        }

    fig, axes = plt.subplots(4, 3, figsize=(18, 16))
    for ax, col in zip(axes.flat, FEATURE_NAMES):
        ax.hist(feature_df[col], bins=30, color="steelblue", edgecolor="black", alpha=0.75)
        ax.set_title(col, fontsize=10, fontweight="bold")
        ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(ASSETS_DIR, "feature_distributions.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    fig, axes = plt.subplots(4, 3, figsize=(18, 16))
    for ax, col in zip(axes.flat, FEATURE_NAMES):
        ax.boxplot(feature_df[col], vert=True)
        ax.set_title(col, fontsize=10, fontweight="bold")
        ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(ASSETS_DIR, "feature_boxplots.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    return stats


def isolation_forest_analysis(results):
    store = ModelStore()
    loaded = store.load_latest()
    _, _, metadata = loaded
    ml_scores = np.array([r.ml_anomaly_score for r in results])

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].hist(ml_scores, bins=30, color="darkorange", edgecolor="black", alpha=0.75)
    axes[0].axvline(ml_scores.mean(), color="red", linestyle="--", label=f"mean={ml_scores.mean():.1f}")
    axes[0].set_title("Isolation Forest anomaly score histogram")
    axes[0].set_xlabel("ml_anomaly_score (0-100)")
    axes[0].legend()
    axes[0].grid(alpha=0.3)

    axes[1].hist(ml_scores, bins=100, cumulative=True, density=True, color="seagreen", alpha=0.75)
    axes[1].set_title("Cumulative anomaly score distribution")
    axes[1].set_xlabel("ml_anomaly_score (0-100)")
    axes[1].grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(ASSETS_DIR, "anomaly_score_distribution.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    return {
        "contamination": metadata.get("contamination"),
        "model_version": metadata.get("version"),
        "trained_at": metadata.get("trained_at"),
        "n_sessions_trained": metadata.get("n_sessions_trained"),
        "score_min_observed": float(ml_scores.min()),
        "score_max_observed": float(ml_scores.max()),
        "score_avg_observed": float(ml_scores.mean()),
    }


def anomaly_analysis(results):
    anomalies = [r for r in results if r.ml_is_anomaly]
    normal = [r for r in results if not r.ml_is_anomaly]

    def top_table(sorted_results, score_attr):
        rows = []
        for r in sorted_results[:20]:
            rows.append(
                {
                    "source_ip": r.source_ip,
                    "session_duration_s": round((r.window_end - r.window_start).total_seconds(), 1),
                    "record_count": r.record_count,
                    "rule_severity": r.rule_severity,
                    "ml_score": round(r.ml_anomaly_score, 2),
                    "fused_score": round(r.fused_score, 2),
                    "fused_severity": r.fused_severity,
                    "threat_type": _dominant_threat_type(r.features),
                    "explanation": r.explanation,
                }
            )
        return pd.DataFrame(rows)

    by_ml = top_table(sorted(results, key=lambda r: r.ml_anomaly_score, reverse=True), "ml_anomaly_score")
    by_fused = top_table(sorted(results, key=lambda r: r.fused_score, reverse=True), "fused_score")
    by_ml.to_csv(os.path.join(ASSETS_DIR, "top_20_by_ml_score.csv"), index=False)
    by_fused.to_csv(os.path.join(ASSETS_DIR, "top_20_by_fused_score.csv"), index=False)

    return {
        "total_anomalies": len(anomalies),
        "total_normal": len(normal),
        "pct_anomalous": round(100 * len(anomalies) / len(results), 2),
    }, by_ml, by_fused


def rule_vs_ml_and_fusion_analysis(results):
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    rule_vs_ml = pd.crosstab(
        pd.Series([r.rule_severity for r in results], name="rule_severity"),
        pd.Series([r.ml_is_anomaly for r in results], name="ml_is_anomaly"),
    ).reindex(SEVERITY_ORDER).fillna(0).astype(int)

    transition = pd.crosstab(
        pd.Series([r.rule_severity for r in results], name="rule_severity"),
        pd.Series([r.fused_severity for r in results], name="fused_severity"),
    ).reindex(index=SEVERITY_ORDER, columns=SEVERITY_ORDER).fillna(0).astype(int)

    unchanged = escalated = downgraded = 0
    overrides = 0
    disagreement_examples = {"escalated": [], "downgraded": []}
    for r in results:
        rr, fr = rank[r.rule_severity], rank[r.fused_severity]
        if r.critical_override:
            overrides += 1
        if fr > rr:
            escalated += 1
            if len(disagreement_examples["escalated"]) < 3:
                disagreement_examples["escalated"].append(
                    f"{r.source_ip}: rule={r.rule_severity} -> fused={r.fused_severity} "
                    f"(ml_score={r.ml_anomaly_score:.1f})"
                )
        elif fr < rr:
            downgraded += 1
            if len(disagreement_examples["downgraded"]) < 3:
                disagreement_examples["downgraded"].append(
                    f"{r.source_ip}: rule={r.rule_severity} -> fused={r.fused_severity} "
                    f"(ml_score={r.ml_anomaly_score:.1f})"
                )
        else:
            unchanged += 1

    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    label=[f"Rule: {s}" for s in SEVERITY_ORDER] + [f"Fused: {s}" for s in SEVERITY_ORDER],
                    pad=15,
                    thickness=15,
                ),
                link=dict(
                    source=[SEVERITY_ORDER.index(a) for a in transition.index for b in SEVERITY_ORDER if transition.loc[a, b] > 0],
                    target=[5 + SEVERITY_ORDER.index(b) for a in transition.index for b in SEVERITY_ORDER if transition.loc[a, b] > 0],
                    value=[transition.loc[a, b] for a in transition.index for b in SEVERITY_ORDER if transition.loc[a, b] > 0],
                ),
            )
        ]
    )
    fig.update_layout(title_text="Rule Severity -> Fused Severity", font_size=11)
    try:
        fig.write_image(os.path.join(ASSETS_DIR, "severity_transition_sankey.png"), width=1000, height=600, scale=2)
        sankey_ok = True
    except Exception as e:
        sankey_ok = False
        print(f"[WARN] could not render Sankey PNG (kaleido issue?): {e}")

    return (
        rule_vs_ml,
        transition,
        {"unchanged": unchanged, "escalated": escalated, "downgraded": downgraded, "critical_override": overrides},
        disagreement_examples,
        sankey_ok,
    )


def session_analysis(results):
    durations_min = [(r.window_end - r.window_start).total_seconds() / 60 for r in results]
    counts = [r.record_count for r in results]
    req_per_min = [c / d if d > 0 else c for c, d in zip(counts, durations_min)]

    ip_counter = Counter(r.source_ip for r in results)
    suspicious_counter = Counter()
    for r in results:
        suspicious_counter[r.source_ip] += r.fused_score
    attack_counter = Counter(_dominant_threat_type(r.features) for r in results if r.rule_severity != "NORMAL")

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    axes[0, 0].hist(durations_min, bins=30, color="slateblue", edgecolor="black", alpha=0.75)
    axes[0, 0].set_title("Session duration (minutes)")
    axes[0, 0].grid(alpha=0.3)

    axes[0, 1].hist(counts, bins=30, color="coral", edgecolor="black", alpha=0.75)
    axes[0, 1].set_title("Requests per session")
    axes[0, 1].grid(alpha=0.3)

    axes[1, 0].hist(req_per_min, bins=30, color="seagreen", edgecolor="black", alpha=0.75)
    axes[1, 0].set_title("Requests per minute")
    axes[1, 0].grid(alpha=0.3)

    top_ips = ip_counter.most_common(10)
    axes[1, 1].barh([ip for ip, _ in top_ips], [c for _, c in top_ips], color="teal")
    axes[1, 1].set_title("Top active IPs (by session count)")
    axes[1, 1].invert_yaxis()

    plt.tight_layout()
    plt.savefig(os.path.join(ASSETS_DIR, "session_analysis.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    return {
        "top_active_ips": ip_counter.most_common(10),
        "top_suspicious_ips": suspicious_counter.most_common(10),
        "most_common_attacks": attack_counter.most_common(10),
    }


def main():
    print(f"[*] Loading and replaying {TESTING_BENCHMARK_PATH} through the shared pipeline...")
    records, raw_row_count = load_records(TESTING_BENCHMARK_PATH)
    results, _ = run_pipeline(records)
    print(f"[OK] {len(records)} records -> {len(results)} sessions")

    report = {"generated_at": datetime.utcnow().isoformat()}
    report["dataset_summary"] = dataset_summary(records, raw_row_count, results)
    print("[OK] dataset summary computed")

    report["feature_analysis"] = feature_analysis(results)
    print("[OK] feature analysis + visualizations saved")

    report["isolation_forest"] = isolation_forest_analysis(results)
    print("[OK] isolation forest analysis + visualizations saved")

    anomaly_stats, top_ml, top_fused = anomaly_analysis(results)
    report["anomaly_analysis"] = anomaly_stats
    print("[OK] anomaly analysis + top-20 tables saved")

    rule_vs_ml, transition, fusion_stats, disagreements, sankey_ok = rule_vs_ml_and_fusion_analysis(results)
    # orient="index" -> {row_label: {col_label: value}}, i.e.
    # report["fusion_transition_table"]["HIGH"]["CRITICAL"] reads exactly
    # as "rule_severity=HIGH, fused_severity=CRITICAL" with no ambiguity
    # (pandas' plain .to_dict() default is column-major and reads
    # backwards for a human skimming the JSON).
    report["rule_vs_ml_crosstab"] = rule_vs_ml.to_dict(orient="index")
    report["fusion_transition_table"] = transition.to_dict(orient="index")
    report["fusion_stats"] = fusion_stats
    report["fusion_disagreement_examples"] = disagreements
    report["sankey_rendered"] = sankey_ok
    print("[OK] rule-vs-ML + fusion analysis saved")

    report["session_analysis"] = session_analysis(results)
    print("[OK] session analysis + visualizations saved")

    with open(os.path.join(ASSETS_DIR, "phase6_ml_evaluation.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n=== SUMMARY ===")
    print(json.dumps(report["dataset_summary"], indent=2))
    print(json.dumps(report["isolation_forest"], indent=2))
    print(json.dumps(report["anomaly_analysis"], indent=2))
    print(json.dumps(report["fusion_stats"], indent=2))
    print("\n[OK] Full report written to docs/assets/phase6_ml_evaluation.json")


if __name__ == "__main__":
    main()
