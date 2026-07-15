#!/usr/bin/env python3
"""Phase 7, Parts 1/2/3/4/6: dataset analysis, Isolation Forest analysis,
rule-vs-ML comparison, detection quality breakdown, and the 10 required
visualizations.

Pure evaluation script: reuses core/ exactly as shipped (classifier,
parser, RollingSessionBuilder, feature extractor, rule scoring,
IsolationForestDetector, fusion) -- no detection logic is added or
changed here. Read-only against the model in models/; does not retrain.

Outputs:
    evaluation/rule_vs_ml.csv
    evaluation/top_anomalies.csv
    evaluation/feature_statistics.csv
    evaluation/visualizations/*.png
    evaluation/phase7_dataset_and_ml_analysis.json  (every number, for the report)
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
from sklearn.decomposition import PCA

from core.alerting.alert_engine import _dominant_threat_type
from core.detection.classifier import classify_threat_type
from core.detection.fusion import RULE_SEVERITY_SCORE
from core.detection.isolation_forest_detector import IsolationForestDetector
from core.features.feature_extractor import FEATURE_NAMES, features_to_vector
from core.parsing.log_parser import parse_weblog_row
from core.paths import TESTING_BENCHMARK_PATH
from core.persistence.model_store import ModelStore
from core.pipeline.streaming_pipeline import StreamingPipeline

EVAL_DIR = "evaluation"
VIZ_DIR = os.path.join(EVAL_DIR, "visualizations")
os.makedirs(VIZ_DIR, exist_ok=True)
CSV_PATH = TESTING_BENCHMARK_PATH
SEVERITY_ORDER = ["NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


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
    return records, len(df)


def run_pipeline(records):
    pipeline = StreamingPipeline()
    results = []
    for rec in records:
        results.extend(pipeline.ingest(rec))
    results.extend(pipeline.flush_remaining())
    return results


def part1_dataset_analysis(records, raw_count, results, report):
    durations = np.array([(r.window_end - r.window_start).total_seconds() for r in results])
    sizes = np.array([r.record_count for r in results])
    ip_counts = Counter(r.source_ip for r in results)
    attack_counts = Counter(_dominant_threat_type(r.features) for r in results if r.rule_severity != "NORMAL")
    rule_dist = Counter(r.rule_severity for r in results)
    fused_dist = Counter(r.fused_severity for r in results)

    report["dataset_analysis"] = {
        "total_records": raw_count,
        "total_sessions": len(results),
        "avg_session_size": float(sizes.mean()),
        "median_session_size": float(np.median(sizes)),
        "session_duration_seconds": {
            "min": float(durations.min()), "p25": float(np.percentile(durations, 25)),
            "median": float(np.median(durations)), "p75": float(np.percentile(durations, 75)),
            "p95": float(np.percentile(durations, 95)), "max": float(durations.max()),
        },
        "requests_per_session": {
            "min": int(sizes.min()), "p25": float(np.percentile(sizes, 25)),
            "median": float(np.median(sizes)), "p75": float(np.percentile(sizes, 75)),
            "p95": float(np.percentile(sizes, 95)), "max": int(sizes.max()),
        },
        "top_source_ips": ip_counts.most_common(10),
        "most_common_attack_categories": attack_counts.most_common(10),
        "rule_severity_distribution": {s: rule_dist.get(s, 0) for s in SEVERITY_ORDER},
        "fusion_severity_distribution": {s: fused_dist.get(s, 0) for s in SEVERITY_ORDER},
    }

    # Visualizations 6 & 7: requests/session, session duration
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].hist(sizes, bins=40, color="coral", edgecolor="black", alpha=0.75)
    axes[0].set_title("Requests per session"); axes[0].set_xlabel("record_count"); axes[0].grid(alpha=0.3)
    axes[1].hist(durations, bins=40, color="slateblue", edgecolor="black", alpha=0.75)
    axes[1].set_title("Session duration (seconds)"); axes[1].set_xlabel("seconds"); axes[1].grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "06_07_requests_and_duration.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    # Visualization 4 & 5: rule / fusion severity histograms
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].bar(SEVERITY_ORDER, [rule_dist.get(s, 0) for s in SEVERITY_ORDER], color="steelblue", edgecolor="black")
    axes[0].set_title("Rule severity distribution"); axes[0].grid(axis="y", alpha=0.3)
    axes[1].bar(SEVERITY_ORDER, [fused_dist.get(s, 0) for s in SEVERITY_ORDER], color="darkorange", edgecolor="black")
    axes[1].set_title("Fusion severity distribution"); axes[1].grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "04_05_severity_histograms.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    # Visualization 8: top anomalous IPs (by summed fused score)
    ip_fused = Counter()
    for r in results:
        ip_fused[r.source_ip] += r.fused_score
    top_ips = ip_fused.most_common(15)
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh([ip for ip, _ in top_ips][::-1], [v for _, v in top_ips][::-1], color="firebrick")
    ax.set_title("Top anomalous IPs (summed fused score across sessions)")
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "08_top_anomalous_ips.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def part2_isolation_forest_analysis(results, report):
    store = ModelStore()
    loaded = store.load_latest()
    model, scaler, metadata = loaded
    ml_scores = np.array([r.ml_anomaly_score for r in results])

    report["isolation_forest_analysis"] = {
        "model_version": metadata.get("version"),
        "training_timestamp": metadata.get("trained_at"),
        "n_estimators": int(model.n_estimators),
        "contamination": metadata.get("contamination"),
        "n_sessions_trained": metadata.get("n_sessions_trained"),
        "feature_schema": metadata.get("feature_names"),
        "score_percentiles": {
            str(p): float(np.percentile(ml_scores, p)) for p in (1, 5, 10, 25, 50, 75, 90, 95, 99)
        },
        "score_min": float(ml_scores.min()),
        "score_max": float(ml_scores.max()),
        "score_mean": float(ml_scores.mean()),
        "score_std": float(ml_scores.std()),
    }

    # Visualization 3: anomaly score histogram + boxplot
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].hist(ml_scores, bins=40, color="darkorange", edgecolor="black", alpha=0.75)
    axes[0].axvline(ml_scores.mean(), color="red", linestyle="--", label=f"mean={ml_scores.mean():.1f}")
    axes[0].set_title("ML anomaly score histogram"); axes[0].legend(); axes[0].grid(alpha=0.3)
    axes[1].boxplot(ml_scores, orientation="vertical")
    axes[1].set_title("ML anomaly score boxplot"); axes[1].grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "03_anomaly_score_histogram_boxplot.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    return model, scaler


def part3_and_4_rule_vs_ml(results, report):
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows = []
    for r in results:
        rule_flag = r.rule_severity != "NORMAL"
        ml_flag = r.ml_is_anomaly
        if rule_flag and ml_flag:
            category = "both"
        elif rule_flag and not ml_flag:
            category = "rules_only"
        elif ml_flag and not rule_flag:
            category = "ml_only"
        else:
            category = "normal"

        rr, fr = rank[r.rule_severity], rank[r.fused_severity]
        if r.critical_override:
            transition = "critical_override"
        elif fr > rr:
            transition = "escalated"
        elif fr < rr:
            transition = "downgraded"
        else:
            transition = "agreement"

        rows.append({
            "source_ip": r.source_ip,
            "session_id": r.session_id,
            "session_duration_s": round((r.window_end - r.window_start).total_seconds(), 1),
            "record_count": r.record_count,
            "rule_severity": r.rule_severity,
            "rule_score": round(r.rule_anomaly_score, 2),
            "ml_score": round(r.ml_anomaly_score, 2),
            "ml_is_anomaly": r.ml_is_anomaly,
            "fused_score": round(r.fused_score, 2),
            "fused_severity": r.fused_severity,
            "detection_category": category,
            "transition": transition,
            "critical_override": r.critical_override,
            "threat_type": _dominant_threat_type(r.features),
            "explanation": r.explanation,
        })

    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(EVAL_DIR, "rule_vs_ml.csv"), index=False)

    top25 = df.sort_values("ml_score", ascending=False).head(25)
    top25.to_csv(os.path.join(EVAL_DIR, "top_anomalies.csv"), index=False)

    detection_counts = df["detection_category"].value_counts().to_dict()
    transition_counts = df["transition"].value_counts().to_dict()

    report["detection_quality"] = {
        "detected_by_rules_only": int(detection_counts.get("rules_only", 0)),
        "detected_by_ml_only": int(detection_counts.get("ml_only", 0)),
        "detected_by_both": int(detection_counts.get("both", 0)),
        "remained_normal": int(detection_counts.get("normal", 0)),
        "transitions": transition_counts,
    }

    # Visualization 1: rule score vs ML score scatter
    fig, ax = plt.subplots(figsize=(8, 7))
    colors = {"normal": "lightgray", "rules_only": "steelblue", "ml_only": "darkorange", "both": "firebrick"}
    for cat, sub in df.groupby("detection_category"):
        ax.scatter(sub["rule_score"], sub["ml_score"], s=25, alpha=0.6, label=cat, color=colors.get(cat, "black"))
    ax.set_xlabel("Rule score (0-100)"); ax.set_ylabel("ML score (0-100)")
    ax.set_title("Rule Score vs ML Score"); ax.legend(); ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "01_rule_vs_ml_scatter.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    # Visualization 9: top anomalous sessions (top 25 by ML score, bar chart)
    fig, ax = plt.subplots(figsize=(10, 8))
    labels = [f"{row.source_ip} ({row.session_id})" for row in top25.itertuples()]
    ax.barh(labels[::-1], top25["ml_score"][::-1], color="darkred")
    ax.set_title("Top 25 anomalous sessions by ML score")
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "09_top_anomalous_sessions.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    return df


def part6_pca_and_correlation(results, report):
    feature_df = pd.DataFrame([r.features for r in results])[list(FEATURE_NAMES)]
    vectors = np.array([features_to_vector(r.features) for r in results])
    ml_flags = np.array([r.ml_is_anomaly for r in results])

    pca = PCA(n_components=2, random_state=42)
    coords = pca.fit_transform((vectors - vectors.mean(axis=0)) / (vectors.std(axis=0) + 1e-9))
    report["pca_explained_variance_ratio"] = pca.explained_variance_ratio_.tolist()

    fig, ax = plt.subplots(figsize=(8, 7))
    ax.scatter(coords[~ml_flags, 0], coords[~ml_flags, 1], s=15, alpha=0.5, color="steelblue", label="normal")
    ax.scatter(coords[ml_flags, 0], coords[ml_flags, 1], s=25, alpha=0.8, color="firebrick", label="ML anomaly")
    ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]:.1%})")
    ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]:.1%})")
    ax.set_title("PCA projection of session feature vectors")
    ax.legend(); ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "02_pca_projection.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    corr = feature_df.corr()
    fig, ax = plt.subplots(figsize=(10, 9))
    im = ax.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(FEATURE_NAMES))); ax.set_xticklabels(FEATURE_NAMES, rotation=90)
    ax.set_yticks(range(len(FEATURE_NAMES))); ax.set_yticklabels(FEATURE_NAMES)
    for i in range(len(FEATURE_NAMES)):
        for j in range(len(FEATURE_NAMES)):
            ax.text(j, i, f"{corr.iloc[i, j]:.2f}", ha="center", va="center", fontsize=7)
    plt.colorbar(im, ax=ax, label="Pearson correlation")
    ax.set_title("Session feature correlation heatmap")
    plt.tight_layout()
    plt.savefig(os.path.join(VIZ_DIR, "10_feature_correlation_heatmap.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)

    stats_rows = []
    for col in FEATURE_NAMES:
        s = feature_df[col]
        stats_rows.append({
            "feature": col, "mean": s.mean(), "median": s.median(), "std": s.std(),
            "min": s.min(), "max": s.max(),
            "p25": s.quantile(0.25), "p75": s.quantile(0.75), "p95": s.quantile(0.95),
        })
    pd.DataFrame(stats_rows).to_csv(os.path.join(EVAL_DIR, "feature_statistics.csv"), index=False)


def main():
    print("[*] Loading and replaying weblog.csv...")
    records, raw_count = load_records()
    results = run_pipeline(records)
    print(f"[OK] {len(records)} records -> {len(results)} sessions")

    report = {"generated_at": datetime.utcnow().isoformat()}
    part1_dataset_analysis(records, raw_count, results, report)
    print("[OK] Part 1 dataset analysis + visualizations 04,05,06,07,08")
    part2_isolation_forest_analysis(results, report)
    print("[OK] Part 2 isolation forest analysis + visualization 03")
    df = part3_and_4_rule_vs_ml(results, report)
    print("[OK] Part 3/4 rule-vs-ML comparison -> rule_vs_ml.csv, top_anomalies.csv + visualizations 01,09")
    part6_pca_and_correlation(results, report)
    print("[OK] Part 6 PCA + correlation heatmap + feature_statistics.csv")

    with open(os.path.join(EVAL_DIR, "phase7_dataset_and_ml_analysis.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n=== SUMMARY ===")
    print(json.dumps(report["dataset_analysis"], indent=2, default=str))
    print(json.dumps(report["isolation_forest_analysis"], indent=2, default=str))
    print(json.dumps(report["detection_quality"], indent=2, default=str))


if __name__ == "__main__":
    main()
