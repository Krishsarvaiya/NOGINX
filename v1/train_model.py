"""
Train and select the best NOGINX anomaly model.

Run from project root:
    python train_model.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import SGDOneClassSVM
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

from ml.features import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, build_feature_frame, build_rule_label

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Input CSV not found: {path}")

    df = pd.read_csv(path)
    required = {"ip", "timestamp", "method", "url", "status", "size", "referer", "user_agent"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Input CSV is missing required NGINX columns: {missing}")
    return df


def build_preprocessor(features: pd.DataFrame) -> tuple[pd.DataFrame, OrdinalEncoder]:
    encoded = features.copy()
    encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    encoded[CATEGORICAL_COLUMNS] = encoder.fit_transform(encoded[CATEGORICAL_COLUMNS].astype(str))
    return encoded[FEATURE_COLUMNS], encoder


def candidate_models(contamination: float, random_state: int) -> dict[str, Pipeline]:
    return {
        "isolation_forest": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=200,
                        contamination=contamination,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "local_outlier_factor": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "model",
                    LocalOutlierFactor(
                        n_neighbors=35,
                        contamination=contamination,
                        novelty=True,
                    ),
                ),
            ]
        ),
        "sgd_one_class_svm": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "model",
                    SGDOneClassSVM(
                        nu=contamination,
                        random_state=random_state,
                        max_iter=2000,
                        tol=1e-4,
                    ),
                ),
            ]
        ),
    }


def score_model(y_true: pd.Series, y_pred: pd.Series) -> dict[str, float]:
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, pos_label=-1, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, pos_label=-1, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, pos_label=-1, zero_division=0)), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the NOGINX model selector.")
    parser.add_argument("--input-csv", default=str(DATA_DIR / "nginx_logs.csv"))
    parser.add_argument("--output-model", default=str(DATA_DIR / "model_retrained.pkl"))
    parser.add_argument("--output-report", default=str(DATA_DIR / "model_report.json"))
    parser.add_argument("--output-features", default=str(DATA_DIR / "features_retrained.csv"))
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=None)
    args = parser.parse_args()

    input_csv = Path(args.input_csv)
    df = load_dataset(input_csv)
    labels = df.apply(lambda row: build_rule_label(row.to_dict()), axis=1)
    threat_ratio = max(float((labels == -1).mean()), 0.001)
    contamination = args.contamination if args.contamination is not None else min(max(threat_ratio * 2, 0.01), 0.25)

    features = build_feature_frame(df)
    encoded_features, encoder = build_preprocessor(features)
    training_features = encoded_features[labels == 1]
    if training_features.empty:
        print("No benign rows available for one-class training.", file=sys.stderr)
        sys.exit(1)

    metrics: dict[str, dict[str, float]] = {}
    fitted_models: dict[str, Pipeline] = {}
    for name, model in candidate_models(contamination, args.random_state).items():
        model.fit(training_features)
        predictions = pd.Series(model.predict(encoded_features), index=encoded_features.index)
        metrics[name] = score_model(labels, predictions)
        fitted_models[name] = model

    best_name = max(metrics, key=lambda item: (metrics[item]["f1"], metrics[item]["recall"], metrics[item]["precision"]))
    bundle = {
        "version": 2,
        "model_name": best_name,
        "model": fitted_models[best_name],
        "encoder": encoder,
        "feature_columns": FEATURE_COLUMNS,
        "categorical_columns": CATEGORICAL_COLUMNS,
        "metrics": metrics,
        "training_rows": int(len(training_features)),
        "evaluation_rows": int(len(encoded_features)),
        "rule_positive_rows": int((labels == -1).sum()),
        "contamination": contamination,
    }

    output_model = Path(args.output_model)
    output_report = Path(args.output_report)
    output_features = Path(args.output_features)
    output_model.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(bundle, output_model)
    output_features.parent.mkdir(parents=True, exist_ok=True)
    encoded_features.to_csv(output_features, index=False)
    output_report.write_text(json.dumps({k: v for k, v in bundle.items() if k not in {"model", "encoder"}}, indent=2), encoding="utf-8")

    print(f"[OK] Best model: {best_name}")
    for name, values in metrics.items():
        print(
            f"  {name}: f1={values['f1']:.4f} recall={values['recall']:.4f} "
            f"precision={values['precision']:.4f} accuracy={values['accuracy']:.4f}"
        )
    print(f"[OK] Model bundle saved to: {output_model}")
    print(f"[OK] Report saved to: {output_report}")


if __name__ == "__main__":
    main()
