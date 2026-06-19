"""
Retrain the NOGINX Isolation Forest model from nginx_logs.csv.
Run from project root: python train_model.py
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

FEATURE_COLUMNS = ["status", "size", "method", "path", "user_agent", "hour_of_day"]


def parse_hour(timestamp: str) -> int:
    raw = str(timestamp).strip().split()[0]
    return int(datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S").hour)


def preprocess(input_csv: Path) -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(input_csv)
    df = df.copy()
    df["hour_of_day"] = df["timestamp"].apply(parse_hour)
    df["path"] = df["url"].astype(str).apply(lambda value: value.split("?")[0])
    df["status"] = pd.to_numeric(df["status"], errors="raise").astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="raise").astype(int)

    method_encoder = LabelEncoder()
    path_encoder = LabelEncoder()
    user_agent_encoder = LabelEncoder()

    df["method"] = method_encoder.fit_transform(df["method"].astype(str))
    df["path"] = path_encoder.fit_transform(df["path"].astype(str))
    df["user_agent"] = user_agent_encoder.fit_transform(df["user_agent"].astype(str))

    features = df[FEATURE_COLUMNS]
    encoder_mappings = {
        "method": {
            "classes": method_encoder.classes_.tolist(),
            "mapping": {
                label: int(index)
                for index, label in enumerate(method_encoder.classes_)
            },
        },
        "path": {
            "classes": path_encoder.classes_.tolist(),
            "mapping": {
                label: int(index) for index, label in enumerate(path_encoder.classes_)
            },
        },
        "user_agent": {
            "classes": user_agent_encoder.classes_.tolist(),
            "mapping": {
                label: int(index)
                for index, label in enumerate(user_agent_encoder.classes_)
            },
        },
    }
    return features, encoder_mappings


def main() -> None:
    parser = argparse.ArgumentParser(description="Train NOGINX Isolation Forest model")
    parser.add_argument("--input-csv", default=str(DATA_DIR / "nginx_logs.csv"))
    parser.add_argument("--output-model", default=str(DATA_DIR / "model_retrained.pkl"))
    parser.add_argument("--output-encoders", default=str(DATA_DIR / "encoder_mappings.json"))
    parser.add_argument("--output-features", default=str(DATA_DIR / "features_retrained.csv"))
    parser.add_argument("--contamination", default="auto")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    input_csv = Path(args.input_csv)
    if not input_csv.exists():
        print(f"Input CSV not found: {input_csv}", file=sys.stderr)
        sys.exit(1)

    contamination: str | float = (
        "auto" if str(args.contamination).lower() == "auto" else float(args.contamination)
    )

    features, encoder_mappings = preprocess(input_csv)
    model = IsolationForest(contamination=contamination, random_state=args.random_state)
    model.fit(features)

    output_model = Path(args.output_model)
    output_encoders = Path(args.output_encoders)
    output_features = Path(args.output_features)
    output_model.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_model)
    with output_encoders.open("w", encoding="utf-8") as handle:
        json.dump(encoder_mappings, handle, indent=4)
    features.to_csv(output_features, index=False)

    print(f"[OK] Model saved to {output_model}")
    print(f"[OK] Encoders saved to {output_encoders}")
    print(f"[OK] Features saved to {output_features}")
    print(f"[OK] Training rows: {len(features)}")


if __name__ == "__main__":
    main()
