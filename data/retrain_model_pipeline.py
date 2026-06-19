"""
Standalone retraining pipeline for NOGINX.

What it does:
1) Reads nginx logs dataset CSV (default: nginx_logs.csv)
2) Builds model features
3) Encodes categorical columns and saves encoder mappings
4) Trains Isolation Forest
5) Saves trained model and optional features CSV
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


EXPECTED_COLUMNS = [
    "timestamp",
    "method",
    "url",
    "status",
    "size",
    "user_agent",
]

FEATURE_COLUMNS = ["status", "size", "method", "path", "user_agent", "hour_of_day"]


def parse_hour(timestamp: str) -> int:
    # NGINX sample timestamp format: 17/May/2015:08:05:32 +0000
    raw = str(timestamp).strip().split()[0]
    return int(datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S").hour)


def preprocess(input_csv: Path) -> tuple[pd.DataFrame, dict]:
    df = pd.read_csv(input_csv)

    missing = [col for col in EXPECTED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(
            f"Input dataset is missing required columns: {missing}. "
            f"Found columns: {list(df.columns)}"
        )

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
            "mapping": {label: int(index) for index, label in enumerate(path_encoder.classes_)},
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


def train(features: pd.DataFrame, contamination: str | float, random_state: int) -> IsolationForest:
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(features)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrain NOGINX Isolation Forest model.")
    parser.add_argument(
        "--input-csv",
        default="nginx_logs.csv",
        help="Path to raw nginx logs CSV containing timestamp/method/url/status/size/user_agent.",
    )
    parser.add_argument(
        "--output-model",
        default="model.pkl",
        help="Path where trained model will be saved.",
    )
    parser.add_argument(
        "--output-encoders",
        default="encoder_mappings.json",
        help="Path where encoder mappings will be saved.",
    )
    parser.add_argument(
        "--output-features",
        default="features.csv",
        help="Path where processed feature CSV will be saved.",
    )
    parser.add_argument(
        "--contamination",
        default="auto",
        help='IsolationForest contamination value (example: "auto" or 0.01).',
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random state for reproducible training.",
    )
    args = parser.parse_args()

    input_csv = Path(args.input_csv).resolve()
    output_model = Path(args.output_model).resolve()
    output_encoders = Path(args.output_encoders).resolve()
    output_features = Path(args.output_features).resolve()

    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    contamination: str | float
    if str(args.contamination).lower() == "auto":
        contamination = "auto"
    else:
        contamination = float(args.contamination)

    features, encoder_mappings = preprocess(input_csv)
    model = train(features, contamination=contamination, random_state=args.random_state)

    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_encoders.parent.mkdir(parents=True, exist_ok=True)
    output_features.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_model)
    with output_encoders.open("w", encoding="utf-8") as file:
        json.dump(encoder_mappings, file, indent=4)
    features.to_csv(output_features, index=False)

    print(f"[OK] Trained model saved to: {output_model}")
    print(f"[OK] Encoder mappings saved to: {output_encoders}")
    print(f"[OK] Processed features saved to: {output_features}")
    print(f"[OK] Total rows used for training: {len(features)}")


if __name__ == "__main__":
    main()
