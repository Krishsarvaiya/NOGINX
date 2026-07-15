from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import pandas as pd

from ml.features import (
    CATEGORICAL_COLUMNS,
    FEATURE_COLUMNS,
    LiveBehaviorTracker,
    build_feature_frame,
    describe_rule_threat,
    normalize_path,
)
from ml.log_parser import parse_log_file, parse_log_line

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MODEL_PATH = DATA_DIR / "model_retrained.pkl"


@dataclass
class ThreatPrediction:
    threat_type: str
    confidence: float
    severity: str
    ip: str
    timestamp: str
    method: str
    path: str
    url: str
    status: int
    user_agent: str
    ml_anomaly: bool
    ml_score: float
    message: str = ""
    source: str = "engine"
    raw_line: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ThreatEngine:
    def __init__(self, model_path: str | Path = MODEL_PATH) -> None:
        self.model_path = Path(model_path)
        self.bundle = joblib.load(self.model_path)
        self.model = self.bundle["model"]
        self.encoder = self.bundle["encoder"]
        self.model_name = self.bundle.get("model_name", "unknown")
        self.feature_columns = self.bundle.get("feature_columns", FEATURE_COLUMNS)
        self.categorical_columns = self.bundle.get("categorical_columns", CATEGORICAL_COLUMNS)
        self.behavior = LiveBehaviorTracker()
        print(f"[ThreatEngine] Loaded {self.model_name} from {self.model_path}")

    def _features_for_rows(self, rows: list[dict], live_behavior: bool = False) -> pd.DataFrame:
        df = pd.DataFrame(rows)
        features = build_feature_frame(df, include_behavior=not live_behavior)
        if live_behavior:
            for index, row in enumerate(rows):
                req_10s, req_1m, error_rate = self.behavior.metrics(
                    str(row.get("ip", "0.0.0.0")),
                    int(row.get("status", 0) or 0),
                )
                features.loc[index, "requests_per_ip_10s"] = req_10s
                features.loc[index, "requests_per_ip_1m"] = req_1m
                features.loc[index, "error_rate"] = error_rate

        encoded = features.copy()
        encoded[self.categorical_columns] = self.encoder.transform(
            encoded[self.categorical_columns].astype(str)
        )
        return encoded[self.feature_columns]

    def _score(self, encoded_features: pd.DataFrame) -> tuple[bool, float, float]:
        prediction = int(self.model.predict(encoded_features)[0])
        score = 0.0
        if hasattr(self.model, "decision_function"):
            score = float(self.model.decision_function(encoded_features)[0])
        confidence = min(max(abs(score), 0.0), 1.0)
        return prediction == -1, score, confidence

    def analyze_entry(self, raw_row: dict, live_behavior: bool = False) -> ThreatPrediction:
        encoded = self._features_for_rows([raw_row], live_behavior=live_behavior)
        ml_anomaly, score, confidence = self._score(encoded)
        rule_threat = describe_rule_threat(raw_row)

        if rule_threat:
            threat_type, severity, message = rule_threat
            confidence = max(confidence, 0.75)
        elif ml_anomaly:
            threat_type = "ML Traffic Anomaly"
            severity = "medium"
            message = f"{self.model_name} flagged the request as outside the learned baseline."
        else:
            threat_type = "Benign"
            severity = "low"
            message = "Traffic matches the learned NGINX baseline."

        url = str(raw_row.get("url", "-"))
        return ThreatPrediction(
            threat_type=threat_type,
            confidence=round(confidence, 4),
            severity=severity,
            ip=str(raw_row.get("ip", "0.0.0.0")),
            timestamp=str(raw_row.get("timestamp", "N/A")),
            method=str(raw_row.get("method", "-")),
            path=normalize_path(url),
            url=url,
            status=int(raw_row.get("status", 0) or 0),
            user_agent=str(raw_row.get("user_agent", "-")),
            ml_anomaly=ml_anomaly,
            ml_score=round(score, 6),
            message=message,
            raw_line=raw_row.get("raw_line"),
        )

    def analyze_line(self, line: str) -> ThreatPrediction | None:
        row = parse_log_line(line)
        if not row:
            return None
        return self.analyze_entry(row, live_behavior=True)

    def analyze_file(
        self,
        path: str | Path,
        top_n: int = 25,
        min_confidence: float = 0.0,
        max_lines: int | None = 15000,
    ) -> dict:
        rows = parse_log_file(path, limit=max_lines)
        threats: list[dict] = []
        if not rows:
            return {
                "total_lines_parsed": 0,
                "total_threats": 0,
                "anomaly_rate": 0.0,
                "model_name": self.model_name,
                "best_prediction": None,
                "top_predictions": [],
            }

        encoded = self._features_for_rows(rows, live_behavior=False)
        ml_predictions = self.model.predict(encoded)
        if hasattr(self.model, "decision_function"):
            scores = self.model.decision_function(encoded)
        else:
            scores = [0.0] * len(rows)

        for row, ml_prediction, score in zip(rows, ml_predictions, scores):
            score = float(score)
            confidence = min(max(abs(score), 0.0), 1.0)
            ml_anomaly = int(ml_prediction) == -1
            rule_threat = describe_rule_threat(row)

            if rule_threat:
                threat_type, severity, message = rule_threat
                confidence = max(confidence, 0.75)
            elif ml_anomaly:
                threat_type = "ML Traffic Anomaly"
                severity = "medium"
                message = f"{self.model_name} flagged the request as outside the learned baseline."
            else:
                continue

            url = str(row.get("url", "-"))
            prediction = ThreatPrediction(
                threat_type=threat_type,
                confidence=round(confidence, 4),
                severity=severity,
                ip=str(row.get("ip", "0.0.0.0")),
                timestamp=str(row.get("timestamp", "N/A")),
                method=str(row.get("method", "-")),
                path=normalize_path(url),
                url=url,
                status=int(row.get("status", 0) or 0),
                user_agent=str(row.get("user_agent", "-")),
                ml_anomaly=ml_anomaly,
                ml_score=round(score, 6),
                message=message,
                raw_line=row.get("raw_line"),
            ).to_dict()
            if prediction["confidence"] >= min_confidence:
                threats.append(prediction)

        threats.sort(key=lambda item: (item["confidence"], item["severity"]), reverse=True)
        best = threats[0] if threats else None

        return {
            "total_lines_parsed": len(rows),
            "total_threats": len(threats),
            "anomaly_rate": round(len(threats) / len(rows), 4) if rows else 0.0,
            "model_name": self.model_name,
            "best_prediction": best,
            "top_predictions": threats[:top_n],
        }

    def predict_one_legacy(self, feature: dict) -> dict:
        frame = pd.DataFrame([feature])
        for column in self.feature_columns:
            if column not in frame:
                frame[column] = 0
        for column in self.categorical_columns:
            if column in frame:
                frame[column] = frame[column].astype(str)
        try:
            frame[self.categorical_columns] = self.encoder.transform(
                frame[self.categorical_columns].astype(str)
            )
        except Exception:
            pass
        is_anomaly, score, confidence = self._score(frame[self.feature_columns])
        return {
            "anomaly": int(is_anomaly),
            "ml_anomaly": is_anomaly,
            "ml_score": round(score, 6),
            "confidence": round(confidence, 4),
            "model_name": self.model_name,
        }
