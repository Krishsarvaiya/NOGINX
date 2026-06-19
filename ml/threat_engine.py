from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from ml.log_parser import parse_log_file, parse_log_line

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MODEL_PATH = DATA_DIR / "model_retrained.pkl"
ENCODER_PATH = DATA_DIR / "encoder_mappings.json"

EXPECTED_FEATURES = ["status", "size", "method", "path", "user_agent", "hour_of_day"]

THREAT_RULES: list[tuple[str, re.Pattern[str], float, str]] = [
    (
        "SQL Injection",
        re.compile(
            r"(?i)(union\s+select|select\s+.+\s+from|'?\s*or\s+'?1'?\s*=\s*'?1|--|drop\s+table|insert\s+into|xp_cmdshell)"
        ),
        0.95,
        "Possible SQL injection pattern detected in the request URL.",
    ),
    (
        "Cross-Site Scripting (XSS)",
        re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()"),
        0.92,
        "Possible cross-site scripting payload found in the request.",
    ),
    (
        "Path Traversal",
        re.compile(r"(\.\./|%2e%2e|%2E%2E|/etc/passwd|/proc/self|win\.ini)"),
        0.90,
        "Directory traversal attempt detected — attacker may be probing filesystem paths.",
    ),
    (
        "Command Injection",
        re.compile(r"(?i)(\||`|wget\s|curl\s|bash\s|/bin/sh|cmd\.exe)"),
        0.88,
        "Possible command injection pattern in the URL.",
    ),
    (
        "Reconnaissance / Scanner",
        re.compile(
            r"(?i)(/admin|/wp-admin|/phpmyadmin|/\.env|/\.git|/xmlrpc|/shell|/cgi-bin|/backup|/config)"
        ),
        0.75,
        "Scanner or reconnaissance probe targeting common admin or config paths.",
    ),
    (
        "Suspicious Bot",
        re.compile(
            r"(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|acunetix|nessus|openvas|zgrab)"
        ),
        0.85,
        "Known security scanner or attack tool detected in user agent.",
    ),
]

SENSITIVE_PATH_HINTS = ("login", "signin", "auth", "password", "admin", "account", "wp-login")
SENSITIVE_EXTENSIONS = (".env", ".git", ".bak", ".sql", ".pem", ".key", ".config", ".ini")
SUSPICIOUS_STATUS = {401, 403, 405, 408, 429, 500, 502, 503}
SUSPICIOUS_METHODS = {"DELETE", "TRACE", "CONNECT", "PATCH", "PUT"}
CREDENTIAL_QUERY = re.compile(r"(?i)(password=|passwd=|api_key=|apikey=|token=|secret=|auth=)")


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
    rule_matched: bool
    raw_line: str
    message: str = ""
    referer: str = ""
    source: str = "engine"

    def to_dict(self) -> dict:
        return asdict(self)


def _severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.45:
        return "medium"
    return "low"


def encode_with_fallback(value: str, mapping: dict[str, int]) -> int:
    return mapping.get(value, -1)


def _is_http_url(value: str) -> bool:
    value = (value or "").strip().lower()
    return value.startswith("http://")


def _path_lower(row: dict) -> str:
    return str(row.get("path", row.get("url", ""))).lower()


class ThreatEngine:
    def __init__(
        self,
        model_path: Path | None = None,
        encoder_path: Path | None = None,
        anomaly_threshold: float | None = None,
    ):
        self.model_path = Path(model_path or MODEL_PATH)
        self.encoder_path = Path(encoder_path or ENCODER_PATH)
        self.anomaly_threshold = float(
            anomaly_threshold
            if anomaly_threshold is not None
            else os.getenv("ANOMALY_SCORE_THRESHOLD", "0.0")
        )
        self.model = joblib.load(self.model_path)
        with open(self.encoder_path, "r", encoding="utf-8") as handle:
            self.encoders = json.load(handle)

    def _is_unknown(self, category: str, value: str) -> bool:
        return value not in self.encoders[category]["mapping"]

    def _encode_row(self, row: dict) -> dict[str, int]:
        return {
            "status": int(row["status"]),
            "size": int(row["size"]),
            "method": encode_with_fallback(
                row["method"], self.encoders["method"]["mapping"]
            ),
            "path": encode_with_fallback(row["path"], self.encoders["path"]["mapping"]),
            "user_agent": encode_with_fallback(
                row["user_agent"], self.encoders["user_agent"]["mapping"]
            ),
            "hour_of_day": int(row["hour_of_day"]),
        }

    def _ml_score(self, features: dict[str, int]) -> tuple[bool, float, int]:
        df = pd.DataFrame([features])[EXPECTED_FEATURES]
        prediction = int(self.model.predict(df)[0])
        score = float(self.model.decision_function(df)[0])
        is_anomaly = prediction == -1 or score < self.anomaly_threshold
        return is_anomaly, score, prediction

    def _insecurity_rules(self, row: dict) -> list[tuple[str, float, str]]:
        hits: list[tuple[str, float, str]] = []
        url = str(row.get("url", ""))
        referer = str(row.get("referer", "-"))
        path = _path_lower(row)
        hour = int(row.get("hour_of_day", 12))

        if _is_http_url(url):
            hits.append(
                (
                    "Insecure HTTP Request",
                    0.84,
                    "Traffic sent over unencrypted HTTP — data can be intercepted in transit.",
                )
            )

        if referer not in ("-", "") and _is_http_url(referer):
            hits.append(
                (
                    "Insecure HTTP Referer",
                    0.78,
                    f"User navigated from an insecure HTTP page: {referer[:120]}",
                )
            )

        if CREDENTIAL_QUERY.search(url):
            hits.append(
                (
                    "Credentials in URL",
                    0.91,
                    "Sensitive credentials appear in the URL query string — major security risk.",
                )
            )

        if any(hint in path for hint in SENSITIVE_PATH_HINTS):
            if _is_http_url(url) or (referer not in ("-", "") and _is_http_url(referer)):
                hits.append(
                    (
                        "Insecure Login / Auth Page",
                        0.89,
                        "Authentication-related page accessed over unencrypted HTTP.",
                    )
                )
            else:
                hits.append(
                    (
                        "Sensitive Auth Endpoint",
                        0.62,
                        "Login or authentication endpoint accessed — monitor for brute force.",
                    )
                )

        if any(ext in path for ext in SENSITIVE_EXTENSIONS):
            hits.append(
                (
                    "Sensitive File Access",
                    0.87,
                    "Request targets sensitive configuration, key, or backup files.",
                )
            )

        if str(row.get("http_version", "")).strip() == "HTTP/0.9":
            hits.append(
                (
                    "Legacy Insecure Protocol",
                    0.70,
                    "Deprecated HTTP/0.9 protocol used — indicates outdated or abnormal client.",
                )
            )

        if hour <= 5 or hour >= 22:
            if any(hint in path for hint in ("admin", "login", "dashboard", "api")):
                hits.append(
                    (
                        "Off-Hours Privileged Access",
                        0.58,
                        "Sensitive endpoint accessed outside normal business hours.",
                    )
                )

        if self._is_unknown("path", row.get("path", "")):
            hits.append(
                (
                    "Unfamiliar Endpoint",
                    0.55,
                    "Request to a path not seen during model training — possible new or suspicious route.",
                )
            )

        if self._is_unknown("user_agent", row.get("user_agent", "")):
            hits.append(
                (
                    "Unknown Client / Browser",
                    0.50,
                    "Unrecognized user agent — may be a custom script, bot, or new browser.",
                )
            )

        if int(row.get("size", 0)) == 0 and int(row.get("status", 0)) == 200:
            if any(hint in path for hint in ("login", "api", "transfer", "payment")):
                hits.append(
                    (
                        "Abnormal Empty Response",
                        0.54,
                        "Sensitive endpoint returned zero bytes — possible misconfiguration or probe.",
                    )
                )

        return hits

    def _rule_scores(self, row: dict) -> list[tuple[str, float, str]]:
        hits: list[tuple[str, float, str]] = []
        url = row.get("url", "")
        user_agent = row.get("user_agent", "")

        for threat_type, pattern, confidence, message in THREAT_RULES[:5]:
            if pattern.search(url):
                hits.append((threat_type, confidence, message))

        bot = THREAT_RULES[5]
        if bot[1].search(user_agent):
            hits.append((bot[0], bot[2], bot[3]))

        hits.extend(self._insecurity_rules(row))

        if row["method"] in SUSPICIOUS_METHODS:
            hits.append(
                (
                    "Suspicious HTTP Method",
                    0.70,
                    f"Unusual HTTP method '{row['method']}' used — may indicate API abuse or probing.",
                )
            )

        if int(row["status"]) in SUSPICIOUS_STATUS:
            hits.append(
                (
                    "Auth / Access Failure",
                    0.55,
                    f"HTTP {row['status']} response — possible failed authentication or forbidden access.",
                )
            )

        if int(row["status"]) == 404 and any(
            p in row.get("path", "").lower()
            for p in (".php", ".asp", ".env", "admin", "wp-")
        ):
            hits.append(
                (
                    "Probe / Enumeration",
                    0.60,
                    "404 on a commonly exploited path — likely vulnerability scanning.",
                )
            )

        return hits

    def _build_prediction(
        self,
        row: dict,
        ml_anomaly: bool,
        ml_score: float,
        rule_hits: list[tuple[str, float, str]],
    ) -> ThreatPrediction:
        if rule_hits:
            threat_type, confidence, message = max(rule_hits, key=lambda item: item[1])
            rule_matched = True
        elif ml_anomaly:
            threat_type = "ML Traffic Anomaly"
            confidence = min(0.99, max(0.48, 0.58 + abs(ml_score) * 0.2))
            message = (
                "Machine learning model flagged this request as statistically abnormal "
                f"compared to trained baseline (score: {ml_score:.4f})."
            )
            rule_matched = False
        else:
            threat_type = "Benign"
            confidence = max(0.05, min(0.30, 0.20 + ml_score * 0.1))
            message = "No significant security concern detected."
            rule_matched = False

        return ThreatPrediction(
            threat_type=threat_type,
            confidence=round(float(confidence), 4),
            severity=_severity(confidence),
            ip=row["ip"],
            timestamp=row["timestamp"],
            method=row["method"],
            path=row["path"],
            url=row["url"],
            status=int(row["status"]),
            user_agent=row["user_agent"],
            ml_anomaly=ml_anomaly,
            ml_score=round(ml_score, 6),
            rule_matched=rule_matched,
            raw_line=row.get("raw_line", ""),
            message=message,
            referer=str(row.get("referer", "-")),
        )

    def analyze_entry(self, row: dict) -> ThreatPrediction:
        features = self._encode_row(row)
        ml_anomaly, ml_score, _ = self._ml_score(features)
        rule_hits = self._rule_scores(row)
        return self._build_prediction(row, ml_anomaly, ml_score, rule_hits)

    def analyze_line(self, line: str) -> ThreatPrediction | None:
        row = parse_log_line(line)
        if not row:
            return None
        return self.analyze_entry(row)

    def analyze_file(
        self,
        path: str | Path,
        top_n: int = 25,
        min_confidence: float = 0.0,
        max_lines: int | None = None,
    ) -> dict:
        entries = parse_log_file(path, limit=max_lines)
        if not entries:
            return {
                "total_lines_parsed": 0,
                "total_threats": 0,
                "best_prediction": None,
                "top_predictions": [],
                "severity_breakdown": {},
                "threat_type_breakdown": {},
                "anomaly_rate": 0.0,
            }

        feature_rows = [self._encode_row(row) for row in entries]
        feature_df = pd.DataFrame(feature_rows)[EXPECTED_FEATURES]
        ml_preds = self.model.predict(feature_df)
        ml_scores = self.model.decision_function(feature_df)

        predictions: list[ThreatPrediction] = []
        for index, row in enumerate(entries):
            ml_anomaly = bool(
                ml_preds[index] == -1 or ml_scores[index] < self.anomaly_threshold
            )
            ml_score = float(ml_scores[index])
            rule_hits = self._rule_scores(row)
            predictions.append(
                self._build_prediction(row, ml_anomaly, ml_score, rule_hits)
            )

        ranked = sorted(predictions, key=lambda item: item.confidence, reverse=True)
        threats = [
            item.to_dict()
            for item in ranked
            if item.confidence >= min_confidence and item.threat_type != "Benign"
        ]
        top_threats = threats[:top_n]

        best = ranked[0].to_dict() if ranked else None
        severity_counts: dict[str, int] = {}
        threat_counts: dict[str, int] = {}
        for item in predictions:
            if item.threat_type != "Benign":
                severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
                threat_counts[item.threat_type] = (
                    threat_counts.get(item.threat_type, 0) + 1
                )

        return {
            "total_lines_parsed": len(entries),
            "total_threats": len(threats),
            "best_prediction": best,
            "top_predictions": top_threats,
            "severity_breakdown": severity_counts,
            "threat_type_breakdown": threat_counts,
            "anomaly_rate": round(
                sum(1 for item in predictions if item.ml_anomaly) / max(len(predictions), 1),
                4,
            ),
        }

    def predict_one_legacy(self, feature: dict[str, int]) -> dict:
        df = pd.DataFrame([feature])[EXPECTED_FEATURES]
        preds = self.model.predict(df)
        scores = self.model.decision_function(df)
        pred = int(preds[0])
        score = float(scores[0])
        return {
            "anomaly": bool(pred == -1 or score < self.anomaly_threshold),
            "prediction": pred,
            "score": score,
            "threshold": self.anomaly_threshold,
        }

    def analyze_raw_row(self, row: dict) -> ThreatPrediction:
        if "path" not in row and "url" in row:
            row = dict(row)
            row["path"] = str(row["url"]).split("?")[0]
        if "hour_of_day" not in row and "timestamp" in row:
            from ml.log_parser import parse_hour

            row = dict(row)
            row["hour_of_day"] = parse_hour(row["timestamp"])
        if "referer" not in row:
            row = dict(row)
            row["referer"] = "-"
        return self.analyze_entry(row)
