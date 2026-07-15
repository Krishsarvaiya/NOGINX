from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd

FEATURE_COLUMNS = [
    "status",
    "size",
    "hour_of_day",
    "method",
    "path",
    "user_agent",
    "path_depth",
    "query_length",
    "url_entropy",
    "sensitive_path",
    "suspicious_extension",
    "sql_injection_pattern",
    "xss_pattern",
    "path_traversal",
    "is_bot",
    "has_referer",
    "client_error",
    "server_error",
    "requests_per_ip_10s",
    "requests_per_ip_1m",
    "error_rate",
]

CATEGORICAL_COLUMNS = ["method", "path", "user_agent"]

SENSITIVE_PATHS = ("/login", "/admin", "/wp-login", "/config", "/etc/passwd")
SUSPICIOUS_EXTENSIONS = (".env", ".git", ".bak", ".sql", ".ini", ".conf")

SQLI_RE = re.compile(
    r"(?i)(union(?:\s|\+|%20)+select|select(?:\s|\+|%20)+.+(?:\s|\+|%20)+from|'?\s*or\s+1\s*=\s*1|--|drop(?:\s|\+|%20)+table)"
)
XSS_RE = re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)")
BOT_RE = re.compile(r"(?i)(sqlmap|nikto|nmap|dirbuster|gobuster|python-requests|curl|wget)")
CREDENTIAL_RE = re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret)=")


def parse_nginx_hour(timestamp: str) -> int:
    raw = str(timestamp).strip().split()[0]
    return int(datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S").hour)


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(char) / len(value) for char in set(value)]
    return round(-sum(probability * math.log(probability, 2) for probability in probabilities), 4)


def normalize_path(url: str) -> str:
    parsed = urlparse(str(url))
    path = parsed.path or str(url).split("?")[0] or "/"
    return path[:512]


def build_rule_label(row: dict) -> int:
    url = str(row.get("url", ""))
    path = normalize_path(url)
    referer = str(row.get("referer", ""))
    user_agent = str(row.get("user_agent", ""))
    status = int(row.get("status", 0) or 0)

    suspicious = (
        url.lower().startswith("http://")
        or referer.lower().startswith("http://")
        or CREDENTIAL_RE.search(url) is not None
        or any(item in path.lower() for item in SENSITIVE_PATHS)
        or any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        or SQLI_RE.search(url) is not None
        or XSS_RE.search(url) is not None
        or "../" in url
        or "etc/passwd" in url.lower()
        or BOT_RE.search(user_agent) is not None
        or status >= 500
    )
    return -1 if suspicious else 1


def describe_rule_threat(row: dict) -> tuple[str, str, str] | None:
    url = str(row.get("url", ""))
    path = normalize_path(url)
    referer = str(row.get("referer", ""))
    user_agent = str(row.get("user_agent", ""))
    status = int(row.get("status", 0) or 0)

    if CREDENTIAL_RE.search(url):
        return "Credentials in URL", "critical", "Sensitive credential-like query parameter is exposed in the URL."
    if SQLI_RE.search(url):
        return "SQL Injection Attempt", "critical", "Request contains SQL injection keywords or operators."
    if XSS_RE.search(url):
        return "Cross-Site Scripting (XSS)", "high", "Request contains script-like browser execution payloads."
    if "../" in url or "etc/passwd" in url.lower():
        return "Path Traversal Attempt", "high", "Request attempts to traverse server paths."
    if url.lower().startswith("http://"):
        return "Insecure HTTP Request", "medium", "Request target uses unencrypted HTTP."
    if referer.lower().startswith("http://"):
        return "Insecure HTTP Referer", "medium", "Referer uses unencrypted HTTP."
    if any(item in path.lower() for item in SENSITIVE_PATHS):
        return "Sensitive Path Probe", "high", "Request targets an authentication, admin, or sensitive path."
    if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        return "Sensitive File Probe", "high", "Request targets a sensitive file extension."
    if BOT_RE.search(user_agent):
        return "Automated Scanner / Script", "medium", "User agent matches common scanner or scripted traffic."
    if status >= 500:
        return "Server Error Spike", "medium", "Request produced a server-side error status."
    return None


def _timestamps(df: pd.DataFrame) -> pd.Series:
    parsed = pd.to_datetime(
        df["timestamp"].astype(str),
        format="%d/%b/%Y:%H:%M:%S %z",
        errors="coerce",
        utc=True,
    )
    fallback = pd.Series(pd.RangeIndex(len(df)), index=df.index, dtype="float64")
    return (parsed.astype("int64") // 1_000_000_000).where(parsed.notna(), fallback)


def build_feature_frame(df: pd.DataFrame, include_behavior: bool = True) -> pd.DataFrame:
    data = df.copy()
    data["url"] = data.get("url", "").astype(str)
    data["referer"] = data.get("referer", "").astype(str)
    data["user_agent"] = data.get("user_agent", "").astype(str)
    data["method"] = data.get("method", "GET").astype(str)
    data["status"] = pd.to_numeric(data.get("status", 200), errors="coerce").fillna(200).astype(int)
    data["size"] = pd.to_numeric(data.get("size", 0), errors="coerce").fillna(0).astype(int)
    data["path"] = data["url"].map(normalize_path)
    data["hour_of_day"] = data["timestamp"].map(parse_nginx_hour) if "timestamp" in data else 0
    data["path_depth"] = data["path"].map(lambda value: value.count("/"))
    data["query_length"] = data["url"].map(lambda value: len(value.split("?", 1)[1]) if "?" in value else 0)
    data["url_entropy"] = data["url"].map(calculate_entropy)
    data["sensitive_path"] = data["path"].str.lower().map(lambda value: int(any(item in value for item in SENSITIVE_PATHS)))
    data["suspicious_extension"] = data["path"].str.lower().map(lambda value: int(any(value.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)))
    data["sql_injection_pattern"] = data["url"].map(lambda value: int(SQLI_RE.search(value) is not None))
    data["xss_pattern"] = data["url"].map(lambda value: int(XSS_RE.search(value) is not None))
    data["path_traversal"] = data["url"].str.lower().map(lambda value: int("../" in value or "etc/passwd" in value))
    data["is_bot"] = data["user_agent"].map(lambda value: int(BOT_RE.search(value) is not None))
    data["has_referer"] = data["referer"].map(lambda value: int(bool(value and value != "-")))
    data["client_error"] = (data["status"] >= 400).astype(int)
    data["server_error"] = (data["status"] >= 500).astype(int)

    if include_behavior and {"ip", "timestamp"}.issubset(data.columns):
        ordered = data.assign(_ts=_timestamps(data)).sort_values(["ip", "_ts"]).copy()
        req_10s = pd.Series(0, index=ordered.index, dtype="int64")
        req_1m = pd.Series(0, index=ordered.index, dtype="int64")
        err_rate = pd.Series(0.0, index=ordered.index, dtype="float64")
        for _, group in ordered.groupby("ip", sort=False):
            times = group["_ts"].tolist()
            errors = group["client_error"].tolist()
            for pos, idx in enumerate(group.index):
                start_10 = pos
                while start_10 < pos and times[start_10] < times[pos] - 10:
                    start_10 += 1
                start_60 = pos
                while start_60 < pos and times[start_60] < times[pos] - 60:
                    start_60 += 1
                req_10s.loc[idx] = pos - start_10 + 1
                req_1m.loc[idx] = pos - start_60 + 1
                window_errors = errors[start_60 : pos + 1]
                err_rate.loc[idx] = sum(window_errors) / max(len(window_errors), 1)
        data["requests_per_ip_10s"] = req_10s.reindex(data.index).fillna(1).astype(int)
        data["requests_per_ip_1m"] = req_1m.reindex(data.index).fillna(1).astype(int)
        data["error_rate"] = err_rate.reindex(data.index).fillna(0.0)
    else:
        data["requests_per_ip_10s"] = 1
        data["requests_per_ip_1m"] = 1
        data["error_rate"] = data["client_error"].astype(float)

    return data[FEATURE_COLUMNS]


class LiveBehaviorTracker:
    def __init__(self) -> None:
        self.requests_10s: defaultdict[str, deque[float]] = defaultdict(deque)
        self.requests_1m: defaultdict[str, deque[float]] = defaultdict(deque)
        self.errors_1m: defaultdict[str, deque[tuple[float, int]]] = defaultdict(deque)

    def metrics(self, ip: str, status: int) -> tuple[int, int, float]:
        now = datetime.now().timestamp()
        self.requests_10s[ip].append(now)
        self.requests_1m[ip].append(now)
        self.errors_1m[ip].append((now, int(status >= 400)))

        while self.requests_10s[ip] and self.requests_10s[ip][0] < now - 10:
            self.requests_10s[ip].popleft()
        while self.requests_1m[ip] and self.requests_1m[ip][0] < now - 60:
            self.requests_1m[ip].popleft()
        while self.errors_1m[ip] and self.errors_1m[ip][0][0] < now - 60:
            self.errors_1m[ip].popleft()

        errors = [flag for _, flag in self.errors_1m[ip]]
        return len(self.requests_10s[ip]), len(self.requests_1m[ip]), sum(errors) / max(len(errors), 1)
