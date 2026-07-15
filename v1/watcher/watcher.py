from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.threat_engine import ThreatEngine

load_dotenv(PROJECT_ROOT / ".env")

DEFAULT_LOG_PATH = r"C:\nginx-1.29.8\logs\access.log"


def tail_file(filepath: Path):
    if not filepath.exists():
        print(f"[-] Target log file not found: {filepath}. Waiting for creation...")
        while not filepath.exists():
            time.sleep(1)

    print("[+] Found log target. Streaming new entries...")
    with filepath.open("r", encoding="utf-8", errors="ignore") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line


def report_to_dashboard(prediction: dict) -> None:
    token = os.getenv("NOGINX_SERVICE_TOKEN", "").strip()
    if not token:
        return

    api_base = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    payload = {**prediction, "source": "watcher"}
    try:
        response = requests.post(
            f"{api_base}/api/live/report",
            headers={"X-Service-Token": token},
            json=payload,
            timeout=5,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"[warn] Could not report incident to dashboard: {exc}")


def main() -> None:
    log_path = Path(os.getenv("NGINX_ACCESS_LOG") or os.getenv("NGINX_LOG_PATH") or DEFAULT_LOG_PATH)
    threshold = float(os.getenv("WATCHER_ALERT_THRESHOLD", "0.45"))

    print("=======================================================")
    print("                NOGINX REAL-TIME WATCHER              ")
    print("=======================================================")
    print(f"[*] Target log: {log_path}")

    try:
        engine = ThreatEngine()
        print("[+] Threat engine loaded successfully.")
    except Exception as exc:
        print(f"[-] Failed to load threat engine: {exc}")
        sys.exit(1)

    print("\nWatching NGINX logs for threats. Press Ctrl+C to stop.\n")

    try:
        for raw_line in tail_file(log_path):
            prediction = engine.analyze_line(raw_line.strip())
            if not prediction:
                continue

            result = prediction.to_dict()
            report_to_dashboard(result)
            if prediction.threat_type != "Benign" and prediction.confidence >= threshold:
                print("[ALERT] Threat detected")
                print(f"    Type:      {prediction.threat_type}")
                print(f"    Severity:  {prediction.severity.upper()}")
                print(f"    Source IP: {prediction.ip}")
                print(f"    Request:   {prediction.method} {prediction.url}")
                print(f"    Status:    {prediction.status}")
                print(f"    Confidence:{prediction.confidence:.2f}")
                print(f"    Message:   {prediction.message}\n")
            else:
                print(f"[traffic] {prediction.ip} - {prediction.method} {prediction.path} -> HTTP {prediction.status}")
    except KeyboardInterrupt:
        print("\n[-] Watcher stopped by user.")


if __name__ == "__main__":
    main()
