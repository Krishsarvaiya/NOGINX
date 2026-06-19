import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv()
_root_env = PROJECT_ROOT / ".env"
if _root_env.exists():
    load_dotenv(dotenv_path=str(_root_env))

from ml.log_parser import LOG_PATTERN, parse_log_line  # noqa: E402
from ml.threat_engine import ThreatEngine  # noqa: E402

# --- Configuration ---
NGINX_ACCESS_LOG = os.getenv("NGINX_ACCESS_LOG", r"C:\nginx-1.29.8\logs\access.log")
DEBUG_WATCHER = os.getenv("DEBUG_WATCHER", "false").strip().lower() == "true"
WATCHER_ALERT_THRESHOLD = float(os.getenv("WATCHER_ALERT_THRESHOLD", "0.45"))
ENABLE_DESKTOP_ALERTS = os.getenv("ENABLE_DESKTOP_ALERTS", "true").strip().lower() == "true"
ENABLE_EMAIL_ALERTS = os.getenv("ENABLE_EMAIL_ALERTS", "false").strip().lower() == "true"

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
INCIDENT_REPORT_URL = os.getenv("INCIDENT_REPORT_URL", f"{API_BASE_URL}/api/incidents/report")
SERVICE_TOKEN = os.getenv("NOGINX_SERVICE_TOKEN", "")
REPORT_TO_DASHBOARD = os.getenv("REPORT_TO_DASHBOARD", "true").strip().lower() == "true"

NOGINX_MAIL_ID = os.getenv("NOGINX_MAIL_ID")
NOGINX_MAIL_PASSWORD = os.getenv("NOGINX_MAIL_PASSWORD")
RECEIVER_MAIL_ID = os.getenv("RECEIVER_MAIL_ID")

BRUTE_FORCE_WINDOW_SEC = 10
BRUTE_FORCE_LIMIT = 10

request_tracker: dict[str, list[float]] = {}
recent_alerts: dict[str, float] = {}
ALERT_COOLDOWN_SEC = 30

threat_engine = ThreatEngine()


def _desktop_notify(title: str, message: str) -> None:
    if not ENABLE_DESKTOP_ALERTS:
        return
    try:
        from plyer import notification

        notification.notify(
            title=title,
            message=message[:256],
            app_name="NOGINX",
            timeout=12,
        )
    except Exception as exc:
        print(f"[alert] desktop notification unavailable: {exc}")


def _email_notify(subject: str, message: str) -> None:
    if not ENABLE_EMAIL_ALERTS:
        return
    if not all([NOGINX_MAIL_ID, NOGINX_MAIL_PASSWORD, RECEIVER_MAIL_ID]):
        print("[alert] email skipped — set NOGINX_MAIL_ID, NOGINX_MAIL_PASSWORD, RECEIVER_MAIL_ID")
        return
    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(message, _charset="utf-8")
        msg["Subject"] = subject
        msg["From"] = NOGINX_MAIL_ID
        msg["To"] = RECEIVER_MAIL_ID

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(NOGINX_MAIL_ID, NOGINX_MAIL_PASSWORD)
            smtp.sendmail(NOGINX_MAIL_ID, RECEIVER_MAIL_ID, msg.as_string())
    except Exception as exc:
        print(f"[alert] email failed: {exc}")


def report_to_dashboard(prediction: dict) -> None:
    if not REPORT_TO_DASHBOARD:
        return
    if not SERVICE_TOKEN:
        if DEBUG_WATCHER:
            print("[dashboard] skipped — set NOGINX_SERVICE_TOKEN in .env")
        return

    payload = {
        "ip": prediction["ip"],
        "timestamp": prediction["timestamp"],
        "method": prediction["method"],
        "path": prediction["path"],
        "status": prediction["status"],
        "threat_type": prediction["threat_type"],
        "confidence": prediction["confidence"],
        "severity": prediction["severity"],
        "user_agent": prediction["user_agent"],
        "ml_score": prediction["ml_score"],
        "raw_line": prediction.get("raw_line"),
        "message": prediction.get("message"),
        "source": "watcher",
    }
    try:
        response = requests.post(
            INCIDENT_REPORT_URL,
            json=payload,
            headers={"X-Service-Token": SERVICE_TOKEN},
            timeout=5,
        )
        if response.status_code >= 400:
            print(f"[dashboard] report failed ({response.status_code}): {response.text[:200]}")
        elif DEBUG_WATCHER:
            print(f"[dashboard] incident recorded id={response.json().get('id')}")
    except Exception as exc:
        print(f"[dashboard] report error: {exc}")


def send_alert(prediction: dict) -> None:
    alert_key = f"{prediction['ip']}:{prediction['threat_type']}:{prediction['path']}"
    now = time.time()
    if now - recent_alerts.get(alert_key, 0) < ALERT_COOLDOWN_SEC:
        return
    recent_alerts[alert_key] = now

    title = f"NOGINX — {prediction['threat_type']}"
    message = (
        f"Severity: {prediction['severity'].upper()} ({prediction['confidence']*100:.1f}%)\n"
        f"IP: {prediction['ip']}\n"
        f"Path: {prediction['path']}\n"
        f"Status: {prediction['status']}\n"
        f"Detail: {prediction.get('message', '')}"
    )

    print("\n" + "=" * 60)
    print(f"🚨 {title}")
    print(message)
    print("=" * 60 + "\n")

    _desktop_notify(title, message)
    _email_notify(f"🚨 NOGINX Alert: {prediction['threat_type']}", message)
    report_to_dashboard(prediction)


def check_brute_force(ip: str) -> dict | None:
    now = time.time()
    if ip not in request_tracker:
        request_tracker[ip] = []
    request_tracker[ip].append(now)
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t < BRUTE_FORCE_WINDOW_SEC]

    if len(request_tracker[ip]) > BRUTE_FORCE_LIMIT:
        return {
            "threat_type": "Brute Force / Rate Abuse",
            "confidence": 0.82,
            "severity": "high",
            "ip": ip,
            "timestamp": "",
            "method": "MULTI",
            "path": "/",
            "url": "/",
            "status": 0,
            "user_agent": "watcher-rate-detector",
            "ml_anomaly": True,
            "ml_score": 0.0,
            "rule_matched": True,
            "raw_line": "",
            "message": (
                f"IP {ip} sent {len(request_tracker[ip])} requests in "
                f"{BRUTE_FORCE_WINDOW_SEC}s — possible brute force or flooding."
            ),
            "referer": "-",
            "source": "watcher",
        }
    return None


def process_line(line: str) -> None:
    row = parse_log_line(line)
    if not row:
        if DEBUG_WATCHER:
            print("⚠️  Unparsed log line")
        return

    ip = row["ip"]
    print(
        f"[traffic] {ip} {row['method']} {row['path']} "
        f"→ {row['status']} ({row.get('referer', '-')[:40]})"
    )

    brute = check_brute_force(ip)
    if brute:
        send_alert(brute)

    prediction = threat_engine.analyze_entry(row).to_dict()

    if DEBUG_WATCHER:
        print(
            f"[analysis] {prediction['threat_type']} "
            f"conf={prediction['confidence']:.2f} ml={prediction['ml_score']:.4f}"
        )

    if prediction["threat_type"] != "Benign" and prediction["confidence"] >= WATCHER_ALERT_THRESHOLD:
        send_alert(prediction)
    elif prediction["ml_anomaly"] and prediction["confidence"] >= WATCHER_ALERT_THRESHOLD:
        send_alert(prediction)


def main() -> None:
    log_path = Path(NGINX_ACCESS_LOG)
    if not log_path.exists():
        raise FileNotFoundError(
            f"NGINX access log not found: {log_path}\n"
            "Set NGINX_ACCESS_LOG in .env. Note: only traffic routed through NGINX is logged."
        )

    print("🚀 NOGINX Live Watcher")
    print(f"   log file     : {log_path}")
    print(f"   alert thresh : {WATCHER_ALERT_THRESHOLD}")
    print(f"   dashboard    : {'ON' if REPORT_TO_DASHBOARD and SERVICE_TOKEN else 'OFF (set NOGINX_SERVICE_TOKEN)'}")
    print(f"   desktop alert: {'ON' if ENABLE_DESKTOP_ALERTS else 'OFF'}")
    print(f"   email alert  : {'ON' if ENABLE_EMAIL_ALERTS else 'OFF'}")
    print()

    with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
        try:
            handle.seek(0)
            sample = handle.readlines()[-50:]
            matched = sum(1 for line in sample if LOG_PATTERN.search(line))
            print(f"[startup] parse_matches_last50={matched}/50")
        except Exception as exc:
            print(f"[startup] sample parse warning: {exc}")

        handle.seek(0, os.SEEK_END)
        print("Watching for new log entries...\n")

        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            process_line(line)


if __name__ == "__main__":
    main()
