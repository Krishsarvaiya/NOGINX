"""End-to-end verification for NOGINX. Run: python verify_stack.py"""

import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
BASE = "http://127.0.0.1:8000"
errors: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    if not ok:
        errors.append(name)


def main() -> None:
    r = requests.get(f"{BASE}/health", timeout=5)
    check("Health", r.status_code == 200, r.json().get("status"))

    username, password, email = "krish_demo", "demo12345", "krish_demo@example.com"
    r = requests.post(
        f"{BASE}/auth/signup",
        json={"username": username, "email": email, "password": password},
        timeout=5,
    )
    if r.status_code == 400:
        r = requests.post(
            f"{BASE}/auth/login",
            json={"username": username, "password": password},
            timeout=5,
        )
    check("Auth", r.status_code == 200)
    token = r.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    line = (
        "192.168.1.5 - - [17/May/2015:10:00:01 +0000] "
        '"GET http://insecure-site.com/login HTTP/1.1" 200 100 "http://fake.com/" "Mozilla/5.0"'
    )
    r = requests.post(f"{BASE}/api/analyze-line", headers=headers, json={"line": line}, timeout=10)
    if r.status_code == 200:
        data = r.json()
        check("HTTP insecurity detection", data.get("threat_type") != "Benign", data.get("threat_type"))
    else:
        check("HTTP insecurity detection", False, r.text[:120])

    r = requests.post(
        f"{BASE}/api/incidents/report",
        headers={"X-Service-Token": os.getenv("NOGINX_SERVICE_TOKEN", "")},
        json={
            "ip": "10.0.0.99",
            "threat_type": "Insecure HTTP Request",
            "confidence": 0.84,
            "severity": "high",
            "path": "/login",
            "message": "retry verification test",
            "source": "watcher",
        },
        timeout=5,
    )
    check("Watcher service token", r.status_code == 200, str(r.json()))

    with open(ROOT / "data" / "nginx.log", "rb") as handle:
        r = requests.post(
            f"{BASE}/api/analyze-log?top_n=3&max_lines=2000",
            headers=headers,
            files={"file": ("nginx.log", handle)},
            timeout=120,
        )
    if r.status_code == 200:
        data = r.json()
        check(
            "Log scan",
            True,
            f"lines={data.get('total_lines_parsed')} threats={data.get('total_threats')}",
        )
    else:
        check("Log scan", False, r.text[:120])

    r = requests.get(f"{BASE}/api/dashboard/stats", headers=headers, timeout=5)
    check("Dashboard stats", r.status_code == 200)
    r = requests.get(f"{BASE}/api/dashboard/scans", headers=headers, timeout=5)
    check("Scan history API", r.status_code == 200 and len(r.json()) > 0)
    r = requests.get(f"{BASE}/api/profile", headers=headers, timeout=5)
    check("Profile API", r.status_code == 200)

    for page in (
        "login.html",
        "dashboard.html",
        "scan.html",
        "history.html",
        "incidents.html",
        "live.html",
        "profile.html",
    ):
        r = requests.get(f"{BASE}/ui/{page}", timeout=5)
        check(f"UI {page}", r.status_code == 200)

    sys.path.insert(0, str(ROOT))
    from ml.log_parser import parse_log_line
    from ml.threat_engine import ThreatEngine

    engine = ThreatEngine()
    with open(ROOT / "data" / "nginx.log", "r", encoding="utf-8", errors="ignore") as handle:
        for index, line in enumerate(handle):
            if index >= 3:
                break
            row = parse_log_line(line)
            if row:
                pred = engine.analyze_entry(row)
                print(f"  sample line: {pred.threat_type} ({pred.confidence})")

    print("---")
    if errors:
        print("FAILED:", ", ".join(errors))
        sys.exit(1)
    print("All checks passed.")
    print("Dashboard: http://127.0.0.1:8000/ui/login.html")
    print("Login: krish_demo / demo12345")


if __name__ == "__main__":
    main()
