#!/usr/bin/env python3
"""Simulates rapid directory/file scanning: many requests to many
distinct, mostly nonexistent URLs in a short window.

Real HTTP requests only. Unlike simulate_recon_scan.py (a curated list
of known sensitive paths), this is about sheer volume and URL
diversity in one session -- the shape of traffic the Isolation Forest
specifically picks up on (record_count / unique_urls far outside the
normal range), independent of whether any individual path matches a
rule-engine keyword. See docs/ML_DETECTION_QUALITY_REPORT.md for the
evidence this pattern is exactly what the ML layer catches that the
rule engine alone would miss.

Usage:
    python demo/simulate_directory_scan.py [--count 150] [--interval 0.05]
"""
import argparse
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

EXTENSIONS = ["php", "asp", "aspx", "jsp", "html", "bak", "old", "zip", "tar.gz"]
WORDS = ["test", "old", "temp", "backup", "dev", "staging", "internal", "private",
         "secret", "hidden", "tmp", "copy", "v2", "new", "draft", "beta"]


def run(count: int, interval: float, ip: str):
    session = spoofed_session(ip)
    n = 0
    for word in WORDS:
        for ext in EXTENSIONS:
            if n >= count:
                return
            path = f"/{word}.{ext}"
            resp = session.get(BASE_URL + path)
            print(f"GET {path} -> {resp.status_code}")
            n += 1
            time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=150)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--ip", default="203.0.113.50", help="Simulated attacker IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.count, args.interval, args.ip)
