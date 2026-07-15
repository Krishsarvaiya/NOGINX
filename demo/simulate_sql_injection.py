#!/usr/bin/env python3
"""Simulates SQL injection probing against the Results and Library
search pages.

Real HTTP requests only. There is no real database behind either
search (see site/data/dummy_data.py) -- these payloads never actually
inject into anything. What this demonstrates is that the *request
itself* gets logged and classified by the existing (unmodified) rule
engine as "SQL/Web Injection Attack", exactly as it would against a
real vulnerable backend.

Note: a payload containing the word "password" (e.g. one that selects
a password column) gets classified as "Credential Attack" instead --
the rule engine checks for password/auth/token/session *before* it
checks for injection syntax. The payloads below deliberately avoid
that word so they land in the injection category; this quirk is
documented in docs/DEMO_GUIDE.md rather than being papered over here.

Usage:
    python demo/simulate_sql_injection.py [--interval 0.3]
"""
import argparse
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

RESULTS_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1'--",
    "' UNION SELECT username, email FROM users--",
    "'; DROP TABLE results;--",
    "1' AND SLEEP(5)--",
]

LIBRARY_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT title, author FROM books--",
]


def run(interval: float, ip: str):
    session = spoofed_session(ip)
    for payload in RESULTS_PAYLOADS:
        resp = session.get(BASE_URL + "/results", params={"roll_no": payload})
        print(f"/results?roll_no={payload!r} -> {resp.status_code}")
        time.sleep(interval)
    for payload in LIBRARY_PAYLOADS:
        resp = session.get(BASE_URL + "/library", params={"q": payload})
        print(f"/library?q={payload!r} -> {resp.status_code}")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=0.3)
    parser.add_argument("--ip", default="203.0.113.30", help="Simulated attacker IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.interval, args.ip)
