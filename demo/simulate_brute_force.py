#!/usr/bin/env python3
"""Simulates a brute-force login attack: many failed /login attempts
from one source in a short window, then one success.

Real HTTP requests only. Every failed attempt gets a real 401 from
site/app.py's /login route, which the existing (unmodified) rule
engine classifies as "Brute Force Attack"
(status in {401,403} and '/login' in the URL).

Usage:
    python demo/simulate_brute_force.py [--count 45] [--interval 0.15]
"""
import argparse
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

PASSWORDS_TO_TRY = ["password", "123456", "admin123", "letmein", "qwerty",
                    "student", "welcome1", "demo1234", "changeme", "iloveyou"]


def run(count: int, interval: float, ip: str):
    session = spoofed_session(ip)
    for i in range(count):
        password = PASSWORDS_TO_TRY[i % len(PASSWORDS_TO_TRY)]
        resp = session.post(BASE_URL + "/login", data={"username": "student1", "password": password})
        print(f"attempt {i + 1}/{count}: password={password!r} -> {resp.status_code}")
        time.sleep(interval)

    # One final, correct attempt -- a real attack usually eventually
    # guesses right, or at least this shows the contrast in the logs.
    resp = session.post(BASE_URL + "/login", data={"username": "student1", "password": "demo123"})
    print("final attempt with correct password ->", resp.status_code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=45)
    parser.add_argument("--interval", type=float, default=0.15)
    parser.add_argument("--ip", default="203.0.113.20", help="Simulated attacker IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.count, args.interval, args.ip)
