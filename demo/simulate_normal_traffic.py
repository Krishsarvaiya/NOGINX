#!/usr/bin/env python3
"""Simulates an ordinary visitor browsing the college website.

Real HTTP requests only -- browses pages, searches the library and
results lookup with valid terms, downloads a PDF, submits the contact
form, and logs in with the correct demo credentials. Useful as a
"normal" baseline to contrast against the attack scripts.

Usage:
    python demo/simulate_normal_traffic.py [--count 30] [--interval 0.5]
"""
import argparse
import random
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

PAGES = ["/", "/about", "/admissions", "/departments", "/faculty",
         "/placements", "/downloads", "/contact"]
LIBRARY_QUERIES = ["algorithms", "electronics", "mechanics", "accounting", ""]
VALID_ROLL_NUMBERS = ["CS2021001", "CS2021002", "EC2021015", "ME2021030", "CE2021042"]
DOWNLOAD_FILES = ["prospectus.pdf", "fee_structure.pdf", "syllabus.pdf"]


def run(count: int, interval: float, ip: str):
    session = spoofed_session(ip)
    for _ in range(count):
        action = random.choice(["page", "library", "results", "download", "login"])
        if action == "page":
            session.get(BASE_URL + random.choice(PAGES))
        elif action == "library":
            session.get(BASE_URL + "/library", params={"q": random.choice(LIBRARY_QUERIES)})
        elif action == "results":
            session.get(BASE_URL + "/results", params={"roll_no": random.choice(VALID_ROLL_NUMBERS)})
        elif action == "download":
            session.get(BASE_URL + "/static/downloads/" + random.choice(DOWNLOAD_FILES))
        elif action == "login":
            session.post(BASE_URL + "/login", data={"username": "student1", "password": "demo123"})
        print("visited:", action)
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--ip", default="203.0.113.10", help="Simulated visitor IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.count, args.interval, args.ip)
