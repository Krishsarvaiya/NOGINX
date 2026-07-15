#!/usr/bin/env python3
"""Simulates reconnaissance probing for common sensitive/admin paths.

Real HTTP requests only. /admin is a real (but unlinked) page on this
site (see site/app.py) -- everything else here genuinely 404s, exactly
like a real deployment being probed for paths that don't exist.

Verified against the actual, unmodified rule engine:
- /admin, /.env, /.git, /config match the exact substrings the rule
  engine looks for and are classified as "Reconnaissance Scan".
- /wp-login.php and /phpmyadmin do NOT match those exact substrings
  (the rule engine matches "/login" with a leading slash, and
  "wp-login.php" doesn't contain that) -- they fall through to a
  generic "Access Denial" classification on their 404. Included anyway
  because that's what a real recon scan actually looks like; the
  contrast is explained in docs/DEMO_GUIDE.md rather than hidden.

Usage:
    python demo/simulate_recon_scan.py [--interval 0.4]
"""
import argparse
import time

from _common import BASE_URL, check_site_is_running, spoofed_session

PATHS = [
    "/admin",
    "/.env",
    "/.git",
    "/.git/config",
    "/config",
    "/config.php",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/server-status",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/backup.zip",
    "/db_backup.sql",
    "/manager/html",
    "/cpanel",
    "/.htaccess",
    "/administrator",
]


def run(interval: float, ip: str):
    session = spoofed_session(ip)
    for path in PATHS:
        resp = session.get(BASE_URL + path)
        print(f"GET {path} -> {resp.status_code}")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=0.4)
    parser.add_argument("--ip", default="203.0.113.40", help="Simulated attacker IP (via X-Forwarded-For)")
    args = parser.parse_args()

    check_site_is_running()
    run(args.interval, args.ip)
