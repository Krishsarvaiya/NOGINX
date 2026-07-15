"""
Synthetic log generator for local testing.

This script appends synthetic CSV rows using the same header format
present in the repository. It only writes local files and does NOT
perform any network scanning or attacks. Use it in a lab or with
consent from everyone on the test network.

Defaults to data/archive/ (core.paths.ARCHIVE_DIR), never the training
or testing datasets -- so a test run of this script can never silently
contaminate what scripts/train_isolation_forest.py trains on or what
the offline evaluation scripts (scripts/phase6_*.py, phase7_*.py) score
against. Pass --path explicitly if you need to target a different file.

Usage examples:
  python Project_Files/log_generator.py --count 100 --interval 0.5
  python Project_Files/log_generator.py --ips 10.0.0.5,10.0.0.6 --count 50

Safety: only run this against your local test CSV. Do not use it to
target external systems.
"""
import argparse
import csv
import os
import random
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.paths import ARCHIVE_DIR

DEFAULT_PATH = os.path.join(ARCHIVE_DIR, "synthetic_test_output.csv")


def apache_time(ts=None):
    ts = ts or datetime.utcnow()
    return ts.strftime("%d/%b/%Y:%H:%M:%S")


def ensure_header(path, header):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def generate_row(ip, endpoint, method="GET", status=200):
    # Match repository CSV header: IP,Time,URL,Staus
    url_field = f"{method} {endpoint}"
    return [ip, apache_time(), url_field, status]


def main():
    parser = argparse.ArgumentParser(description="Append synthetic log lines to a CSV in weblog.csv's format")
    parser.add_argument("--path", default=DEFAULT_PATH, help="CSV file to append to (default: data/archive/, never training or testing data)")
    parser.add_argument("--count", type=int, default=50, help="Number of lines to append")
    parser.add_argument("--interval", type=float, default=0.25, help="Seconds between appended lines")
    parser.add_argument("--ips", default="192.168.1.101,192.168.1.102,192.168.1.103",
                        help="Comma-separated source IPs to simulate")
    parser.add_argument("--endpoints", default="/login,/admin,/index.html,/api/data,/wp-login.php",
                        help="Comma-separated endpoints to choose from")
    parser.add_argument("--status", default="200,401,403,404,500", help="Comma-separated status codes")
    parser.add_argument("--randomize", action="store_true", help="Randomize methods and endpoints")

    args = parser.parse_args()

    ips = [x.strip() for x in args.ips.split(",") if x.strip()]
    endpoints = [x.strip() for x in args.endpoints.split(",") if x.strip()]
    statuses = [int(x) for x in args.status.split(",") if x.strip()]

    header = ["IP", "Time", "URL", "Staus"]
    ensure_header(args.path, header)

    print(f"Appending {args.count} lines to {args.path} (interval={args.interval}s)")

    with open(args.path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for i in range(args.count):
            ip = random.choice(ips)
            endpoint = random.choice(endpoints)
            method = random.choice(["GET", "POST", "PUT", "DELETE"]) if args.randomize else "GET"
            status = random.choice(statuses)
            row = generate_row(ip, endpoint, method=method, status=status)
            writer.writerow(row)
            f.flush()
            print("wrote:", row)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
