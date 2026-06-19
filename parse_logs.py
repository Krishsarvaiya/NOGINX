"""Parse raw NGINX logs into nginx_logs.csv. Run from project root."""

import csv
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"

pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\]\s"'
    r'(?P<method>\w+)\s(?P<url>\S+)\s(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d+)\s(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

log_path = DATA_DIR / "nginx.log"
csv_path = DATA_DIR / "nginx_logs.csv"

parsed_logs = []
with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
    for line in handle:
        match = pattern.search(line)
        if match:
            row = match.groupdict()
            if row["size"] == "-":
                row["size"] = "0"
            parsed_logs.append(row)

with open(csv_path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(
        handle,
        fieldnames=[
            "ip",
            "timestamp",
            "method",
            "url",
            "http_version",
            "status",
            "size",
            "referer",
            "user_agent",
        ],
    )
    writer.writeheader()
    writer.writerows(parsed_logs)

print(f"[OK] Parsed {len(parsed_logs)} lines to {csv_path}")
