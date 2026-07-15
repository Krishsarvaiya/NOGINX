import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\['
    r'(?P<timestamp>[^\]]+)'
    r'\]\s+"(?P<method>\w+)\s(?P<url>\S+)\s(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d+)\s(?P<size>\d+|-)'
    r'\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


def parse_hour(timestamp: str) -> int:
    raw = str(timestamp).strip().split()[0]
    return int(datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S").hour)


def parse_log_line(line: str) -> dict | None:
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    row = match.groupdict()
    row["path"] = row["url"].split("?")[0]
    row["status"] = int(row["status"])
    row["size"] = 0 if row["size"] == "-" else int(row["size"])
    row["hour_of_day"] = parse_hour(row["timestamp"])
    row["raw_line"] = line.strip()
    return row


def parse_log_file(path: str | Path, limit: int | None = None) -> list[dict]:
    entries: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
                if limit and len(entries) >= limit:
                    break
    return entries


def iter_log_file(path: str | Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parsed = parse_log_line(line)
            if parsed:
                yield parsed
