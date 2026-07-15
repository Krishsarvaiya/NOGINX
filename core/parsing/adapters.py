"""Format-specific line -> row-dict adapters, sharing one downstream
interface: core.parsing.log_parser.parse_weblog_row(row) already accepts
any dict with case-insensitive IP/Time/URL/Status keys, so every adapter
here only needs to produce that same 4-key dict -- nothing downstream
(parse_weblog_row, classify_threat_type, session building, feature
extraction) needs to know or care which adapter produced it.

csv_row_from_line() is CSV-tailing's adapter (data/live/college_site_access.csv,
written by site/app.py) -- moved here unchanged from src/live_analyzer.py
so both adapters live in one place instead of the CSV one being buried
in the live analyzer's transport loop.

nginx_row_from_line() is NGINX-tailing's adapter, for the custom
pipe-delimited log_format scripts/generate_nginx_conf.py writes into
nginx.conf: '$remote_addr|$time_local|$request|$status'.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import unquote

from core.parsing.log_parser import _HTTP_VERSION_SUFFIX, TIME_FORMAT

# NGINX's $time_local is "<local wall clock> <UTC offset>", e.g.
# "13/Jul/2026:23:15:45 +0530" -- unlike site/app.py's CSV Time column
# (always UTC), $time_local is in the *server's local* timezone.
# Every naive timestamp already flowing through this pipeline is
# implicitly UTC (StreamingPipeline.tick(), core/pipeline/streaming_pipeline.py,
# directly subtracts a wall-clock UTC `now` from a session's last
# record timestamp to decide whether to flush) -- so merely stripping
# this offset and keeping the local wall-clock digits would desync
# that comparison by the offset's magnitude (e.g. every session would
# look ~5.5 hours old under IST, and the batch-interval flush would
# never fire). _nginx_time_to_utc_field() converts using the offset
# instead, preserving the naive-but-UTC invariant every other
# timestamp source already upholds.
_NGINX_TIME_RE = re.compile(
    r"^(?P<dt>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+(?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})$"
)


def _nginx_time_to_utc_field(time_local: str) -> str:
    match = _NGINX_TIME_RE.match(time_local)
    if not match:
        # Malformed/unexpected format -- return as-is, bracket-prefixed;
        # parse_timestamp() will reject it (returns None) rather than
        # silently using a wrong-timezone value.
        return "[" + time_local

    naive_local = datetime.strptime(match.group("dt"), TIME_FORMAT)
    offset = timedelta(hours=int(match.group("oh")), minutes=int(match.group("om")))
    utc = naive_local - offset if match.group("sign") == "+" else naive_local + offset
    return "[" + utc.strftime(TIME_FORMAT)


def csv_row_from_line(line: str, headers: list[str]) -> Optional[dict]:
    """Turn one raw college_site_access.csv line into a header-keyed
    dict, tolerating rows with extra commas (e.g. an unescaped comma
    inside a field). Unchanged file-tailing heuristic -- not semantic
    parsing, so it stays a thin adapter rather than moving into
    core.parsing.log_parser.
    """
    try:
        row = next(csv.reader([line]))
    except Exception:
        return None

    if len(row) == len(headers):
        return {h: v for h, v in zip(headers, row)}

    if len(row) > len(headers):
        ip = row[0].strip()
        status = row[-1].strip()
        middle = [m.strip() for m in row[1:-1]]
        time_field = middle[0] if middle else ""
        url_field = ",".join(middle[1:]) if len(middle) > 1 else (middle[0] if middle else "")
        h0 = headers[0] if len(headers) > 0 else "ip"
        h1 = headers[1] if len(headers) > 1 else "time"
        h2 = headers[2] if len(headers) > 2 else "url"
        h3 = headers[3] if len(headers) > 3 else "status"
        return {h0: ip, h1: time_field, h2: url_field, h3: status}

    return None


def nginx_row_from_line(line: str) -> Optional[dict]:
    """Turn one NGINX access-log line (our custom log_format:
    '$remote_addr|$time_local|$request|$status') into the same
    IP/Time/URL/Status dict shape csv_row_from_line() produces.

    Reconstructs the URL field as "METHOD /path?decoded_query HTTP/1.1"
    -- the exact shape site/app.py's own CSV writer produces (single
    unquote() of the query string only, method/path left alone) -- so
    parse_weblog_row() and classify_threat_type() behave identically
    regardless of which log source produced the row.
    """
    parts = line.rstrip("\r\n").split("|", 3)
    if len(parts) != 4:
        return None

    ip, time_local, request_line, status = (p.strip() for p in parts)
    if not ip or not request_line:
        return None

    time_field = _nginx_time_to_utc_field(time_local)

    method, sep, rest = request_line.partition(" ")
    if not sep:
        return {"IP": ip, "Time": time_field, "URL": request_line, "Status": status}

    rest = _HTTP_VERSION_SUFFIX.sub("", rest)
    path, has_query, query = rest.partition("?")
    if has_query:
        url_field = f"{method} {path}?{unquote(query)} HTTP/1.1"
    else:
        url_field = f"{method} {rest} HTTP/1.1"

    return {"IP": ip, "Time": time_field, "URL": url_field, "Status": status}
