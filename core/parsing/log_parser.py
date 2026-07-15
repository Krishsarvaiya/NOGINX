"""Parses the repository's weblog.csv row format into LogRecord objects.

CSV columns: IP, Time, URL, Staus (typo preserved in the source data; the
offline pipeline already renames "Staus" -> "Status" on load, while the
live analyzer keeps the raw lowercased CSV headers -- field lookups here
are case-insensitive so both callers share this one implementation).

  IP     -> source_ip
  Time   -> e.g. "[9/May/2026:06:58:55" (leading bracket, no closing
            bracket, no timezone)
  URL    -> e.g. "GET /login.php HTTP/1.1" (method + path + protocol)
  Status -> HTTP status code
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional
from urllib.parse import unquote

from core.models import LogRecord
from core.utils import get_ci

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S"

# Matches a trailing " HTTP/1.1" (or any digit.digit version) protocol
# marker so it can be stripped without truncating everything before it --
# see parse_url_field()'s docstring for why this replaced a naive split.
_HTTP_VERSION_SUFFIX = re.compile(r"\s+HTTP/\d\.\d\s*$", re.IGNORECASE)

# A literal %XX escape still present after site/app.py's own unquote()
# pass means the original request was double- (or multi-) encoded (e.g.
# %252e%252e -> %2e%2e after one decode) -- a common WAF-evasion
# technique. Detecting the residual escape is the only signal of this
# available from the CSV, since single-encoding is already normalized
# away before logging.
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


def parse_timestamp(raw: object) -> Optional[datetime]:
    """Parse the bracket-prefixed, timezone-less timestamp used in weblog.csv."""
    if raw is None:
        return None
    cleaned = str(raw).strip().lstrip("[").rstrip("]")
    try:
        return datetime.strptime(cleaned, TIME_FORMAT)
    except ValueError:
        return None


def parse_url_field(raw: object) -> tuple[str, str]:
    """Split "GET /path?query HTTP/1.1" into (method, path).

    Splits on the *first* space only (method vs. everything else), then
    strips a trailing " HTTP/x.x" marker -- rather than splitting on
    every space and keeping just the second token. That naive approach
    silently truncated the path at the first internal space, which any
    decoded payload containing one (e.g. "' OR '1'='1", "UNION SELECT ...")
    has -- meaning query-string attack payloads never actually reached
    record.url, only whatever preceded their first space. This was a
    real, confirmed bug (verified empirically), not a hypothetical one.
    """
    text = str(raw).strip()
    parts = text.split(" ", 1)
    if len(parts) < 2:
        return "UNKNOWN", text
    method, rest = parts[0], parts[1]
    path = _HTTP_VERSION_SUFFIX.sub("", rest)
    return method, path


def has_residual_encoding(raw_url: object) -> bool:
    """True if `raw_url` still contains a %XX escape sequence.

    Request logging (site/app.py) already decodes once before writing the
    CSV, so a %XX surviving that means the original was double- (or
    multi-) encoded -- e.g. %252e%252e -> %2e%2e after one decode still
    has escapes left. Also true for any URL that reaches this parser
    without having been decoded upstream at all (offline replay of
    already-encoded historical/demo data, synthetic test rows, etc.).
    """
    return bool(_PERCENT_ESCAPE.search(str(raw_url)))


def _legacy_endpoint(raw_url: object) -> str:
    """Reproduces live_analyzer.py's pre-refactor endpoint value (path plus
    trailing protocol, e.g. "/login.php HTTP/1.1"), so the existing
    "stats" WebSocket payload's top_endpoints values stay byte-identical
    to before this refactor."""
    text = str(raw_url).strip()
    parts = text.split(" ", 1)
    return parts[1] if len(parts) == 2 else text


def parse_weblog_row(row: dict) -> Optional[LogRecord]:
    """Build a LogRecord from a dict-like row (a pandas Series.to_dict()
    with capitalized headers, or the live analyzer's lowercased CSV
    header dict -- lookups are case-insensitive).

    Accepts either "Status" or "Staus" for the status column, and passes
    through any pre-computed "threat_type"/"confidence" keys (set by the
    shared classifier) so downstream feature extraction can still use
    them without this parser knowing about threat classification.
    """
    ip = get_ci(row, "IP")
    timestamp = parse_timestamp(get_ci(row, "Time"))
    if not ip or timestamp is None:
        return None

    raw_url = get_ci(row, "URL", default="")
    method, path = parse_url_field(raw_url)

    status_raw = get_ci(row, "Status", "Staus")
    try:
        status_code = int(float(status_raw))
    except (TypeError, ValueError):
        status_code = 0

    return LogRecord(
        timestamp=timestamp,
        source_ip=str(ip).strip(),
        user_agent=None,
        method=method,
        url=path,
        status_code=status_code,
        extra={
            "threat_type": get_ci(row, "threat_type"),
            "confidence": get_ci(row, "confidence"),
            "legacy_endpoint": _legacy_endpoint(raw_url),
            "is_encoded": has_residual_encoding(raw_url),
        },
    )
