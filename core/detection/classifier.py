"""Per-record rule-based threat classification.

Originally moved verbatim from THREAT_DETECTION_PIPELINE.py with a
handful of categories and a short keyword list each. This version keeps
the same function contract -- classify_threat_type(row) -> (threat_type,
confidence) -- and the same *existing* category strings/trigger
conditions unchanged wherever they already worked correctly, but:

  - Substantially widens keyword coverage for SQL injection,
    reconnaissance, and adds four new categories (Command Injection,
    Cross-Site Scripting (XSS), Directory Traversal, Sensitive File
    Access) that were previously either undetected or miscategorized.
  - Reorders the priority chain so specific attack patterns are checked
    BEFORE the generic "Credential Attack" keyword check. Previously a
    SQLi/XSS payload that happened to also contain "password" (e.g.
    "SELECT username, password FROM users") was classified as
    Credential Attack instead of an injection attack -- a real,
    previously-documented quirk (see docs/DEMO_GUIDE.md's SQL Injection
    section) that this reordering fixes as a side effect.
  - Normalizes whitespace and applies a defensive double-unquote before
    matching, so multi-word keywords survive whitespace variations and
    payloads reach this function decoded even if something upstream
    didn't already decode them (site/app.py does, but offline replay of
    historical/synthetic data may not).

Field lookups stay case-insensitive via core.utils.get_ci, so this works
unchanged for both a pandas row (offline, capitalized headers) and a
plain dict (live, lowercased headers).
"""
from __future__ import annotations

import re
from urllib.parse import unquote

import pandas as pd

from core.utils import get_ci

# --- Command Injection ------------------------------------------------
# Symbols rarely appear in legitimate query strings and are strong
# signals on their own. Short command words ("sh", "cat", "ls", "dir")
# are matched with a word boundary so they don't fire on substrings of
# unrelated words (e.g. "cat" inside "category").
_CMDI_SYMBOLS = (";", "&&", "||", "`", "$(", "cmd.exe", "powershell", "wget", "curl")
_CMDI_WORDS = re.compile(r"\b(bash|sh|nc|ping|whoami|cat|type|dir|ls)\b")

# --- SQL Injection ------------------------------------------------------
_SQLI_PATTERNS = (
    "' or '1'='1", "or 1=1", "union select", "union all select", "drop table",
    "delete from", "insert into", "update ", "information_schema", "sleep(",
    "benchmark(", "waitfor delay", "xp_cmdshell", "load_file", "into outfile",
    "show databases", "select *", "order by", "limit ", "having", "case when",
    "ascii(", "char(", "cast(", "convert(", "openrowset", "exec(", "sp_executesql",
    "'", "--", "/*", "*/", "#",
)

# --- Cross-Site Scripting (XSS) ----------------------------------------
_XSS_PATTERNS = (
    "<script", "javascript:", "alert(", "document.cookie", "onload=", "onerror=",
    "onclick=", "<svg", "svg", "<iframe", "iframe", "<embed", "embed", "<object",
    "object", "eval(", "string.fromcharcode", "innerhtml", "document.write",
    "fetch(", "xmlhttprequest",
)

# --- Directory Traversal ------------------------------------------------
# Checked against the DECODED url (after this classifier's own unquote
# pass): once decoded, %2e%2e/%252e%252e become "..".
_TRAVERSAL_PATTERNS = (
    "../", "..\\", "etc/passwd", "etc/shadow", "windows/system32", "system32",
    "boot.ini", "proc/self",
)
# Checked against the RAW (pre-decode) url: a request that is STILL
# encoded at this point (single- or double-encoded) is itself a signal,
# independent of what it decodes to.
_TRAVERSAL_RAW_PATTERNS = ("%2e%2e", "%252e%252e")

# --- Sensitive File Access ----------------------------------------------
_SENSITIVE_FILE_PATTERNS = (
    ".env", ".git", ".svn", ".hg", "docker-compose.yml", "config.php",
    "backup.zip", "database.sql", "id_rsa", "passwd", "shadow",
    "server-status", "phpinfo",
)

# --- Reconnaissance ------------------------------------------------------
_RECON_PATTERNS = (
    "/admin", "/login", "/config", "wp-admin", "wp-login", "phpmyadmin",
    "cgi-bin", "actuator", "swagger", "api-docs", "metrics", "prometheus",
    "robots.txt", "backup", "old", "test", "staging", "dev", "debug", "console",
)

# --- Credential Attack (existing, unchanged trigger) --------------------
_CREDENTIAL_PATTERNS = ("password", "auth", "token", "session")

_WHITESPACE = re.compile(r"\s+")


def _normalize(url: str) -> str:
    """Collapse whitespace runs to one space so multi-word keywords
    ("union select", "waitfor delay", ...) match regardless of how many
    spaces/tabs separate the words in the actual request."""
    return _WHITESPACE.sub(" ", url)


def classify_threat_type(row):
    """
    Advanced threat classification with 12 attack/traffic categories.
    Returns: (threat_type, confidence_score)
    """
    threat_type = 'unknown'
    confidence = 0.0

    try:
        url_val = get_ci(row, 'URL')
        status_val = get_ci(row, 'Status', 'Staus')
        time_val = get_ci(row, 'Time')

        raw_url = str(url_val).lower() if pd.notna(url_val) else ''
        status = str(status_val).strip() if pd.notna(status_val) else ''
        time_str = str(time_val).lower() if pd.notna(time_val) else ''

        # Defensive decode: idempotent if already decoded upstream
        # (site/app.py), necessary if not (offline/synthetic data).
        # Applied twice to also reveal double-encoded payloads.
        decoded_url = _normalize(unquote(unquote(raw_url)))

        # Attack Pattern Detection (most specific/severe first, so a
        # payload matching multiple categories gets its most actionable
        # label -- see module docstring for the reordering rationale).
        if status in ['401', '403'] and ('login' in raw_url or 'admin' in raw_url):
            threat_type = 'Brute Force Attack'
            confidence = 0.85
        elif any(sym in decoded_url for sym in _CMDI_SYMBOLS) or _CMDI_WORDS.search(decoded_url):
            threat_type = 'Command Injection'
            confidence = 0.92
        elif any(pattern in decoded_url for pattern in _SQLI_PATTERNS):
            threat_type = 'SQL/Web Injection Attack'
            confidence = 0.9
        elif any(pattern in decoded_url for pattern in _XSS_PATTERNS):
            threat_type = 'Cross-Site Scripting (XSS)'
            confidence = 0.88
        elif any(pattern in decoded_url for pattern in _TRAVERSAL_PATTERNS) or \
                any(pattern in raw_url for pattern in _TRAVERSAL_RAW_PATTERNS):
            threat_type = 'Directory Traversal'
            confidence = 0.87
        elif any(pattern in decoded_url for pattern in _SENSITIVE_FILE_PATTERNS):
            threat_type = 'Sensitive File Access'
            confidence = 0.82
        elif any(pattern in decoded_url for pattern in _CREDENTIAL_PATTERNS):
            threat_type = 'Credential Attack'
            confidence = 0.75
        elif any(pattern in decoded_url for pattern in _RECON_PATTERNS):
            threat_type = 'Reconnaissance Scan'
            confidence = 0.8
        elif status in ['500', '502', '503', '504']:
            threat_type = 'DoS Pattern'
            confidence = 0.65
        elif status in ['200', '301', '302', '304']:
            threat_type = 'Normal Connection'
            confidence = 0.95
        elif status in ['403', '404']:
            threat_type = 'Access Denial'
            confidence = 0.70
        else:
            threat_type = 'Suspicious Activity'
            confidence = 0.5
    except Exception:
        threat_type = 'Classification Error'
        confidence = 0.0

    return threat_type, confidence
