"""Shared helpers for the demo traffic/attack scripts.

Every script in this folder sends real HTTP requests to the running
Flask site (see site/app.py) using the `requests` library -- none of
them ever open or write to a log file. The site's own access-log
middleware is what produces the log line; these scripts only generate
the traffic that causes that to happen.
"""
import json
import os
import sys

# Allow `import core...` regardless of cwd -- these scripts are run as
# `python demo/simulate_*.py`, so sys.path[0] is demo/, not the repo
# root where core/ lives (same pattern as site/app.py, src/live_analyzer.py).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

import requests

from core.config import FLASK_PORT, NGINX_PORT


def _resolve_log_source() -> str:
    """Which log source the currently-running demo is using.

    Checked in this order:
      1. LOG_SOURCE, if set in *this* process's own environment.
      2. .demo_pids.json's "mode" field, written by run_demo.ps1 at
         startup. Necessary because `$env:LOG_SOURCE` set inside
         run_demo.ps1's own PowerShell process is only ever inherited by
         *its own child processes* (the analyzer it starts directly) --
         never by a separate terminal opened afterward to run a demo
         script. Confirmed by reproducing exactly that: a fresh shell
         with LOG_SOURCE unset resolved BASE_URL to Flask directly, and
         simulated attack traffic never reached nginx/logs/access.log at
         all, even with the NGINX-mode demo already running. Reading this
         file (already deleted by stop_demo.ps1 on shutdown, so it can't
         go stale beyond one demo's lifetime) lets any later, independent
         terminal still find the real running mode.
      3. "csv", matching core.config.LOG_SOURCE's own default, if neither
         of the above is available.
    """
    env_value = os.environ.get("LOG_SOURCE")
    if env_value:
        return env_value.strip().lower()

    pid_file = os.path.join(_REPO_ROOT, ".demo_pids.json")
    try:
        # utf-8-sig, not utf-8: Windows PowerShell 5.1's `Set-Content
        # -Encoding utf8` (used by run_demo.ps1 to write this file) always
        # writes a UTF-8 BOM -- plain utf-8 decoding leaves it in the
        # stream, which json.load then rejects (JSONDecodeError, silently
        # falling through to the "csv" default below and reintroducing
        # this exact bug). Confirmed by testing: this was caught on the
        # first attempt at this fix, not hypothetical.
        with open(pid_file, "r", encoding="utf-8-sig") as f:
            mode = json.load(f).get("mode")
        if mode:
            return str(mode).strip().lower()
    except (OSError, ValueError):
        pass

    return "csv"


_LOG_SOURCE = _resolve_log_source()

# In NGINX mode, traffic must go through NGINX (port NGINX_PORT) to
# land in the log file src/live_analyzer.py is tailing -- hitting Flask
# directly on FLASK_PORT would still work (Flask still logs its own
# CSV, see site/app.py) but would bypass NGINX's access.log entirely.
# DEMO_BASE_URL still overrides either default directly.
BASE_URL = os.environ.get(
    "DEMO_BASE_URL",
    f"http://127.0.0.1:{NGINX_PORT if _LOG_SOURCE == 'nginx' else FLASK_PORT}",
)


def spoofed_session(fake_ip: str) -> requests.Session:
    """A requests.Session that presents as `fake_ip` to the site via
    X-Forwarded-For, so each attack script can look like a distinct
    attacker without needing separate real hosts. site/app.py's
    _client_ip() already honors this header."""
    session = requests.Session()
    session.headers.update({"X-Forwarded-For": fake_ip})
    return session


def check_site_is_running():
    try:
        requests.get(BASE_URL + "/", timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: could not reach {BASE_URL} -- is site/app.py running? "
              f"(python site/app.py, in its own terminal)")
        sys.exit(1)
