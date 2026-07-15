"""Centralized, environment-overridable runtime configuration for the live
log source and the ports the demo site / reverse proxy listen on.

Companion to core/paths.py (which covers dataset *file* paths only) --
this covers *which* log source is live right now (CSV demo mode vs. a
real NGINX reverse proxy in front of the Flask demo site) and where
each server listens. Every constant follows the same
os.environ.get(...) pattern core/paths.py already established, so
switching modes or ports never requires a code change -- only an
environment variable.
"""
import os

from core.paths import _env_path

# "csv"   -- src/live_analyzer.py tails the Flask demo site's own CSV
#            access log (core.paths.LIVE_ACCESS_LOG_PATH). Default --
#            works with zero setup, matches every prior phase of this
#            project.
# "nginx" -- src/live_analyzer.py tails NGINX_ACCESS_LOG_PATH instead,
#            written by NGINX reverse-proxying the same Flask app.
LOG_SOURCE = os.environ.get("LOG_SOURCE", "csv").strip().lower()

FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))

NGINX_PORT = int(os.environ.get("NGINX_PORT", "80"))

# Project-local by default (nginx/ at the repo root, the layout
# scripts/setup_nginx_windows.ps1 creates) -- override if NGINX is
# installed elsewhere (e.g. C:\nginx\logs\access.log).
NGINX_ACCESS_LOG_PATH = _env_path(
    "NGINX_ACCESS_LOG_PATH", os.path.join("nginx", "logs", "access.log")
)


def is_nginx_mode() -> bool:
    return LOG_SOURCE == "nginx"
