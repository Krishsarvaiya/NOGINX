"""Renders nginx/conf/anomaly.conf.template -> nginx/conf/nginx.conf using
core.config's FLASK_PORT/NGINX_PORT/NGINX_ACCESS_LOG_PATH -- the single
source of truth for both the Python side (src/live_analyzer.py tails
NGINX_ACCESS_LOG_PATH) and the NGINX side (this generates the matching
listen/proxy_pass/access_log directives), so the two can never drift
out of sync.

Run any time FLASK_PORT/NGINX_PORT/NGINX_ACCESS_LOG_PATH change (via
environment variables, see core/config.py), then reload NGINX
(nginx/nginx.exe -s reload) to pick up the regenerated nginx.conf.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.config import FLASK_PORT, NGINX_ACCESS_LOG_PATH, NGINX_PORT

TEMPLATE_PATH = os.path.join(REPO_ROOT, "nginx", "conf", "anomaly.conf.template")
OUTPUT_PATH = os.path.join(REPO_ROOT, "nginx", "conf", "nginx.conf")


def _nginx_path(path: str) -> str:
    """NGINX on Windows wants forward slashes in its conf. Using an
    absolute path also sidesteps any ambiguity over what directory a
    relative access_log path would be resolved against (NGINX's own
    prefix directory, which need not be the repo root)."""
    absolute = os.path.abspath(os.path.join(REPO_ROOT, path))
    return absolute.replace("\\", "/")


def render() -> str:
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()
    return (
        template.replace("{{NGINX_PORT}}", str(NGINX_PORT))
        .replace("{{FLASK_PORT}}", str(FLASK_PORT))
        .replace("{{NGINX_ACCESS_LOG_PATH}}", _nginx_path(NGINX_ACCESS_LOG_PATH))
    )


def main():
    rendered = render()
    log_dir = os.path.dirname(_nginx_path(NGINX_ACCESS_LOG_PATH))
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(rendered)
    print(f"Wrote {OUTPUT_PATH}")
    print(f"  NGINX_PORT={NGINX_PORT}  FLASK_PORT={FLASK_PORT}")
    print(f"  access_log={_nginx_path(NGINX_ACCESS_LOG_PATH)}")


if __name__ == "__main__":
    main()
