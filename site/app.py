"""Demo college website (Flask).

Real HTTP server for demonstration purposes only -- every request it
handles is logged in the exact CSV shape core.parsing.log_parser
already parses, so the existing, unmodified detection pipeline can
observe real traffic instead of hand-written rows.

The access log is written to a dedicated file, never to the training
dataset (core.paths.TRAINING_DATA_PATH) -- keeping demo/attack traffic
out of the historical training corpus is the whole point (see
docs/DATASET_GUIDE.md and docs/DEMO_GUIDE.md for why).
"""
import csv
import os
import sys
from datetime import datetime, timezone
from urllib.parse import unquote

from flask import Flask, abort, redirect, render_template, request, url_for

from data.dummy_data import (
    COLLEGE_NAME,
    DEMO_STUDENT_PASSWORD,
    DEMO_STUDENT_USERNAME,
    DEPARTMENTS,
    FACULTY,
    LIBRARY_BOOKS,
    PLACEMENTS,
    RESULTS,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Allow `import core...` whether this is run as `python site/app.py` or
# from elsewhere (sys.path[0] is `site/`, not the repo root where core/ lives).
sys.path.insert(0, REPO_ROOT)
from core.config import FLASK_HOST, FLASK_PORT
from core.paths import LIVE_ACCESS_LOG_PATH

ACCESS_LOG_PATH = os.environ.get("COLLEGE_SITE_LOG_PATH", LIVE_ACCESS_LOG_PATH)

app = Flask(__name__)


def _ensure_log_header():
    os.makedirs(os.path.dirname(ACCESS_LOG_PATH), exist_ok=True)
    if not os.path.exists(ACCESS_LOG_PATH) or os.path.getsize(ACCESS_LOG_PATH) == 0:
        with open(ACCESS_LOG_PATH, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["IP", "Time", "URL", "Status"])


def _client_ip() -> str:
    # Honor X-Forwarded-For so demo/attack scripts can present as
    # distinct "attacker" IPs without needing real separate hosts --
    # the same pattern any app behind a reverse proxy already uses.
    # Take only the first (left-most/original client) entry: once a
    # real reverse proxy (NGINX) is in front, it appends its own hop via
    # proxy_add_x_forwarded_for, turning this into "<client>, <proxy-ip>"
    # -- treating that whole string as one IP would corrupt source_ip
    # for every session. In CSV/no-proxy mode there's only ever one
    # entry, so this is a no-op there.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@app.after_request
def log_request(response):
    # Logging must never break a real page load.
    try:
        ip = _client_ip()
        # datetime.now(timezone.utc) replaces the deprecated datetime.utcnow() --
        # same UTC instant, same strftime() output (the format below has no
        # %z/%Z token, so tzinfo doesn't change what's written), so the CSV
        # value and downstream core.parsing.log_parser parsing are unaffected.
        timestamp = datetime.now(timezone.utc).strftime("[%d/%b/%Y:%H:%M:%S")
        # Decode the query string before logging it -- browsers, curl,
        # Postman, and the `requests` library all percent-encode
        # special characters (' -> %27, < -> %3C) differently, and the
        # detection engine's keyword matching (core/detection/classifier.py,
        # unmodified) looks for literal characters. Decoding here, once,
        # is the standard place for that normalization to happen -- the
        # same reason real WAFs decode before signature matching -- and
        # keeps every client (this file's own demo scripts, or a human
        # with a browser/curl/Postman) detected consistently.
        query = unquote(request.query_string.decode("utf-8", "ignore"))
        path = request.path + (f"?{query}" if query else "")
        url_field = f"{request.method} {path} HTTP/1.1"
        with open(ACCESS_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ip, timestamp, url_field, response.status_code])
    except Exception:
        pass
    return response


@app.route("/")
def home():
    return render_template("home.html", college=COLLEGE_NAME)


@app.route("/about")
def about():
    return render_template("about.html", college=COLLEGE_NAME)


@app.route("/admissions")
def admissions():
    return render_template("admissions.html", college=COLLEGE_NAME)


@app.route("/departments")
def departments():
    return render_template("departments.html", college=COLLEGE_NAME, departments=DEPARTMENTS)


@app.route("/faculty")
def faculty():
    return render_template("faculty.html", college=COLLEGE_NAME, faculty=FACULTY)


@app.route("/library")
def library():
    query = request.args.get("q", "").strip()
    if query:
        results = [b for b in LIBRARY_BOOKS if query.lower() in b["title"].lower()]
    else:
        results = LIBRARY_BOOKS
    return render_template("library.html", college=COLLEGE_NAME, books=results, query=query)


@app.route("/placements")
def placements():
    return render_template("placements.html", college=COLLEGE_NAME, placements=PLACEMENTS)


@app.route("/results")
def results():
    roll_no = request.args.get("roll_no", "").strip()
    record = RESULTS.get(roll_no) if roll_no else None
    searched = bool(roll_no)
    return render_template("results.html", college=COLLEGE_NAME, record=record, roll_no=roll_no, searched=searched)


@app.route("/downloads")
def downloads():
    files = [
        {"name": "College Prospectus 2026", "filename": "prospectus.pdf"},
        {"name": "Fee Structure 2026", "filename": "fee_structure.pdf"},
        {"name": "B.Tech Syllabus", "filename": "syllabus.pdf"},
    ]
    return render_template("downloads.html", college=COLLEGE_NAME, files=files)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    submitted = False
    if request.method == "POST":
        submitted = True
    return render_template("contact.html", college=COLLEGE_NAME, submitted=submitted)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_STUDENT_USERNAME and password == DEMO_STUDENT_PASSWORD:
            return redirect(url_for("login_success"))
        error = "Invalid username or password."
        return render_template("login.html", college=COLLEGE_NAME, error=error), 401
    return render_template("login.html", college=COLLEGE_NAME, error=error)


@app.route("/login/success")
def login_success():
    return render_template("login_success.html", college=COLLEGE_NAME)


# Intentionally NOT linked from base.html's navigation -- this route
# only exists to give reconnaissance scans a real target to find,
# instead of every sensitive-looking path being a 404.
@app.route("/admin", methods=["GET", "POST"])
def admin_portal():
    if request.method == "POST":
        abort(403)
    return render_template("admin.html", college=COLLEGE_NAME)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html", college=COLLEGE_NAME), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html", college=COLLEGE_NAME), 404


if __name__ == "__main__":
    _ensure_log_header()
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, threaded=True)
