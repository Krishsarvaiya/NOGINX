# NGINX Web Server Log Anomaly Detection

A real-time web log anomaly detection platform that behaves like a lightweight
SIEM/IDS: it turns raw web-server access logs into rule-based threat
classifications, session-level anomaly scores, an Isolation Forest ML
verdict, and fused alerts — surfaced live on a Streamlit SOC dashboard.

Traffic can be captured **two ways**, switchable by one configuration value,
with zero code changes:

- **CSV Demo Mode** — the bundled Flask "college website" demo logs directly
  to a CSV file. Zero setup, works out of the box.
- **NGINX Mode** — NGINX reverse-proxies the same Flask site and becomes the
  primary log source, matching a real production web-server deployment.

Both modes feed the exact same detection pipeline (parser → session builder
→ feature extraction → rule engine + Isolation Forest → decision engine →
alerts → dashboard) — only the log *source* changes.

## Project Overview

| Layer | What it does |
|---|---|
| **Traffic source** | A demo Flask "college website" (`site/app.py`) generates real HTTP traffic. NGINX can sit in front of it as a reverse proxy. |
| **Log ingestion** | `src/live_analyzer.py` tails either the CSV access log or NGINX's `access.log` and turns each line into a common internal record. |
| **Detection pipeline** | `core/` — parsing, session building, 24-feature extraction, a keyword/heuristic rule engine, an Isolation Forest anomaly detector, and a 4-path decision engine (Rule Override / ML Override / Consensus / Fusion) that fuses both scores into one severity. |
| **Alerting** | Qualifying sessions (HIGH/CRITICAL by default) are written to `alerts.log` and printed to the analyzer's console. |
| **Dashboard** | `src/app.py` (Streamlit) — a SOC-style UI showing current threat status, recent alerts, decision-engine statistics, live metrics, a real-time Live Log Monitor, charts, attack timeline, active sessions, historical data preview, and system health. |

## Architecture

```
Browser
  │
  ▼
NGINX (reverse proxy, port 80)  ──writes──►  nginx/logs/access.log ──┐
  │                                                                   │
  ▼                                                                   │
Flask demo site (port 5000)  ──writes──►  data/live/college_site_access.csv ──┤ (always-on fallback)
                                                                       │
                                                                       ▼
                                                      src/live_analyzer.py
                                              (tails whichever LOG_SOURCE selects)
                                                                       │
                                                                       ▼
                                          core/parsing/adapters.py  (csv_row_from_line / nginx_row_from_line)
                                                                       │
                                                                       ▼
                                    core/parsing/log_parser.py → LogRecord
                                                                       │
                                                                       ▼
                                     core/sessions/session_builder.py → Session
                                                                       │
                                                                       ▼
                                  core/features/feature_extractor.py → 24 features
                                                                       │
                                        ┌──────────────────────────────┼──────────────────────────────┐
                                        ▼                                                              ▼
                          core/detection/rule_scoring.py                              core/detection/isolation_forest_detector.py
                          + classifier.py (rule score)                                        (ML anomaly score)
                                        │                                                              │
                                        └──────────────────────► core/detection/decision_engine.py ◄───┘
                                                                       │
                                                                       ▼
                                                     core/alerting/alert_engine.py → alerts.log
                                                                       │
                                                                       ▼
                                                        Streamlit SOC Dashboard (src/app.py)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full module-by-module breakdown.

## Features

- **Dual log source** (CSV / NGINX) switchable via `LOG_SOURCE`, no code changes.
- **Rule engine + Isolation Forest**, fused through a 4-path decision engine (Rule Override, ML Override, Consensus, Fusion).
- **Real-time SOC dashboard**: current threat status, recent alerts, decision-engine statistics, live metrics, a 2-second auto-refreshing Live Log Monitor (newest-first, with a "Hide Static Assets" toggle to cut CSS/JS/image noise while never hiding real attack traffic), charts, attack timeline, active sessions, historical mode, CSV export.
- **Demo attack scripts**: normal browsing, SQL injection, XSS, brute force, reconnaissance/sensitive-file scanning, directory scanning — each simulating a distinct spoofed attacker IP.
- **One-command startup/shutdown** (`run_demo.bat` / `stop_demo.bat`) and an environment pre-flight checker (`verify_environment.py`).

## Technologies Used

Python 3.9+, Flask, NGINX (Windows build), `websockets`, Streamlit, Plotly, pandas, NumPy, scikit-learn (Isolation Forest), joblib, PowerShell (automation scripts).

## Folder Structure

```
site/                Flask demo "college website" -- the traffic source
  app.py                Flask app + CSV access-log writer
  templates/, static/, data/

src/                  Live runtime + dashboard
  live_analyzer.py       Tails the log source, runs the core/ pipeline, broadcasts over WebSocket
  app.py                 Streamlit SOC dashboard
  dashboard_theme.py, dashboard_components.py

core/                 Transport-agnostic detection library
  config.py               LOG_SOURCE / ports / NGINX log path (env-overridable)
  paths.py                Dataset path constants (env-overridable)
  models.py                LogRecord, Session, SessionResult, ThreatAssessment, Alert
  parsing/                 log_parser.py (shared parser), adapters.py (CSV/NGINX line adapters)
  sessions/session_builder.py
  features/feature_extractor.py
  detection/               rule_scoring.py, classifier.py, fusion.py, decision_engine.py, isolation_forest_detector.py
  alerting/                alert_engine.py + console/file transports
  persistence/model_store.py
  pipeline/streaming_pipeline.py

nginx/                Project-local NGINX install (created by scripts/setup_nginx_windows.ps1)
  conf/anomaly.conf.template, conf/nginx.conf (generated), logs/access.log

demo/                 Traffic/attack generator scripts (target either Flask directly or through NGINX)
scripts/               Model training, NGINX config generation/setup, offline evaluation tools
data/                  training/, testing/, live/, archive/ CSV datasets
models/isolation_forest/  Versioned trained model artifacts
docs/                  Full documentation set (this folder)

run_demo.bat / run_demo_csv.bat / run_demo_nginx.bat   One-command startup
stop_demo.bat                                          One-command shutdown
verify_environment.py                                  Pre-flight environment checker
```

## Starting the Project

Requirements: **Python 3.9+** (developed/tested on 3.13/3.14), Windows 10/11.
No Docker, no cloud, no paid hosting — everything runs locally.

These are the exact commands, in order, for a fresh clone:

```powershell
# 1. Clone the repo
git clone <this-repo-url>
cd Log-Analysis-Live-Anomaly-Detection-main

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
venv\Scripts\activate

# 4. Install requirements
pip install -r requirements.txt

# 5. Verify the environment (PASS/FAIL report with explanations)
python verify_environment.py

# 6. (NGINX mode only) Install NGINX into a project-local nginx\ folder
powershell -ExecutionPolicy Bypass -File scripts\setup_nginx_windows.ps1
```

### Start everything: one command (recommended)

```powershell
run_demo_csv.bat       :: CSV mode
run_demo_nginx.bat      :: NGINX mode
```

Both always launch every Python process through **this project's own
`venv\Scripts\python.exe`** — never a bare `python`/`streamlit` command
resolved via PATH — so they work correctly even in a fresh terminal where
you haven't manually run `venv\Scripts\activate` yet. Expected output:

```
=====================================
 NGINX Web Server Log Anomaly Detection
 Starting demo in 'csv' mode...
=====================================
Website .......... OK
Analyzer ......... OK
Dashboard ........ OK
=====================================
Demo Ready
=====================================
```

### Start everything: manually, one terminal each

Activate the virtual environment in **every** terminal first
(`venv\Scripts\activate`), then:

```powershell
python site\app.py                            # 1. Flask website

nginx\nginx.exe -p nginx -c conf\nginx.conf    # 2. NGINX (NGINX mode only)

$env:LOG_SOURCE = "nginx"                      # 3. Live analyzer (or "csv")
python src\live_analyzer.py

python -m streamlit run src\app.py             # 4. Dashboard
```

**Always use `python -m streamlit run ...`, not the bare `streamlit run
...` command.** On a machine with more than one Python installation, the
bare `streamlit` command and the bare `python` command can each resolve to
a *different* installation (Windows searches PATH for each command name
independently) — one might have this project's dependencies, the other
might not, producing a `ModuleNotFoundError` even though
`pip install -r requirements.txt` succeeded. `python -m streamlit run`
guarantees the dashboard runs under the exact same interpreter you just
installed everything into.

### Stopping everything

```powershell
stop_demo.bat
```

```
=====================================
 Stopping demo
=====================================
Dashboard ............ stopped (PID ...)
Analyzer  ............ stopped (PID ...)
Website   ............ stopped (PID ...)
NGINX     ............ stopped (PID ...)

Demo stopped successfully
```

### Changing the log source

```powershell
$env:LOG_SOURCE = "nginx"   # or "csv" (default)
```

Set before starting `src\live_analyzer.py` (and, for manual startup,
before the dashboard too if you want its health check to point at NGINX —
`run_demo_nginx.bat` handles this automatically). See
[`docs/NGINX_SETUP.md`](docs/NGINX_SETUP.md).

### Generating traffic

```powershell
python demo\simulate_normal_traffic.py
python demo\simulate_sql_injection.py
python demo\simulate_xss.py
python demo\simulate_brute_force.py
python demo\simulate_recon_scan.py
python demo\simulate_directory_scan.py
```

Each accepts `--ip <address>` to simulate a distinct attacker, and routes through NGINX automatically when `LOG_SOURCE=nginx` is set.

### Vulnerability Scanning & JWT Authentication

- **JWT Claims & Role-Based Access Control**:
  - Log in with any email containing `admin` (e.g. `admin@noginx.com`) to receive the **Admin** role.
  - Log in with any other email to receive the **SOC_Analyst** role.
  - The Settings page displays base64 decoded claims, signatures, and expiration parameters of the active JWT token.
- **Active Scanning & Log Correlation**:
  - The **Network Scanner** tab is restricted to Admins.
  - Clicking "Launch Vulnerability Scan" executes `complete_threat_detection.py` and displays stdout logs in a terminal window.
  - The scanner probes for open ports (FTP, SSH, HTTP, etc.) and performs log-correlation with `weblog.csv` (correlating scanned host IPs with attacker IPs from weblogs) to output a unified security recommendations report.

## Expected Terminal Output

**Flask site:**
```
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
127.0.0.1 - - [.../about HTTP/1.1] 200 -
```

**Live analyzer:**
```
WebSocket server listening on ws://0.0.0.0:8765
Log source: csv
Tailing (CSV mode): ...\data\live\college_site_access.csv
[Session]
IP: 203.0.113.20
Threat: SQL/Web Injection Attack
Rule Score: 80.7
ML Score: 22.9
Decision Source: RULE_OVERRIDE
Final Score: 80.7
Severity: CRITICAL
```

**Dashboard:** starts a local web server; `streamlit run` prints its own local URL (`http://localhost:8501`).

## Expected Browser Output

- **Demo site** (`http://127.0.0.1:5000/` or `http://127.0.0.1/` in NGINX mode): a plain college-website-style HTML site (home, about, admissions, results, library, login, etc.).
- **Dashboard** (`http://127.0.0.1:8501/`): a dark, Apple-inspired SOC console — sign-in screen first (protected by JWT tokens), then 7 distinct navigation pages (SOC Dashboard, Live Monitoring, Threat Analytics, Incidents & Alerts, Network Scanner, Data Explorer, Profile & Settings).

## Common Errors & Solutions

| Error | Solution |
|---|---|
| `Refusing to start a second demo` | A demo is already running (or `.demo_pids.json` is stale). Run `stop_demo.bat`, or delete `.demo_pids.json` if nothing is actually running. |
| Port already in use | Another process is bound to 80/5000/8765/8501. Run `stop_demo.bat`, or find and close the other process. |
| `nginx.exe not found` | Run `scripts\setup_nginx_windows.ps1` once (NGINX mode only; not needed for CSV mode). |
| Dashboard shows "No data found" | Generate some traffic first (visit the site or run a `demo/simulate_*.py` script). |
| `ModuleNotFoundError` (e.g. `No module named 'plotly'`) when the dashboard opens | A package is missing from **whichever Python interpreter actually ran Streamlit** — on a machine with multiple Python installations, that may not be the one `pip install -r requirements.txt` was run into. `run_demo.bat`/`run_demo_nginx.bat` avoid this by always using `venv\Scripts\python.exe -m streamlit run` explicitly; if starting manually, always run `python -m streamlit run src\app.py` (not bare `streamlit run ...`) with the project's venv activated. Run `python verify_environment.py` to confirm which interpreter and packages are actually in play. |
| Live Log Monitor looks empty in NGINX mode | Confirm `$env:LOG_SOURCE = "nginx"` was set *before* starting `live_analyzer.py`, and that NGINX itself is running. |

See [`docs/RUN_PROJECT.md`](docs/RUN_PROJECT.md) for a complete step-by-step troubleshooting walkthrough.

## Documentation

- [`docs/RUN_PROJECT.md`](docs/RUN_PROJECT.md) — complete clone-to-running-demo guide for a new user
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full architecture, detection pipeline, and module reference
- [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) — 15-minute presentation script with speaking notes and viva Q&A
- [`docs/NGINX_SETUP.md`](docs/NGINX_SETUP.md) — NGINX installation, reverse-proxy config, log format
- [`docs/DATASET_GUIDE.md`](docs/DATASET_GUIDE.md) — training/testing/live data separation, model lifecycle

## Screenshots

*(Placeholders — insert screenshots here before the final submission.)*

- `docs/assets/screenshot_dashboard_overview.png` — full dashboard, Live Mode
- `docs/assets/screenshot_live_log_monitor.png` — Live Log Monitor with the static-asset filter
- `docs/assets/screenshot_recent_alerts.png` — Recent Alerts after running an attack script
- `docs/assets/screenshot_nginx_terminal.png` — `run_demo_nginx.bat` startup output

## Future Work

- Batch-score sessions closed within one flush together (the Isolation Forest is vectorized; scoring one-at-a-time leaves throughput on the table at high session-close rates)
- Additional alert transports: Slack, email, webhooks, PagerDuty, Teams
- Extend the rule engine toward a broader category set (excessive request rate, impossible frequency, time-of-day access, suspicious user agents, etc.)
- A dedicated demo script for directory-traversal payloads (currently only exercised incidentally via `simulate_recon_scan.py`'s sensitive-file patterns)
- Alert deduplication/cooldown if repeat-alert volume becomes noisy in a real deployment
- A Windows Service wrapper for NGINX/analyzer (currently manual/scripted process management, by design, to avoid requiring admin rights)

## Credits

Built as an M.Tech project demonstrating log-based anomaly detection with a hybrid rule-engine + machine-learning approach, reverse-proxy log ingestion, and a real-time SOC dashboard.
