# noginx
> AI/ML-powered NGINX log security platform — detect anomalies, classify cyber threats, and monitor incidents from a live dashboard.

[Demo Video](https://github.com/Krishsarvaiya/NOGINX)

---

## Features

- **Ensemble threat engine** — Isolation Forest + 15+ cybersecurity rules
- **Insecurity detection** — HTTP (non-HTTPS), insecure referers, credentials in URL, login over HTTP
- **Live watcher** — desktop alerts, email alerts, dashboard reporting
- **Multi-page dashboard** — scan, history, incidents, live monitor, profile
- **JWT auth** + service token for watcher → dashboard integration

---

## Quick start

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### `.env` (project root)

```env
# API
NOGINX_SECRET_KEY=change-me-in-production
ANOMALY_SCORE_THRESHOLD=0.0

# Watcher → Dashboard
NOGINX_SERVICE_TOKEN=your-long-random-token
NOGINX_SERVICE_USER=watcher
API_BASE_URL=http://127.0.0.1:8000
NGINX_ACCESS_LOG=C:\nginx-1.29.8\logs\access.log
WATCHER_ALERT_THRESHOLD=0.45
ENABLE_DESKTOP_ALERTS=true
ENABLE_EMAIL_ALERTS=false

# Email (optional)
NOGINX_MAIL_ID=you@gmail.com
NOGINX_MAIL_PASSWORD=app-password
RECEIVER_MAIL_ID=alerts@you.com
```

### Run

```bash
# Terminal 1 — API + Dashboard
cd fastapi_backend
uvicorn app:app --reload

# Terminal 2 — Live watcher (optional)
cd watcher
python watcher.py
```

Open: **http://127.0.0.1:8000/ui/login.html**

---

## Dashboard pages

| Page | URL | Purpose |
|------|-----|---------|
| Overview | `/ui/dashboard.html` | Stats & quick actions |
| Log Scanner | `/ui/scan.html` | Upload & analyze log files |
| Scan History | `/ui/history.html` | Past scans with details |
| Incidents | `/ui/incidents.html` | All threats (watcher + scans) |
| Live Monitor | `/ui/live.html` | Watcher setup & live alerts |
| Profile | `/ui/profile.html` | Account & activity (top-right icon) |

---

## Important: why watcher may show no alerts

The watcher only sees traffic in your **NGINX access.log**. If you browse insecure HTTP websites directly in Chrome/Firefox, those requests **do not** go through NGINX unless you configure it as a reverse proxy.

To monitor browsing:
1. Route traffic through NGINX, or
2. Upload exported logs via **Log Scanner**, or
3. Point `NGINX_ACCESS_LOG` at any NGINX-format log file

Every parsed request now prints `[traffic]` in the watcher terminal so you can confirm logs are flowing.

---

## Retrain on your logs

```bash
python parse_logs.py      # data/nginx.log → nginx_logs.csv
python train_model.py     # → model_retrained.pkl + encoders
```

---

## Detection rules (examples)

| Threat | Trigger |
|--------|---------|
| Insecure HTTP Request | URL starts with `http://` |
| Insecure HTTP Referer | Referer header uses HTTP |
| Insecure Login / Auth Page | Login path over HTTP |
| Credentials in URL | `password=`, `token=` in query string |
| Brute Force | 10+ requests from same IP in 10 seconds |
| ML Traffic Anomaly | Isolation Forest outlier score |

---

## Project structure

```
noginx/
├── ml/                   # Threat engine + log parser
├── fastapi_backend/      # API, auth, database
├── frontend/             # Multi-page UI
├── watcher/              # Live log monitor
├── parse_logs.py
├── train_model.py
└── data/                 # Models, logs, DB (gitignored)
```

---

Contributions welcome on [GitHub](https://github.com/Krishsarvaiya/NOGINX).
