# NOGINX

AI/ML-powered NGINX log security platform for anomaly detection, threat classification, incident history, and live monitoring.

## Features

- Model selector that trains and compares 3 anomaly models:
  - Isolation Forest
  - Local Outlier Factor
  - SGD One-Class SVM
- Self-contained runtime model bundle at `data/model_retrained.pkl`
- Security-rule labels for HTTP insecurity, credential leakage, scanner traffic, SQLi, XSS, path traversal, sensitive file probes, and server-error patterns
- FastAPI backend with JWT auth and service-token watcher integration
- Static dashboard for scans, incidents, history, live alerts, and profile data
- Live watcher for tailing an NGINX `access.log`

## Quick Start

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Create `.env` in the project root:

```env
NOGINX_SECRET_KEY=change-me-in-production

NOGINX_SERVICE_TOKEN=your-long-random-token
NOGINX_SERVICE_USER=watcher
API_BASE_URL=http://127.0.0.1:8000
NGINX_ACCESS_LOG=C:\nginx-1.29.8\logs\access.log
WATCHER_ALERT_THRESHOLD=0.45
```

Run the API and dashboard:

```bash
cd fastapi_backend
uvicorn app:app --reload
```

Open:

```text
http://127.0.0.1:8000/ui/login.html
```

Run the live watcher in another terminal:

```bash
cd watcher
python watcher.py
```

## Training

Parse raw NGINX logs:

```bash
python parse_logs.py
```

Train and compare the candidate models:

```bash
python train_model.py
```

The trainer writes:

- `data/model_retrained.pkl`: selected model bundle used by the app
- `data/model_report.json`: metrics for each candidate model
- `data/features_retrained.csv`: processed feature matrix for inspection

## API Pages

| Page | URL |
| --- | --- |
| Overview | `/ui/dashboard.html` |
| Log Scanner | `/ui/scan.html` |
| Scan History | `/ui/history.html` |
| Incidents | `/ui/incidents.html` |
| Live Monitor | `/ui/live.html` |
| Profile | `/ui/profile.html` |

## Project Structure

```text
noginx/
  ml/                Threat engine, log parser, feature builder
  fastapi_backend/   API, auth, database
  frontend/          Dashboard UI
  watcher/           Live log monitor
  data/              NGINX logs, selected model, reports
  Datasets/          Extra uploaded datasets
```
