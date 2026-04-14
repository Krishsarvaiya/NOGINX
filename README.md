# noginx
> Real-time NGINX anomaly detection — watches your logs, thinks with ML, screams when something's wrong.

[Demo Video](https://github.com/Krishsarvaiya/NOGINX)

---

## What's happening under the hood

Every line that hits your NGINX access log gets scored by an Isolation Forest model in real time. Normal request? Ignored. Anomaly? You get a push notification and an email with full context — before you've even had a chance to check your dashboard.

---

## Get up and running

**Prerequisites:** NGINX installed, logs at `/var/log/nginx/access.log`

```bash
# 1. Set up the environment
python3 -m venv venv && pip install -r requirements.txt

# 2. Create .env at project root
PREDICT_ONE_URL      = "http://127.0.0.1:8000/predict_one"
NOGINX_MAIL_ID       = "you@gmail.com"
NOGINX_MAIL_PASSWORD = "xxxx xxxx xxxx xxxx"   # Gmail App Password (Settings → 2FA → App passwords)
RECEIVER_MAIL_ID     = "alerts@you.com"

# 3. Start the backend (terminal 1)
cd fastapi_backend && uvicorn api_server:app --reload

# 4. Start the watcher (terminal 2)
cd watcher && python3 watcher.py
```

---

## API

Two endpoints, same idea — send log features, get an anomaly verdict.

| Endpoint | Use |
|---|---|
| `POST /predict` | Score a batch of log entries |
| `POST /predict_one` | Score a single entry (used by the watcher) |

**Payload:** `status`, `size`, `method`, `path`, `user_agent`, `hour_of_day`  
**Response:** `{ "anomaly": true/false }`

---

## The model

Trained on the [Elastic NGINX logs dataset](https://github.com/elastic/examples/blob/master/Common%20Data%20Formats/nginx_logs/README.md) using **Isolation Forest** — an algorithm that learns what "normal" traffic looks like and flags deviations. Saved to `data/model.pkl`.

Features are label-encoded strings → integers (see `data/encoder_mappings.json`).

---

## Retrain on your own traffic

For production use, train the model on your company's actual log patterns:

```bash
# Drop your logs at data/nginx.log, then:
python3 parse_logs.py    # raw logs → CSV
python3 process_csv.py   # CSV → encoded features
python3 train_model.py   # features → model.pkl
```

Tweak the Isolation Forest hyperparameters or add new feature engineering in `process_csv.py` to match your traffic profile.

---

## Project structure

```
noginx/
├── data/
│   ├── model.pkl
│   ├── nginx_logs.csv
│   ├── nginx.log
│   └── encoder_mappings.json
├── fastapi_backend/
│   └── api_server.py
├── watcher/
│   └── watcher.py
├── parse_logs.py
├── process_csv.py
├── train_model.py
├── requirements.txt
└── .env
```

---

Open to contributions — feel free to open a PR or file an issue on [GitHub](https://github.com/Krishsarvaiya/NOGINX).
