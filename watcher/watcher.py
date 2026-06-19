import os
import re
import pandas as pd
from datetime import datetime
import json
import requests
from pathlib import Path
# from plyer import notification   # ❌ disabled for now
# import smtplib                  # ❌ disabled for now
# from email.mime.text import MIMEText  # ❌ disabled for now
import time
from dotenv import load_dotenv

load_dotenv()
# If you start watcher from inside `watcher/`, the project-root `.env` may not be found.
_root_env = Path(__file__).resolve().parent.parent / ".env"
if _root_env.exists():
    load_dotenv(dotenv_path=str(_root_env))

predict_one_url = os.getenv('PREDICT_ONE_URL')
noginx_mail_id = os.getenv('NOGINX_MAIL_ID')
noginx_mail_password = os.getenv('NOGINX_MAIL_PASSWORD')
receiver_mail_id = os.getenv('RECEIVER_MAIL_ID')

# Debug flag: set DEBUG_WATCHER=true to see extra parsing/payload logs.
DEBUG_WATCHER = os.getenv("DEBUG_WATCHER", "false").strip().lower() == "true"
WATCHER_SCORE_THRESHOLD = float(os.getenv("WATCHER_SCORE_THRESHOLD", "0.0"))

if not predict_one_url:
    raise ValueError("PREDICT_ONE_URL is not set. Create/verify .env at project root.")

# ✅ Windows NGINX log path (override with env var if needed)
filename = os.getenv("NGINX_ACCESS_LOG", r"C:\nginx-1.29.8\logs\access.log")

# ❌ OLD REGEX (buggy for IP)
# pattern = r'(?P<ip>[\d.:a-fA-F]+)...'

# ✅ More flexible regex (works with different nginx log formats)
# It captures:
# - ip
# - timestamp
# - method, url, http_version
# - status, size (size can be '-' sometimes)
# - user_agent (inside quotes)
pattern = (
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\['
    r'(?P<timestamp>[^\]]+)'
    r'\]\s+"(?P<method>\w+)\s(?P<url>\S+)\s(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d+)\s(?P<size>\d+|-)'
    r'\s"[^"]*"\s"(?P<user_agent>[^"]*)"'
)


def encode_with_fallback(value, dict):
    return dict.get(value, -1)


# ✅ ALERT FUNCTION (EMAIL DISABLED → TERMINAL ONLY)
def send_alert(df, method, path, user_agent):
    ip = df['ip'].values[0]
    user_agent = user_agent.values[0]
    timestamp = df['timestamp'].values[0]
    path = path.values[0]

    message = (
        f"🚨 Anomaly Detected!\n\n"
        f"IP Address: {ip}\n"
        f"Timestamp: {timestamp}\n"
        f"Path: {path}\n"
        f"User Agent: {user_agent}"
    )

    # ✅ Terminal output
    print("\n" + "="*50)
    print(message)
    print("="*50 + "\n")

    # ❌ EMAIL + NOTIFICATION DISABLED (for now)
    """
    notification.notify(
        title="🚨 Anomaly Alert!",
        message=message,
        app_name="noginx",
        timeout=10,
        ticker="Anomaly detected",
        toast=False
    )

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(noginx_mail_id, noginx_mail_password)

    msg = MIMEText(message, _charset="utf-8")
    msg['Subject'] = "🚨 noginx Anomaly Detected"
    msg['From'] = noginx_mail_id
    msg['To'] = receiver_mail_id

    s.sendmail(noginx_mail_id, receiver_mail_id, msg.as_string())
    s.quit()
    """

    return


# ✅ NEW: Track requests per IP (for brute-force detection)
request_tracker = {}


# Load encoder mappings
encoding_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'data', 'encoder_mappings.json')
)

with open(encoding_path, "r") as f:
    encoder_mappings = json.load(f)


# Start watching log file
log_path = Path(filename)
if not log_path.exists():
    raise FileNotFoundError(f"NGINX access log not found: {log_path}")

with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
    # Jump to end so we only process new lines
    file.seek(0, os.SEEK_END)

    # Startup sanity check to confirm the regex matches some lines
    try:
        file.seek(0)
        sample = file.readlines()[-50:]
        matched = sum(1 for line in sample if re.search(pattern, line))
        print(f"[startup] log_path={log_path} size_bytes={log_path.stat().st_size} parse_matches_last50={matched}/50")
    except Exception as e:
        print(f"[startup] could not parse sample lines: {e}")
    file.seek(0, os.SEEK_END)

    print("🚀 Watching NGINX logs for anomalies...\n")

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        match = re.search(pattern, line)

        if match:
            df = pd.DataFrame([match.groupdict()])

            # Extract hour
            df['hour_of_day'] = df['timestamp'].apply(
                lambda x: int(datetime.strptime(x.split()[0], "%d/%b/%Y:%H:%M:%S").hour)
            )

            # Extract path
            df['path'] = df['url'].apply(lambda x: x.split('?')[0])

            df['status'] = df['status'].astype(int)
            # NGINX may put '-' for size
            df['size'] = df['size'].replace('-', 0).astype(int)

            cur_method = df['method']
            cur_path = df['path']
            cur_user_agent = df['user_agent']

            # 🔥 DEBUG (optional)
            # print(df[['ip', 'status', 'path']])

            # ❗ OPTIONAL: Ignore 404 (uncomment if needed)
            """
            if df['status'].values[0] == 404:
                continue
            """

            # ✅ Encode features
            df['method'] = df['method'].apply(
                lambda x: encode_with_fallback(x, encoder_mappings['method']['mapping'])
            )
            df['path'] = df['path'].apply(
                lambda x: encode_with_fallback(x, encoder_mappings['path']['mapping'])
            )
            df['user_agent'] = df['user_agent'].apply(
                lambda x: encode_with_fallback(x, encoder_mappings['user_agent']['mapping'])
            )

            feature_df = df[['status', 'size', 'method', 'path', 'user_agent', 'hour_of_day']]
            payload = {"feature": feature_df.iloc[0].to_dict()}

            ip = df['ip'].values[0]

            # ✅ NEW: Track request frequency (last 10 sec)
            if ip not in request_tracker:
                request_tracker[ip] = []

            request_tracker[ip].append(time.time())

            # Keep only last 10 seconds
            request_tracker[ip] = [
                t for t in request_tracker[ip] if time.time() - t < 10
            ]

            # 🚨 Brute force detection
            if len(request_tracker[ip]) > 10:
                print(f"🚨 Possible Brute Force Attack from {ip}")

            try:
                res = requests.post(predict_one_url, json=payload, timeout=5)
                result = res.json()

                print("Prediction Response:", result)

                model_anomaly = bool(result[0].get("anomaly", False))
                score = result[0].get("score")
                score_anomaly = (score is not None) and (float(score) < WATCHER_SCORE_THRESHOLD)
                is_anomaly = model_anomaly or score_anomaly

                if score is not None:
                    print(
                        f"[score] value={float(score):.6f}, "
                        f"watcher_threshold={WATCHER_SCORE_THRESHOLD:.6f}"
                    )

                if is_anomaly:
                    print("🔥 Anomaly Detected")
                    send_alert(df, cur_method, cur_path, cur_user_agent)
                elif DEBUG_WATCHER:
                    print(f"[debug] normal prediction ip={ip} payload={payload}")

            except Exception as e:
                print("❌ Prediction failed:", e)
                if DEBUG_WATCHER:
                    print(f"[debug] predict_one_url={predict_one_url} payload={payload}")

        else:
            if DEBUG_WATCHER:
                print("⚠️ Log line did not match expected format.")