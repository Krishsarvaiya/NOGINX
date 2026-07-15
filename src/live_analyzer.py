"""Live WebSocket log tailing server.

Thin transport layer: tails a log file (LOG_PATH, source selected by
core.config.LOG_SOURCE -- "csv" tails the Flask demo site's own CSV
access log, "nginx" tails NGINX's access.log from the same site
reverse-proxied), hands each row to the shared core/ parsing +
classification + streaming pipeline, and broadcasts the results over
WebSocket. All detection logic (parsing, threat classification, rolling
session building, rule-based scoring) lives in core/ and is the same
code THREAT_DETECTION_PIPELINE.py uses offline -- this file does no
parsing of its own beyond turning a raw log line into a header-keyed
dict for core to consume (core.parsing.adapters).
"""
import asyncio
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import websockets

# Allow `import core...` whether this is run as `python src/live_analyzer.py`
# or `streamlit run src/app.py` (sys.path[0] is `src/` either way, not the
# repo root where core/ lives).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alerting.alert_engine import AlertEngine, _dominant_threat_type
from core.alerting.transports.console_transport import ConsoleAlertTransport
from core.alerting.transports.file_transport import FileAlertTransport
from core.config import LOG_SOURCE, NGINX_ACCESS_LOG_PATH
from core.detection.classifier import classify_threat_type
from core.parsing.adapters import csv_row_from_line, nginx_row_from_line
from core.parsing.log_parser import parse_weblog_row
from core.paths import LIVE_ACCESS_LOG_PATH
from core.pipeline.streaming_pipeline import StreamingPipeline

# Configuration
# LOG_SOURCE ("csv" default, or "nginx" -- see core/config.py) selects
# which file this tails, with zero code change required to switch.
# LIVE_LOG_PATH still overrides either default directly, e.g. to replay
# the training corpus (core.paths.TRAINING_DATA_PATH) instead.
if LOG_SOURCE == "nginx":
    LOG_PATH = os.environ.get("LIVE_LOG_PATH", NGINX_ACCESS_LOG_PATH)
else:
    LOG_PATH = os.environ.get("LIVE_LOG_PATH", LIVE_ACCESS_LOG_PATH)
WS_HOST = "0.0.0.0"
WS_PORT = 8765
TICK_SECONDS = 0.5


class LiveStats:
    """Existing descriptive counters used by the "stats" WebSocket
    message -- output shape and values are unchanged from before this
    refactor. Reads only already-parsed LogRecord fields; does no
    parsing of its own.
    """

    def __init__(self):
        self.total = 0
        self.by_ip = Counter()
        self.by_status = Counter()
        self.by_endpoint = Counter()

    def add_record(self, record):
        self.total += 1
        self.by_ip[record.source_ip] += 1
        self.by_status[str(record.status_code)] += 1
        endpoint = record.extra.get("legacy_endpoint") or record.url
        self.by_endpoint[endpoint] += 1

    def snapshot(self, top_n=10):
        return {
            "total": self.total,
            "top_ips": self.by_ip.most_common(top_n),
            "status_counts": self.by_status.most_common(),
            "top_endpoints": self.by_endpoint.most_common(top_n),
        }


async def _broadcast_stats(stats, clients):
    if not clients:
        return
    payload = {"type": "stats", "data": stats.snapshot()}
    message = json.dumps(payload)
    try:
        await asyncio.gather(*[c.send(message) for c in clients])
        print(f"Broadcasted stats to {len(clients)} client(s)")
    except Exception as e:
        print(f"Error broadcasting stats to clients: {e}")


def _process_alerts(alert_engine, session_results):
    """Synchronous by design (per-alert cost is a rank check plus, only
    for qualifying severities, one small append to alerts.log) -- not
    worth asyncio complexity for work this light."""
    for result in session_results:
        # Unconditional, regardless of WebSocket clients or alert
        # severity: without this, a session that never crosses the
        # alert threshold (i.e. normal traffic) produces zero console
        # output at all whenever no client is connected -- "session was
        # correctly evaluated as NORMAL" and "nothing has happened yet"
        # were indistinguishable from the console alone. Logging only --
        # scoring already happened in StreamingPipeline._evaluate();
        # nothing here feeds back into it.
        print("[Session]")
        print(f"IP: {result.source_ip}")
        print(f"Threat: {_dominant_threat_type(result.features)}")
        print(f"Rule Score: {result.rule_anomaly_score:.1f}")
        print(f"ML Score: {result.ml_anomaly_score:.1f}")
        print(f"Decision Source: {result.decision_source}")
        print(f"Final Score: {result.fused_score:.1f}")
        print(f"Severity: {result.fused_severity}")
        alert_engine.process(result)


async def _broadcast_sessions(session_results, clients):
    if not session_results or not clients:
        return
    payload = {
        "type": "sessions",
        "data": {
            # Broadcast-time metadata only (never compared/parsed downstream) --
            # safe to use the non-deprecated, timezone-aware replacement.
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sessions": [r.to_dict() for r in session_results],
        },
    }
    message = json.dumps(payload)
    try:
        await asyncio.gather(*[c.send(message) for c in clients])
        print(f"Broadcasted {len(session_results)} session result(s) to {len(clients)} client(s)")
    except Exception as e:
        print(f"Error broadcasting sessions to clients: {e}")


async def _handle_idle_tick(pipeline, alert_engine, clients):
    """Shared by both tail loops for the "no new line yet" branch:
    evaluates idle-timeout sessions and sleeps TICK_SECONDS.

    NOT datetime.now(timezone.utc) here: this value flows into
    StreamingPipeline.tick() -> RollingSessionBuilder.sweep(), which
    subtracts it from session.last_activity -- a naive datetime derived
    from record.timestamp (core.parsing.log_parser, session-clock logic
    this module must not touch). Mixing an aware value with those naive
    ones would raise "can't subtract offset-naive and offset-aware
    datetimes". .replace(tzinfo=None) keeps the exact same UTC
    wall-clock value as the deprecated datetime.utcnow() call while
    staying naive.
    """
    tick_results = pipeline.tick(datetime.now(timezone.utc).replace(tzinfo=None))
    _process_alerts(alert_engine, tick_results)
    if tick_results:
        # Persist only when something changed -- avoids a disk write
        # every idle 0.5s tick. Evaluation-only counters, see
        # core.detection.decision_engine.DecisionStats; the dashboard
        # (a separate process) reads this file back.
        pipeline.decision_stats.save()
    await _broadcast_sessions(tick_results, clients)
    await asyncio.sleep(TICK_SECONDS)


async def _ingest_row(row, stats, pipeline, alert_engine, clients):
    """Shared by both tail loops for the "got a row dict" branch:
    classify -> parse -> ingest -> alert -> broadcast. Written once here
    so adding a log format only ever means adding a new adapter
    (core.parsing.adapters), never duplicating this sequence.
    """
    if row is None:
        return

    threat_type, confidence = classify_threat_type(row)
    row["threat_type"] = threat_type
    row["confidence"] = confidence

    record = parse_weblog_row(row)
    if record is None:
        return

    stats.add_record(record)
    session_results = pipeline.ingest(record)
    _process_alerts(alert_engine, session_results)
    if session_results:
        pipeline.decision_stats.save()

    await _broadcast_stats(stats, clients)
    await _broadcast_sessions(session_results, clients)


async def tail_csv_and_broadcast(path, clients):
    """CSV mode (default): tails a headered CSV, using
    core.parsing.adapters.csv_row_from_line to turn each line into a
    header-keyed dict tolerant of embedded-comma rows.
    """
    stats = LiveStats()
    pipeline = StreamingPipeline()
    alert_engine = AlertEngine([ConsoleAlertTransport(), FileAlertTransport()])

    # Printed once at startup so a stale/misconfigured process is
    # immediately visible: "nothing happening" because the wrong file
    # is being tailed (e.g. this process predates a LOG_PATH default
    # change, or was started from an unexpected working directory --
    # LOG_PATH is relative) looks identical to "no traffic yet" without
    # this, since both produce silence after the WebSocket line below.
    print(f"Tailing (CSV mode): {os.path.abspath(path)}")

    # Wait for file to exist
    while not os.path.exists(path):
        print(f"Waiting for log file: {path}")
        await asyncio.sleep(1)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            # Empty file, wait for header
            headers = None

        # If header not present, attempt to read first non-empty line
        if headers is None:
            while headers is None:
                line = f.readline()
                if not line:
                    await asyncio.sleep(1)
                    continue
                headers = next(csv.reader([line]))

        # normalize headers to lowercase keys for consistent lookup
        headers = [h.strip().lower() for h in headers]

        # Move to end to watch new lines
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            if not line:
                await _handle_idle_tick(pipeline, alert_engine, clients)
                continue

            row = csv_row_from_line(line, headers)
            await _ingest_row(row, stats, pipeline, alert_engine, clients)


async def tail_nginx_and_broadcast(path, clients):
    """NGINX mode: tails NGINX's access.log (our custom log_format --
    see nginx/conf/anomaly.conf.template -- via
    core.parsing.adapters.nginx_row_from_line). No header row to wait
    for: NGINX writes one complete record per physical line from the
    moment the file exists, unlike the CSV format's header + possible
    embedded-comma rows.
    """
    stats = LiveStats()
    pipeline = StreamingPipeline()
    alert_engine = AlertEngine([ConsoleAlertTransport(), FileAlertTransport()])

    print(f"Tailing (NGINX mode): {os.path.abspath(path)}")

    while not os.path.exists(path):
        print(f"Waiting for log file: {path}")
        await asyncio.sleep(1)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # Move to end to watch new lines, same as CSV mode.
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            if not line:
                await _handle_idle_tick(pipeline, alert_engine, clients)
                continue

            row = nginx_row_from_line(line)
            await _ingest_row(row, stats, pipeline, alert_engine, clients)


async def ws_handler(websocket, path, clients):
    # New client connected
    clients.add(websocket)
    print(f"Client connected: {websocket.remote_address}")
    try:
        # Send a simple welcome
        await websocket.send(json.dumps({"type": "hello", "msg": "connected to live log analyzer"}))
        async for _ in websocket:
            # Echo or ignore incoming messages
            pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        clients.remove(websocket)
        print(f"Client disconnected: {websocket.remote_address}")


async def main():
    clients = set()

    async def _handler(ws, path=None):
        # Accept either (ws, path) or just (ws,) depending on websockets version
        await ws_handler(ws, path, clients)

    server = await websockets.serve(_handler, WS_HOST, WS_PORT)
    print(f"WebSocket server listening on ws://{WS_HOST}:{WS_PORT}")
    print(f"Log source: {LOG_SOURCE}")

    tail_coro = tail_nginx_and_broadcast if LOG_SOURCE == "nginx" else tail_csv_and_broadcast
    tail_task = asyncio.create_task(tail_coro(LOG_PATH, clients))

    await tail_task


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down live analyzer")
