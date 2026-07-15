import os
import sys
import tempfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.threat_engine import ThreatEngine  # noqa: E402

from auth_utils import create_access_token, hash_password, verify_password
from database import Incident, ScanJob, User, SessionLocal, get_db, init_db
from dependencies import get_current_user, get_user_or_service
from schemas import Feature, Features, LoginRequest, SignupRequest, TokenResponse, UserProfile

FRONTEND_DIR = PROJECT_ROOT / "frontend"
engine = ThreatEngine()
LIVE_EVENTS: deque[dict] = deque(maxlen=500)
LIVE_EVENT_ID = 0

app = FastAPI(
    title="NOGINX Security Platform",
    description="AI/ML-powered NGINX log threat detection and security dashboard",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    _ensure_service_user()


def _ensure_service_user() -> None:
    token = os.getenv("NOGINX_SERVICE_TOKEN")
    service_user = os.getenv("NOGINX_SERVICE_USER", "watcher")
    if not token:
        return

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == service_user).first()
        if existing:
            return
        user = User(
            username=service_user,
            email=f"{service_user}@example.com",
            password_hash=hash_password(os.urandom(16).hex()),
        )
        db.add(user)
        db.commit()
        print(f"[startup] created service user '{service_user}' for watcher incidents")
    finally:
        db.close()


@app.get("/")
async def root():
    return {
        "message": "NOGINX Security Platform is running",
        "docs": "/docs",
        "dashboard": "/ui/login.html",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": engine.model is not None,
        "service_token_configured": bool(os.getenv("NOGINX_SERVICE_TOKEN")),
    }


# --- Auth ---


@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.username)
    return TokenResponse(access_token=token, username=user.username)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(user.username)
    return TokenResponse(access_token=token, username=user.username)


@app.get("/auth/me", response_model=UserProfile)
def me(current_user: User = Depends(get_current_user)):
    return current_user


# --- Legacy ML endpoints (watcher compatibility) ---


@app.post("/predict")
async def predict_batch(input: Features):
    results = []
    for feature in input.features:
        legacy = engine.predict_one_legacy(feature)
        results.append({"anomaly": legacy["anomaly"]})
    return results


@app.post("/predict_one")
async def predict_one(input: Feature):
    legacy = engine.predict_one_legacy(input.feature)
    return [legacy]


# --- New cybersecurity endpoints ---


@app.post("/api/analyze-line")
def analyze_line(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    line = payload.get("line", "")
    if not line:
        raise HTTPException(status_code=400, detail="Log line is required")

    prediction = engine.analyze_line(line)
    if not prediction:
        raise HTTPException(status_code=400, detail="Could not parse log line")

    result = prediction.to_dict()
    if prediction.threat_type != "Benign":
        _store_incident(db, current_user, result)

    return result


@app.post("/api/analyze-log")
async def analyze_log(
    file: UploadFile = File(...),
    top_n: int = 25,
    min_confidence: float = 0.0,
    max_lines: int = 15000,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    suffix = Path(file.filename).suffix or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        analysis = engine.analyze_file(
            tmp_path,
            top_n=top_n,
            min_confidence=min_confidence,
            max_lines=max_lines if max_lines > 0 else None,
        )
    finally:
        os.unlink(tmp_path)

    scan = ScanJob(
        user_id=current_user.id,
        filename=file.filename,
        total_lines=analysis["total_lines_parsed"],
        threats_found=analysis["total_threats"],
        best_threat=(analysis["best_prediction"] or {}).get("threat_type"),
        best_confidence=(analysis["best_prediction"] or {}).get("confidence"),
        status="completed",
    )
    db.add(scan)

    for item in analysis.get("top_predictions", [])[:50]:
        db.add(
            Incident(
                user_id=current_user.id,
                ip=item["ip"],
                timestamp=item["timestamp"],
                method=item["method"],
                path=item["path"],
                status=item["status"],
                threat_type=item["threat_type"],
                confidence=item["confidence"],
                severity=item["severity"],
                user_agent=item["user_agent"],
                ml_score=item["ml_score"],
                raw_line=item.get("raw_line"),
                message=item.get("message"),
                source="scan",
            )
        )

    db.commit()
    db.refresh(scan)
    analysis["scan_id"] = scan.id
    return analysis


def _store_incident(db: Session, user: User, prediction: dict, source: str = "dashboard") -> None:
    db.add(
        Incident(
            user_id=user.id,
            ip=prediction["ip"],
            timestamp=prediction.get("timestamp"),
            method=prediction.get("method"),
            path=prediction.get("path"),
            status=prediction.get("status"),
            threat_type=prediction["threat_type"],
            confidence=float(prediction["confidence"]),
            severity=prediction["severity"],
            user_agent=prediction.get("user_agent"),
            ml_score=prediction.get("ml_score"),
            raw_line=prediction.get("raw_line"),
            message=prediction.get("message"),
            source=prediction.get("source", source),
        )
    )
    db.commit()


def _live_explanation(payload: dict) -> dict:
    threat = payload.get("threat_type", "Benign")
    path = payload.get("path") or payload.get("url") or "-"
    status_code = payload.get("status")
    common = {
        "Benign": (
            "Request matched the learned baseline.",
            "Normal method, path, status, and client profile for this log stream.",
            "No action needed. Keep monitoring for bursts or repeated failures.",
        ),
        "Credentials in URL": (
            "Sensitive data was placed in the query string.",
            "URLs can be stored in browser history, logs, proxies, and analytics tools.",
            "Move secrets to POST bodies or Authorization headers and rotate exposed tokens.",
        ),
        "SQL Injection Attempt": (
            "The request contains SQL-like operators or keywords.",
            "Attackers use these payloads to test whether input reaches a database query unsafely.",
            "Check input validation, parameterized queries, and WAF rules for this route.",
        ),
        "Cross-Site Scripting (XSS)": (
            "The request contains script-like browser execution payloads.",
            "This usually targets pages that reflect user input into HTML or JavaScript.",
            "Review output encoding and content security policy for the affected endpoint.",
        ),
        "Path Traversal Attempt": (
            "The path tries to escape the intended web directory.",
            "Attackers use traversal sequences to probe files outside the public web root.",
            "Block traversal patterns and verify file-serving code normalizes paths safely.",
        ),
        "Insecure HTTP Request": (
            "The logged request targets unencrypted HTTP.",
            "Credentials and session data can be exposed in transit when HTTPS is not enforced.",
            "Redirect HTTP to HTTPS and enable HSTS for production domains.",
        ),
        "Insecure HTTP Referer": (
            "The referer came from an unencrypted HTTP page.",
            "This can leak navigation context and may indicate mixed security posture.",
            "Prefer HTTPS-only links and check external redirects/referrers.",
        ),
        "Sensitive Path Probe": (
            "The request targets an admin, auth, or sensitive path.",
            "Automated scanners often probe known panels and login routes.",
            "Verify authentication, rate limits, and whether this IP repeats attempts.",
        ),
        "Sensitive File Probe": (
            "The request targets a sensitive file extension.",
            "Attackers look for exposed backups, configs, secrets, and repository metadata.",
            "Ensure static serving denies dotfiles, backups, keys, and config files.",
        ),
        "Automated Scanner / Script": (
            "The user agent matches scripted or scanner-style traffic.",
            "Tools like wget, curl, or scanners often create repetitive probing patterns.",
            "Check request volume, source reputation, and whether paths are enumerated.",
        ),
        "ML Traffic Anomaly": (
            "The ML model marked this request outside the normal NGINX baseline.",
            "The combination of method, path, status, client, timing, or response shape is unusual.",
            "Compare nearby requests from the same IP and inspect server logs around this event.",
        ),
    }
    summary, cause, action = common.get(
        threat,
        (
            "Traffic triggered a security signal.",
            "The request matched a suspicious rule or unusual ML pattern.",
            "Inspect the source IP, path, status code, and surrounding traffic.",
        ),
    )
    return {
        "summary": summary,
        "cause": cause,
        "action": action,
        "context": f"{payload.get('method', '-')} {path} returned HTTP {status_code or '-'}",
    }


def _append_live_event(payload: dict) -> dict:
    global LIVE_EVENT_ID
    LIVE_EVENT_ID += 1
    event = {
        "id": LIVE_EVENT_ID,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "ip": payload.get("ip", "0.0.0.0"),
        "timestamp": payload.get("timestamp"),
        "method": payload.get("method"),
        "path": payload.get("path"),
        "url": payload.get("url"),
        "status": payload.get("status"),
        "threat_type": payload.get("threat_type", "Benign"),
        "confidence": float(payload.get("confidence", 0.0) or 0.0),
        "severity": payload.get("severity", "low"),
        "user_agent": payload.get("user_agent"),
        "ml_score": payload.get("ml_score"),
        "message": payload.get("message"),
        "source": payload.get("source", "watcher"),
        "explanation": _live_explanation(payload),
    }
    LIVE_EVENTS.append(event)
    return event


def _synthetic_log_line(request: Request, target: str, status_code: int = 200) -> str:
    client_ip = request.client.host if request.client else "127.0.0.1"
    timestamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_agent = request.headers.get("user-agent", "browser")
    referer = request.headers.get("referer", "-")
    return (
        f'{client_ip} - - [{timestamp}] '
        f'"GET {target} HTTP/1.1" {status_code} 512 '
        f'"{referer}" "{user_agent}"'
    )


def _record_lab_event(request: Request, target: str, status_code: int = 200) -> dict:
    prediction = engine.analyze_line(_synthetic_log_line(request, target, status_code))
    if not prediction:
        raise HTTPException(status_code=500, detail="Could not generate lab event")
    payload = prediction.to_dict()
    payload["source"] = "attack-lab"
    return _append_live_event(payload)


@app.get("/api/dashboard/stats")
def dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incidents = (
        db.query(Incident)
        .filter(Incident.user_id == current_user.id)
        .order_by(Incident.created_at.desc())
        .all()
    )
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.user_id == current_user.id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )

    severity_counts: dict[str, int] = {}
    threat_counts: dict[str, int] = {}
    for item in incidents:
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        threat_counts[item.threat_type] = threat_counts.get(item.threat_type, 0) + 1

    best_incident = max(incidents, key=lambda row: row.confidence, default=None)

    return {
        "total_scans": len(scans),
        "total_incidents": len(incidents),
        "severity_breakdown": severity_counts,
        "threat_type_breakdown": threat_counts,
        "recent_scans": [
            {
                "id": scan.id,
                "filename": scan.filename,
                "total_lines": scan.total_lines,
                "threats_found": scan.threats_found,
                "best_threat": scan.best_threat,
                "best_confidence": scan.best_confidence,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            }
            for scan in scans[:10]
        ],
        "highest_confidence_threat": (
            {
                "threat_type": best_incident.threat_type,
                "confidence": best_incident.confidence,
                "severity": best_incident.severity,
                "ip": best_incident.ip,
                "path": best_incident.path,
                "created_at": best_incident.created_at.isoformat()
                if best_incident.created_at
                else None,
            }
            if best_incident
            else None
        ),
    }


@app.get("/api/dashboard/incidents")
def dashboard_incidents(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Incident)
        .filter(Incident.user_id == current_user.id)
        .order_by(Incident.confidence.desc(), Incident.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": row.id,
            "ip": row.ip,
            "timestamp": row.timestamp,
            "method": row.method,
            "path": row.path,
            "status": row.status,
            "threat_type": row.threat_type,
            "confidence": row.confidence,
            "severity": row.severity,
            "user_agent": row.user_agent,
            "ml_score": row.ml_score,
            "message": row.message,
            "source": row.source or "dashboard",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@app.post("/api/incidents/report")
def report_incident(
    payload: dict,
    current_user: User = Depends(get_user_or_service),
    db: Session = Depends(get_db),
):
    required = ["ip", "threat_type", "confidence", "severity"]
    missing = [field for field in required if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing fields: {missing}")

    _store_incident(db, current_user, payload, source=payload.get("source", "watcher"))
    incident = (
        db.query(Incident)
        .filter(Incident.user_id == current_user.id)
        .order_by(Incident.id.desc())
        .first()
    )
    return {"id": incident.id if incident else None, "status": "recorded"}


@app.post("/api/live/report")
def report_live_event(
    payload: dict,
    current_user: User = Depends(get_user_or_service),
    db: Session = Depends(get_db),
):
    required = ["ip", "threat_type", "confidence", "severity"]
    missing = [field for field in required if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing fields: {missing}")

    payload["source"] = payload.get("source", "watcher")
    event = _append_live_event(payload)
    if payload.get("threat_type") != "Benign":
        _store_incident(db, current_user, payload, source=payload["source"])
    return {"status": "recorded", "event": event}


@app.get("/api/live/events")
def live_events(
    after: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
):
    bounded_limit = max(1, min(limit, 200))
    events = [event for event in LIVE_EVENTS if event["id"] > after]
    return {
        "events": events[-bounded_limit:],
        "latest_id": LIVE_EVENT_ID,
        "buffer_size": len(LIVE_EVENTS),
    }


@app.get("/api/dashboard/scans")
def dashboard_scans(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.user_id == current_user.id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": scan.id,
            "filename": scan.filename,
            "total_lines": scan.total_lines,
            "threats_found": scan.threats_found,
            "best_threat": scan.best_threat,
            "best_confidence": scan.best_confidence,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        }
        for scan in scans
    ]


@app.get("/api/dashboard/scans/{scan_id}")
def dashboard_scan_detail(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    related = (
        db.query(Incident)
        .filter(Incident.user_id == current_user.id, Incident.source == "scan")
        .order_by(Incident.confidence.desc())
        .limit(50)
        .all()
    )

    return {
        "scan": {
            "id": scan.id,
            "filename": scan.filename,
            "total_lines": scan.total_lines,
            "threats_found": scan.threats_found,
            "best_threat": scan.best_threat,
            "best_confidence": scan.best_confidence,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        },
        "incidents": [
            {
                "threat_type": row.threat_type,
                "confidence": row.confidence,
                "severity": row.severity,
                "ip": row.ip,
                "path": row.path,
                "message": row.message,
            }
            for row in related
        ],
    }


@app.get("/api/profile")
def user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident_count = (
        db.query(Incident).filter(Incident.user_id == current_user.id).count()
    )
    scan_count = db.query(ScanJob).filter(ScanJob.user_id == current_user.id).count()
    watcher_count = (
        db.query(Incident)
        .filter(Incident.user_id == current_user.id, Incident.source == "watcher")
        .count()
    )
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "created_at": current_user.created_at.isoformat()
        if current_user.created_at
        else None,
        "stats": {
            "total_incidents": incident_count,
            "total_scans": scan_count,
            "watcher_alerts": watcher_count,
        },
    }


# --- Browser-triggered demo lab ---


@app.get("/lab")
def attack_lab_index() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html>
        <head>
          <title>NOGINX Attack Lab</title>
          <style>
            body{font-family:Segoe UI,Arial,sans-serif;background:#0a0e17;color:#e5e7eb;padding:32px}
            a{display:block;margin:12px 0;color:#22d3ee;font-size:18px}
            code{background:#111827;padding:3px 6px;border-radius:6px}
          </style>
        </head>
        <body>
          <h1>NOGINX Attack Lab</h1>
          <p>Open the Live Monitor, then click any URL below. Each click creates a live security event.</p>
          <a href="/lab/credential-leak">Credential leak: <code>/login?password=secret</code></a>
          <a href="/lab/sql-injection">SQL injection: <code>/search?q=union select</code></a>
          <a href="/lab/xss">XSS payload: <code>/comment?msg=&lt;script&gt;</code></a>
          <a href="/lab/path-traversal">Path traversal: <code>/download?file=../../etc/passwd</code></a>
          <a href="/lab/sensitive-file">Sensitive file probe: <code>/.env</code></a>
          <a href="/lab/benign">Benign request: <code>/downloads/product_1</code></a>
        </body>
        </html>
        """
    )


@app.get("/lab/{scenario}")
def attack_lab_scenario(scenario: str, request: Request) -> HTMLResponse:
    scenarios = {
        "credential-leak": ("/login?password=secret-token-123", 200),
        "sql-injection": ("/search?q=1%20union%20select%20password%20from%20users", 403),
        "xss": ("/comment?msg=<script>alert(1)</script>", 200),
        "path-traversal": ("/download?file=../../etc/passwd", 404),
        "sensitive-file": ("/.env", 404),
        "benign": ("/downloads/product_1", 200),
    }
    if scenario not in scenarios:
        raise HTTPException(status_code=404, detail="Unknown lab scenario")

    target, status_code = scenarios[scenario]
    event = _record_lab_event(request, target, status_code)
    return HTMLResponse(
        f"""
        <!doctype html>
        <html>
        <head>
          <title>NOGINX Lab Event</title>
          <style>
            body{{font-family:Segoe UI,Arial,sans-serif;background:#0a0e17;color:#e5e7eb;padding:32px}}
            .box{{max-width:760px;background:#111827;border:1px solid #243047;border-radius:10px;padding:24px}}
            strong{{color:#22d3ee}} code{{color:#a7f3d0}}
            a{{color:#22d3ee}}
          </style>
        </head>
        <body>
          <div class="box">
            <h1>Event sent to Live Monitor</h1>
            <p><strong>{event["threat_type"]}</strong> with {event["confidence"] * 100:.1f}% confidence.</p>
            <p><code>{event.get("method")} {event.get("path")}</code></p>
            <p>{event.get("explanation", {}).get("summary", "")}</p>
            <p><a href="/ui/live.html">Open Live Monitor</a> | <a href="/lab">Run another test</a></p>
          </div>
        </body>
        </html>
        """
    )


# --- Static UI ---


@app.get("/ui")
async def ui_root():
    login_page = FRONTEND_DIR / "login.html"
    if login_page.exists():
        return FileResponse(login_page)
    raise HTTPException(status_code=404, detail="UI not found")


if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")
