"""SOC-style Streamlit dashboard.

Refactored to support multi-page layout, JWT authentication,
and integrated Network Scanner with live vulnerability-to-log correlation.
"""
import csv
import os
import re
import sys
import time
import urllib.request
import subprocess
import base64
import json
from collections import Counter
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from pandas.errors import ParserError

# Setup paths
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_SRC_DIR)
for _p in (_SRC_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dashboard_components import (
    alert_card,
    html_table,
    metric_card,
    section_header,
    severity_status_card,
    status_dot,
    system_status_card,
    timeline_item,
)
from dashboard_theme import DARK, LIGHT, chart_color_sequence, inject_auth_css, inject_css

from core.alerting.config import ALERT_LOG_PATH, MAX_ALERT_HISTORY
from core.alerting.history import read_recent_alerts
from core.config import FLASK_PORT, LOG_SOURCE, NGINX_ACCESS_LOG_PATH, NGINX_PORT, is_nginx_mode
from core.detection.classifier import classify_threat_type
from core.detection.decision_engine import DECISION_STATS_PATH, DecisionStats
from core.parsing.adapters import nginx_row_from_line
from core.paths import LIVE_ACCESS_LOG_PATH, TRAINING_DATA_PATH
from core.persistence.model_store import DEFAULT_BASE_DIR as MODEL_STORE_BASE_DIR
from core.auth import generate_jwt, verify_jwt

# Set page config
st.set_page_config(page_title="Threat Detection SOC", layout="wide", initial_sidebar_state="expanded")

APP_VERSION = "2.1.0"
LIVE_REFRESH_SECONDS = 2
MAIN_REFRESH_SECONDS = 5
STATUS_REFRESH_SECONDS = 10

WEBSITE_URL = f"http://127.0.0.1:{NGINX_PORT if is_nginx_mode() else FLASK_PORT}/"
ANALYZER_FRESHNESS_SECONDS = 90

# =======================================================================
# Session State Initialization
# =======================================================================
_DEFAULTS = {
    "authenticated": False,
    "auth_view": "login",
    "dark_mode": True,  # Cybersecurity focused default
    "live_monitoring": True,  # Default to active live logs on start
    "user_email": "",
    "user_name": "",
    "user_role": "SOC_Analyst",
    "jwt_token": None,
    "uploaded_file": None,
    "hide_static_assets": True,
}
for _key, _value in _DEFAULTS.items():
    if _key not in st.session_state:
        st.session_state[_key] = _value

# Verify JWT token if present
if st.session_state.jwt_token:
    claims = verify_jwt(st.session_state.jwt_token)
    if claims:
        st.session_state.authenticated = True
        st.session_state.user_email = claims.get("email")
        st.session_state.user_name = claims.get("user_name")
        st.session_state.user_role = claims.get("role", "SOC_Analyst")
    else:
        st.session_state.authenticated = False
        st.session_state.jwt_token = None

PALETTE = DARK if st.session_state.dark_mode else LIGHT
st.markdown(inject_css(PALETTE), unsafe_allow_html=True)

# =======================================================================
# Auth UI (Login / Sign-up Forms)
# =======================================================================
def _render_login_form():
    with st.form("login_form", border=False):
        st.text_input("Email", placeholder="you@example.com", key="login_email")
        st.text_input("Password", type="password", placeholder="••••••••", key="login_password")
        rc1, rc2 = st.columns(2)
        with rc1:
            st.checkbox("Remember me", key="login_remember")
        with rc2:
            forgot_clicked = st.form_submit_button("Forgot password?", use_container_width=True, key="forgot_password_btn")
        submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

    if forgot_clicked:
        st.session_state.auth_view = "forgot"
        st.rerun()
    if submitted:
        email = st.session_state.login_email
        password = st.session_state.login_password
        if email and password:
            role = "Admin" if "admin" in email.lower() else "SOC_Analyst"
            name = email.split('@')[0].capitalize()
            payload = {
                "email": email,
                "user_name": name,
                "role": role,
                "exp": time.time() + 3600
            }
            token = generate_jwt(payload)
            st.session_state.jwt_token = token
            st.session_state.authenticated = True
            st.session_state.user_email = email
            st.session_state.user_name = name
            st.session_state.user_role = role
            st.session_state.remember_me = st.session_state.login_remember
            st.rerun()
        else:
            st.error("Enter both an email and a password to continue.")


def _render_signup_form():
    with st.form("signup_form", border=False):
        nc1, nc2 = st.columns(2)
        with nc1:
            st.text_input("First name", placeholder="John", key="signup_first_name")
        with nc2:
            st.text_input("Last name", placeholder="Appleseed", key="signup_last_name")
        st.text_input("Email", placeholder="you@example.com", key="signup_email")
        st.text_input("Password", type="password", placeholder="••••••••", key="signup_password")
        st.text_input("Confirm password", type="password", placeholder="••••••••", key="signup_confirm")
        submitted = st.form_submit_button("Create Account", use_container_width=True, type="primary")

    if submitted:
        first = st.session_state.signup_first_name
        last = st.session_state.signup_last_name
        email = st.session_state.signup_email
        password = st.session_state.signup_password
        if not (first and last and email and password):
            st.error("Please fill in every field.")
        elif password != st.session_state.signup_confirm:
            st.error("Passwords don't match.")
        else:
            role = "Admin" if "admin" in email.lower() else "SOC_Analyst"
            name = f"{first} {last}"
            payload = {
                "email": email,
                "user_name": name,
                "role": role,
                "exp": time.time() + 3600
            }
            token = generate_jwt(payload)
            st.session_state.jwt_token = token
            st.session_state.authenticated = True
            st.session_state.user_email = email
            st.session_state.user_name = name
            st.session_state.user_role = role
            st.rerun()

    if st.button("Already have an account? Sign in", use_container_width=True, key="signup_to_login"):
        st.session_state.auth_view = "login"
        st.rerun()


def _render_forgot_password_form():
    with st.form("forgot_form", border=False):
        st.text_input("Email", placeholder="you@example.com", key="forgot_email")
        submitted = st.form_submit_button("Send Reset Link", use_container_width=True, type="primary")

    if submitted:
        email = st.session_state.forgot_email
        if email:
            st.success(f"If an account exists for {email}, a reset link has been sent. (Demo only — no email is actually sent.)")
        else:
            st.error("Enter your email first.")

    if st.button("← Back to Sign In", use_container_width=True, key="forgot_to_login"):
        st.session_state.auth_view = "login"
        st.rerun()


def render_auth_ui(*_unused):
    st.markdown(inject_auth_css(DARK), unsafe_allow_html=True)
    with st.container(key="auth_card"):
        view = st.session_state.auth_view
        view_label = {"signup": "Create your account", "forgot": "Reset your password"}.get(view, "Sign in to continue")
        st.markdown(
            f"""
<div class="auth-brand">
    <div class="auth-logo">🛡️</div>
    <div class="auth-title">Threat Detection SOC</div>
    <div class="auth-subtitle">AI-Powered Web Log Threat Detection Platform</div>
    <div class="auth-view-label">{view_label}</div>
</div>
""",
            unsafe_allow_html=True,
        )

        if view != "forgot":
            with st.container(key="auth_tabs"):
                t1, t2 = st.columns(2)
                with t1:
                    if st.button("Sign In", use_container_width=True, key="auth_tab_signin",
                                 type="primary" if view != "signup" else "secondary"):
                        st.session_state.auth_view = "login"
                        st.rerun()
                with t2:
                    if st.button("Sign Up", use_container_width=True, key="auth_tab_signup",
                                 type="primary" if view == "signup" else "secondary"):
                        st.session_state.auth_view = "signup"
                        st.rerun()

        if view == "signup":
            _render_signup_form()
        elif view == "forgot":
            _render_forgot_password_form()
        else:
            _render_login_form()

    st.markdown(
        '<div class="auth-footer-note">Demo sign-in for presentation purposes only — '
        "a mock JWT token containing your role will be generated.</div>",
        unsafe_allow_html=True,
    )


# Auth gate is now handled dynamically at the bottom of the file during page assembly.


# =======================================================================
# Shared Data Readers & Normalizers
# =======================================================================
def _safe_read_csv(path):
    if not os.path.exists(path):
        return None
    try:
        return pd.read_csv(path)
    except ParserError:
        rows = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                if len(row) == 4:
                    rows.append(row)
                elif len(row) > 4:
                    ip = row[0]
                    status = row[-1]
                    middle = row[1:-1]
                    time_field = middle[0] if middle else ""
                    url_field = ",".join(middle[1:]) if len(middle) > 1 else (middle[0] if middle else "")
                    rows.append([ip, time_field, url_field, status])
                else:
                    continue
        if not rows:
            return None
        return pd.DataFrame(rows, columns=["IP", "Time", "URL", "Staus"])
    except Exception:
        try:
            return pd.read_csv(path, engine="python")
        except Exception:
            return None


def _read_nginx_access_log_df(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return None

    rows = [row for row in (nginx_row_from_line(line) for line in lines[-500:]) if row is not None]
    if not rows:
        return None
    return pd.DataFrame(rows)


def _live_monitor_source():
    if LOG_SOURCE == "nginx":
        return NGINX_ACCESS_LOG_PATH, "NGINX Access Log"
    return LIVE_ACCESS_LOG_PATH, "CSV Live Log"


def _read_live_monitor_df(path):
    df = _read_nginx_access_log_df(path) if LOG_SOURCE == "nginx" else _safe_read_csv(path)
    return normalize_data(df) if df is not None else None


_STATIC_ASSET_PATH_PREFIXES = ("/static/", "/favicon.ico", "/robots.txt")
_STATIC_ASSET_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map",
)
_NEVER_HIDE_THREAT_TYPES = {
    "SQL/Web Injection Attack",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Directory Traversal",
    "Sensitive File Access",
    "Credential Attack",
    "Brute Force Attack",
    "DoS Pattern",
    "Suspicious Activity",
    "Classification Error",
}


def _looks_like_static_asset(path_or_endpoint) -> bool:
    path_only = str(path_or_endpoint).strip().lower().split("?", 1)[0]
    if any(path_only.startswith(prefix) for prefix in _STATIC_ASSET_PATH_PREFIXES):
        return True
    return path_only.endswith(_STATIC_ASSET_EXTENSIONS)


def _hide_static_assets(df):
    if df is None or df.empty or "endpoint" not in df.columns:
        return df

    def _is_hideable(row):
        if not _looks_like_static_asset(row.get("endpoint", "")):
            return False
        classify_row = {"URL": row.get("url", row.get("endpoint", "")), "Status": row.get("status_code", "")}
        threat_type, _ = classify_threat_type(classify_row)
        return threat_type not in _NEVER_HIDE_THREAT_TYPES

    mask = df.apply(_is_hideable, axis=1)
    return df[~mask]


@st.cache_data(ttl=MAIN_REFRESH_SECONDS)
def _load_data_cached(path):
    return _safe_read_csv(path)


def normalize_data(df):
    renamed = df.copy()
    col_map = {c.lower(): c for c in renamed.columns}

    if "time" in col_map and "timestamp" not in renamed.columns:
        raw = renamed[col_map["time"]].astype(str).str.strip()
        raw = raw.str.replace(r"^\[+", "", regex=True).str.replace(r"\]+$", "", regex=True)

        def extract_ts(s):
            if not isinstance(s, str):
                return None
            m = re.search(r"\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}", s)
            if m:
                return m.group(0)
            m2 = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", s)
            if m2:
                return m2.group(0)
            return s

        extracted = raw.apply(extract_ts)
        ts = pd.to_datetime(extracted, format="%d/%b/%Y:%H:%M:%S", errors="coerce")
        if ts.isna().all():
            ts = pd.to_datetime(extracted, infer_datetime_format=True, errors="coerce")
        renamed["timestamp"] = ts

    if "url" in col_map and "url" not in renamed.columns:
        renamed["url"] = renamed[col_map["url"]].astype(str)
        parts = renamed["url"].str.split(n=2, expand=True)
        renamed["method"] = parts[0]
        renamed["endpoint"] = parts[1]

    if "staus" in col_map and "status_code" not in renamed.columns and "status" not in renamed.columns:
        renamed["status_code"] = pd.to_numeric(renamed[col_map["staus"]], errors="coerce")
    elif "status" in col_map and "status_code" not in renamed.columns:
        renamed["status_code"] = pd.to_numeric(renamed[col_map["status"]], errors="coerce")

    if "ip" in col_map and "ip" not in renamed.columns:
        renamed["ip"] = renamed[col_map["ip"]]

    return renamed


def safe_preview(df):
    return df.astype("string")


def get_active_dataframe():
    uploaded = st.session_state.get("uploaded_file")
    if uploaded is not None:
        try:
            df = pd.read_csv(uploaded)
        except Exception:
            df = pd.read_csv(uploaded, engine="python")
        return (normalize_data(df) if df is not None else None), "Uploaded CSV", False

    is_live = st.session_state.get("live_monitoring", False)
    path = LIVE_ACCESS_LOG_PATH if is_live else TRAINING_DATA_PATH
    df = _safe_read_csv(path) if is_live else _load_data_cached(path)
    if df is not None:
        df = normalize_data(df)
    return df, path, is_live


def apply_filters(df):
    df_filter = df.copy()
    date_range = st.session_state.get("filter_date_range")
    if "timestamp" in df_filter.columns and date_range and len(date_range) == 2:
        start_dt = pd.to_datetime(str(date_range[0]))
        end_dt = pd.to_datetime(str(date_range[1])) + pd.Timedelta(days=1)
        df_filter = df_filter[pd.to_datetime(df_filter["timestamp"]).between(start_dt, end_dt)]

    chosen_status = st.session_state.get("filter_status_codes")
    if "status_code" in df_filter.columns and chosen_status:
        df_filter = df_filter[df_filter["status_code"].isin(chosen_status)]

    chosen_ip = st.session_state.get("filter_ip", "All")
    if "ip" in df_filter.columns and chosen_ip and chosen_ip != "All":
        df_filter = df_filter[df_filter["ip"] == chosen_ip]

    url_query = st.session_state.get("filter_url_query", "")
    if url_query:
        if "endpoint" in df_filter.columns:
            df_filter = df_filter[df_filter["endpoint"].str.contains(url_query, na=False)]
        elif "url" in df_filter.columns:
            df_filter = df_filter[df_filter["url"].str.contains(url_query, na=False)]
    return df_filter


def _check_http_up(url, timeout=0.3):
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except Exception:
        return False


def _analyzer_activity_status():
    candidates = [p for p in (DECISION_STATS_PATH, ALERT_LOG_PATH) if os.path.exists(p)]
    if not candidates:
        return "unknown"
    age_seconds = time.time() - max(os.path.getmtime(p) for p in candidates)
    return "active" if age_seconds <= ANALYZER_FRESHNESS_SECONDS else "idle"


_ANALYZER_STATUS_DISPLAY = {
    "active": ("Active", True, False),
    "idle": ("Idle", False, True),
    "unknown": ("No Data Yet", False, False),
}


@st.cache_data(ttl=LIVE_REFRESH_SECONDS)
def _load_recent_alerts_cached(path, limit):
    return read_recent_alerts(path=path, limit=limit)


# =======================================================================
# Common Sidebar & Filters
# =======================================================================
def render_sidebar(palette):
    st.sidebar.markdown(
        f"""
<div class="sidebar-brand-block" style="text-align:center;">
    <div style="font-size:1.45rem; font-weight:900; color:#00f0ff; letter-spacing:0.15em; margin-bottom:4px; font-family: 'Outfit', 'Inter', sans-serif; text-shadow:0 0 10px rgba(0,240,255,0.45);">NOGINX</div>
    <div style="font-weight:700; font-size:0.75rem; color:{palette['text']}; text-transform:uppercase; letter-spacing:0.06em;">Threat Detection SOC</div>
    <div class="soc-muted" style="font-size:0.7rem;">M.Tech Capstone Project</div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.sidebar.markdown("##### Configuration")
    st.sidebar.toggle(
        "Live Mode",
        key="live_monitoring",
        help=(
            "Switches the dashboard's data source between the live access log "
            "and the historical training dataset."
        ),
    )
    st.sidebar.caption(f"Live Mode is **{'ON' if st.session_state.live_monitoring else 'OFF'}**")

    st.sidebar.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)
    st.sidebar.caption("Active Session")
    st.sidebar.caption(f"User: **{st.session_state.user_email or 'demo user'}**")
    st.sidebar.caption(f"Role: **{st.session_state.user_role}**")
    if st.sidebar.button("Sign Out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.jwt_token = None
        st.rerun()


def render_filters_expander(df):
    """Renders a collapsible expander containing search & filter options on log views."""
    if df is None:
        return
    with st.expander("🔍 Search & Filter Settings", expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.checkbox("Hide Static Assets", value=True, key="hide_static_assets")
            if "timestamp" in df.columns:
                min_ts = pd.to_datetime(df["timestamp"]).min()
                max_ts = pd.to_datetime(df["timestamp"]).max()
                if pd.notna(min_ts) and pd.notna(max_ts):
                    st.date_input("Time range", [min_ts.date(), max_ts.date()], key="filter_date_range")
        with c2:
            if "status_code" in df.columns:
                statuses = sorted(df["status_code"].dropna().unique().astype(int).tolist())
                st.multiselect("Status codes", statuses, default=statuses, key="filter_status_codes")
        with c3:
            if "ip" in df.columns:
                ips = df["ip"].dropna().unique().tolist()
                st.selectbox("IP filter", options=["All"] + ips, key="filter_ip")
        st.text_input("URL contains", key="filter_url_query")


# =======================================================================
# Top Header Block
# =======================================================================
def render_top_header(palette):
    is_live = st.session_state.get("live_monitoring", False)
    mode_label = "[ LIVE_FEED ]" if is_live else "[ HISTORICAL_ARCHIVE ]"
    mode_color = palette["green"] if is_live else palette["graphite"]
    analyzer_label, analyzer_is_up, analyzer_warn = _ANALYZER_STATUS_DISPLAY[_analyzer_activity_status()]
    now = datetime.now()
    st.markdown(
        f"""
<div class="soc-card soc-glass soc-header" style="display:flex; justify-content:space-between; align-items:center; padding: 0.9rem 1.4rem; border-radius:18px;">
    <div class="soc-brand" style="font-family: 'Outfit', 'Inter', sans-serif; font-size:1.65rem; font-weight:900; letter-spacing:-0.03em; display:flex; align-items:center; margin:0;">
        <span style="color:#00f0ff; text-shadow:0 0 10px rgba(0,240,255,0.4); margin-right:10px;">NOGINX</span>
        <span style="color:{palette['text_secondary']}; font-weight:300; font-size:0.95rem; border-left:1px solid {palette['border']}; padding-left:12px;">Threat Detection SOC</span>
    </div>
    <div class="soc-mode-pill" style="color:{mode_color}; font-weight:700; font-family: 'Fira Code', monospace; font-size:0.75rem;">{mode_label}</div>
    <div class="soc-right" style="text-align:right; font-size:0.75rem; color:{palette['text_secondary']};">
        {status_dot(analyzer_is_up, warn=analyzer_warn)} <span style="font-weight:600; color:{palette['text']};">Analyzer {analyzer_label}</span><br/>
        {now.strftime('%H:%M:%S')} &nbsp;·&nbsp; {now.strftime('%Y-%m-%d')} &nbsp;·&nbsp; v{APP_VERSION}
    </div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_mode_badge(is_live, source_path, palette):
    mode_text = "LIVE MODE" if is_live else "HISTORICAL MODE"
    st.info(f"💾 **SYSTEM STATUS:** Operating in `{mode_text}` | Active Data Log: `{source_path}`")


# =======================================================================
# PAGE 1: SOC OVERVIEW
# =======================================================================
def page_overview():
    render_top_header(PALETTE)
    
    # Live status badge
    df, source_path, is_live = get_active_dataframe()
    render_mode_badge(is_live, source_path, PALETTE)
    
    # 1. System Status
    st.markdown('<div id="section-10-system-status"></div>', unsafe_allow_html=True)
    section_header("System Health & Infrastructure")
    
    website_up = _check_http_up(WEBSITE_URL)
    analyzer_label, analyzer_is_up, analyzer_warn = _ANALYZER_STATUS_DISPLAY[_analyzer_activity_status()]
    decision_engine_active = os.path.exists(DECISION_STATS_PATH)
    model_available = os.path.exists(os.path.join(MODEL_STORE_BASE_DIR, "latest.json"))

    items = [
        ("Website", website_up, False, "python site/app.py", WEBSITE_URL, True),
        ("Live Analyzer", analyzer_is_up, analyzer_warn, f"{analyzer_label} (from alerts.log / decision_stats.json)", "/?page=live_monitoring", False),
        ("Dashboard", True, False, "this app", "/?page=soc_dashboard", False),
        ("Decision Engine", decision_engine_active, not decision_engine_active, "decision_stats.json found" if decision_engine_active else "no sessions evaluated yet", "/?page=soc_dashboard", False),
        ("Rule Engine", True, False, "always active, no external dependency", "/?page=incidents_%26_alerts", False),
        ("ML Model", model_available, not model_available, "trained model found" if model_available else "rules-only fallback", "/?page=threat_analytics", False),
    ]
    cols = st.columns(3)
    for i, (name, up, warn, note, url, new_tab) in enumerate(items):
        with cols[i % 3]:
            st.markdown(system_status_card(name, up, PALETTE, warn, note, url, new_tab), unsafe_allow_html=True)
            
    st.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)

    # 2. Threat Status
    alerts = _load_recent_alerts_cached(ALERT_LOG_PATH, MAX_ALERT_HISTORY)
    st.markdown('<div id="section-1-current-threat-status"></div>', unsafe_allow_html=True)
    section_header(
        "Current Threat Status",
        "Counts reflect alerts.log (sessions that crossed the alert threshold).",
    )
    severity_counts = Counter(a.get("severity", "NORMAL") for a in alerts)
    cols = st.columns(5)
    for col, sev in zip(cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL"]):
        with col:
            st.markdown(severity_status_card(sev, severity_counts.get(sev, 0), PALETTE), unsafe_allow_html=True)

    st.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)

    # 3. Decision Engine Statistics
    st.markdown('<div id="section-3-decision-engine-statistics"></div>', unsafe_allow_html=True)
    section_header(
        "Decision Engine Statistics",
        "How many sessions each decision path has handled since live_analyzer.py started.",
    )
    counts = DecisionStats.load()
    cols = st.columns(len(counts))
    decision_accent = {"RULE_OVERRIDE": "red", "ML_OVERRIDE": "blue", "CONSENSUS": "orange", "FUSION": "graphite"}
    for col, (source, count) in zip(cols, counts.items()):
        with col:
            st.markdown(
                metric_card(source.replace("_", " ").title(), count, PALETTE, decision_accent.get(source, "graphite")),
                unsafe_allow_html=True,
            )

    st.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)

    # 4. Live Metrics
    if df is not None:
        section_header("Live Session Metrics")
        total_requests = len(df)
        unique_ips = df["ip"].nunique() if "ip" in df.columns else 0
        unique_endpoints = df["endpoint"].nunique() if "endpoint" in df.columns else 0
        http_errors = int((df["status_code"] >= 400).sum()) if "status_code" in df.columns else 0
        sessions_evaluated = sum(DecisionStats.load().values())

        rpm = 0.0
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce").dropna()
            if len(ts) >= 2:
                span_minutes = max((ts.max() - ts.min()).total_seconds() / 60.0, 1 / 60)
                rpm = len(ts) / span_minutes

        metrics = [
            ("Total Requests", total_requests, "blue", ""),
            ("Requests / Min", f"{rpm:.1f}", "green", "avg over visible window"),
            ("Unique IPs", unique_ips, "graphite", ""),
            ("Unique Endpoints", unique_endpoints, "graphite", ""),
            ("HTTP Errors", http_errors, "red", "status >= 400"),
            ("Sessions Evaluated", sessions_evaluated, "orange", "all-time, from decision_stats.json"),
        ]
        cols = st.columns(3)
        for i, (label, value, accent, cap) in enumerate(metrics):
            with cols[i % 3]:
                st.markdown(metric_card(label, value, PALETTE, accent, cap), unsafe_allow_html=True)


# =======================================================================
# PAGE 2: LIVE MONITORING
# =======================================================================
def page_live_monitoring():
    render_top_header(PALETTE)
    
    is_live = st.session_state.get("live_monitoring", False)
    if is_live:
        path, source_label = _live_monitor_source()
        df = _read_live_monitor_df(path)
    else:
        df, path, _ = get_active_dataframe()
        source_label = "Uploaded CSV" if path == "Uploaded CSV" else "Historical Dataset"

    section_header("Live Log Monitor", "Newest first. Real-time logging console.")
    st.caption(f"Source: **{source_label}** | Path: `{path}`")

    if df is None:
        st.warning(f"No data found at `{path}` yet. Browse the site to generate logs.")
        return

    # Render inline search & filters
    render_filters_expander(df)

    df_filter = apply_filters(df)
    if st.session_state.get("hide_static_assets", True):
        df_filter = _hide_static_assets(df_filter)
        
    monitor_cols = [c for c in ["timestamp", "ip", "method", "endpoint", "status_code"] if c in df_filter.columns]
    if not monitor_cols:
        st.warning("No recognizable columns in data source.")
        return

    monitor_df = (
        df_filter[monitor_cols]
        .tail(100)
        .iloc[::-1]
        .rename(columns={"timestamp": "Timestamp", "ip": "IP", "method": "Method", "endpoint": "Endpoint", "status_code": "Status"})
    )
    st.markdown(html_table(safe_preview(monitor_df)), unsafe_allow_html=True)


# =======================================================================
# PAGE 3: THREAT ANALYTICS (Charts)
# =======================================================================
def page_analytics():
    render_top_header(PALETTE)
    df, source_path, _ = get_active_dataframe()
    if df is None:
        st.error(f"No data found at {source_path}.")
        return

    df_filter = apply_filters(df)
    section_header("Threat & Traffic Analytics")
    colors = chart_color_sequence(PALETTE)

    c1, c2 = st.columns(2)
    with c1:
        if "status_code" in df_filter.columns:
            scounts = df_filter["status_code"].value_counts().rename_axis("status_code").reset_index(name="count")
            fig = px.bar(scounts, x="status_code", y="count", title="Status Code Distribution", color_discrete_sequence=colors)
            st.plotly_chart(_style_chart(fig, PALETTE), use_container_width=True)
        else:
            st.warning("No `status_code` column available.")
    with c2:
        if "endpoint" in df_filter.columns:
            top = df_filter["endpoint"].value_counts().head(10).rename_axis("endpoint").reset_index(name="count")
            fig = px.bar(top, x="count", y="endpoint", orientation="h", title="Top Endpoints", color_discrete_sequence=colors)
            st.plotly_chart(_style_chart(fig, PALETTE), use_container_width=True)
        else:
            st.warning("No `endpoint` column available.")

    c3, c4 = st.columns(2)
    with c3:
        if "ip" in df_filter.columns:
            top_ips = df_filter["ip"].value_counts().head(10).rename_axis("ip").reset_index(name="count")
            fig = px.bar(top_ips, x="count", y="ip", orientation="h", title="Top attacker/client IPs", color_discrete_sequence=colors)
            st.plotly_chart(_style_chart(fig, PALETTE), use_container_width=True)
        else:
            st.warning("No `ip` column available.")
    with c4:
        threat_alerts = _load_recent_alerts_cached(ALERT_LOG_PATH, MAX_ALERT_HISTORY)
        if threat_alerts:
            threat_counts = Counter(a.get("threat_type", "Unknown") for a in threat_alerts)
            tdf = pd.DataFrame(sorted(threat_counts.items(), key=lambda kv: -kv[1]), columns=["threat_type", "count"])
            fig = px.pie(tdf, names="threat_type", values="count", title="Threat Distribution (Alerted Sessions)", color_discrete_sequence=colors, hole=0.5)
            st.plotly_chart(_style_chart(fig, PALETTE), use_container_width=True)
        else:
            st.caption("No alerted sessions yet to build a threat distribution.")


def _style_chart(fig, palette):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, -apple-system, sans-serif", color=palette["text"]),
        title_font=dict(size=14, color=palette["text"]),
        margin=dict(l=10, r=10, t=45, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=palette["text"])),
    )
    fig.update_xaxes(gridcolor=palette["border"], zeroline=False, tickfont=dict(color=palette["text"]))
    fig.update_yaxes(gridcolor=palette["border"], zeroline=False, tickfont=dict(color=palette["text"]))
    try:
        fig.update_traces(marker_cornerradius=6)
    except Exception:
        pass
    return fig


# =======================================================================
# PAGE 4: INCIDENTS & ALERTS
# =======================================================================
def page_alerts():
    render_top_header(PALETTE)
    alerts = _load_recent_alerts_cached(ALERT_LOG_PATH, MAX_ALERT_HISTORY)

    c1, c2 = st.columns([2, 1])
    with c1:
        section_header("Recent Incident Alerts")
        if not alerts:
            st.caption("No alerts recorded yet.")
        else:
            for alert in list(reversed(alerts))[:20]:
                st.markdown(alert_card(alert, PALETTE), unsafe_allow_html=True)
    with c2:
        section_header("Attack Timeline")
        if not alerts:
            st.caption("No attacks recorded yet.")
        else:
            for alert in list(reversed(alerts))[:15]:
                st.markdown(timeline_item(alert, PALETTE), unsafe_allow_html=True)

    st.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)
    section_header("Active Sessions Profile", "Most recent threat severity per IP.")
    if alerts:
        latest_per_ip = {}
        for a in alerts:
            latest_per_ip[a.get("source_ip")] = a
        rows = [
            {
                "IP": ip,
                "Requests": a.get("record_count", ""),
                "Threat": a.get("threat_type", ""),
                "Current Severity": a.get("severity", ""),
                "Decision Path": a.get("decision_source", ""),
                "Session Duration (s)": a.get("session_duration", ""),
            }
            for ip, a in latest_per_ip.items()
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.caption("No active threat sessions.")


# =======================================================================
# PAGE 5: NETWORK SCANNER & CORRELATION
# =======================================================================
def page_scanner():
    render_top_header(PALETTE)
    section_header("Network Vulnerability Scanner", "Active probing & multi-source correlation")

    role = st.session_state.get("user_role", "SOC_Analyst")
    
    # 1. Scanner Launch Section
    st.markdown("### 1. Launch Active Vulnerability Scan")
    
    # Targets configuration
    scan_targets = st.text_input("Scanner Target IP / Subnet Range", "192.168.1.100")
    
    if role != "Admin":
        st.error("ACCESS DENIED: Active scanning requires elevated Admin privileges. Your current role is SOC_Analyst.")
        st.button("Launch Vulnerability Scan", disabled=True, use_container_width=True)
    else:
        st.warning("Warning: Port scanning should only be run against authorized assets.")
        if st.button("Launch Vulnerability Scan", type="primary", use_container_width=True):
            # Run scan in subprocess
            script_path = os.path.join(_REPO_ROOT, "complete_threat_detection.py")
            
            st.info("Scanner initiated. Fetching console log feed...")
            console_box = st.empty()
            
            try:
                # Set environment variable to enable UTF-8 for subprocess stdout
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                
                process = subprocess.Popen(
                    [sys.executable, script_path],
                    cwd=_REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env
                )
                
                log_feed = ""
                # Read stdout line by line
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        log_feed += line
                        console_box.code(log_feed)
                
                st.success("Network Vulnerability Scan and Threat correlation completed successfully!")
                st.cache_data.clear() # clear cached data to load new scan results
            except Exception as e:
                st.error(f"Execution failed: {e}")

    st.markdown("<hr class='soc-divider'/>", unsafe_allow_html=True)

    # 2. Correlated Threat Intelligence Table
    st.markdown("### 2. Correlated Threat Intelligence Report")
    st.caption("Matches network vulnerabilities (scanned open ports) with passive web intrusion anomalies from same source IPs.")

    # Search for latest scan files
    reports_dir = os.path.join(_REPO_ROOT, "threat_reports")
    scan_files = []
    if os.path.exists(reports_dir):
        scan_files = [f for f in os.listdir(reports_dir) if f.startswith("threat_scan_analysis") and f.endswith(".csv")]
        
    if not scan_files:
        st.info("No scan reports found. Run a scan to generate a report.")
        return
        
    latest_file = sorted(scan_files)[-1]
    report_path = os.path.join(reports_dir, latest_file)
    
    st.markdown(f"**Latest Correlated Report File:** `{latest_file}`")
    
    try:
        # Load scan results
        scan_df = pd.read_csv(report_path)
        
        # Load pipeline correlation
        from Project_Files.ThreatDetectionPipeline import ThreatDetectionPipeline
        pipeline = ThreatDetectionPipeline(scan_dir=os.path.join(_REPO_ROOT, "scan_results"), output_dir=reports_dir)
        
        weblog_path = os.path.join(_REPO_ROOT, "Project_Files", "weblog.csv")
        
        if os.path.exists(weblog_path):
            correlation_df = pipeline.correlate_with_logs(scan_df, weblog_path)
            
            if correlation_df is not None and not correlation_df.empty:
                # Add action verdict columns
                def get_verdict(row):
                    if row['threat_level'] == 'HIGH' or row['severity'] == 'high':
                        return '🚫 BLOCK IP IMMEDIATELY'
                    elif row['threat_level'] == 'MEDIUM' or row['severity'] == 'medium':
                        return '⚠️ ENABLE STAGE-2 MONITORING'
                    else:
                        return '✅ SAFE CONNECTION'
                        
                correlation_df['verdict_action'] = correlation_df.apply(get_verdict, axis=1)
                
                # Show correlation dataframe beautifully
                st.dataframe(
                    correlation_df[['host', 'port', 'service', 'threat_level', 'attack_type', 'event_count', 'severity', 'verdict_action']],
                    use_container_width=True
                )
                
                # Download button
                csv_data = correlation_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download Threat Intelligence CSV",
                    data=csv_data,
                    file_name="correlated_threat_intel.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.info("No active log correlation events found for scanned hosts.")
        else:
            st.error(f"weblog.csv not found at {weblog_path}")
    except Exception as e:
        st.error(f"Failed to render correlation report: {e}")


# =======================================================================
# PAGE 6: DATA EXPLORER
# =======================================================================
def page_explorer():
    render_top_header(PALETTE)
    
    # Google Drive-Style Uploader Card
    st.markdown("### Upload new logs")
    uploaded = st.file_uploader(
        "Drag and drop your access log CSV here to analyze", 
        type=["csv"],
        key="log_uploader_widget"
    )
    if uploaded:
        st.session_state.uploaded_file = uploaded
        st.success("New log file loaded successfully!")
        
    if st.session_state.uploaded_file is not None:
        if st.button("Reset to System Logs", type="secondary"):
            st.session_state.uploaded_file = None
            st.rerun()

    df, source_path, _ = get_active_dataframe()
    section_header("Data Explorer & Export", "Review raw web server access logs.")

    if df is None:
        st.caption(f"No data available at {source_path}.")
        return

    # Render inline search & filters
    render_filters_expander(df)

    st.dataframe(safe_preview(df.tail(100).iloc[::-1]), use_container_width=True)

    with st.expander("Dataset Statistics Summary"):
        st.write(df.describe(include="all"))

    df_filter = apply_filters(df)
    st.markdown("##### Filtered Dataset Export")
    cols = df_filter.columns.tolist()
    chosen = st.multiselect("Columns to include", cols, default=cols[:6], key="export_columns")
    st.dataframe(safe_preview(df_filter[chosen].head(200)), use_container_width=True)
    csv_bytes = df_filter.to_csv(index=False).encode("utf-8")
    st.download_button("Download Filtered CSV", data=csv_bytes, file_name="filtered_weblog.csv", mime="text/csv")


# =======================================================================
# PAGE 7: PROFILE & SYSTEM SETTINGS
# =======================================================================
def page_profile():
    render_top_header(PALETTE)
    section_header("User Profile & System Settings")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### User Credentials Claims")
        st.write(f"**Email:** `{st.session_state.user_email}`")
        st.write(f"**Full Name:** `{st.session_state.user_name}`")
        st.write(f"**Access Role:** `{st.session_state.user_role}`")
        
        # Display raw JWT token details
        st.markdown("### Decoded JWT Authorization Token")
        token = st.session_state.get("jwt_token", "")
        if token:
            parts = token.split('.')
            if len(parts) == 3:
                header_raw = base64.urlsafe_b64decode(parts[0] + "==").decode('utf-8')
                payload_raw = base64.urlsafe_b64decode(parts[1] + "==").decode('utf-8')
                
                st.code(token, line_numbers=False)
                
                with st.expander("Inspect Decoded JWT Token Structure"):
                    st.markdown("**Header:**")
                    st.json(json.loads(header_raw))
                    
                    st.markdown("**Payload Claims:**")
                    st.json(json.loads(payload_raw))
                    
                    st.markdown("**Verification Signature:**")
                    st.success("Signature Validated (HMAC-SHA256)")
            else:
                st.error("Malformed JWT Token.")
        else:
            st.info("No active JWT session found.")

    with c2:
        st.markdown("### Configuration Details")
        st.write(f"**App Version:** `{APP_VERSION}`")
        st.write(f"**WebSocket Port:** `{8765}`")
        st.write(f"**Flask Port:** `{FLASK_PORT}`")
        st.write(f"**Nginx Port:** `{NGINX_PORT}`")
        st.write(f"**Nginx Log Mode:** `{'ON' if is_nginx_mode() else 'OFF'}`")
        st.write(f"**Log Path:** `{LIVE_ACCESS_LOG_PATH}`")
        st.write(f"**Training Log Path:** `{TRAINING_DATA_PATH}`")
        
        st.markdown("### SOC Parameters")
        st.write(f"**Live Refresh Rate:** `{LIVE_REFRESH_SECONDS} seconds`")
        st.write(f"**Main Refresh Rate:** `{MAIN_REFRESH_SECONDS} seconds`")


# =======================================================================
# PAGE ASSEMBLY & NAVIGATION RUNNER
# =======================================================================
if not st.session_state.authenticated:
    # If not logged in, render only the auth UI and completely hide the sidebar navigation
    login_p = st.Page(render_auth_ui, title="Sign In", icon="🔒")
    pg = st.navigation([login_p], position="hidden")
    pg.run()
else:
    # Render sidebar
    render_sidebar(PALETTE)

    # Define pages
    overview_p = st.Page(page_overview, title="SOC Dashboard", icon=":material/dashboard:")
    live_p = st.Page(page_live_monitoring, title="Live Monitoring", icon=":material/terminal:")
    analytics_p = st.Page(page_analytics, title="Threat Analytics", icon=":material/insights:")
    alerts_p = st.Page(page_alerts, title="Incidents & Alerts", icon=":material/warning:")
    scanner_p = st.Page(page_scanner, title="Network Scanner", icon=":material/shield:")
    explorer_p = st.Page(page_explorer, title="Data Explorer", icon=":material/folder_open:")
    profile_p = st.Page(page_profile, title="Profile & Settings", icon=":material/settings:")

    # Build and run navigation menu
    pg = st.navigation([overview_p, live_p, analytics_p, alerts_p, scanner_p, explorer_p, profile_p])
    pg.run()
