"""Reusable, stateless SOC dashboard components.

Every function here takes plain data (numbers, dicts, dataframes) and
renders Streamlit/HTML -- none of them read a file, call core.*, or
touch st.session_state. That keeps them safe to reuse across sections
and easy to reason about (Problem: "split large UI blocks into reusable
functions", "avoid duplicate layout code").
"""
from __future__ import annotations

from html import escape

import pandas as pd
import streamlit as st

from dashboard_theme import SEVERITY_COLOR_KEY, SEVERITY_ICON


def status_dot(is_up: bool, warn: bool = False) -> str:
    color = "#FF9500" if warn else ("#34C759" if is_up else "#FF3B30")
    return f'<span class="soc-status-dot" style="background:{color};"></span>'


def severity_badge_html(severity: str, palette: dict) -> str:
    key = SEVERITY_COLOR_KEY.get(severity, "graphite")
    color = palette[key]
    icon = SEVERITY_ICON.get(severity, "⚪")
    return (
        f'<span class="soc-badge" style="background:{color}22; color:{color};">'
        f"{icon} {escape(str(severity))}</span>"
    )


def metric_card(label: str, value, palette: dict, accent: str = "graphite", caption: str = "") -> str:
    color = palette.get(accent, palette["graphite"])
    cap = f'<div class="soc-muted" style="font-size:0.72rem; margin-top:2px;">{escape(caption)}</div>' if caption else ""
    return f"""
<div class="soc-card soc-animate" style="border-top: 3px solid {color};">
    <div class="soc-muted" style="font-size:0.78rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em;">{escape(str(label))}</div>
    <div style="font-size:1.9rem; font-weight:800; margin-top:2px; color:{palette['text']};">{value}</div>
    {cap}
</div>
"""


def severity_status_card(severity: str, count: int, palette: dict) -> str:
    key = SEVERITY_COLOR_KEY.get(severity, "graphite")
    color = palette[key]
    icon = SEVERITY_ICON.get(severity, "⚪")
    return f"""
<div class="soc-card soc-animate" style="text-align:center; border-top: 3px solid {color};">
    <div style="font-size:1.6rem;">{icon}</div>
    <div style="font-size:1.7rem; font-weight:800; color:{palette['text']};">{count}</div>
    <div class="soc-muted" style="font-size:0.75rem; font-weight:700; letter-spacing:0.05em;">{escape(severity)}</div>
</div>
"""


def alert_card(alert: dict, palette: dict) -> str:
    severity = alert.get("severity", "NORMAL")
    key = SEVERITY_COLOR_KEY.get(severity, "graphite")
    color = palette[key]
    return f"""
<div class="soc-card soc-animate" style="border-left: 4px solid {color}; margin-bottom: 0.7rem;">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
        <div>{severity_badge_html(severity, palette)}
            <span style="margin-left:0.6rem; font-weight:700;">{escape(str(alert.get("threat_type", "Unknown")))}</span>
        </div>
        <span class="soc-muted" style="font-size:0.78rem;">{escape(str(alert.get("timestamp", "")))}</span>
    </div>
    <div class="soc-muted" style="margin-top:0.45rem; font-size:0.85rem;">
        <b>IP:</b> {escape(str(alert.get("source_ip", "")))}
        &nbsp;·&nbsp; <b>Decision:</b> {escape(str(alert.get("decision_source", "")))}
    </div>
    <div class="soc-muted" style="margin-top:0.35rem; font-size:0.78rem; line-height:1.4;">{escape(str(alert.get("explanation", "")))}</div>
</div>
"""


def timeline_item(alert: dict, palette: dict) -> str:
    severity = alert.get("severity", "NORMAL")
    color = palette[SEVERITY_COLOR_KEY.get(severity, "graphite")]
    return f"""
<div class="soc-animate" style="display:flex; gap:0.9rem; margin-bottom:1rem;">
    <div style="display:flex; flex-direction:column; align-items:center;">
        <div style="width:11px; height:11px; border-radius:999px; background:{color}; box-shadow:0 0 0 4px {color}22;"></div>
        <div style="flex:1; width:2px; background:{palette['border']}; margin-top:4px;"></div>
    </div>
    <div style="padding-bottom:0.4rem;">
        <div style="font-weight:700; font-size:0.88rem;">{escape(str(alert.get("threat_type", "Unknown")))}
            <span class="soc-muted" style="font-weight:400;"> — {escape(str(alert.get("source_ip", "")))}</span>
        </div>
        <div class="soc-muted" style="font-size:0.76rem;">{escape(str(alert.get("timestamp", "")))} · {severity_badge_html(severity, palette)}</div>
    </div>
</div>
"""


def html_table(df: pd.DataFrame) -> str:
    """Renders a small dataframe as a styled HTML table (soc-table CSS
    class) -- used where alternating rows / hover need real per-row
    styling that st.dataframe's grid widget can't reliably take from
    injected CSS."""
    header = "".join(f"<th>{escape(str(c))}</th>" for c in df.columns)
    body_rows = []
    for _, row in df.iterrows():
        cells = "".join(f"<td>{escape(str(v))}</td>" for v in row)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"""
<div class="soc-table-wrap">
<table class="soc-table">
<thead><tr>{header}</tr></thead>
<tbody>{''.join(body_rows)}</tbody>
</table>
</div>
"""


def section_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"### {title}")
    if subtitle:
        st.caption(subtitle)


def system_status_card(name: str, is_up: bool, palette: dict, warn: bool = False, note: str = "") -> str:
    color = palette["orange"] if warn else (palette["green"] if is_up else palette["red"])
    label = "DEGRADED" if warn else ("ONLINE" if is_up else "OFFLINE")
    return f"""
<div class="soc-card soc-animate" style="text-align:center;">
    <div style="font-weight:700; font-size:0.85rem;">{escape(name)}</div>
    <div style="margin-top:0.4rem;">
        <span class="soc-badge" style="background:{color}22; color:{color};">{label}</span>
    </div>
    {f'<div class="soc-muted" style="font-size:0.7rem; margin-top:0.4rem;">{escape(note)}</div>' if note else ''}
</div>
"""
