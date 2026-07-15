"""Visual theme for the SOC dashboard: color palettes, severity colors,
and the injected CSS block. Pure presentation -- no detection logic, no
data loading, nothing here reads a CSV or talks to core/.

Split out of src/app.py so the (large) CSS string and color constants
don't clutter the page logic, and so every widget pulls colors from one
place instead of hardcoding hex values in several files.
"""

FONT_STACK = (
    '-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", '
    '"Inter", "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
)

LIGHT = {
    "bg": "#F5F5F7",
    "surface": "rgba(255, 255, 255, 0.72)",
    "surface_solid": "#FFFFFF",
    "surface_alt": "#FBFBFD",
    "text": "#1D1D1F",
    "text_secondary": "#6E6E73",
    "border": "rgba(0, 0, 0, 0.08)",
    "shadow": "0 4px 24px rgba(0, 0, 0, 0.06)",
    "blue": "#0071E3",
    "green": "#34C759",
    "orange": "#FF9500",
    "red": "#FF3B30",
    "yellow": "#FFCC00",
    "purple": "#AF52DE",
    "graphite": "#48484A",
}

DARK = {
    "bg": "#06080b",
    "surface": "rgba(13, 17, 23, 0.72)",
    "surface_solid": "#0d1117",
    "surface_alt": "#161b22",
    "text": "#c9d1d9",
    "text_secondary": "#8b949e",
    "border": "rgba(0, 240, 255, 0.18)",
    "shadow": "0 0 15px rgba(0, 240, 255, 0.08)",
    "blue": "#00f0ff",
    "green": "#00ff66",
    "orange": "#ffaa00",
    "red": "#ff3366",
    "yellow": "#ffea00",
    "purple": "#d300ff",
    "graphite": "#8b949e",
}

# Severity -> palette key, one place so every card/badge/chart agrees.
SEVERITY_COLOR_KEY = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "NORMAL": "green",
}
SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "NORMAL": "🟢",
}

# Plotly categorical sequence, reused by every chart (Problem: "avoid
# duplicate CSS" extends to avoid duplicate chart styling too).
def chart_color_sequence(palette: dict) -> list:
    return [palette["blue"], palette["green"], palette["orange"], palette["red"], palette["graphite"]]


def inject_css(palette: dict) -> str:
    """Returns a <style> block styling Streamlit's default chrome away
    and adding the card/badge/table primitives every component helper
    in dashboard_components.py relies on. Regenerated on every rerun
    from the *current* palette (light or dark) -- there is no separate
    dark-mode stylesheet to keep in sync, just one template + one dict.
    """
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {{
    font-family: {FONT_STACK};
}}

/* Hide Streamlit's default chrome but keep header space for the sidebar toggle */
button[data-testid="stHeaderActionButton"] {{ display: none; }}
#MainMenu {{ visibility: hidden; }}
footer {{ visibility: hidden; }}
header {{ background: transparent !important; }}
div[data-testid="stDecoration"] {{ display: none; }}

.stApp {{
    background: {palette["bg"]};
    color: {palette["text"]};
}}

section[data-testid="stSidebar"] {{
    background: {palette["surface_alt"]};
    border-right: 1px solid {palette["border"]};
}}
/* Pin brand block to the top of the sidebar */
.sidebar-brand-block {{
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 90px;
    background: {palette["surface_alt"]};
    z-index: 99;
    padding-top: 12px;
    border-bottom: 1px solid {palette["border"]};
}}
[data-testid="stSidebarNav"] {{
    margin-top: 85px !important;
}}
[data-testid="stSidebarUserContent"] {{
    padding-top: 0 !important;
}}

/* Generous, calm spacing instead of Streamlit's cramped default */
.block-container {{
    padding-top: 1.25rem;
    padding-bottom: 3rem;
    max-width: 1280px;
}}

* {{
    scroll-behavior: smooth;
}}

h1, h2, h3 {{
    font-weight: 700;
    letter-spacing: -0.02em;
    color: {palette["text"]};
}}

hr {{
    border: none;
    border-top: 1px solid {palette["border"]};
    margin: 1.75rem 0;
}}

/* ---- Core card primitive, reused by every *_card() helper ---- */
.soc-card {{
    background: {palette["surface_solid"]};
    border: 1px solid {palette["border"]};
    border-radius: 16px;
    padding: 1.1rem 1.3rem;
    box-shadow: {palette["shadow"]};
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
}}
.soc-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 0 22px rgba(0, 240, 255, 0.22);
    border-color: {palette["blue"]};
}}

.soc-glass {{
    background: {palette["surface"]};
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 1px solid {palette["border"]};
    border-radius: 18px;
}}

@keyframes soc-fade-in {{
    from {{ opacity: 0; transform: translateY(6px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}
.soc-animate {{
    animation: soc-fade-in 0.35s ease both;
}}

.soc-badge {{
    display: inline-block;
    padding: 0.2rem 0.65rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}}

.soc-divider {{
    height: 1px;
    background: {palette["border"]};
    margin: 1.5rem 0;
    border: none;
}}

.soc-muted {{ color: {palette["text_secondary"]}; }}

/* Custom HTML table (Live Log Monitor) -- st.dataframe can't reliably
   take per-row hover/stripe styling via CSS injection, so this one
   section renders as plain HTML instead. */
.soc-table-wrap {{
    background: {palette["surface_solid"]};
    border: 1px solid {palette["border"]};
    border-radius: 16px;
    overflow: hidden;
    box-shadow: {palette["shadow"]};
}}
table.soc-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    font-family: 'Fira Code', 'Ubuntu Mono', 'Courier New', Courier, monospace;
}}
table.soc-table th {{
    text-align: left;
    padding: 0.6rem 1rem;
    background: {palette["surface_alt"]};
    color: {palette["text_secondary"]};
    font-weight: 600;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-bottom: 1px solid {palette["border"]};
}}
table.soc-table td {{
    padding: 0.55rem 1rem;
    border-bottom: 1px solid {palette["border"]};
    color: {palette["text"]};
}}
table.soc-table tr:nth-child(even) td {{
    background: {palette["surface_alt"]};
}}
table.soc-table tr:hover td {{
    background: {palette["blue"]}18;
    transition: background 0.15s ease;
}}
table.soc-table tr:last-child td {{ border-bottom: none; }}

/* Buttons */
.stButton > button, .stDownloadButton > button {{
    border-radius: 12px;
    border: 1px solid {palette["border"]};
    font-weight: 600;
    transition: transform 0.12s ease, box-shadow 0.12s ease;
}}
.stButton > button:hover, .stDownloadButton > button:hover {{
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.10);
}}

/* Inputs */
.stTextInput input, .stTextArea textarea {{
    border-radius: 10px !important;
}}

/* Top header bar */
.soc-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.9rem 1.5rem;
    border-radius: 18px;
    margin-bottom: 1.5rem;
}}
.soc-header .soc-brand {{
    font-size: 1.15rem;
    font-weight: 800;
    letter-spacing: -0.01em;
}}
.soc-header .soc-mode-pill {{
    font-weight: 700;
    font-size: 0.8rem;
    letter-spacing: 0.04em;
}}
.soc-header .soc-right {{
    text-align: right;
    font-size: 0.78rem;
    line-height: 1.35;
    color: {palette["text_secondary"]};
}}
.soc-status-dot {{
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 999px;
    margin-right: 6px;
}}
</style>
"""


def inject_auth_css(palette: dict) -> str:
    """Auth-page-only styling layered on top of inject_css()'s base
    primitives: a fixed dark gradient background with soft color glows,
    a floating glassmorphic card, pill-style tab buttons, and larger
    rounded inputs with animated focus states.

    Always built from the DARK palette regardless of the dashboard's
    own light/dark toggle -- the sign-in experience has a fixed,
    deliberately premium dark look per the design brief, independent of
    whatever a signed-in user later picks for the dashboard itself.

    Targets .st-key-auth_card / .st-key-auth_tabs, the CSS classes
    Streamlit generates for `st.container(key="auth_card")` /
    `st.container(key="auth_tabs")` -- using real containers (rather
    than markdown-opened/closed <div> tags, which don't actually nest
    Streamlit's native widgets in the DOM) so this styling reliably
    wraps the real inputs and buttons instead of sitting beside them.
    """
    return f"""
<style>
.stApp {{
    background:
        radial-gradient(circle at 10% 92%, {palette["blue"]}4D 0%, transparent 42%),
        radial-gradient(circle at 88% 80%, {palette["purple"]}40 0%, transparent 40%),
        radial-gradient(circle at 66% 96%, {palette["orange"]}33 0%, transparent 35%),
        radial-gradient(circle at 96% 55%, {palette["green"]}26 0%, transparent 35%),
        #000000 !important;
    background-attachment: fixed !important;
}}

.st-key-auth_card {{
    max-width: 460px;
    margin: 4vh auto 0 auto;
    padding: 2.4rem 2.6rem 1.6rem;
    background: rgba(28, 28, 30, 0.6);
    backdrop-filter: blur(32px) saturate(180%);
    -webkit-backdrop-filter: blur(32px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 28px;
    box-shadow: 0 25px 70px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.06);
    animation: auth-card-in 0.55s cubic-bezier(0.16, 1, 0.3, 1) both;
}}
@keyframes auth-card-in {{
    from {{ opacity: 0; transform: translateY(28px) scale(0.97); }}
    to {{ opacity: 1; transform: translateY(0) scale(1); }}
}}
@keyframes auth-fade-slide {{
    from {{ opacity: 0; transform: translateY(10px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}
.st-key-auth_card * {{
    animation: auth-fade-slide 0.4s ease both;
}}

.auth-brand {{ text-align: center; margin-bottom: 1.5rem; }}
.auth-brand .auth-logo {{ font-size: 2.6rem; line-height: 1; }}
.auth-brand .auth-title {{
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
    color: #F5F5F7;
    margin-top: 0.5rem;
}}
.auth-brand .auth-subtitle {{
    font-size: 0.82rem;
    font-weight: 300;
    color: #9B9BA1;
    margin-top: 0.3rem;
}}
.auth-brand .auth-view-label {{
    font-size: 0.78rem;
    color: #6E6E73;
    margin-top: 0.9rem;
}}

.st-key-auth_tabs {{
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 999px;
    padding: 0.28rem;
    margin-bottom: 1.6rem;
}}
.st-key-auth_tabs .stButton > button {{
    border-radius: 999px !important;
    border: none !important;
    font-weight: 600;
    font-size: 0.88rem;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}}
.st-key-auth_tabs .stButton > button[kind="primary"] {{
    background: #FFFFFF !important;
    color: #000000 !important;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.25);
}}
.st-key-auth_tabs .stButton > button[kind="secondary"] {{
    background: transparent !important;
    color: #9B9BA1 !important;
    box-shadow: none !important;
}}
.st-key-auth_tabs .stButton > button[kind="secondary"]:hover {{
    color: #F5F5F7 !important;
    transform: none;
}}

.st-key-auth_card .stTextInput input {{
    background: rgba(255, 255, 255, 0.06) !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: 14px !important;
    color: #F5F5F7 !important;
    padding: 0.8rem 1rem !important;
    font-size: 0.92rem !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
}}
.st-key-auth_card .stTextInput input:focus {{
    border-color: {palette["blue"]} !important;
    box-shadow: 0 0 0 3px {palette["blue"]}33 !important;
    background: rgba(255, 255, 255, 0.09) !important;
}}
.st-key-auth_card .stTextInput input::placeholder {{ color: #6E6E73 !important; }}
.st-key-auth_card label {{
    color: #9B9BA1 !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
}}
.st-key-auth_card .stCheckbox label p {{
    color: #C7C7CC !important;
    font-size: 0.85rem !important;
}}

/* Primary CTA: Sign In / Create Account / Send Reset Link */
.st-key-auth_card .stForm button,
.st-key-auth_card div[data-testid="stFormSubmitButton"] button {{
    background: linear-gradient(180deg, #FFFFFF, #E5E5EA) !important;
    color: #000000 !important;
    border: none !important;
    border-radius: 14px !important;
    padding: 0.85rem 1rem !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    letter-spacing: -0.01em;
    box-shadow: 0 8px 24px rgba(255, 255, 255, 0.08);
    transition: transform 0.18s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.18s ease;
}}
.st-key-auth_card .stForm button:hover,
.st-key-auth_card div[data-testid="stFormSubmitButton"] button:hover {{
    transform: translateY(-2px) scale(1.01);
    box-shadow: 0 12px 32px rgba(255, 255, 255, 0.14);
}}
/* Style the forgot password submit button to look like a subtle, muted text link */
.st-key-forgot_password_btn button {{
    background: transparent !important;
    border: none !important;
    color: #8b949e !important;
    font-size: 0.8rem !important;
    text-decoration: underline !important;
    box-shadow: none !important;
    padding: 0.5rem 0.4rem !important;
    transform: none !important;
}}
.st-key-forgot_password_btn button:hover {{
    color: #00f0ff !important;
    background: transparent !important;
}}

/* Custom styling for password eye visibility button to avoid bright solid white shapes */
button[data-testid="stTextInputAdornmentVisibility"] {{
    background: rgba(255, 255, 255, 0.08) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 999px !important;
    color: #c9d1d9 !important;
    box-shadow: none !important;
}}
button[data-testid="stTextInputAdornmentVisibility"] svg {{
    fill: #c9d1d9 !important;
}}
button[data-testid="stTextInputAdornmentVisibility"]:hover {{
    background: rgba(255, 255, 255, 0.15) !important;
    color: #00f0ff !important;
}}

/* Secondary text links outside the form (create account / back to sign in) */
.st-key-auth_card .stButton > button {{
    background: transparent !important;
    border: none !important;
    color: #9B9BA1 !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    padding: 0.3rem 0.4rem !important;
    box-shadow: none !important;
}}
.st-key-auth_card .stButton > button:hover {{
    color: #F5F5F7 !important;
    transform: none !important;
    box-shadow: none !important;
}}

.auth-footer-note {{
    max-width: 460px;
    margin: 1rem auto 0 auto;
    text-align: center;
    color: #6E6E73;
    font-size: 0.72rem;
    line-height: 1.5;
}}
</style>
"""
