"""Environment verification for the NGINX Web Server Log Anomaly Detection
project.

Run this right after cloning the repo and installing requirements -- before
run_demo.bat or any manual startup -- to catch a missing dependency, a
missing model/dataset, or a busy port with one clear PASS/FAIL report,
instead of a confusing crash halfway through starting four separate
processes.

Usage:
    python verify_environment.py
"""
from __future__ import annotations

import importlib
import os
import platform
import socket
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# (requirements.txt entry, importable module name) -- differ for a few
# packages (scikit-learn -> sklearn being the classic one).
REQUIRED_PACKAGES = [
    ("streamlit", "streamlit"),
    ("pandas", "pandas"),
    ("plotly", "plotly"),
    ("kaleido", "kaleido"),
    ("websockets", "websockets"),
    ("numpy", "numpy"),
    ("matplotlib", "matplotlib"),
    ("seaborn", "seaborn"),
    ("scikit-learn", "sklearn"),
    ("scipy", "scipy"),
    ("nltk", "nltk"),
    ("joblib", "joblib"),
    ("psutil", "psutil"),
    ("flask", "flask"),
    ("requests", "requests"),
]

REQUIRED_DASHBOARD_FILES = [
    "src/app.py",
    "src/dashboard_theme.py",
    "src/dashboard_components.py",
    "src/live_analyzer.py",
    "site/app.py",
]

REQUIRED_DATASET_FILES = [
    "data/training/normal_training_logs.csv",
    "data/testing/benchmark_logs.csv",
    "data/testing/attack_test_logs.csv",
]

# Required to actually run; the demo doesn't fail overall without a free
# port, but a busy one will make run_demo.bat fail with a clear message
# pointing back here.
PORTS_TO_CHECK = [
    (5000, "Flask demo site"),
    (80, "NGINX (only needed for NGINX mode)"),
    (8765, "live_analyzer WebSocket server"),
    (8501, "Streamlit dashboard"),
]

_results = []  # (name, status: "PASS"|"FAIL"|"INFO", detail)


def record(name, ok_or_info, detail):
    _results.append((name, ok_or_info, detail))


def check_python_version():
    v = sys.version_info
    ok = v >= (3, 9)
    detail = f"Detected Python {platform.python_version()} at {sys.executable}"
    record("Python version (>= 3.9)", "PASS" if ok else "FAIL", detail)


def check_virtual_env():
    in_venv = getattr(sys, "base_prefix", sys.prefix) != sys.prefix or hasattr(sys, "real_prefix")
    expected_venv_python = os.path.join(REPO_ROOT, "venv", "Scripts", "python.exe")
    expected_exists = os.path.exists(expected_venv_python)

    if not in_venv:
        record(
            "Virtual environment",
            "INFO",
            "No virtual environment detected (using system/global Python). "
            "Not required, but recommended -- see docs/RUN_PROJECT.md.",
        )
        return

    # Confirmed by testing that this specific mismatch is not hypothetical:
    # a machine with more than one Python installation can have this script
    # (or run_demo.ps1, before it was fixed to always use venv\Scripts\python.exe
    # explicitly) resolve "python"/"streamlit" to *different* installations,
    # one of which lacked this project's dependencies -- ModuleNotFoundError
    # at dashboard startup despite "pip install -r requirements.txt" having
    # succeeded, just in a different environment than the one actually used
    # to run things.
    if expected_exists and os.path.normcase(sys.executable) != os.path.normcase(expected_venv_python):
        record(
            "Virtual environment",
            "FAIL",
            f"Active venv is {sys.prefix}, but this project's own venv is at "
            f"{os.path.dirname(os.path.dirname(expected_venv_python))} -- run "
            f"venv\\Scripts\\activate (or delete the other one) before continuing, "
            f"or packages installed in one won't be visible to processes started from the other.",
        )
    else:
        record("Virtual environment", "PASS", f"Active: {sys.prefix}")


def check_packages():
    missing = []
    for pip_name, import_name in REQUIRED_PACKAGES:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        record(
            "Required pip packages",
            "FAIL",
            f"Missing: {', '.join(missing)} -- run: pip install -r requirements.txt",
        )
    else:
        record("Required pip packages", "PASS", f"All {len(REQUIRED_PACKAGES)} packages importable")


def check_nginx():
    local_exe = os.path.join(REPO_ROOT, "nginx", "nginx.exe")
    if os.path.exists(local_exe):
        record("NGINX installed", "PASS", f"Found at {local_exe}")
        return
    import shutil

    on_path = shutil.which("nginx")
    if on_path:
        record("NGINX installed", "PASS", f"Found on PATH at {on_path}")
    else:
        record(
            "NGINX installed",
            "INFO",
            "Not found -- only required for NGINX mode. CSV mode works without it. "
            "Run: powershell -ExecutionPolicy Bypass -File scripts\\setup_nginx_windows.ps1",
        )


def check_model():
    try:
        sys.path.insert(0, REPO_ROOT)
        from core.persistence.model_store import DEFAULT_BASE_DIR

        base_dir = os.path.join(REPO_ROOT, DEFAULT_BASE_DIR) if not os.path.isabs(DEFAULT_BASE_DIR) else DEFAULT_BASE_DIR
    except Exception as e:
        record("Isolation Forest model", "FAIL", f"Could not import core.persistence.model_store: {e}")
        return

    if not os.path.isdir(base_dir):
        record("Isolation Forest model", "FAIL", f"Model directory not found: {base_dir}")
        return

    versions = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    if not versions:
        record(
            "Isolation Forest model",
            "FAIL",
            f"No trained model versions found under {base_dir} -- run scripts/train_isolation_forest.py",
        )
    else:
        record("Isolation Forest model", "PASS", f"{len(versions)} version(s) found under {base_dir}")


def check_datasets():
    missing = [p for p in REQUIRED_DATASET_FILES if not os.path.exists(os.path.join(REPO_ROOT, p))]
    if missing:
        record("Training/testing datasets", "FAIL", f"Missing: {', '.join(missing)}")
    else:
        record("Training/testing datasets", "PASS", f"All {len(REQUIRED_DATASET_FILES)} dataset files present")


def check_dashboard_files():
    missing = [p for p in REQUIRED_DASHBOARD_FILES if not os.path.exists(os.path.join(REPO_ROOT, p))]
    if missing:
        record("Dashboard/site files", "FAIL", f"Missing: {', '.join(missing)}")
    else:
        record("Dashboard/site files", "PASS", f"All {len(REQUIRED_DASHBOARD_FILES)} files present")


def check_ports():
    busy = []
    for port, purpose in PORTS_TO_CHECK:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            in_use = s.connect_ex(("127.0.0.1", port)) == 0
        if in_use:
            busy.append(f"{port} ({purpose})")
    if busy:
        record(
            "Port availability",
            "INFO",
            f"Currently in use: {', '.join(busy)} -- stop_demo.bat first, or these will fail to start.",
        )
    else:
        record("Port availability", "PASS", "5000, 80, 8765, 8501 are all free right now")


def check_configuration():
    try:
        sys.path.insert(0, REPO_ROOT)
        from core.config import FLASK_PORT, LOG_SOURCE, NGINX_PORT
        from core.paths import LIVE_ACCESS_LOG_PATH, TRAINING_DATA_PATH
    except Exception as e:
        record("Configuration (core.config / core.paths)", "FAIL", f"Import failed: {e}")
        return

    if LOG_SOURCE not in ("csv", "nginx"):
        record(
            "Configuration (core.config / core.paths)",
            "FAIL",
            f"LOG_SOURCE={LOG_SOURCE!r} is invalid -- must be 'csv' or 'nginx'",
        )
        return

    record(
        "Configuration (core.config / core.paths)",
        "PASS",
        f"LOG_SOURCE={LOG_SOURCE!r}, FLASK_PORT={FLASK_PORT}, NGINX_PORT={NGINX_PORT}, "
        f"live_log={LIVE_ACCESS_LOG_PATH!r}, training_data={TRAINING_DATA_PATH!r}",
    )


def main():
    check_python_version()
    check_virtual_env()
    check_packages()
    check_nginx()
    check_model()
    check_datasets()
    check_dashboard_files()
    check_ports()
    check_configuration()

    print("=" * 70)
    print(" Environment Verification -- NGINX Web Server Log Anomaly Detection")
    print("=" * 70)
    width = max(len(name) for name, _, _ in _results)
    any_fail = False
    for name, status, detail in _results:
        if status == "FAIL":
            any_fail = True
        print(f"[{status:4s}] {name.ljust(width)}  -- {detail}")

    print("=" * 70)
    if any_fail:
        print("RESULT: FAIL -- fix the FAIL item(s) above, then re-run this script.")
        print("See docs/RUN_PROJECT.md for setup steps and troubleshooting.")
    else:
        print("RESULT: PASS -- environment looks ready. Run run_demo.bat (or run_demo_csv.bat / run_demo_nginx.bat).")
    print("=" * 70)

    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
