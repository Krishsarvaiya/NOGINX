"""Centralized, environment-overridable dataset path constants.

Splits three roles that used to share one file (Project_Files/weblog.csv):

  TRAINING_DATA_PATH     the historical corpus scripts/train_isolation_forest.py
                         trains on, and THREAT_DETECTION_PIPELINE.py / the
                         dashboard read for their offline/default view.
                         Never written to by live traffic.
  TESTING_BENCHMARK_PATH held-out data for offline evaluation scripts
                         (scripts/phase6_*.py, scripts/phase7_*.py).
                         Never used for training.
  TESTING_ATTACK_PATH    reserved slot for attack-only evaluation data.
  LIVE_ACCESS_LOG_PATH   the demo college website's real-time access log
                         (site/app.py writes it, src/live_analyzer.py can
                         tail it). Never used for training or evaluation
                         by default.
  ARCHIVE_DIR            scratch/output location for ad-hoc or synthetic
                         data (e.g. Project_Files/log_generator.py) that
                         must never land in a training or evaluation path
                         by default.

Every constant can be overridden via an environment variable without
touching code. Relative defaults resolve against REPO_ROOT (the v2/
directory containing core/), so scripts work regardless of the process
current working directory.
"""
import os

# core/ lives at <repo>/core/ -- parent-of-parent is the repository root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_path(path: str) -> str:
    """Resolve a relative path against REPO_ROOT; leave absolute paths unchanged."""
    if os.path.isabs(path):
        return path
    return os.path.join(REPO_ROOT, path)


def _env_path(name: str, default_relative: str) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return resolve_path(default_relative)
    return resolve_path(raw)


TRAINING_DATA_PATH = _env_path(
    "TRAINING_DATA_PATH", os.path.join("data", "training", "normal_training_logs.csv")
)
TESTING_BENCHMARK_PATH = _env_path(
    "TESTING_BENCHMARK_PATH", os.path.join("data", "testing", "benchmark_logs.csv")
)
TESTING_ATTACK_PATH = _env_path(
    "TESTING_ATTACK_PATH", os.path.join("data", "testing", "attack_test_logs.csv")
)
LIVE_ACCESS_LOG_PATH = _env_path(
    "LIVE_ACCESS_LOG_PATH", os.path.join("data", "live", "college_site_access.csv")
)
ARCHIVE_DIR = _env_path("ARCHIVE_DIR", os.path.join("data", "archive"))
