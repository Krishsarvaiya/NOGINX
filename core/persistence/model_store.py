"""Versioned persistence for trained ML detection models.

Layout::

    models/isolation_forest/
        latest.json              {"version": "<timestamp>"}
        <version>/
            model.joblib
            scaler.joblib
            metadata.json

Models are trained OFFLINE ONLY (see scripts/train_isolation_forest.py)
and loaded read-only at live-inference startup -- nothing at inference
time ever writes here. This is the only file that touches disk for
model artifacts; IsolationForestDetector delegates all I/O to it.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

import joblib

from core.paths import _env_path

DEFAULT_BASE_DIR = _env_path(
    "MODEL_STORE_DIR", os.path.join("models", "isolation_forest")
)


class ModelStore:
    def __init__(self, base_dir: str = DEFAULT_BASE_DIR):
        self.base_dir = base_dir

    def save(self, model: Any, scaler: Any, metadata: dict) -> str:
        version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        version_dir = os.path.join(self.base_dir, version)
        os.makedirs(version_dir, exist_ok=True)

        joblib.dump(model, os.path.join(version_dir, "model.joblib"))
        joblib.dump(scaler, os.path.join(version_dir, "scaler.joblib"))
        with open(os.path.join(version_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        with open(os.path.join(self.base_dir, "latest.json"), "w") as f:
            json.dump({"version": version}, f)

        return version

    def load_latest(self) -> Optional[tuple[Any, Any, dict]]:
        pointer_path = os.path.join(self.base_dir, "latest.json")
        if not os.path.exists(pointer_path):
            return None
        with open(pointer_path) as f:
            version = json.load(f).get("version")
        if not version:
            return None
        return self.load_version(version)

    def load_version(self, version: str) -> Optional[tuple[Any, Any, dict]]:
        version_dir = os.path.join(self.base_dir, version)
        model_path = os.path.join(version_dir, "model.joblib")
        scaler_path = os.path.join(version_dir, "scaler.joblib")
        metadata_path = os.path.join(version_dir, "metadata.json")
        if not (os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(metadata_path)):
            return None

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        with open(metadata_path) as f:
            metadata = json.load(f)
        metadata["version"] = version
        return model, scaler, metadata
