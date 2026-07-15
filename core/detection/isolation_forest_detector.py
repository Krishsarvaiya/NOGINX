"""Isolation Forest anomaly detector over session feature vectors.

Lifecycle: trained OFFLINE ONLY, via scripts/train_isolation_forest.py.
Live inference (StreamingPipeline) only ever calls load_latest() --
nothing in the live path fits a model. This keeps inference latency
predictable and means a bad training run can never happen inline while
traffic is being processed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.features.feature_extractor import FEATURE_NAMES, features_to_vector
from core.persistence.model_store import ModelStore


class IsolationForestDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self.scaler = StandardScaler()
        self.feature_names: Optional[list] = None
        self.score_min: Optional[float] = None
        self.score_max: Optional[float] = None
        self.trained_at: Optional[str] = None
        self.n_sessions_trained: Optional[int] = None
        self.version: Optional[str] = None

    def fit(self, feature_rows: list) -> None:
        """Fit on a list of session feature dicts (offline only).

        Validates every row against the canonical FEATURE_NAMES schema
        (via features_to_vector) before fitting -- a malformed row fails
        training loudly rather than silently skewing the model.
        """
        if len(feature_rows) < 10:
            raise ValueError(
                f"need at least 10 sessions to fit an Isolation Forest, got {len(feature_rows)}"
            )

        X = [features_to_vector(row) for row in feature_rows]
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        self.feature_names = list(FEATURE_NAMES)
        self.n_sessions_trained = len(feature_rows)
        self.trained_at = datetime.now(timezone.utc).isoformat()

        # sklearn's decision_function is positive for inliers, negative
        # for outliers -- flip sign so higher always means "more
        # anomalous", consistent with the rule engine's convention.
        raw_scores = -self.model.decision_function(X_scaled)
        self.score_min = float(raw_scores.min())
        self.score_max = float(raw_scores.max())

    def score(self, features: dict) -> tuple:
        """Return (ml_anomaly_score in 0-100, is_anomaly) for one session.

        Validates `features` against FEATURE_NAMES before scoring.
        """
        if self.feature_names is None:
            raise RuntimeError("IsolationForestDetector has no fitted/loaded model")

        vector = features_to_vector(features)
        X_scaled = self.scaler.transform([vector])
        raw = float(-self.model.decision_function(X_scaled)[0])

        denom = (self.score_max - self.score_min) or 1e-9
        normalized = 100.0 * (raw - self.score_min) / denom
        normalized = max(0.0, min(100.0, normalized))

        # sklearn's IsolationForest.predict() is defined as
        # `-1 if decision_function(X) < 0 else 1`, i.e. exactly
        # `raw > 0` here (raw = -decision_function). Deriving it from
        # the score we already computed avoids a second full forest
        # traversal -- calling .predict() separately measured ~2x the
        # latency of a single decision_function() call for no benefit.
        is_anomaly = raw > 0
        return normalized, is_anomaly

    def save(self, store: Optional[ModelStore] = None) -> str:
        store = store or ModelStore()
        metadata = {
            "feature_names": self.feature_names,
            "contamination": self.model.contamination,
            "score_min": self.score_min,
            "score_max": self.score_max,
            "trained_at": self.trained_at,
            "n_sessions_trained": self.n_sessions_trained,
        }
        self.version = store.save(self.model, self.scaler, metadata)
        return self.version

    @classmethod
    def load_latest(cls, store: Optional[ModelStore] = None) -> Optional["IsolationForestDetector"]:
        """Load the most recently trained model, or None if none exists
        or its feature schema no longer matches FEATURE_NAMES. Callers
        must treat None as "run rules-only" -- never as an error.
        """
        store = store or ModelStore()
        loaded = store.load_latest()
        if loaded is None:
            print("[IsolationForestDetector] no trained model found -- fusion will run rules-only")
            return None

        model, scaler, metadata = loaded
        if metadata.get("feature_names") != list(FEATURE_NAMES):
            print(
                "[IsolationForestDetector] stored model's feature schema does not match "
                "the current FEATURE_NAMES -- refusing to load; fusion will run rules-only"
            )
            return None

        detector = cls()
        detector.model = model
        detector.scaler = scaler
        detector.feature_names = metadata["feature_names"]
        detector.score_min = metadata["score_min"]
        detector.score_max = metadata["score_max"]
        detector.trained_at = metadata.get("trained_at")
        detector.n_sessions_trained = metadata.get("n_sessions_trained")
        detector.version = metadata.get("version")
        return detector
