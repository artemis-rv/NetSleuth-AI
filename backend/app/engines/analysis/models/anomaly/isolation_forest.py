"""
isolation_forest.py
-------------------
M2 Phase 5 — Isolation Forest wrapper for unsupervised anomaly detection.

Wraps scikit-learn IsolationForest with deterministic training, score
calibration against a benign reference distribution, and serialization.
"""

from __future__ import annotations

import base64
import io
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

DEFAULT_HYPERPARAMETERS: dict[str, Any] = {
    "n_estimators": 100,
    "max_samples": "auto",
    "contamination": "auto",
    "bootstrap": False,
    "n_jobs": -1,
}

MODEL_TYPE = "isolation_forest"
MODEL_VERSION = "1.0"


class IsolationForestAnomalyModel:
    """Production Isolation Forest baseline for behavioral deviation detection.

    Raw sklearn ``score_samples`` returns higher values for inliers and lower
    values for outliers.  This wrapper calibrates raw scores against a benign
    reference distribution so that outputs are in [0.0, 1.0] with higher
    values indicating greater deviation from baseline behaviour.

    An anomaly score reflects behavioral deviation — it is NOT equivalent to
    malicious intent.
    """

    def __init__(
        self,
        hyperparameters: Optional[dict[str, Any]] = None,
        random_state: int = 42,
    ) -> None:
        self.hyperparameters = {**DEFAULT_HYPERPARAMETERS, **(hyperparameters or {})}
        self.random_state = random_state
        self._model: Optional[IsolationForest] = None
        self.feature_names: list[str] = []
        self._benign_raw_scores: list[float] = []

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def fit(self, X: np.ndarray, feature_names: list[str]) -> "IsolationForestAnomalyModel":
        """Fit the Isolation Forest on benign-only transformed feature matrices."""
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("Training matrix must be 2-D with at least one row")

        params = {**self.hyperparameters, "random_state": self.random_state}
        self._model = IsolationForest(**params)
        self._model.fit(X)
        self.feature_names = list(feature_names)
        self._benign_raw_scores = self._model.score_samples(X).tolist()
        return self

    def raw_score_samples(self, X: np.ndarray) -> np.ndarray:
        """Return raw sklearn score_samples (higher = more inlier-like)."""
        if not self.is_fitted:
            raise RuntimeError("IsolationForestAnomalyModel must be fitted before scoring")
        return self._model.score_samples(X)

    def calibrated_scores(self, X: np.ndarray) -> np.ndarray:
        """Map raw scores to [0.0, 1.0] using the benign reference distribution."""
        raw = self.raw_score_samples(X)
        ref = np.asarray(self._benign_raw_scores, dtype=float)
        if ref.size == 0:
            return np.zeros(len(raw), dtype=float)

        calibrated = np.empty(len(raw), dtype=float)
        for i, score in enumerate(raw):
            # Fraction of benign reference scores >= this sample's raw score.
            # Lower raw scores (more abnormal) → fewer benign >= → lower fraction → higher anomaly.
            inlier_fraction = float(np.mean(ref >= score))
            calibrated[i] = np.clip(1.0 - inlier_fraction, 0.0, 1.0)
        return calibrated

    def to_dict(self) -> dict[str, Any]:
        """Serialize model state to a plain dict (embedded joblib blob)."""
        if not self.is_fitted:
            raise RuntimeError("Cannot serialize an unfitted model")

        buffer = io.BytesIO()
        joblib.dump(self._model, buffer)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")

        return {
            "model_type": MODEL_TYPE,
            "model_version": MODEL_VERSION,
            "hyperparameters": self.hyperparameters,
            "random_state": self.random_state,
            "feature_names": self.feature_names,
            "benign_raw_scores": self._benign_raw_scores,
            "model_blob": encoded,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IsolationForestAnomalyModel":
        """Restore a model from a serialized dict."""
        inst = cls(
            hyperparameters=data.get("hyperparameters"),
            random_state=data.get("random_state", 42),
        )
        blob = base64.b64decode(data["model_blob"])
        inst._model = joblib.load(io.BytesIO(blob))
        inst.feature_names = list(data.get("feature_names", []))
        inst._benign_raw_scores = list(data.get("benign_raw_scores", []))
        return inst
