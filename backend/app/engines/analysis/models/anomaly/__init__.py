"""
M2 Phase 5 — Unsupervised anomaly detection models.

Detects behavioral deviation from a benign baseline without using attack labels
during training or inference.
"""

from backend.app.engines.analysis.models.anomaly.model_artifact import AnomalyModelArtifact
from backend.app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from backend.app.engines.analysis.models.anomaly.trainer import (
    AnomalyEvaluationReport,
    train_anomaly_model,
)

__all__ = [
    "AnomalyEvaluationReport",
    "AnomalyModelArtifact",
    "AnomalyPredictor",
    "train_anomaly_model",
]
