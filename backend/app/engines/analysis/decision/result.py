"""
result.py
---------
M2 Phase 7 — Analysis Decision Engine output structures and DecisionState enum.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from backend.app.contracts.analysis import (
    ActivityClass,
    AnomalyResult,
    ClassificationResult,
    FeatureVector,
)

ENGINE_VERSION = "1.0"


class DecisionState(str, Enum):
    """M2 V1 Canonical Decision States for Combined Analysis.

    States represent the overall evaluation of behavioral activity:
      - BENIGN: Normal baseline behavior.
      - ANOMALOUS: Deviates from baseline with low/uncertain classification (unknown pattern).
      - SUSPICIOUS_ACTIVITY: Non-benign activity detected with moderate confidence or risk.
      - HIGH_CONFIDENCE_ACTIVITY: Non-benign activity detected with high classification confidence and high risk.
    """

    BENIGN = "BENIGN"
    ANOMALOUS = "ANOMALOUS"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    HIGH_CONFIDENCE_ACTIVITY = "HIGH_CONFIDENCE_ACTIVITY"


class AnalysisDecisionResult(BaseModel):
    """Combined output of the M2 Phase 7 Analysis Decision Engine.

    Preserves raw outputs from both the unsupervised anomaly detector (Phase 5)
    and the supervised activity classifier (Phase 6), along with composite risk,
    confidence, and decision state.
    """

    decision_id: str = Field(
        default_factory=lambda: f"ADR-{uuid4().hex[:12].upper()}",
        description="Unique decision result identifier",
    )
    acquisition_id: str = Field(..., description="Source acquisition identifier")
    raw_feature_vector: FeatureVector = Field(..., description="Input feature vector analyzed")
    anomaly_result: AnomalyResult = Field(..., description="Raw output of anomaly detection model")
    classification_result: ClassificationResult = Field(
        ..., description="Raw output of activity classification model"
    )
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated anomaly score [0.0, 1.0]")
    classifier_probabilities: dict[str, float] = Field(
        default_factory=dict, description="Probability distribution across ActivityClass taxonomy"
    )
    predicted_activity: ActivityClass = Field(..., description="Top predicted activity class")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Overall composite confidence score [0.0, 1.0]"
    )
    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="Composite risk score [0.0, 1.0] (NOT equal to anomaly_score)"
    )
    decision_state: DecisionState = Field(..., description="Final decision state")
    model_versions: dict[str, str] = Field(
        default_factory=dict, description="Version map for anomaly, classifier, and decision models"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of decision result creation",
    )

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("anomaly_score", "confidence", "risk_score")
    @classmethod
    def _scores_finite(cls, v: float) -> float:
        import math

        if not math.isfinite(v):
            raise ValueError(f"Score fields must be finite floats, got {v}")
        return v

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
