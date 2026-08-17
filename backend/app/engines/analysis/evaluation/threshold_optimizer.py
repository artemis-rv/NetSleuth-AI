"""
threshold_optimizer.py
---------------------
M2 Phase 9 — Threshold Optimization Engine.

Optimizes operating thresholds on Thursday validation data (WITHOUT using unseen Friday test data)
to target a documented false-positive rate (FPR) on benign traffic.
"""

from __future__ import annotations

import logging
from typing import Any
import numpy as np
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_TARGET_FPR = 0.01
DEFAULT_CONFIDENCE_THRESHOLD = 0.60
DEFAULT_RISK_THRESHOLD = 0.50


class ThresholdConfig(BaseModel):
    """Configuration bundling all tuned operating thresholds for M2."""

    anomaly_threshold: float = Field(..., ge=0.0, le=1.0)
    confidence_threshold: float = Field(..., ge=0.0, le=1.0)
    risk_threshold: float = Field(..., ge=0.0, le=1.0)
    target_benign_fpr: float = Field(..., ge=0.0, le=1.0)
    observed_benign_fpr: float = Field(..., ge=0.0, le=1.0)
    selected_on_split: str = Field(default="Thursday validation")
    documentation: str = Field(...)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThresholdConfig":
        return cls.model_validate(data)


class ThresholdOptimizer:
    """Production optimizer for M2 operating thresholds."""

    def __init__(self, target_fpr: float = DEFAULT_TARGET_FPR) -> None:
        self.target_fpr = target_fpr

    def optimize_thresholds(
        self,
        benign_validation_scores: list[float] | np.ndarray,
        target_fpr: Optional[float] = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        risk_threshold: float = DEFAULT_RISK_THRESHOLD,
        validation_split_name: str = "Thursday validation",
    ) -> ThresholdConfig:
        """Optimize operating anomaly, confidence, and risk thresholds on benign validation traffic.

        Args:
            benign_validation_scores: Calibrated anomaly scores for benign validation traffic only.
            target_fpr: Maximum acceptable false-positive rate on benign validation traffic.
            confidence_threshold: Minimum confidence threshold for high-confidence decisions.
            risk_threshold: Threshold for risk escalation.
            validation_split_name: Name of the validation split (e.g., 'Thursday validation').

        Returns:
            ThresholdConfig object.
        """
        fpr_target = target_fpr if target_fpr is not None else self.target_fpr
        scores = np.asarray(benign_validation_scores, dtype=float)

        if scores.size == 0:
            logger.warning("Empty benign validation scores provided; using fallback default anomaly threshold 0.50")
            anomaly_threshold = 0.50
            observed_fpr = 0.0
        else:
            percentile = 100.0 * (1.0 - fpr_target)
            anomaly_threshold = float(np.percentile(scores, percentile))
            anomaly_threshold = float(np.clip(anomaly_threshold, 0.0, 1.0))
            flagged = int(np.sum(scores >= anomaly_threshold))
            observed_fpr = float(flagged / scores.size)

        doc = (
            f"Anomaly threshold ({anomaly_threshold:.4f}) selected at {100.0 * (1.0 - fpr_target):.2f}th "
            f"percentile of {validation_split_name} benign scores to target FPR={fpr_target:.4f}. "
            f"Observed benign validation FPR={observed_fpr:.4f}. Confidence threshold={confidence_threshold:.2f}, "
            f"risk threshold={risk_threshold:.2f}."
        )

        return ThresholdConfig(
            anomaly_threshold=round(anomaly_threshold, 6),
            confidence_threshold=round(confidence_threshold, 6),
            risk_threshold=round(risk_threshold, 6),
            target_benign_fpr=round(fpr_target, 6),
            observed_benign_fpr=round(observed_fpr, 6),
            selected_on_split=validation_split_name,
            documentation=doc,
        )
