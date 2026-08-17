"""
threshold.py
------------
M2 Phase 5 — Operating threshold selection for anomaly detection.

Thresholds are selected by evaluating benign validation data against a
documented false-positive-rate (FPR) target.  This avoids arbitrary cutoffs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

# Default: flag at most 1% of benign validation traffic as anomalous.
DEFAULT_TARGET_FPR = 0.01


@dataclass(frozen=True)
class ThresholdSelection:
    """Result of threshold selection on benign validation scores."""

    threshold: float
    target_fpr: float
    observed_fpr: float
    benign_validation_count: int
    flagged_benign_count: int
    selection_method: str
    documentation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "target_fpr": self.target_fpr,
            "observed_fpr": self.observed_fpr,
            "benign_validation_count": self.benign_validation_count,
            "flagged_benign_count": self.flagged_benign_count,
            "selection_method": self.selection_method,
            "documentation": self.documentation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThresholdSelection":
        return cls(
            threshold=float(data["threshold"]),
            target_fpr=float(data["target_fpr"]),
            observed_fpr=float(data["observed_fpr"]),
            benign_validation_count=int(data["benign_validation_count"]),
            flagged_benign_count=int(data["flagged_benign_count"]),
            selection_method=str(data["selection_method"]),
            documentation=str(data["documentation"]),
        )


def select_threshold_from_benign_validation(
    benign_scores: list[float] | np.ndarray,
    target_fpr: float = DEFAULT_TARGET_FPR,
) -> ThresholdSelection:
    """Select an operating threshold from benign validation anomaly scores.

    Scores are calibrated so that **higher = more deviant**.  Anomaly is
    flagged when ``score >= threshold``.

    To achieve a target FPR of ``target_fpr`` on benign data, the threshold
    is set at the ``(1 - target_fpr)`` percentile of benign validation scores.
    For example, ``target_fpr=0.01`` selects the 99th percentile.

    Args:
        benign_scores: Calibrated anomaly scores for benign validation rows only.
        target_fpr: Maximum acceptable fraction of benign rows flagged as anomalous.

    Returns:
        ThresholdSelection with the chosen threshold and observed FPR.
    """
    if not 0.0 < target_fpr < 1.0:
        raise ValueError(f"target_fpr must be in (0, 1), got {target_fpr}")

    scores = np.asarray(benign_scores, dtype=float)
    if scores.size == 0:
        raise ValueError("At least one benign validation score is required")

    percentile = 100.0 * (1.0 - target_fpr)
    threshold = float(np.percentile(scores, percentile))
    threshold = float(np.clip(threshold, 0.0, 1.0))

    flagged = int(np.sum(scores >= threshold))
    observed_fpr = flagged / scores.size

    documentation = (
        f"Threshold selected at the {percentile:.2f}th percentile of benign "
        f"validation scores to target a false-positive rate of "
        f"{target_fpr:.4f} on benign traffic. Observed benign validation FPR: "
        f"{observed_fpr:.4f} ({flagged}/{scores.size} flagged). "
        f"An anomaly indicates behavioral deviation, not malicious intent."
    )

    return ThresholdSelection(
        threshold=threshold,
        target_fpr=target_fpr,
        observed_fpr=observed_fpr,
        benign_validation_count=int(scores.size),
        flagged_benign_count=flagged,
        selection_method="benign_validation_percentile",
        documentation=documentation,
    )
