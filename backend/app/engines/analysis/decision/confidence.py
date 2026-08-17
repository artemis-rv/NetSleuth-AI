"""
confidence.py
-------------
M2 Phase 7 — Unified Confidence Calculation logic.

Calculates composite decision confidence combining top-1 probability, prediction margin,
and model alignment.
"""

from __future__ import annotations

import math
from typing import Optional

from backend.app.contracts.analysis import AnomalyResult, ClassificationResult


def calculate_confidence(
    classification_result: ClassificationResult,
    anomaly_result: Optional[AnomalyResult] = None,
) -> float:
    """Calculate composite confidence score in [0.0, 1.0].

    Combines:
      - Top-1 class probability
      - Classification margin (top1_prob - top2_prob)

    Args:
        classification_result: Raw classification result.
        anomaly_result: Optional raw anomaly result.

    Returns:
        Float confidence score bounded in [0.0, 1.0].
    """
    probs = classification_result.class_probabilities
    if not probs:
        return float(np.clip(classification_result.confidence, 0.0, 1.0))

    sorted_probs = sorted(probs.values(), reverse=True)
    p_top = sorted_probs[0] if len(sorted_probs) > 0 else 0.0
    p_second = sorted_probs[1] if len(sorted_probs) > 1 else 0.0

    margin = p_top - p_second

    # Composite confidence combines absolute top-1 probability and prediction margin
    composite = 0.7 * p_top + 0.3 * margin
    clipped = max(0.0, min(1.0, float(composite)))

    if not math.isfinite(clipped):
        return 0.0

    return round(clipped, 6)
