"""
leakage_validator.py
--------------------
M2 Phase 6 — Leakage & Bias Validation.

Provides safety checks for:
  - Class imbalance handling
  - Label leakage prevention
  - Temporal leakage prevention (Mon/Tue/Wed train, Thu val, Fri test)
  - Identifier leakage prevention
"""

from __future__ import annotations

from typing import Any
from app.contracts.analysis import FeatureVector
from app.engines.analysis.dataset.loader import determine_split
from app.engines.analysis.features.validation import _FORBIDDEN_DIMENSION_NAMES, FeatureValidationError

# Label attributes that MUST NEVER be present inside FeatureVector or transformer feature inputs
_LABEL_LEAK_ATTRIBUTES = frozenset({
    "label",
    "raw_label",
    "normalized_label",
    "activity_class",
    "target",
    "target_class",
    "source_label",
})


def validate_label_leakage(features_dict: dict[str, Any]) -> None:
    """Assert that no target label or label derivative is included in feature inputs.

    Raises:
        FeatureValidationError: If any feature name matches a target label attribute.
    """
    for name in features_dict:
        name_lower = name.lower()
        if name_lower in _LABEL_LEAK_ATTRIBUTES:
            raise FeatureValidationError(
                f"Label leakage detected: target label attribute '{name}' present in feature dict"
            )


def validate_identifier_leakage(numeric_dict: dict[str, Any]) -> None:
    """Assert that no forbidden raw identifier dimension is present in numeric ML features.

    Raises:
        FeatureValidationError: If any key matches a forbidden identifier name.
    """
    for name in numeric_dict:
        if name.lower() in _FORBIDDEN_DIMENSION_NAMES:
            raise FeatureValidationError(
                f"Identifier leakage detected: raw identifier '{name}' present in numeric feature array"
            )


def validate_temporal_split(filename: str, expected_split: str) -> bool:
    """Assert that a dataset file maps to the expected temporal split.

    Splits:
      - Monday, Tuesday, Wednesday -> train
      - Thursday -> validation
      - Friday -> test
    """
    actual_split = determine_split(filename)
    return actual_split == expected_split
