"""
validation.py
-------------
M2 Phase 4 — Feature vector validation.

Validates a feature vector before and after transformation:
  - Schema version compatibility.
  - No evidence identifier leakage into ML dimensions.
  - No NaN / Inf values in the output numeric array.
  - Missing values handled deterministically.
"""

from __future__ import annotations

import math
from typing import Optional

from backend.app.contracts.analysis import FeatureVector
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION


class FeatureValidationError(Exception):
    """Raised when a feature vector fails safety validation."""


# Raw identifier dimension names that must NEVER appear in the ML input array.
# These are evidence identifiers — they carry no behavioral signal.
# Legitimate behavioral aggregates that contain similar words (e.g.
# 'unique_destination_ips', 'unique_tls_destinations') are NOT in this set.
_FORBIDDEN_DIMENSION_NAMES = frozenset({
    "src_ip", "source_ip", "dst_ip", "destination_ip",
    "flow_id", "event_id", "zeek_uid", "uid",
    "acquisition_id", "evidence_id", "packet_id",
})

# For external inspection
_IDENTIFIER_PATTERNS = sorted(_FORBIDDEN_DIMENSION_NAMES)


def validate_schema_version(vector: FeatureVector) -> None:
    """Assert the feature vector's schema version matches the current schema.

    Raises:
        FeatureValidationError: If there is a schema version mismatch.
    """
    if vector.schema_version != FEATURE_SCHEMA_VERSION:
        raise FeatureValidationError(
            f"Schema version mismatch: vector has '{vector.schema_version}', "
            f"current schema is '{FEATURE_SCHEMA_VERSION}'"
        )


def validate_no_identifier_leakage(numeric_array: dict[str, Optional[float]]) -> None:
    """Assert that no raw identifier has leaked into the ML feature dimensions.

    Uses exact name matching.  Legitimate behavioral aggregates that happen to
    contain similar substrings (e.g. 'unique_destination_ips') are NOT flagged.

    Args:
        numeric_array: The {feature_name: value} dict that will be fed to a model.

    Raises:
        FeatureValidationError: If any dimension name exactly matches a forbidden identifier.
    """
    for name in numeric_array:
        if name.lower() in _FORBIDDEN_DIMENSION_NAMES:
            raise FeatureValidationError(
                f"Identifier leak detected: feature dimension '{name}' is a raw identifier"
            )


def validate_numeric_array(numeric_array: dict[str, Optional[float]]) -> None:
    """Assert all values in the numeric array are finite (no NaN, no Inf).

    Args:
        numeric_array: The {feature_name: value} dict after transformation.

    Raises:
        FeatureValidationError: If any value is NaN, Inf, or -Inf.
    """
    for name, value in numeric_array.items():
        if value is None:
            continue
        if not math.isfinite(value):
            raise FeatureValidationError(
                f"Non-finite value in feature '{name}': {value}"
            )


def validate_missing_values(
    numeric_array: dict[str, Optional[float]],
    fill_value: float = 0.0
) -> dict[str, float]:
    """Replace None values with a deterministic fill value.

    Args:
        numeric_array: The {feature_name: value} dict, possibly containing None.
        fill_value: Value to use for missing entries. Default 0.0.

    Returns:
        A new dict with all None values replaced by fill_value.
    """
    return {
        name: (value if value is not None else fill_value)
        for name, value in numeric_array.items()
    }


def run_all_validations(
    vector: FeatureVector,
    numeric_array: dict[str, Optional[float]],
) -> dict[str, float]:
    """Run all validation checks and return a clean numeric dict.

    This is the single entry point used by the pipeline after transformation.

    Args:
        vector: The source FeatureVector (for schema version check).
        numeric_array: The transformed numeric feature dict.

    Returns:
        A validated, None-free numeric dict.

    Raises:
        FeatureValidationError: If any check fails.
    """
    validate_schema_version(vector)
    validate_no_identifier_leakage(numeric_array)
    filled = validate_missing_values(numeric_array)
    validate_numeric_array(filled)
    return filled
