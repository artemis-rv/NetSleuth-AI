"""
encoding.py
-----------
M2 Phase 4 — Categorical feature encoding.

Encodes categorical feature distributions (TLS version counts, cipher counts)
into numeric vectors suitable for ML models.

RULES:
  - Raw IP addresses MUST NOT be encoded as model dimensions.
  - Raw domain strings MUST NOT be encoded as model dimensions.
  - source_ip / destination_ip / flow_id / event_id / uid are evidence
    identifiers — NEVER model dimensions.
  - Only behavioral aggregates (counts, entropies, ratios) are encoded.

Categorical distributions stored as JSON strings (TLS version distribution,
cipher distribution) are projected to entropy + cardinality only.
"""

from __future__ import annotations

import json
import math
from typing import Optional


def entropy_from_json_dist(json_str: Optional[str]) -> float:
    """Compute Shannon entropy from a JSON-encoded {label: count} distribution.

    Args:
        json_str: JSON string like '{"TLSv1.2": 10, "TLSv1.3": 5}' or None.

    Returns:
        Shannon entropy in bits, or 0.0 if empty/invalid.
    """
    if not json_str:
        return 0.0
    try:
        dist = json.loads(json_str)
        if not isinstance(dist, dict):
            return 0.0
        total = sum(dist.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in dist.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    except (json.JSONDecodeError, TypeError, ZeroDivisionError):
        return 0.0


def cardinality_from_json_dist(json_str: Optional[str]) -> float:
    """Count number of distinct categories in a JSON distribution.

    Args:
        json_str: JSON string like '{"TLSv1.2": 10, "TLSv1.3": 5}' or None.

    Returns:
        Number of distinct categories, or 0.0 if empty/invalid.
    """
    if not json_str:
        return 0.0
    try:
        dist = json.loads(json_str)
        if not isinstance(dist, dict):
            return 0.0
        return float(len([k for k, v in dist.items() if v > 0]))
    except (json.JSONDecodeError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# IDENTIFIER SAFETY GUARD
# ---------------------------------------------------------------------------

# Feature names that encode raw identifiers — these MUST be excluded from ML.
_FORBIDDEN_ML_FEATURE_NAMES = frozenset({
    # IPs, UIDs, flow IDs, acquisition IDs, event IDs
    # We use a prefix guard in validation.py; here we document the intent.
})

# Categorical features that must be encoded via entropy/cardinality only:
CATEGORICAL_TO_NUMERIC_FEATURES = {
    # TLS version distribution → two derived numerics
    "tls_version_distribution": ["tls_version_entropy", "tls_version_cardinality"],
    # Cipher distribution → two derived numerics
    "cipher_distribution": ["cipher_entropy", "cipher_cardinality"],
}


def encode_categorical_feature(name: str, value: Optional[str]) -> dict[str, float]:
    """Encode a categorical JSON-distribution feature into numeric dimensions.

    Args:
        name: The canonical FeatureName value (string).
        value: The JSON-encoded distribution string, or None.

    Returns:
        A dict of {derived_feature_name: float_value}.
    """
    if name == "tls_version_distribution":
        return {
            "tls_version_entropy": entropy_from_json_dist(value),
            "tls_version_cardinality": cardinality_from_json_dist(value),
        }
    elif name == "cipher_distribution":
        return {
            "cipher_entropy": entropy_from_json_dist(value),
            "cipher_cardinality": cardinality_from_json_dist(value),
        }
    return {}
