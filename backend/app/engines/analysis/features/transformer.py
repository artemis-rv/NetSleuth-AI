"""
transformer.py
--------------
M2 Phase 4 — Serializable FeatureTransformer.

The FeatureTransformer holds a per-feature scaling strategy and the fitted
parameters.  It can be serialized to/from a plain dict for storage.

ARCHITECTURE:
  - fit(training_vectors)   — compute and store scaler parameters
  - transform(vector)       — apply stored parameters; NO re-fitting
  - fit_transform(vectors)  — fit then transform in one step (training only)
  - to_dict() / from_dict() — full serialization round-trip

LEAKAGE PREVENTION:
  - transform() and fit_transform() both call validation.validate_no_identifier_leakage()
  - Categorical features are NOT passed as raw strings; they are projected
    via encoding.encode_categorical_feature() to entropy + cardinality.
  - Raw identifiers (IPs, flow_ids, UIDs) are stripped before returning.
"""

from __future__ import annotations

import json
from typing import Optional

from app.contracts.analysis import FeatureVector
from app.contracts.feature_schema import FeatureName, FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION
from app.engines.analysis.features.normalization import (
    MinMaxScaler, StandardScaler, LogScaler, load_scaler
)
from app.engines.analysis.features.encoding import encode_categorical_feature
from app.engines.analysis.features.validation import validate_no_identifier_leakage

# ---------------------------------------------------------------------------
# SCALING STRATEGY MAP
# ---------------------------------------------------------------------------
# Maps FeatureName → scaler type.
# "log"      — log1p + minmax; for heavily right-skewed quantities
# "minmax"   — direct minmax; for bounded quantities
# "standard" — z-score; for symmetric, unbounded quantities
# "identity" — no scaling; already in [0,1] (ratios, entropy, etc.)

_SCALER_STRATEGY: dict[str, str] = {
    # --- FLOW (skewed counts and byte totals) ---
    FeatureName.FLOW_COUNT.value: "log",
    FeatureName.FLOW_UNIQUE_SOURCE_IPS.value: "log",
    FeatureName.FLOW_UNIQUE_DESTINATION_IPS.value: "log",
    FeatureName.FLOW_UNIQUE_DESTINATION_PORTS.value: "log",
    FeatureName.FLOW_TCP_COUNT.value: "log",
    FeatureName.FLOW_UDP_COUNT.value: "log",
    FeatureName.FLOW_ICMP_COUNT.value: "log",
    FeatureName.FLOW_MEAN_DURATION.value: "log",
    FeatureName.FLOW_MEDIAN_DURATION.value: "log",
    FeatureName.FLOW_MAX_DURATION.value: "log",
    FeatureName.FLOW_TOTAL_BYTES.value: "log",
    FeatureName.FLOW_TOTAL_PACKETS.value: "log",
    FeatureName.FLOW_MEAN_BYTES_PER_FLOW.value: "log",
    FeatureName.FLOW_MEAN_PACKETS_PER_FLOW.value: "log",
    FeatureName.FLOW_OUTBOUND_BYTES.value: "log",
    FeatureName.FLOW_INBOUND_BYTES.value: "log",
    FeatureName.FLOW_BYTES_RATIO.value: "log",     # can be large; log-compress
    FeatureName.FLOW_PACKETS_RATIO.value: "log",
    # --- CONNECTION BEHAVIOUR (ratios already in [0,1]) ---
    FeatureName.CONN_FAILED_RATIO.value: "identity",
    FeatureName.CONN_SHORT_RATIO.value: "identity",
    FeatureName.CONN_LONG_RATIO.value: "identity",
    FeatureName.CONN_UNIQUE_DESTINATIONS_PER_SOURCE.value: "log",
    FeatureName.CONN_UNIQUE_PORTS_PER_SOURCE.value: "log",
    FeatureName.CONN_CONNECTION_RATE.value: "log",
    FeatureName.CONN_NEW_DESTINATION_RATE.value: "log",
    FeatureName.CONN_NEW_PORT_RATE.value: "log",
    # --- DNS ---
    FeatureName.DNS_QUERY_COUNT.value: "log",
    FeatureName.DNS_UNIQUE_DOMAINS.value: "log",
    FeatureName.DNS_UNIQUE_QUERY_TYPES.value: "log",
    FeatureName.DNS_NXDOMAIN_RATIO.value: "identity",
    FeatureName.DNS_ANSWER_COUNT.value: "log",
    FeatureName.DNS_UNIQUE_ANSWER_IPS.value: "log",
    FeatureName.DNS_MEAN_DOMAIN_LENGTH.value: "minmax",
    FeatureName.DNS_MAX_DOMAIN_LENGTH.value: "minmax",
    FeatureName.DNS_MEAN_LABEL_LENGTH.value: "minmax",
    FeatureName.DNS_MAX_LABEL_LENGTH.value: "minmax",
    FeatureName.DNS_SUBDOMAIN_DEPTH.value: "minmax",
    FeatureName.DNS_QUERY_RATE.value: "log",
    FeatureName.DNS_UNIQUE_DOMAINS_PER_SOURCE.value: "log",
    # --- HTTP ---
    FeatureName.HTTP_REQUEST_COUNT.value: "log",
    FeatureName.HTTP_UNIQUE_HOSTS.value: "log",
    FeatureName.HTTP_UNIQUE_URIS.value: "log",
    FeatureName.HTTP_METHOD_COUNT.value: "log",
    FeatureName.HTTP_GET_RATIO.value: "identity",
    FeatureName.HTTP_POST_RATIO.value: "identity",
    FeatureName.HTTP_ERROR_STATUS_RATIO.value: "identity",
    FeatureName.HTTP_REDIRECT_RATIO.value: "identity",
    FeatureName.HTTP_DOWNLOAD_BYTES.value: "log",
    FeatureName.HTTP_UPLOAD_BYTES.value: "log",
    FeatureName.HTTP_UNIQUE_USER_AGENTS.value: "log",
    FeatureName.HTTP_MISSING_USER_AGENT_RATIO.value: "identity",
    FeatureName.HTTP_URI_LENGTH_MEAN.value: "minmax",
    FeatureName.HTTP_URI_LENGTH_MAX.value: "minmax",
    # --- TLS ---
    FeatureName.TLS_CONNECTION_COUNT.value: "log",
    FeatureName.TLS_UNIQUE_SNI.value: "log",
    # TLS_VERSION_DISTRIBUTION + TLS_CIPHER_DISTRIBUTION → encoded separately
    FeatureName.TLS_MISSING_SNI_RATIO.value: "identity",
    FeatureName.TLS_CERT_VALIDITY_DURATION.value: "minmax",
    FeatureName.TLS_UNIQUE_DESTINATIONS.value: "log",
    # derived from categoricals
    "tls_version_entropy": "identity",
    "tls_version_cardinality": "log",
    "cipher_entropy": "identity",
    "cipher_cardinality": "log",
    # --- TEMPORAL ---
    FeatureName.TEMPORAL_OBSERVATION_DURATION.value: "log",
    FeatureName.TEMPORAL_EVENT_RATE.value: "log",
    FeatureName.TEMPORAL_FLOW_RATE.value: "log",
    FeatureName.TEMPORAL_DNS_RATE.value: "log",
    FeatureName.TEMPORAL_HTTP_RATE.value: "log",
    FeatureName.TEMPORAL_TLS_RATE.value: "log",
    FeatureName.TEMPORAL_PERIODICITY_SCORE.value: "identity",
    FeatureName.TEMPORAL_INTERARRIVAL_MEAN.value: "log",
    FeatureName.TEMPORAL_INTERARRIVAL_STD.value: "log",
    FeatureName.TEMPORAL_INTERARRIVAL_CV.value: "minmax",
    # --- DISTRIBUTION / ENTROPY (already in [0, log2(N)] range) ---
    FeatureName.DIST_DESTINATION_ENTROPY.value: "minmax",
    FeatureName.DIST_PORT_ENTROPY.value: "minmax",
    FeatureName.DIST_DOMAIN_ENTROPY.value: "minmax",
    FeatureName.DIST_PROTOCOL_ENTROPY.value: "minmax",
}

_CATEGORICAL_FEATURES = {
    FeatureName.TLS_VERSION_DISTRIBUTION.value,
    FeatureName.TLS_CIPHER_DISTRIBUTION.value,
}


def _make_scaler(strategy: str):
    if strategy == "log":
        return LogScaler()
    elif strategy == "standard":
        return StandardScaler()
    elif strategy == "minmax":
        return MinMaxScaler()
    else:  # identity
        return None


class FeatureTransformer:
    """Serializable, train-only feature scaling pipeline.

    Usage:
        # Training:
        transformer = FeatureTransformer()
        transformed = transformer.fit_transform(training_vectors)

        # Inference:
        transformed = transformer.transform(new_vector)

        # Persistence:
        state = transformer.to_dict()
        transformer2 = FeatureTransformer.from_dict(state)
    """

    def __init__(self) -> None:
        # {feature_name: scaler_instance | None}
        self._scalers: dict[str, object] = {}
        self.schema_version: str = FEATURE_SCHEMA_VERSION
        self.is_fitted: bool = False

    def _collect_numeric_values(self, vectors: list[FeatureVector]) -> dict[str, list[float]]:
        """Collect per-feature value lists from a list of FeatureVectors."""
        values: dict[str, list[float]] = {name: [] for name in _SCALER_STRATEGY}

        for vector in vectors:
            for fv in vector.features:
                if fv.categorical:
                    # Encode categorical → derived numerics
                    derived = encode_categorical_feature(fv.name, fv.value)
                    for dname, dval in derived.items():
                        if dname in values:
                            values[dname].append(dval)
                elif fv.name in values and fv.present and fv.value is not None:
                    if isinstance(fv.value, (int, float)):
                        values[fv.name].append(float(fv.value))

        return values

    def fit(self, training_vectors: list[FeatureVector]) -> "FeatureTransformer":
        """Fit scalers to training data.

        Args:
            training_vectors: FeatureVectors produced from TRAINING data only.

        Returns:
            self (for chaining).
        """
        value_lists = self._collect_numeric_values(training_vectors)

        for feature_name, strategy in _SCALER_STRATEGY.items():
            scaler = _make_scaler(strategy)
            if scaler is not None:
                scaler.fit(value_lists.get(feature_name, []))
            self._scalers[feature_name] = scaler

        self.is_fitted = True
        return self

    def transform(self, vector: FeatureVector) -> dict[str, float]:
        """Apply fitted scalers to produce a normalized numeric array.

        Categorical features are encoded to entropy + cardinality.
        Missing values are filled with 0.0.
        Raw identifiers are never included.

        Args:
            vector: A FeatureVector extracted from a NetworkIntelligencePackage.

        Returns:
            A {feature_name: float} dict suitable for model input.

        Raises:
            RuntimeError: If called before fit().
        """
        if not self.is_fitted:
            raise RuntimeError("FeatureTransformer must be fitted before calling transform()")

        numeric: dict[str, float] = {}

        for fv in vector.features:
            if fv.categorical:
                derived = encode_categorical_feature(fv.name, fv.value)
                for dname, dval in derived.items():
                    scaler = self._scalers.get(dname)
                    numeric[dname] = scaler.transform(dval) if scaler else dval
            else:
                if fv.name not in _SCALER_STRATEGY:
                    continue  # skip unmapped features (not a model dimension)
                raw_value = float(fv.value) if (fv.present and fv.value is not None
                                                and isinstance(fv.value, (int, float))) else None
                scaler = self._scalers.get(fv.name)
                if scaler is None:
                    # Identity strategy
                    numeric[fv.name] = raw_value if raw_value is not None else 0.0
                else:
                    numeric[fv.name] = scaler.transform(raw_value)

        # Fill any missing dimensions with 0.0
        for feature_name in _SCALER_STRATEGY:
            if feature_name not in numeric:
                numeric[feature_name] = 0.0

        # Safety guard — no identifier leakage
        validate_no_identifier_leakage(numeric)

        return numeric

    def fit_transform(self, training_vectors: list[FeatureVector]) -> list[dict[str, float]]:
        """Fit on and transform training vectors in one step.

        Args:
            training_vectors: FeatureVectors from TRAINING data only.

        Returns:
            List of normalized numeric dicts.
        """
        self.fit(training_vectors)
        return [self.transform(v) for v in training_vectors]

    # ---------------------------------------------------------------------------
    # SERIALIZATION
    # ---------------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the fitted transformer to a plain Python dict."""
        serialized_scalers = {}
        for name, scaler in self._scalers.items():
            if scaler is None:
                serialized_scalers[name] = {"type": "identity"}
            elif hasattr(scaler, "to_dict"):
                serialized_scalers[name] = scaler.to_dict()

        return {
            "schema_version": self.schema_version,
            "is_fitted": self.is_fitted,
            "scalers": serialized_scalers,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureTransformer":
        """Deserialize a FeatureTransformer from a dict."""
        ft = cls()
        ft.schema_version = d.get("schema_version", FEATURE_SCHEMA_VERSION)
        ft.is_fitted = d.get("is_fitted", False)

        for name, scaler_dict in d.get("scalers", {}).items():
            if scaler_dict.get("type") == "identity":
                ft._scalers[name] = None
            else:
                ft._scalers[name] = load_scaler(scaler_dict)

        return ft

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "FeatureTransformer":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))
