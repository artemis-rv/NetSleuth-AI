"""
pipeline.py
-----------
M2 Phase 4 — Feature Engineering Pipeline.

The FeatureEngineeringPipeline is the single entry point for converting a
raw M1 NetworkIntelligencePackage into a fully normalized numeric array.

Flow:
    NetworkIntelligencePackage
        → extract_all_features()          [Phase 3]
        → FeatureTransformer.transform()  [Phase 4]
        → validate_no_identifier_leakage()
        → dict[str, float]                [ML-ready]

METADATA:
    FeatureMetadata documents the provenance and schema of the vector:
    - schema_version
    - feature_names (ordered)
    - source acquisition_id
    - observation_window (start, end)
    - source references (flow_ids, event_ids) for evidence trace-back
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from backend.app.contracts.network_intelligence import NetworkIntelligencePackage
from backend.app.contracts.analysis import FeatureVector
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.transformer import FeatureTransformer
from backend.app.engines.analysis.features.validation import run_all_validations


# ---------------------------------------------------------------------------
# FEATURE METADATA
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservationWindow:
    """The temporal span of the observation represented by a feature vector."""
    start: Optional[datetime]
    end: Optional[datetime]
    duration_seconds: float


@dataclass(frozen=True)
class FeatureMetadata:
    """Provenance and schema metadata for a feature vector.

    Attached to every ML-ready numeric array to maintain forensic traceability.
    """
    vector_id: str
    schema_version: str
    acquisition_id: str
    feature_names: tuple[str, ...]  # ordered, deterministic
    observation_window: ObservationWindow
    # Evidence trace-back references (NOT passed to ML model)
    source_flow_ids: tuple[str, ...]
    source_event_ids: tuple[str, ...]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "vector_id": self.vector_id,
            "schema_version": self.schema_version,
            "acquisition_id": self.acquisition_id,
            "feature_names": list(self.feature_names),
            "observation_window": {
                "start": self.observation_window.start.isoformat()
                         if self.observation_window.start else None,
                "end": self.observation_window.end.isoformat()
                       if self.observation_window.end else None,
                "duration_seconds": self.observation_window.duration_seconds,
            },
            "source_flow_ids": list(self.source_flow_ids),
            "source_event_ids": list(self.source_event_ids),
            "created_at": self.created_at.isoformat(),
        }


def _build_observation_window(package: NetworkIntelligencePackage) -> ObservationWindow:
    timestamps = (
        [f.timestamp for f in package.flows]
        + [e.timestamp for e in package.protocol_events]
    )
    if not timestamps:
        return ObservationWindow(start=None, end=None, duration_seconds=0.0)
    start = min(timestamps)
    end = max(timestamps)
    return ObservationWindow(
        start=start,
        end=end,
        duration_seconds=(end - start).total_seconds(),
    )


# ---------------------------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------------------------


class FeatureEngineeringPipeline:
    """End-to-end feature engineering: extraction → transformation → validation.

    Usage (training):
        pipeline = FeatureEngineeringPipeline()
        train_arrays = pipeline.fit_transform(training_packages)

    Usage (inference):
        pipeline = FeatureEngineeringPipeline.from_dict(state)
        numeric, metadata = pipeline.transform(new_package)
    """

    def __init__(self) -> None:
        self.transformer = FeatureTransformer()

    # ---------------------------------------------------------------------------
    # EXTRACTION HELPER
    # ---------------------------------------------------------------------------

    def _extract(self, package: NetworkIntelligencePackage) -> tuple[FeatureVector, FeatureMetadata]:
        """Extract raw features and build metadata."""
        vector = extract_all_features(package)

        window = _build_observation_window(package)
        metadata = FeatureMetadata(
            vector_id=vector.vector_id,
            schema_version=FEATURE_SCHEMA_VERSION,
            acquisition_id=package.acquisition_id,
            feature_names=tuple(vector.feature_names()),
            observation_window=window,
            source_flow_ids=tuple(f.flow_id for f in package.flows),
            source_event_ids=tuple(e.event_id for e in package.protocol_events),
        )
        return vector, metadata

    # ---------------------------------------------------------------------------
    # FIT (training data only)
    # ---------------------------------------------------------------------------

    def fit(self, training_packages: list[NetworkIntelligencePackage]) -> "FeatureEngineeringPipeline":
        """Fit scalers on training data.

        Args:
            training_packages: M1 packages from the TRAINING split only.

        Returns:
            self (for chaining).
        """
        training_vectors = [extract_all_features(pkg) for pkg in training_packages]
        self.transformer.fit(training_vectors)
        return self

    # ---------------------------------------------------------------------------
    # TRANSFORM (training or inference)
    # ---------------------------------------------------------------------------

    def transform(
        self, package: NetworkIntelligencePackage
    ) -> tuple[dict[str, float], FeatureMetadata]:
        """Transform a package into a validated ML-ready numeric array.

        Args:
            package: M1 NetworkIntelligencePackage (train, validation, or test).

        Returns:
            (numeric_array, metadata) tuple.
        """
        vector, metadata = self._extract(package)
        numeric = self.transformer.transform(vector)
        validated = run_all_validations(vector, numeric)
        return validated, metadata

    # ---------------------------------------------------------------------------
    # FIT + TRANSFORM (convenience for training loop)
    # ---------------------------------------------------------------------------

    def fit_transform(
        self, training_packages: list[NetworkIntelligencePackage]
    ) -> list[tuple[dict[str, float], FeatureMetadata]]:
        """Fit and transform training packages.

        MUST NOT be called on validation or test data to prevent leakage.

        Args:
            training_packages: M1 packages from the TRAINING split only.

        Returns:
            List of (numeric_array, metadata) tuples.
        """
        self.fit(training_packages)
        return [self.transform(pkg) for pkg in training_packages]

    # ---------------------------------------------------------------------------
    # SERIALIZATION
    # ---------------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the pipeline state (fitted transformer)."""
        return {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "transformer": self.transformer.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureEngineeringPipeline":
        """Deserialize a fitted pipeline from a dict."""
        pipeline = cls()
        pipeline.transformer = FeatureTransformer.from_dict(d["transformer"])
        return pipeline

    @classmethod
    def from_json(cls, json_str: str) -> "FeatureEngineeringPipeline":
        return cls.from_dict(json.loads(json_str))
