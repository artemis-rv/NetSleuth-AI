"""
model_artifact.py
-----------------
M2 Phase 5 — Persisted anomaly model artifact.

Bundles the fitted Isolation Forest, FeatureTransformer state, threshold
metadata, and training provenance for reproducible inference.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.engines.analysis.features.transformer import FeatureTransformer
from backend.app.engines.analysis.models.anomaly.isolation_forest import (
    IsolationForestAnomalyModel,
    MODEL_TYPE,
    MODEL_VERSION,
)
from backend.app.engines.analysis.models.anomaly.threshold import ThresholdSelection

TRAINING_DATASET_VERSION = "CICIDS2017-v1-train-benign-mon-tue-wed"
TRANSFORMER_VERSION = FEATURE_SCHEMA_VERSION


class AnomalyModelArtifact(BaseModel):
    """Complete persisted state for the M2 anomaly detection model."""

    model_id: str = Field(
        default_factory=lambda: f"AM-{uuid4().hex[:12].upper()}",
        description="Unique artifact identifier",
    )
    model_type: str = Field(default=MODEL_TYPE)
    model_version: str = Field(default=MODEL_VERSION)
    feature_schema_version: str = Field(default=FEATURE_SCHEMA_VERSION)
    transformer_version: str = Field(default=TRANSFORMER_VERSION)
    training_dataset_version: str = Field(default=TRAINING_DATASET_VERSION)
    trained_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when training completed",
    )
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    random_state: int = Field(default=42)
    feature_names: list[str] = Field(default_factory=list)
    threshold: float = Field(..., ge=0.0, le=1.0)
    threshold_metadata: dict[str, Any] = Field(default_factory=dict)
    training_feature_means: dict[str, float] = Field(default_factory=dict)
    training_feature_stds: dict[str, float] = Field(default_factory=dict)
    isolation_forest_state: dict[str, Any] = Field(default_factory=dict)
    transformer_state: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnomalyModelArtifact":
        return cls.model_validate(data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "AnomalyModelArtifact":
        return cls.from_dict(json.loads(json_str))

    def load_transformer(self) -> FeatureTransformer:
        return FeatureTransformer.from_dict(self.transformer_state)

    def load_isolation_forest(self) -> IsolationForestAnomalyModel:
        return IsolationForestAnomalyModel.from_dict(self.isolation_forest_state)


def build_artifact(
    *,
    isolation_forest: IsolationForestAnomalyModel,
    transformer: FeatureTransformer,
    threshold_selection: ThresholdSelection,
    training_feature_means: dict[str, float],
    training_feature_stds: dict[str, float],
    hyperparameters: dict[str, Any],
    random_state: int,
    training_dataset_version: str = TRAINING_DATASET_VERSION,
    model_id: Optional[str] = None,
) -> AnomalyModelArtifact:
    """Construct a persisted artifact from trained components."""
    return AnomalyModelArtifact(
        model_id=model_id or f"AM-{uuid4().hex[:12].upper()}",
        model_type=MODEL_TYPE,
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        transformer_version=transformer.schema_version,
        training_dataset_version=training_dataset_version,
        trained_at=datetime.now(timezone.utc),
        hyperparameters=hyperparameters,
        random_state=random_state,
        feature_names=list(isolation_forest.feature_names),
        threshold=threshold_selection.threshold,
        threshold_metadata=threshold_selection.to_dict(),
        training_feature_means=training_feature_means,
        training_feature_stds=training_feature_stds,
        isolation_forest_state=isolation_forest.to_dict(),
        transformer_state=transformer.to_dict(),
    )
