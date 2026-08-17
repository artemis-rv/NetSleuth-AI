"""
model_artifact.py
-----------------
M2 Phase 6 — Persisted classification model artifact.

Bundles the fitted RandomForestClassifier, FeatureTransformer state, label mapping
version, schema versions, and training provenance for reproducible inference.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.engines.analysis.features.transformer import FeatureTransformer
from backend.app.engines.analysis.models.classification.label_map import LABEL_MAPPING_VERSION
from backend.app.engines.analysis.models.classification.random_forest import (
    MODEL_TYPE,
    MODEL_VERSION,
    RandomForestActivityModel,
)

TRAINING_DATASET_VERSION = "CICIDS2017-v1-train-mon-tue-wed"
TRANSFORMER_VERSION = FEATURE_SCHEMA_VERSION


class ClassificationModelArtifact(BaseModel):
    """Complete persisted state for the M2 supervised activity classifier model."""

    model_id: str = Field(
        default_factory=lambda: f"CM-{uuid4().hex[:12].upper()}",
        description="Unique classification artifact identifier",
    )
    model_type: str = Field(default=MODEL_TYPE)
    model_version: str = Field(default=MODEL_VERSION)
    feature_schema_version: str = Field(default=FEATURE_SCHEMA_VERSION)
    label_mapping_version: str = Field(default=LABEL_MAPPING_VERSION)
    training_dataset_version: str = Field(default=TRAINING_DATASET_VERSION)
    transformer_version: str = Field(default=TRANSFORMER_VERSION)
    trained_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when training completed",
    )
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    random_state: int = Field(default=42)
    feature_names: list[str] = Field(default_factory=list)
    learned_classes: list[str] = Field(default_factory=list)
    training_class_counts: dict[str, int] = Field(default_factory=dict)
    missing_classes: list[str] = Field(default_factory=list)
    random_forest_state: dict[str, Any] = Field(default_factory=dict)
    transformer_state: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClassificationModelArtifact":
        return cls.model_validate(data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "ClassificationModelArtifact":
        return cls.from_dict(json.loads(json_str))

    def load_transformer(self) -> FeatureTransformer:
        return FeatureTransformer.from_dict(self.transformer_state)

    def load_random_forest(self) -> RandomForestActivityModel:
        return RandomForestActivityModel.from_dict(self.random_forest_state)


def build_classification_artifact(
    *,
    random_forest: RandomForestActivityModel,
    transformer: FeatureTransformer,
    hyperparameters: dict[str, Any],
    random_state: int,
    training_dataset_version: str = TRAINING_DATASET_VERSION,
    label_mapping_version: str = LABEL_MAPPING_VERSION,
    model_id: Optional[str] = None,
) -> ClassificationModelArtifact:
    """Construct a persisted classification artifact from fitted components."""
    return ClassificationModelArtifact(
        model_id=model_id or f"CM-{uuid4().hex[:12].upper()}",
        model_type=MODEL_TYPE,
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        label_mapping_version=label_mapping_version,
        training_dataset_version=training_dataset_version,
        transformer_version=transformer.schema_version,
        trained_at=datetime.now(timezone.utc),
        hyperparameters=hyperparameters,
        random_state=random_state,
        feature_names=list(random_forest.feature_names),
        learned_classes=list(random_forest.learned_classes),
        training_class_counts=dict(random_forest.training_class_counts),
        missing_classes=list(random_forest.missing_classes),
        random_forest_state=random_forest.to_dict(),
        transformer_state=transformer.to_dict(),
    )
