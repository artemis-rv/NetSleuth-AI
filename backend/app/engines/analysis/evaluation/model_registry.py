"""
model_registry.py
-----------------
M2 Phase 9 — Centralized Model & Threshold Registry.

Manages model artifacts, version metadata, threshold configurations, and evaluation metrics.
Ensures every model is versioned, auditable, and reproducible. Supports saving JSON and PKL exports.
"""

from __future__ import annotations

import base64
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

import joblib
from pydantic import BaseModel, Field

from app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from app.engines.analysis.evaluation.threshold_optimizer import ThresholdConfig
from app.engines.analysis.models.anomaly.model_artifact import AnomalyModelArtifact
from app.engines.analysis.models.classification.label_map import LABEL_MAPPING_VERSION
from app.engines.analysis.models.classification.model_artifact import ClassificationModelArtifact

logger = logging.getLogger(__name__)

DEFAULT_TRAINING_SPLIT = "Monday + Tuesday + Wednesday"


class RegistryArtifactEntry(BaseModel):
    """Version metadata and evaluation provenance for a registered model artifact."""

    model_id: str
    model_type: str
    model_version: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    label_mapping_version: str = LABEL_MAPPING_VERSION
    training_dataset_version: str
    training_split: str = DEFAULT_TRAINING_SPLIT
    trained_at: datetime
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    random_seed: int = 42
    evaluation_metrics: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ModelRegistry(BaseModel):
    """Centralized production registry for M2 models, thresholds, and version provenance."""

    registry_id: str = Field(
        default_factory=lambda: f"MR-{uuid4().hex[:12].upper()}",
        description="Unique model registry identifier",
    )
    anomaly_artifact: AnomalyModelArtifact
    classification_artifact: ClassificationModelArtifact
    threshold_config: ThresholdConfig
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of registry entry creation",
    )
    anomaly_metrics: dict[str, Any] = Field(default_factory=dict)
    classification_metrics: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelRegistry":
        return cls.model_validate(data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "ModelRegistry":
        return cls.from_dict(json.loads(json_str))

    def save(self, directory: Path | str) -> None:
        """Save registry metadata and model JSON artifacts to target directory.

        Also exports isolation_forest.pkl and activity_classifier.pkl for external compatibility.
        """
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)

        # Save registry file
        reg_path = dir_path / "model_registry.json"
        reg_path.write_text(self.to_json(), encoding="utf-8")

        # Save anomaly artifact JSON
        anom_json_path = dir_path / "anomaly_model.json"
        anom_json_path.write_text(self.anomaly_artifact.to_json(), encoding="utf-8")

        # Save classification artifact JSON
        cls_json_path = dir_path / "activity_classifier.json"
        cls_json_path.write_text(self.classification_artifact.to_json(), encoding="utf-8")

        # Export .pkl binary files for external tooling
        self.export_pkl(dir_path)
        logger.info("Saved ModelRegistry and exported .pkl model files to %s", dir_path)

    @classmethod
    def load(cls, directory: Path | str) -> "ModelRegistry":
        """Load ModelRegistry from directory containing model_registry.json."""
        dir_path = Path(directory)
        reg_path = dir_path / "model_registry.json"
        if not reg_path.exists():
            raise FileNotFoundError(f"Model registry file not found: {reg_path}")
        return cls.from_json(reg_path.read_text(encoding="utf-8"))

    def export_pkl(self, output_directory: Path | str) -> None:
        """Export scikit-learn models as standalone .pkl pickle files.

        Writes:
          - isolation_forest.pkl
          - activity_classifier.pkl
        """
        out_dir = Path(output_directory)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Export Isolation Forest pickle
        if "model_blob" in self.anomaly_artifact.isolation_forest_state:
            blob = base64.b64decode(self.anomaly_artifact.isolation_forest_state["model_blob"])
            (out_dir / "isolation_forest.pkl").write_bytes(blob)

        # Export Random Forest Classifier pickle
        if "model_blob" in self.classification_artifact.random_forest_state:
            blob = base64.b64decode(self.classification_artifact.random_forest_state["model_blob"])
            (out_dir / "activity_classifier.pkl").write_bytes(blob)
