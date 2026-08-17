"""
predictor.py
------------
M2 Phase 6 — Supervised activity model inference API.

Loads a persisted ClassificationModelArtifact and produces ClassificationResult
objects for input FeatureVectors. Targets or labels are never supplied during inference.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import numpy as np

from backend.app.contracts.analysis import ClassificationResult, FeatureVector
from backend.app.engines.analysis.features.transformer import FeatureTransformer, _SCALER_STRATEGY
from backend.app.engines.analysis.features.validation import run_all_validations
from backend.app.engines.analysis.models.classification.errors import (
    MissingFeatureError,
    ModelNotFittedError,
    SchemaVersionMismatchError,
)
from backend.app.engines.analysis.models.classification.model_artifact import ClassificationModelArtifact
from backend.app.engines.analysis.models.classification.random_forest import RandomForestActivityModel


class ClassificationPrediction:
    """Full classification inference output including raw and transformed feature state."""

    def __init__(
        self,
        result: ClassificationResult,
        transformed_features: dict[str, float],
        raw_feature_vector: FeatureVector,
    ) -> None:
        self.result = result
        self.transformed_features = transformed_features
        self.raw_feature_vector = raw_feature_vector

    @property
    def predicted_activity(self):
        """Property accessor for predicted activity class."""
        return self.result.activity_class


class ActivityClassifier:
    """Production inference wrapper for the M2 supervised activity classifier."""

    def __init__(self, artifact: ClassificationModelArtifact) -> None:
        self.artifact = artifact
        self._transformer: Optional[FeatureTransformer] = None
        self._model: Optional[RandomForestActivityModel] = None

    @classmethod
    def from_artifact(cls, artifact: ClassificationModelArtifact) -> "ActivityClassifier":
        return cls(artifact)

    @classmethod
    def load(cls, path: Path | str) -> "ActivityClassifier":
        path = Path(path)
        artifact = ClassificationModelArtifact.from_json(path.read_text(encoding="utf-8"))
        return cls(artifact)

    def _ensure_loaded(self) -> tuple[FeatureTransformer, RandomForestActivityModel]:
        if self._transformer is None:
            self._transformer = self.artifact.load_transformer()
        if self._model is None:
            self._model = self.artifact.load_random_forest()
        if not self._transformer.is_fitted or not self._model.is_fitted:
            raise ModelNotFittedError("Artifact does not contain a fitted classifier model")
        return self._transformer, self._model

    def _validate_input_vector(self, vector: FeatureVector) -> None:
        if vector.schema_version != self.artifact.feature_schema_version:
            raise SchemaVersionMismatchError(
                f"FeatureVector schema '{vector.schema_version}' does not match "
                f"artifact schema '{self.artifact.feature_schema_version}'"
            )

        present_model_dims = 0
        for fv in vector.features:
            if not fv.present or fv.categorical:
                continue
            if fv.name in _SCALER_STRATEGY and fv.value is not None:
                present_model_dims += 1

        if present_model_dims == 0:
            raise MissingFeatureError(
                "FeatureVector contains no present numeric features required by the classifier"
            )

    def _vector_to_matrix(
        self,
        transformed: dict[str, float],
        feature_names: list[str],
    ) -> np.ndarray:
        row = [float(transformed.get(name, 0.0)) for name in feature_names]
        return np.asarray([row], dtype=float)

    def predict(self, vector: FeatureVector) -> ClassificationPrediction:
        """Classify a single FeatureVector into the M2 activity taxonomy.

        No label or target is supplied to the classifier.
        """
        self._validate_input_vector(vector)
        transformer, model = self._ensure_loaded()

        numeric = transformer.transform(vector)
        validated = run_all_validations(vector, numeric)
        matrix = self._vector_to_matrix(validated, model.feature_names)

        predictions = model.predict(matrix)
        top_activity, confidence, class_probabilities = predictions[0]

        result = ClassificationResult(
            activity_class=top_activity,
            confidence=confidence,
            class_probabilities=class_probabilities,
            model_id=self.artifact.model_id,
            model_version=self.artifact.model_version,
        )

        return ClassificationPrediction(
            result=result,
            transformed_features=dict(validated),
            raw_feature_vector=vector,
        )

    def save(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.artifact.to_json(), encoding="utf-8")

    @property
    def feature_schema_version(self) -> str:
        return self.artifact.feature_schema_version

    @property
    def label_mapping_version(self) -> str:
        return self.artifact.label_mapping_version
