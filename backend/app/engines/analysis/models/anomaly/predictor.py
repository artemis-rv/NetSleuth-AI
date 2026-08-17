"""
predictor.py
------------
M2 Phase 5 — Anomaly model inference.

Loads a persisted artifact and produces AnomalyResult objects with feature
attribution.  Labels are never supplied to the model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import numpy as np

from backend.app.contracts.analysis import AnomalyResult, FeatureVector
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.engines.analysis.features.transformer import FeatureTransformer, _SCALER_STRATEGY
from backend.app.engines.analysis.features.validation import run_all_validations
from backend.app.engines.analysis.models.anomaly.errors import (
    MissingFeatureError,
    ModelNotFittedError,
    SchemaVersionMismatchError,
)
from backend.app.engines.analysis.models.anomaly.isolation_forest import IsolationForestAnomalyModel
from backend.app.engines.analysis.models.anomaly.model_artifact import AnomalyModelArtifact


class AnomalyPrediction:
    """Full inference output including audit trail for feature attribution."""

    result: AnomalyResult
    transformed_features: dict[str, float]
    raw_feature_vector: FeatureVector

    def __init__(
        self,
        result: AnomalyResult,
        transformed_features: dict[str, float],
        raw_feature_vector: FeatureVector,
    ) -> None:
        self.result = result
        self.transformed_features = transformed_features
        self.raw_feature_vector = raw_feature_vector


class AnomalyPredictor:
    """Inference wrapper for the M2 unsupervised anomaly baseline."""

    def __init__(self, artifact: AnomalyModelArtifact) -> None:
        self.artifact = artifact
        self._transformer: Optional[FeatureTransformer] = None
        self._model: Optional[IsolationForestAnomalyModel] = None

    @classmethod
    def from_artifact(cls, artifact: AnomalyModelArtifact) -> "AnomalyPredictor":
        return cls(artifact)

    @classmethod
    def load(cls, path: Path | str) -> "AnomalyPredictor":
        path = Path(path)
        artifact = AnomalyModelArtifact.from_json(path.read_text(encoding="utf-8"))
        return cls(artifact)

    def _ensure_loaded(self) -> tuple[FeatureTransformer, IsolationForestAnomalyModel]:
        if self._transformer is None:
            self._transformer = self.artifact.load_transformer()
        if self._model is None:
            self._model = self.artifact.load_isolation_forest()
        if not self._transformer.is_fitted or not self._model.is_fitted:
            raise ModelNotFittedError("Artifact does not contain a fitted model")
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
                "FeatureVector contains no present numeric features required by the model"
            )

    def _vector_to_matrix(
        self,
        transformed: dict[str, float],
        feature_names: list[str],
    ) -> np.ndarray:
        row = [float(transformed.get(name, 0.0)) for name in feature_names]
        return np.asarray([row], dtype=float)

    def _contributing_features(
        self,
        transformed: dict[str, float],
        top_n: int = 5,
    ) -> list[str]:
        """Rank features by absolute z-score deviation from benign training stats."""
        deviations: list[tuple[str, float]] = []
        for name, value in transformed.items():
            mean = self.artifact.training_feature_means.get(name, 0.0)
            std = self.artifact.training_feature_stds.get(name, 0.0)
            if std <= 1e-12:
                z = abs(value - mean)
            else:
                z = abs((value - mean) / std)
            deviations.append((name, z))
        deviations.sort(key=lambda item: item[1], reverse=True)
        return [name for name, _ in deviations[:top_n]]

    def predict(self, vector: FeatureVector) -> AnomalyPrediction:
        """Score a single FeatureVector for behavioral deviation.

        The label is never supplied to the model.  An elevated score indicates
        deviation from the benign baseline — not malicious intent.
        """
        self._validate_input_vector(vector)
        transformer, model = self._ensure_loaded()

        numeric = transformer.transform(vector)
        validated = run_all_validations(vector, numeric)
        matrix = self._vector_to_matrix(validated, model.feature_names)
        score = float(model.calibrated_scores(matrix)[0])
        threshold = self.artifact.threshold
        detected = score >= threshold

        result = AnomalyResult(
            anomaly_detected=detected,
            score=score,
            threshold=threshold,
            model_id=self.artifact.model_id,
            model_version=self.artifact.model_version,
            contributing_features=self._contributing_features(validated),
        )
        return AnomalyPrediction(
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
