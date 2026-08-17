"""
random_forest.py
----------------
M2 Phase 6 — Random Forest classifier wrapper for Supervised Activity Classification.

Wraps scikit-learn RandomForestClassifier with deterministic training, full
6-class probability distribution preservation, explicit handling of classes with
insufficient training examples, and joblib serialization.
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from app.contracts.analysis import ActivityClass
from app.engines.analysis.dataset.labels import UNMAPPED
from app.engines.analysis.models.classification.errors import (
    InsufficientClassSamplesError,
    ModelNotFittedError,
)
from app.engines.analysis.models.classification.label_map import (
    ALL_ACTIVITY_CLASSES,
    map_cicids_label,
    validate_activity_class,
)

logger = logging.getLogger(__name__)

DEFAULT_HYPERPARAMETERS: dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "class_weight": "balanced",
    "n_jobs": -1,
}

MODEL_TYPE = "random_forest"
MODEL_VERSION = "1.0"


class RandomForestActivityModel:
    """Production Random Forest model for Supervised Activity Classification.

    Classifies preprocessed feature vectors into the 6-class M2 activity taxonomy.
    Preserves the full probability distribution across all 6 ActivityClass members
    and explicitly handles classes with 0 or few training samples.
    """

    def __init__(
        self,
        hyperparameters: Optional[dict[str, Any]] = None,
        random_state: int = 42,
    ) -> None:
        self.hyperparameters = {**DEFAULT_HYPERPARAMETERS, **(hyperparameters or {})}
        self.random_state = random_state
        self._model: Optional[RandomForestClassifier] = None
        self.feature_names: list[str] = []
        self.learned_classes: list[str] = []
        self.training_class_counts: dict[str, int] = {}
        self.missing_classes: list[str] = []

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def fit(
        self,
        X: np.ndarray,
        y: list[ActivityClass | str],
        feature_names: list[str],
        min_samples_per_class: int = 1,
    ) -> "RandomForestActivityModel":
        """Fit the Random Forest classifier on transformed feature matrices.

        Args:
            X: 2-D float numpy array of shape (N_samples, N_features).
            y: List of target activity classes or raw string labels.
            feature_names: List of canonical feature names corresponding to X columns.
            min_samples_per_class: Minimum samples required per present class.

        Returns:
            self
        """
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("Training matrix X must be 2-D with at least one row")

        if len(y) != X.shape[0]:
            raise ValueError(f"X rows ({X.shape[0]}) and y length ({len(y)}) mismatch")

        # Clean and normalize labels; filter out UNMAPPED explicitly
        clean_y: list[str] = []
        valid_indices: list[int] = []
        unmapped_count = 0

        for idx, label in enumerate(y):
            if isinstance(label, ActivityClass):
                ac = label
            else:
                ac = map_cicids_label(str(label), strict=False)

            if ac == UNMAPPED or not isinstance(ac, ActivityClass):
                unmapped_count += 1
                continue

            clean_y.append(ac.value)
            valid_indices.append(idx)

        if unmapped_count > 0:
            logger.info(
                "Explicitly excluded %d unmapped/uncertain rows from training", unmapped_count
            )

        if len(clean_y) == 0:
            raise InsufficientClassSamplesError(
                "No valid mapped target labels available for training"
            )

        X_train = X[valid_indices] if len(valid_indices) < len(y) else X
        y_train = np.array(clean_y)

        # Count occurrences per class
        unique_classes, counts = np.unique(y_train, return_counts=True)
        class_counts = dict(zip(unique_classes.tolist(), counts.tolist()))
        self.training_class_counts = class_counts

        # Check all 6 taxonomy classes
        all_class_values = [ac.value for ac in ALL_ACTIVITY_CLASSES]
        missing = [c for c in all_class_values if c not in class_counts or class_counts[c] == 0]
        self.missing_classes = missing

        if missing:
            logger.warning(
                "The following ActivityClass taxonomy members have 0 training samples: %s",
                missing,
            )

        # Validate that at least 1 class has sufficient samples
        for cls_name, count in class_counts.items():
            if count < min_samples_per_class:
                logger.warning(
                    "Class '%s' has only %d samples (less than min_samples_per_class=%d)",
                    cls_name,
                    count,
                    min_samples_per_class,
                )

        params = {**self.hyperparameters, "random_state": self.random_state}
        self._model = RandomForestClassifier(**params)
        self._model.fit(X_train, y_train)

        self.feature_names = list(feature_names)
        self.learned_classes = [str(c) for c in self._model.classes_]

        return self

    def predict_proba_dict(self, X: np.ndarray) -> list[dict[str, float]]:
        """Predict class probabilities for X across all 6 ActivityClass members.

        Guarantees that:
        1. All 6 ActivityClass enum values are present as keys in each dict.
        2. Absent/missing training classes receive 0.0 probability.
        3. Probabilities in each dict sum to 1.0 (within 1e-6 tolerance).

        Returns:
            List of dicts mapping ActivityClass value str -> probability float.
        """
        if not self.is_fitted or self._model is None:
            raise ModelNotFittedError("RandomForestActivityModel must be fitted before prediction")

        if X.ndim == 1:
            X = X.reshape(1, -1)

        raw_probs = self._model.predict_proba(X)  # shape (N_samples, N_learned_classes)
        all_class_values = [ac.value for ac in ALL_ACTIVITY_CLASSES]
        results: list[dict[str, float]] = []

        for sample_idx in range(X.shape[0]):
            prob_dict: dict[str, float] = {ac_val: 0.0 for ac_val in all_class_values}

            # Map raw sklearn class indices to taxonomy values
            for learned_idx, cls_name in enumerate(self.learned_classes):
                if cls_name in prob_dict:
                    prob_dict[cls_name] = float(raw_probs[sample_idx, learned_idx])

            # Normalize to guarantee exact sum = 1.0
            total = sum(prob_dict.values())
            if total > 1e-12:
                prob_dict = {k: v / total for k, v in prob_dict.items()}
            else:
                # Uniform fallback if sum is 0
                prob_dict = {k: 1.0 / len(all_class_values) for k in all_class_values}

            results.append(prob_dict)

        return results

    def predict(
        self, X: np.ndarray
    ) -> list[tuple[ActivityClass, float, dict[str, float]]]:
        """Predict top ActivityClass, confidence, and full probability distribution.

        Returns:
            List of tuples: (predicted_activity_class, confidence, class_probabilities_dict)
        """
        prob_dicts = self.predict_proba_dict(X)
        outputs: list[tuple[ActivityClass, float, dict[str, float]]] = []

        for prob_dict in prob_dicts:
            # Find class with maximum probability
            top_class_str = max(prob_dict.keys(), key=lambda k: prob_dict[k])
            confidence = prob_dict[top_class_str]
            top_activity = validate_activity_class(top_class_str)
            outputs.append((top_activity, confidence, prob_dict))

        return outputs

    def to_dict(self) -> dict[str, Any]:
        """Serialize model state to a dict with embedded joblib blob."""
        if not self.is_fitted or self._model is None:
            raise ModelNotFittedError("Cannot serialize an unfitted model")

        buffer = io.BytesIO()
        joblib.dump(self._model, buffer)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")

        return {
            "model_type": MODEL_TYPE,
            "model_version": MODEL_VERSION,
            "hyperparameters": self.hyperparameters,
            "random_state": self.random_state,
            "feature_names": self.feature_names,
            "learned_classes": self.learned_classes,
            "training_class_counts": self.training_class_counts,
            "missing_classes": self.missing_classes,
            "model_blob": encoded,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RandomForestActivityModel":
        """Restore a model instance from a serialized dict."""
        inst = cls(
            hyperparameters=data.get("hyperparameters"),
            random_state=data.get("random_state", 42),
        )
        blob = base64.b64decode(data["model_blob"])
        inst._model = joblib.load(io.BytesIO(blob))
        inst.feature_names = list(data.get("feature_names", []))
        inst.learned_classes = list(data.get("learned_classes", []))
        inst.training_class_counts = dict(data.get("training_class_counts", {}))
        inst.missing_classes = list(data.get("missing_classes", []))
        return inst
