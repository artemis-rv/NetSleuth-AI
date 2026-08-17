"""
M2 Phase 6 — Supervised Activity Classification Package.

Exposes production components for training, evaluating, serializing, and running
inference with the M2 Supervised Activity Classifier.
"""

from app.engines.analysis.models.classification.errors import (
    ClassificationError,
    InsufficientClassSamplesError,
    LabelMappingError,
    MissingFeatureError,
    ModelNotFittedError,
    SchemaVersionMismatchError,
)
from app.engines.analysis.models.classification.evaluator import (
    ClassificationEvaluationReport,
    evaluate_classifier,
)
from app.engines.analysis.models.classification.label_map import (
    ALL_ACTIVITY_CLASSES,
    CICIDS_LABEL_MAP,
    LABEL_MAPPING_VERSION,
    map_cicids_label,
    validate_activity_class,
)
from app.engines.analysis.models.classification.model_artifact import (
    ClassificationModelArtifact,
    build_classification_artifact,
)
from app.engines.analysis.models.classification.predictor import (
    ActivityClassifier,
    ClassificationPrediction,
)
from app.engines.analysis.models.classification.random_forest import (
    DEFAULT_HYPERPARAMETERS,
    MODEL_TYPE,
    MODEL_VERSION,
    RandomForestActivityModel,
)

__all__ = [
    "ClassificationError",
    "ModelNotFittedError",
    "SchemaVersionMismatchError",
    "MissingFeatureError",
    "LabelMappingError",
    "InsufficientClassSamplesError",
    "ClassificationEvaluationReport",
    "evaluate_classifier",
    "ALL_ACTIVITY_CLASSES",
    "CICIDS_LABEL_MAP",
    "LABEL_MAPPING_VERSION",
    "map_cicids_label",
    "validate_activity_class",
    "ClassificationModelArtifact",
    "build_classification_artifact",
    "ActivityClassifier",
    "ClassificationPrediction",
    "DEFAULT_HYPERPARAMETERS",
    "MODEL_TYPE",
    "MODEL_VERSION",
    "RandomForestActivityModel",
]
