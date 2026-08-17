"""M2 Phase 5 anomaly model errors."""


class AnomalyModelError(Exception):
    """Base error for anomaly model operations."""


class SchemaVersionMismatchError(AnomalyModelError):
    """Raised when a FeatureVector schema version does not match the artifact."""


class MissingFeatureError(AnomalyModelError):
    """Raised when a FeatureVector lacks required present features for inference."""


class ModelNotFittedError(AnomalyModelError):
    """Raised when inference is attempted on an unfitted artifact."""
