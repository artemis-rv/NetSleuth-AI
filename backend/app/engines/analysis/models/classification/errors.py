"""
errors.py
---------
M2 Phase 6 — Classification engine exception types.
"""

from __future__ import annotations


class ClassificationError(Exception):
    """Base exception for M2 classification errors."""


class ModelNotFittedError(ClassificationError):
    """Raised when attempting inference or serialization on an unfitted model."""


class SchemaVersionMismatchError(ClassificationError):
    """Raised when a feature vector or artifact schema version does not match."""


class MissingFeatureError(ClassificationError):
    """Raised when required features are missing from an input vector."""


class LabelMappingError(ClassificationError):
    """Raised when an invalid or uncertain label cannot be normalized."""


class InsufficientClassSamplesError(ClassificationError):
    """Raised when training data has insufficient samples for classification."""
