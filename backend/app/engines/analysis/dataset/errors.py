"""
errors.py
---------
M2 dataset engine exception hierarchy.

All exceptions raised by the dataset package (loader, cleaner, labels)
inherit from DatasetError so callers can catch the full family in one clause.
"""

from __future__ import annotations


class DatasetError(Exception):
    """Base class for all M2 dataset errors."""


class DatasetFileNotFoundError(DatasetError):
    """Raised when a required dataset CSV file cannot be located."""


class DatasetEmptyError(DatasetError):
    """Raised when a dataset file contains no data rows after loading."""


class DatasetSchemaError(DatasetError):
    """Raised when a required column is absent from the dataset file."""


class DatasetCleaningError(DatasetError):
    """Raised when a fatal data-quality problem is detected during cleaning."""


class LabelMappingError(DatasetError):
    """Raised when the label mapping table itself contains a configuration error."""
