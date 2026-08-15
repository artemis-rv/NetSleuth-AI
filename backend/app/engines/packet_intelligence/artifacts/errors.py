"""
backend/app/engines/packet_intelligence/artifacts/errors.py
-----------------------------------------------------------
Domain errors for Artifact Extraction.
"""

from dataclasses import dataclass
from enum import Enum


class ArtifactExtractionErrorCode(str, Enum):
    """Classification codes for artifact extraction failures."""

    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    MALFORMED_DATA = "MALFORMED_DATA"


@dataclass(frozen=True)
class ArtifactExtractionError(Exception):
    """Exception raised when an artifact cannot be extracted deterministically."""

    code: ArtifactExtractionErrorCode
    message: str
    event_id: str
