"""
backend/app/engines/packet_intelligence/provenance/errors.py
------------------------------------------------------------
Domain errors for Provenance validation.
"""

from dataclasses import dataclass
from enum import Enum


class ProvenanceErrorCode(str, Enum):
    """Classification codes for provenance validation failures."""

    MISMATCHED_EVENT_ID = "MISMATCHED_EVENT_ID"
    MISMATCHED_FLOW_ID = "MISMATCHED_FLOW_ID"
    MISMATCHED_ACQUISITION_ID = "MISMATCHED_ACQUISITION_ID"
    MISSING_REQUIRED_REFERENCE = "MISSING_REQUIRED_REFERENCE"


@dataclass(frozen=True)
class ProvenanceError(Exception):
    """Exception raised when an object's provenance references do not match its claimed source."""

    code: ProvenanceErrorCode
    message: str
    artifact_id: str
    source_event_id: str
