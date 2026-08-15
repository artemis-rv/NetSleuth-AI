"""
backend/app/engines/packet_intelligence/errors.py
-------------------------------------------------
High-level errors for the Packet Intelligence Orchestrator.
"""

from dataclasses import dataclass
from enum import Enum


class PackageAssemblyErrorCode(str, Enum):
    """Classification codes for package assembly failures."""

    ACQUISITION_MISMATCH = "ACQUISITION_MISMATCH"
    BROKEN_FLOW_REFERENCE = "BROKEN_FLOW_REFERENCE"
    BROKEN_EVENT_REFERENCE = "BROKEN_EVENT_REFERENCE"
    PROVENANCE_FAILURE = "PROVENANCE_FAILURE"
    MISSING_REQUIRED_DATA = "MISSING_REQUIRED_DATA"


@dataclass(frozen=True)
class PackageAssemblyError(Exception):
    """Exception raised when referential integrity fails during package assembly."""

    code: PackageAssemblyErrorCode
    message: str
    acquisition_id: str
