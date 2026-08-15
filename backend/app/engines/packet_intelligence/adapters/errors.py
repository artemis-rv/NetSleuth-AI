"""
backend/app/engines/packet_intelligence/adapters/errors.py
----------------------------------------------------------
Domain errors for the Packet Intelligence adapters.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AdapterErrorCode(str, Enum):
    """Classification codes for adapter mapping failures."""

    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_TYPE = "INVALID_TYPE"
    UNSUPPORTED_LOG_TYPE = "UNSUPPORTED_LOG_TYPE"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    UNKNOWN_UID = "UNKNOWN_UID"


@dataclass(frozen=True)
class AdapterError:
    """A deterministic mapping failure returned by an adapter.
    
    Used in place of raising exceptions to allow for safe, streaming
    processing of Zeek logs without crashing the pipeline on a single
    bad record.
    """

    code: AdapterErrorCode
    message: str
    source_log: str
    line_number: int
    raw_record: dict[str, Any]
