"""
backend/app/engines/packet_intelligence/zeek/result.py
------------------------------------------------------
Result types for the Zeek Runner (Phase 3).
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ZeekRunnerStatus(str, Enum):
    """Execution status codes for a Zeek run."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


@dataclass(frozen=True)
class ZeekRunnerResult:
    """Immutable execution result for the Zeek Runner.

    This represents the execution metadata and is an M1 internal structure,
    NOT the downstream NetworkIntelligencePackage.
    """

    acquisition_id: str
    status: ZeekRunnerStatus
    bucket: str
    prefix: str
    generated_objects: list[str]       # keys of files uploaded to MinIO
    exit_code: int | None
    execution_duration_s: float
    zeek_image: str
    zeek_version: str
    stderr_tail: str                   # last N lines of stderr, never None
