"""
backend/app/engines/packet_intelligence/zeek/errors.py
------------------------------------------------------
Domain error types for the Zeek Runner (Phase 3).

Design principles:
  - Each failure mode has an explicit, named code.
  - Callers can branch on `code` without parsing message strings.
  - Stack traces are never exposed as the primary domain error.
"""

from enum import Enum


class ZeekRunnerErrorCode(str, Enum):
    """Classification codes for Zeek Runner failures."""

    DOCKER_NOT_FOUND = "DOCKER_NOT_FOUND"
    DOCKER_DAEMON_UNAVAILABLE = "DOCKER_DAEMON_UNAVAILABLE"
    IMAGE_UNAVAILABLE = "IMAGE_UNAVAILABLE"
    INVALID_INPUT_PATH = "INVALID_INPUT_PATH"
    PATH_TRAVERSAL_DETECTED = "PATH_TRAVERSAL_DETECTED"
    OUTPUT_DIR_ERROR = "OUTPUT_DIR_ERROR"
    DOCKER_PROCESS_FAILED = "DOCKER_PROCESS_FAILED"
    ZEEK_NONZERO_EXIT = "ZEEK_NONZERO_EXIT"
    TIMEOUT = "TIMEOUT"
    CAPTURE_NOT_FOUND = "CAPTURE_NOT_FOUND"


class ZeekRunnerError(Exception):
    """Controlled domain error raised by the Zeek Runner.

    Attributes:
        code   -- machine-readable failure classification
        detail -- human-readable description
    """

    def __init__(self, code: ZeekRunnerErrorCode, detail: str) -> None:
        if not isinstance(code, ZeekRunnerErrorCode):
            raise TypeError(
                f"code must be ZeekRunnerErrorCode, got {type(code).__name__!r}"
            )
        self.code = code
        self.detail = detail
        super().__init__(f"[{code.value}] {detail}")

    def __repr__(self) -> str:
        return f"ZeekRunnerError(code={self.code!r}, detail={self.detail!r})"
