"""
backend/app/engines/acquisition/errors.py
------------------------------------------
Domain error types for the Acquisition Engine.

Design principles:
  - Each failure mode has an explicit, named code.
  - Callers can branch on `code` without parsing message strings.
  - Stack traces are never exposed as the primary domain error;
    the original exception is preserved as __cause__ for debugging.
  - No third-party dependencies.
"""

from enum import Enum


class AcquisitionErrorCode(str, Enum):
    """Classification codes for acquisition failures.

    Each code maps to exactly one failure category. Callers must
    handle these explicitly rather than catching bare Exception.
    """

    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    NOT_A_FILE = "NOT_A_FILE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    EMPTY_FILE = "EMPTY_FILE"
    UNREADABLE_FILE = "UNREADABLE_FILE"
    INVALID_CAPTURE = "INVALID_CAPTURE"
    HASH_FAILURE = "HASH_FAILURE"


class AcquisitionError(Exception):
    """Controlled domain error raised by the Acquisition Engine.

    Attributes:
        code   -- machine-readable failure classification
        detail -- human-readable description (never a raw traceback)

    Example:
        raise AcquisitionError(
            AcquisitionErrorCode.FILE_NOT_FOUND,
            f"Evidence file not found: {path!r}"
        )
    """

    def __init__(self, code: AcquisitionErrorCode, detail: str) -> None:
        if not isinstance(code, AcquisitionErrorCode):
            raise TypeError(
                f"code must be AcquisitionErrorCode, got {type(code).__name__!r}"
            )
        self.code = code
        self.detail = detail
        super().__init__(f"[{code.value}] {detail}")

    def __repr__(self) -> str:
        return f"AcquisitionError(code={self.code!r}, detail={self.detail!r})"
