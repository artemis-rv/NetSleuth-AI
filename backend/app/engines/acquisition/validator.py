"""
backend/app/engines/acquisition/validator.py
---------------------------------------------
Input validation for PCAP/PCAPNG evidence files.

Validation pipeline (in execution order):
  1. Path existence
  2. Regular-file assertion (not a directory, symlink-to-dir, device, etc.)
  3. Extension check (.pcap / .pcapng only)
  4. Non-empty file
  5. Readability (open for binary read)
  6. Magic-byte format verification

Security design:
  - Path is resolved to an absolute, canonical path via Path.resolve()
    before any filesystem operation. This eliminates path-traversal vectors
    (e.g. "../../../etc/passwd", null bytes, etc.).
  - No subprocess / shell calls.
  - No arbitrary binary execution.
  - File is opened read-only; the original is never modified.
  - Only the first few bytes are read for magic validation — minimal I/O.

Format detection:
  Magic bytes are read directly; extension alone is not trusted.

  PCAP  (libpcap classic):
    Little-endian: 0xd4 0xc3 0xb2 0xa1
    Big-endian:    0xa1 0xb2 0xc3 0xd4
    Nanosecond LE: 0x4d 0x3c 0xb2 0xa1
    Nanosecond BE: 0xa1 0xb2 0x3c 0x4d

  PCAPNG (Section Header Block):
    Bytes 0-3:  0x0a 0x0d 0x0d 0x0a  (SHB block type)

  Reference: https://pcapng.com / https://wiki.wireshark.org/Development/LibpcapFileFormat

No max-file-size check is implemented — no project policy exists.
See: RISKS in docs/M1_V1_IMPLEMENTATION_SUMMARY.md
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from .errors import AcquisitionError, AcquisitionErrorCode

# ---------------------------------------------------------------------------
# Supported extensions (lowercase, with leading dot)
# ---------------------------------------------------------------------------

_SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({".pcap", ".pcapng"})

# ---------------------------------------------------------------------------
# Magic bytes
# PCAP: 4-byte magic at offset 0
# PCAPNG: 4-byte SHB block type at offset 0
# ---------------------------------------------------------------------------

_PCAP_MAGIC_BYTES: frozenset[bytes] = frozenset({
    b"\xd4\xc3\xb2\xa1",  # libpcap LE
    b"\xa1\xb2\xc3\xd4",  # libpcap BE
    b"\x4d\x3c\xb2\xa1",  # libpcap nanosecond LE
    b"\xa1\xb2\x3c\x4d",  # libpcap nanosecond BE
})

_PCAPNG_MAGIC: bytes = b"\x0a\x0d\x0d\x0a"  # SHB block type

_MAGIC_READ_BYTES = 4  # bytes needed to identify either format


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

class ValidationResult(NamedTuple):
    """Returned by validate() on success.

    Attributes:
        resolved_path -- absolute, canonical path (use this for all I/O)
        format        -- 'pcap' or 'pcapng' (derived from magic bytes)
        file_size     -- file size in bytes
        file_name     -- basename of the original path
    """

    resolved_path: Path
    format: str          # 'pcap' | 'pcapng'
    file_size: int
    file_name: str


# ---------------------------------------------------------------------------
# Public validator
# ---------------------------------------------------------------------------

def validate(path: str | os.PathLike) -> ValidationResult:
    """Validate a PCAP/PCAPNG file at *path*.

    Parameters:
        path -- filesystem path to the evidence file (treated as untrusted)

    Returns:
        ValidationResult on success.

    Raises:
        AcquisitionError with a specific AcquisitionErrorCode on any failure.
        No other exceptions escape this function.
    """
    # --- Step 1: Resolve to canonical, absolute path (path-traversal guard) ---
    try:
        resolved = Path(path).resolve()
    except (TypeError, ValueError) as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.FILE_NOT_FOUND,
            f"Invalid path argument: {path!r}",
        ) from exc

    # --- Step 2: Existence check ---
    if not resolved.exists():
        raise AcquisitionError(
            AcquisitionErrorCode.FILE_NOT_FOUND,
            f"Evidence file not found: {resolved}",
        )

    # --- Step 3: Regular-file assertion ---
    if not resolved.is_file():
        raise AcquisitionError(
            AcquisitionErrorCode.NOT_A_FILE,
            f"Path is not a regular file: {resolved}",
        )

    # --- Step 4: Extension check (fast pre-filter; magic still required) ---
    suffix = resolved.suffix.lower()
    if suffix not in _SUPPORTED_EXTENSIONS:
        raise AcquisitionError(
            AcquisitionErrorCode.UNSUPPORTED_FORMAT,
            f"Unsupported file extension {suffix!r}. "
            f"Supported: {sorted(_SUPPORTED_EXTENSIONS)}",
        )

    # --- Step 5: Non-empty file ---
    try:
        file_size = resolved.stat().st_size
    except OSError as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.UNREADABLE_FILE,
            f"Cannot stat file: {resolved} — {exc}",
        ) from exc

    if file_size == 0:
        raise AcquisitionError(
            AcquisitionErrorCode.EMPTY_FILE,
            f"Evidence file is empty (0 bytes): {resolved}",
        )

    # --- Step 6: Readability + magic-byte validation ---
    detected_format = _read_and_validate_magic(resolved)

    return ValidationResult(
        resolved_path=resolved,
        format=detected_format,
        file_size=file_size,
        file_name=resolved.name,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_and_validate_magic(resolved: Path) -> str:
    """Read the first 4 bytes and identify the capture format.

    Returns 'pcap' or 'pcapng'.
    Raises AcquisitionError on read failure or unrecognised magic.
    """
    try:
        with resolved.open("rb") as fh:
            magic = fh.read(_MAGIC_READ_BYTES)
    except PermissionError as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.UNREADABLE_FILE,
            f"Permission denied reading evidence file: {resolved}",
        ) from exc
    except OSError as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.UNREADABLE_FILE,
            f"Cannot read evidence file: {resolved} — {exc}",
        ) from exc

    if len(magic) < _MAGIC_READ_BYTES:
        raise AcquisitionError(
            AcquisitionErrorCode.INVALID_CAPTURE,
            f"File is too short to be a valid capture ({len(magic)} bytes): {resolved}",
        )

    if magic == _PCAPNG_MAGIC:
        return "pcapng"

    if magic in _PCAP_MAGIC_BYTES:
        return "pcap"

    raise AcquisitionError(
        AcquisitionErrorCode.INVALID_CAPTURE,
        f"Unrecognised capture magic bytes {magic.hex()!r}: {resolved}. "
        "File does not appear to be a valid PCAP or PCAPNG capture.",
    )
