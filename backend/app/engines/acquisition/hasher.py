"""
backend/app/engines/acquisition/hasher.py
------------------------------------------
SHA-256 computation for evidence files.

Design principles:
  - Streamed/chunked reading: never loads the entire file into memory.
  - Chunk size (64 KB) is a well-tested balance between I/O call overhead
    and memory usage; appropriate for arbitrarily large captures.
  - Returns lowercase hexadecimal digest as required by the contract.
  - Uses only Python standard library (hashlib) — no new dependencies.
  - The file is opened in binary mode; no transformation or normalisation
    is applied. The digest corresponds exactly to the original file bytes.
  - No write operations. The original evidence file is never modified.

Security:
  - Input path must be pre-validated by validator.validate() before calling
    compute_sha256(). This module trusts that the caller has performed path
    resolution and existence checks.
  - Opens file read-only (mode "rb").
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .errors import AcquisitionError, AcquisitionErrorCode

# ---------------------------------------------------------------------------
# Tuning
# ---------------------------------------------------------------------------

# 64 KiB per read. Keeps memory footprint constant regardless of file size.
# For most capture files this means the hot loop runs in < 1 ms per 64 KB.
_CHUNK_SIZE: int = 65536


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_sha256(path: Path | str | os.PathLike) -> str:
    """Compute the SHA-256 digest of the file at *path*.

    Reads the file in 64 KiB chunks to bound memory usage.

    Parameters:
        path -- absolute, resolved path to the evidence file.
                Must already be validated (exists, is a regular file).

    Returns:
        Lowercase hexadecimal SHA-256 digest string (64 characters).

    Raises:
        AcquisitionError(HASH_FAILURE) if the file cannot be read.
        AcquisitionError(UNREADABLE_FILE) if permission is denied.
    """
    resolved = Path(path)
    digest = hashlib.sha256()

    try:
        with resolved.open("rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except PermissionError as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.UNREADABLE_FILE,
            f"Permission denied while hashing evidence file: {resolved}",
        ) from exc
    except OSError as exc:
        raise AcquisitionError(
            AcquisitionErrorCode.HASH_FAILURE,
            f"I/O error while hashing evidence file: {resolved} — {exc}",
        ) from exc

    return digest.hexdigest()
