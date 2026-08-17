"""
backend/app/engines/acquisition/service.py
-------------------------------------------
Acquisition Engine orchestrator — Phase 2.

Responsibility:
  Orchestrate the acquisition pipeline and return a valid AcquisitionReference.

Pipeline:
  INPUT PATH
      ↓ validator.validate()       — path resolution, format, magic bytes
      ↓ hasher.compute_sha256()    — streamed SHA-256 of the original file
      ↓ _build_reference()         — construct immutable AcquisitionReference
      ↓ return AcquisitionReference

Design principles:
  - service.py contains ONLY orchestration. No validation logic. No hashing.
  - All I/O errors surface as AcquisitionError with a specific code.
  - IDs use uuid4 (universally unique, no coordination required).
  - acquired_at is set once at the moment acquire() is called.
  - The original file is never modified.

Boundary (Phase 2):
  This service does NOT:
    - invoke Zeek
    - parse conn.log / dns.log / http.log / ssl.log
    - create Flow / ProtocolEvent / Artifact objects
    - write to a database or object store
    - produce a NetworkIntelligencePackage
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.contracts.network_intelligence import AcquisitionReference, Provenance
from .errors import AcquisitionError, AcquisitionErrorCode
from .hasher import compute_sha256
from .validator import validate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACQUISITION_SOURCE = "m1-acquisition"
_ACQUISITION_PROCESSOR_VERSION = "m1-v1.0"


# ---------------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------------

class AcquisitionService:
    """Acquires a PCAP/PCAPNG evidence file and returns an AcquisitionReference.

    Usage:
        service = AcquisitionService()
        ref = service.acquire("/path/to/evidence.pcap")

    Raises:
        AcquisitionError — on any validation or I/O failure.
        No other exceptions escape this class.
    """

    def acquire(self, path: str | os.PathLike) -> AcquisitionReference:
        """Run the full acquisition pipeline on *path*.

        Parameters:
            path -- filesystem path to the PCAP or PCAPNG evidence file.

        Returns:
            AcquisitionReference — frozen Pydantic model, ready to attach
            to a NetworkIntelligencePackage.

        Raises:
            AcquisitionError with an AcquisitionErrorCode on failure.
        """
        # Step 1: Validate (path traversal guard, existence, magic bytes)
        validation = validate(path)

        # Step 2: Hash (streamed, read-only, original file untouched)
        sha256_digest = compute_sha256(validation.resolved_path)

        # Step 3: Build the immutable reference
        return _build_reference(
            validation_result=validation,
            sha256_digest=sha256_digest,
        )


# ---------------------------------------------------------------------------
# Internal builder
# ---------------------------------------------------------------------------

def _build_reference(
    validation_result,
    sha256_digest: str,
) -> AcquisitionReference:
    """Construct an AcquisitionReference from validated facts.

    Only factual, verifiable data is populated:
      - acquisition_id / evidence_id: uuid4 (standard; no project convention conflicts)
      - file_name:          from resolved path basename
      - file_size:          from stat (already computed during validation)
      - format:             from magic-byte detection ('pcap' | 'pcapng')
      - sha256:             streamed digest of original file bytes
      - capture_reference:  absolute path string (local dev; no object store)
      - acquired_at:        UTC timestamp at acquisition time
      - provenance:         source only; no Zeek data available yet

    Fields NOT populated (because they require Zeek / Phase 3+):
      - provenance.zeek_uid
      - provenance.source_log
      - provenance.processor_version (set to acquisition version only)
    """
    now_utc = datetime.now(timezone.utc)
    acquisition_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())

    provenance = Provenance(
        acquisition_id=acquisition_id,
        evidence_id=evidence_id,
        source=_ACQUISITION_SOURCE,
        source_log=None,          # Not yet available — populated in Phase 3+
        zeek_uid=None,            # Not yet available — populated in Phase 3+
        processed_at=now_utc,
        processor_version=_ACQUISITION_PROCESSOR_VERSION,
    )

    return AcquisitionReference(
        acquisition_id=acquisition_id,
        evidence_id=evidence_id,
        file_name=validation_result.file_name,
        file_size=validation_result.file_size,
        format=validation_result.format,
        sha256=sha256_digest,
        capture_reference=str(validation_result.resolved_path),
        acquired_at=now_utc,
        provenance=provenance,
    )
