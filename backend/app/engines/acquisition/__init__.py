"""
backend/app/engines/acquisition/__init__.py
-------------------------------------------
Acquisition Engine — Phase 2, M1 V1.

Public surface:
    AcquisitionError       — domain error class
    AcquisitionErrorCode   — error classification enum
    AcquisitionService     — orchestrator (primary entry point)

Usage:
    from app.engines.acquisition import AcquisitionService, AcquisitionError, AcquisitionErrorCode

    service = AcquisitionService()
    try:
        ref = service.acquire("/path/to/evidence.pcap")
    except AcquisitionError as exc:
        print(exc.code, exc.detail)
"""

from .errors import AcquisitionError, AcquisitionErrorCode
from .service import AcquisitionService

__all__ = [
    "AcquisitionError",
    "AcquisitionErrorCode",
    "AcquisitionService",
]
