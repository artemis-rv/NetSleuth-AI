"""
errors.py
---------
M2 Phase 8 — Findings generation and evidence attribution exceptions.
"""

from __future__ import annotations


class FindingsGenerationError(Exception):
    """Base exception for findings generation errors."""


class FabricatedEvidenceError(FindingsGenerationError):
    """Raised when an evidence reference contains fabricated or unverified M1 object IDs."""


class MissingSourcePackageError(FindingsGenerationError):
    """Raised when source NetworkIntelligencePackage is missing or invalid."""
