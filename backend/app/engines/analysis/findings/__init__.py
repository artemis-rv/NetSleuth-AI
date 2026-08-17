"""
M2 Phase 8 — Evidence Attribution and FindingsPackage Generation Package.

Exposes production components for converting decision results into evidence-backed
FindingsPackage objects consumable by M3.
"""

from app.engines.analysis.findings.attribution import FeatureAttributor
from app.engines.analysis.findings.builder import FindingBuilder
from app.engines.analysis.findings.errors import (
    FabricatedEvidenceError,
    FindingsGenerationError,
    MissingSourcePackageError,
)
from app.engines.analysis.findings.generator import FindingsGenerator

__all__ = [
    "FindingsGenerator",
    "FindingBuilder",
    "FeatureAttributor",
    "FindingsGenerationError",
    "FabricatedEvidenceError",
    "MissingSourcePackageError",
]
