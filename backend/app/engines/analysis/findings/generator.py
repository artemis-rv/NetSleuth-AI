"""
generator.py
------------
M2 Phase 8 — FindingsPackage Generator.

Converts AnalysisDecisionResult objects into immutable FindingsPackage output objects
consumable downstream by M3 (Correlation & Investigation).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from backend.app.contracts.analysis import (
    M2_CONTRACT_VERSION,
    Finding,
    FindingsPackage,
)
from backend.app.contracts.network_intelligence import NetworkIntelligencePackage
from backend.app.contracts.analysis import FeatureVector
from backend.app.engines.analysis.decision.result import AnalysisDecisionResult, DecisionState
from backend.app.engines.analysis.findings.builder import FindingBuilder, M2_ENGINE_VERSION
from backend.app.engines.analysis.findings.errors import MissingSourcePackageError

logger = logging.getLogger(__name__)


class FindingsGenerator:
    """Production generator for M2 FindingsPackage objects."""

    def __init__(self, builder: Optional[FindingBuilder] = None) -> None:
        self.builder = builder or FindingBuilder()

    def generate(
        self,
        package: NetworkIntelligencePackage,
        feature_vector: FeatureVector,
        decision_result: AnalysisDecisionResult,
        engine_version: str = M2_ENGINE_VERSION,
    ) -> FindingsPackage:
        """Generate an evidence-backed FindingsPackage.

        Args:
            package: Source NetworkIntelligencePackage.
            feature_vector: Source FeatureVector.
            decision_result: Output of Phase 7 AnalysisDecisionEngine.
            engine_version: Engine version string.

        Returns:
            An immutable FindingsPackage object.
        """
        if not package or not package.acquisition_id:
            raise MissingSourcePackageError("Source NetworkIntelligencePackage is missing or invalid")

        if package.acquisition_id != feature_vector.acquisition_id:
            raise MissingSourcePackageError(
                f"Acquisition ID mismatch: package '{package.acquisition_id}' vs "
                f"feature vector '{feature_vector.acquisition_id}'"
            )

        findings: list[Finding] = []

        # Empty finding case: benign traffic without anomaly flags produces an empty findings list
        if (
            decision_result.decision_state == DecisionState.BENIGN
            and not decision_result.anomaly_result.anomaly_detected
        ):
            logger.info("Acquisition '%s' evaluated as BENIGN; producing empty findings list", package.acquisition_id)
        else:
            # Produce finding for non-benign or anomalous activity
            finding = self.builder.build_finding(package, feature_vector, decision_result, engine_version)
            findings.append(finding)

        package_id = f"FP-{uuid4().hex[:12].upper()}"

        return FindingsPackage(
            package_id=package_id,
            contract_version=M2_CONTRACT_VERSION,
            acquisition_id=package.acquisition_id,
            source_package_id=package.package_id,
            findings=findings,
            analysis_engine_version=engine_version,
            feature_schema_version=feature_vector.schema_version,
            anomaly_model_version=decision_result.anomaly_result.model_version,
            classifier_model_version=decision_result.classification_result.model_version,
            analysed_at=datetime.now(timezone.utc),
        )
