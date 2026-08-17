"""
builder.py
----------
M2 Phase 8 — Finding Builder.

Constructs immutable Finding objects from AnalysisDecisionResult, FeatureVector,
and source NetworkIntelligencePackage.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from backend.app.contracts.analysis import Finding
from backend.app.contracts.network_intelligence import NetworkIntelligencePackage
from backend.app.engines.analysis.decision.result import AnalysisDecisionResult
from backend.app.engines.analysis.findings.attribution import FeatureAttributor

logger = logging.getLogger(__name__)

M2_ENGINE_VERSION = "1.0"


class FindingBuilder:
    """Production builder for immutable M2 Finding objects."""

    def __init__(self, attributor: Optional[FeatureAttributor] = None) -> None:
        self.attributor = attributor or FeatureAttributor()

    def _extract_observation_window(
        self, package: NetworkIntelligencePackage
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """Extract min start timestamp and max end timestamp from package flows and events."""
        timestamps: list[datetime] = []

        for flow in package.flows:
            if flow.timestamp is not None:
                timestamps.append(flow.timestamp)

        for event in package.protocol_events:
            if event.timestamp is not None:
                timestamps.append(event.timestamp)

        if not timestamps:
            return None, None

        return min(timestamps), max(timestamps)

    def build_finding(
        self,
        package: NetworkIntelligencePackage,
        feature_vector: FeatureVector,
        decision_result: AnalysisDecisionResult,
        engine_version: str = M2_ENGINE_VERSION,
    ) -> Finding:
        """Construct a valid, evidence-backed Finding object.

        Args:
            package: Source NetworkIntelligencePackage.
            feature_vector: FeatureVector analyzed.
            decision_result: Output of Phase 7 AnalysisDecisionEngine.
            engine_version: M2 engine version string.

        Returns:
            An immutable Finding object.
        """
        obs_start, obs_end = self._extract_observation_window(package)
        evidence_refs = self.attributor.extract_evidence_references(
            package, decision_result, feature_vector
        )

        feature_snapshot = feature_vector.as_numeric_dict()
        finding_id = f"F-{uuid4().hex[:12].upper()}"

        return Finding(
            finding_id=finding_id,
            acquisition_id=package.acquisition_id,
            activity_class=decision_result.predicted_activity,
            decision_state=decision_result.decision_state.value,
            anomaly_score=decision_result.anomaly_score,
            anomaly_detected=decision_result.anomaly_result.anomaly_detected,
            classification_confidence=decision_result.confidence,
            risk_score=decision_result.risk_score,
            feature_schema_version=feature_vector.schema_version,
            anomaly_model_version=decision_result.anomaly_result.model_version,
            classifier_model_version=decision_result.classification_result.model_version,
            evidence_references=evidence_refs,
            feature_snapshot=feature_snapshot,
            observation_start=obs_start,
            observation_end=obs_end,
            anomaly_result=decision_result.anomaly_result,
            classification_result=decision_result.classification_result,
            model_version=engine_version,
            created_at=datetime.now(timezone.utc),
        )
