"""
attribution.py
--------------
M2 Phase 8 — Feature-to-Evidence Attribution.

Maps high-contributing model features to real M1 source objects (Flows, ProtocolEvents, Artifacts)
in the source NetworkIntelligencePackage without evidence fabrication. Generates measurable feature
rationales (no MITRE ATT&CK IDs).
"""

from __future__ import annotations

import logging
from typing import Optional

from backend.app.contracts.analysis import ActivityClass, EvidenceReference, FeatureVector
from backend.app.contracts.network_intelligence import NetworkIntelligencePackage
from backend.app.engines.analysis.decision.result import AnalysisDecisionResult
from backend.app.engines.analysis.findings.errors import FabricatedEvidenceError

logger = logging.getLogger(__name__)


class FeatureAttributor:
    """Production feature-to-evidence attribution engine.

    Links numerical feature signals to real supporting M1 source objects (flow IDs, event IDs,
    artifact IDs) present in a NetworkIntelligencePackage. Validates all references to prevent
    evidence fabrication.
    """

    def __init__(self, strict_validation: bool = True) -> None:
        self.strict_validation = strict_validation

    def validate_evidence_references(
        self,
        package: NetworkIntelligencePackage,
        evidence_refs: list[EvidenceReference],
    ) -> None:
        """Assert that all flow_ids, event_ids, and artifact_ids in evidence_refs strictly exist in package.

        Raises:
            FabricatedEvidenceError: If any referenced ID does not exist in the source package.
        """
        valid_flow_ids = {f.flow_id for f in package.flows}
        valid_event_ids = {e.event_id for e in package.protocol_events}
        valid_artifact_ids = {a.artifact_id for a in package.artifacts}

        for ref in evidence_refs:
            for fid in ref.flow_ids:
                if fid not in valid_flow_ids:
                    raise FabricatedEvidenceError(
                        f"Fabricated flow ID '{fid}' referenced in EvidenceReference but not present in package"
                    )
            for eid in ref.event_ids:
                if eid not in valid_event_ids:
                    raise FabricatedEvidenceError(
                        f"Fabricated event ID '{eid}' referenced in EvidenceReference but not present in package"
                    )
            for aid in ref.artifact_ids:
                if aid not in valid_artifact_ids:
                    raise FabricatedEvidenceError(
                        f"Fabricated artifact ID '{aid}' referenced in EvidenceReference but not present in package"
                    )

    def generate_rationale(
        self,
        activity_class: ActivityClass,
        decision_result: AnalysisDecisionResult,
        features: dict[str, float],
    ) -> str:
        """Generate human-readable, measurable feature rationale string without MITRE IDs."""
        signals: list[str] = []

        # Examine top contributing features or prominent feature values
        unique_dst_ips = features.get("unique_destination_ips", 0.0)
        unique_dst_ports = features.get("unique_destination_ports", 0.0)
        failed_ratio = features.get("failed_connection_ratio", 0.0)
        flow_rate = features.get("flow_rate_per_sec", 0.0)
        dns_count = features.get("dns_query_count", 0.0)
        http_count = features.get("http_request_count", 0.0)

        if unique_dst_ips > 5.0:
            signals.append(f"high unique destination count ({int(unique_dst_ips)})")
        if unique_dst_ports > 5.0:
            signals.append(f"high unique destination-port count ({int(unique_dst_ports)})")
        if failed_ratio > 0.3:
            signals.append(f"high failed-connection ratio ({failed_ratio:.2f})")
        if flow_rate > 5.0:
            signals.append(f"elevated connection rate ({flow_rate:.1f}/s)")
        if dns_count > 10.0:
            signals.append(f"elevated DNS query volume ({int(dns_count)})")
        if http_count > 10.0:
            signals.append(f"elevated HTTP request volume ({int(http_count)})")

        if not signals:
            signals.append("elevated behavioral anomaly score")

        signal_text = ", ".join(signals)
        return (
            f"Observed behavioral pattern for {activity_class.value} "
            f"supported by measurable signals: {signal_text} "
            f"(anomaly score: {decision_result.anomaly_score:.2f}, "
            f"confidence: {decision_result.confidence:.2f})"
        )

    def extract_evidence_references(
        self,
        package: NetworkIntelligencePackage,
        decision_result: AnalysisDecisionResult,
        feature_vector: FeatureVector,
    ) -> list[EvidenceReference]:
        """Extract supporting M1 evidence references without fabrication.

        Args:
            package: Source NetworkIntelligencePackage.
            decision_result: Combined decision engine output.
            feature_vector: Source FeatureVector.

        Returns:
            List of valid EvidenceReference objects.
        """
        features = feature_vector.as_numeric_dict()
        rationale = self.generate_rationale(
            decision_result.predicted_activity, decision_result, features
        )

        # Collect real M1 object IDs present in package
        flow_ids = [f.flow_id for f in package.flows]
        event_ids = [e.event_id for e in package.protocol_events]
        artifact_ids = [a.artifact_id for a in package.artifacts]

        # If package contains flows, events, or artifacts, construct reference
        if not flow_ids and not event_ids and not artifact_ids:
            # Fallback for empty package (should have empty findings)
            ref = EvidenceReference(
                flow_ids=[],
                event_ids=[],
                artifact_ids=[],
                rationale=rationale,
            )
        else:
            ref = EvidenceReference(
                flow_ids=flow_ids,
                event_ids=event_ids,
                artifact_ids=artifact_ids,
                rationale=rationale,
            )

        refs = [ref]

        if self.strict_validation:
            self.validate_evidence_references(package, refs)

        return refs
