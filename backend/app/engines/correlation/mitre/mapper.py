import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.app.engines.correlation.domain.input import M3InvestigationInput
from backend.app.engines.correlation.mitre.models import MitreMapping, MappingStatus
from backend.app.engines.correlation.mitre.repository import MitreKnowledgeRepository


class MitreMapper:
    """
    Runtime mapping engine that evaluates an M2 finding inside an M3 investigation
    context against the static MITRE knowledge base, producing deterministic MitreMappings.
    """
    def __init__(self, repository: MitreKnowledgeRepository):
        self.repo = repository

    def _generate_mapping_id(self, finding_id: str, technique_id: str) -> str:
        """Deterministic ID based on finding, technique, and knowledge profile."""
        seed = f"{finding_id}|{technique_id}|{self.repo.profile_id}".encode("utf-8")
        return "map-" + hashlib.sha256(seed).hexdigest()[:24]
        
    def _calculate_confidence(self, base_confidence: float, status: MappingStatus) -> float:
        """
        Derives mapping confidence from M2's base confidence modified by
        the telemetry evidence sufficiency.
        """
        if status == MappingStatus.SUPPORTED:
            modifier = 1.0
        elif status == MappingStatus.PARTIAL:
            modifier = 0.8
        elif status == MappingStatus.POTENTIAL:
            modifier = 0.5
        else:
            modifier = 0.0
            
        return max(0.0, min(1.0, base_confidence * modifier))

    def _get_valid_evidence(self, input_ctx: M3InvestigationInput, finding: Any) -> List[str]:
        """
        Ensures the evidence referenced by the finding actually exists in the EvidenceIndex.
        """
        valid = []
        for ev_ref in finding.evidence_references:
            for flow_id in ev_ref.flow_ids:
                if flow_id in input_ctx.evidence_index.flows:
                    valid.append(flow_id)
            for event_id in ev_ref.event_ids:
                if event_id in input_ctx.evidence_index.events:
                    valid.append(event_id)
            for artifact_id in ev_ref.artifact_ids:
                if artifact_id in input_ctx.evidence_index.artifacts:
                    valid.append(artifact_id)
        return valid

    def map_finding(self, input_ctx: M3InvestigationInput, finding_id: str) -> List[MitreMapping]:
        finding = input_ctx.evidence_index.findings.get(finding_id)
        if not finding:
            return []
            
        valid_evidence = self._get_valid_evidence(input_ctx, finding)
        if not valid_evidence:
            return []
            
        behavior = self.repo.get_behavior_mapping(finding.activity_class)
        if not behavior:
            return []
            
        results = []
        
        # Evaluate each candidate technique
        for candidate in behavior.get("candidate_techniques", []):
            tech_id = candidate["id"]
            
            status, rationale = self._evaluate_technique(input_ctx, finding, behavior["behavior_id"], candidate)
            
            if status != MappingStatus.NOT_APPLICABLE and status != MappingStatus.INSUFFICIENT_EVIDENCE:
                tech_details = self.repo.get_technique_details(tech_id)
                confidence = self._calculate_confidence(finding.classification_confidence, status)
                
                mapping = MitreMapping(
                    mapping_id=self._generate_mapping_id(finding_id, tech_id),
                    finding_id=finding_id,
                    behavior_id=behavior["behavior_id"],
                    technique_id=tech_id,
                    technique_name=tech_details["name"],
                    tactic_id=tech_details.get("tactic_id"),
                    tactic_name=tech_details.get("tactic_name"),
                    detection_strategy_ids=tech_details.get("detection_strategies", []),
                    analytic_ids=tech_details.get("analytics", []),
                    data_component_ids=candidate.get("required_telemetry", []),
                    channels=candidate.get("local_channels", []),
                    mapping_status=status,
                    mapping_confidence=confidence,
                    rationale=rationale,
                    evidence_ids=valid_evidence,
                    first_seen=finding.observation_start,
                    last_seen=finding.observation_end,
                    knowledge_profile_id=self.repo.profile_id,
                    mitre_version=self.repo.mitre_version
                )
                results.append(mapping)
                
        return results

    def _evaluate_technique(self, input_ctx: M3InvestigationInput, finding: Any, behavior_id: str, candidate: Dict[str, Any]) -> tuple[MappingStatus, str]:
        """
        The core five-behavior evaluation logic.
        """
        tech_id = candidate["id"]
        
        if behavior_id == "C2_MALWARE_COMMUNICATION":
            if tech_id == "T1071.001":
                # Web Protocol
                if input_ctx.telemetry_capabilities.http or input_ctx.telemetry_capabilities.tls:
                    return MappingStatus.SUPPORTED, "Web protocol evidence (HTTP/TLS) satisfies technique requirements."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "Missing required HTTP/TLS evidence."
                
            elif tech_id == "T1071.004":
                # DNS Protocol
                if input_ctx.telemetry_capabilities.dns:
                    return MappingStatus.SUPPORTED, "DNS protocol evidence satisfies technique requirements."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "Missing required DNS evidence."
                
            elif tech_id == "T1095":
                # Non-App Layer
                if not input_ctx.telemetry_capabilities.http and not input_ctx.telemetry_capabilities.tls and not input_ctx.telemetry_capabilities.dns:
                    return MappingStatus.SUPPORTED, "Non-application layer anomaly fits T1095 profile."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "Application-layer evidence overrides non-app profile."
                
        elif behavior_id == "DNS_ANOMALY_TUNNELING":
            if tech_id == "T1071.004":
                if input_ctx.telemetry_capabilities.dns:
                    return MappingStatus.SUPPORTED, "DNS protocol evidence explicitly supports anomaly."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "No DNS telemetry found to support tunneling."
                
        elif behavior_id == "SCANNING_RECONNAISSANCE":
            if tech_id == "T1046":
                # Even if flow is present, it's statically PARTIAL because we lack endpoint/auditd data
                if input_ctx.telemetry_capabilities.network_flow:
                    return MappingStatus.PARTIAL, "Network flow supports scanning behavior, but required endpoint telemetry is unavailable."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "No network flow evidence to support scanning."
                
        elif behavior_id == "POSSIBLE_EXFILTRATION":
            if tech_id == "T1041":
                if input_ctx.telemetry_capabilities.network_flow:
                    # Never claim SUPPORTED for exfil without endpoint data
                    if finding.risk_score > 0.75:
                        return MappingStatus.PARTIAL, "High-risk flow anomaly supports exfiltration partially without file telemetry."
                    return MappingStatus.POTENTIAL, "Large flow anomaly suggests potential exfiltration."
                return MappingStatus.INSUFFICIENT_EVIDENCE, "No flow evidence to support exfiltration."
                
        elif behavior_id == "SUSPICIOUS_WEB_ACTIVITY":
            if tech_id == "T1071.001":
                if not input_ctx.telemetry_capabilities.http:
                    return MappingStatus.INSUFFICIENT_EVIDENCE, "No HTTP telemetry to support suspicious web activity."
                if finding.risk_score > 0.80 or finding.anomaly_score > 0.9:
                    return MappingStatus.SUPPORTED, "Correlated web C2 evidence supports technique mapping."
                return MappingStatus.POTENTIAL, "Unusual HTTP observed, but insufficient severity to confirm web C2."
                
        return MappingStatus.NOT_APPLICABLE, "Technique did not match behavior rules."
