from typing import Dict, Any, Tuple
from pydantic import ValidationError

from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FindingsPackage
from app.engines.correlation.domain.input import (
    M3InvestigationInput, 
    EvidenceIndex, 
    TelemetryCapability
)

class M3InputAdapter:
    """Composite adapter that merges M1 and M2 packages into the canonical M3Input."""
    
    def adapt(self, m1_payload: Dict[str, Any], m2_payload: Dict[str, Any]) -> M3InvestigationInput:
        """
        Takes raw dictionaries from M1 and M2, validates them via Pydantic,
        and constructs the single M3InvestigationInput object.
        """
        try:
            m1_pkg = NetworkIntelligencePackage.model_validate(m1_payload)
            m2_pkg = FindingsPackage.model_validate(m2_payload)
        except ValidationError as e:
            raise ValueError(f"Contract validation failed: {e}")
            
        # Verify timestamp safety (all datetimes must be timezone-aware)
        for flow in m1_pkg.flows:
            if flow.timestamp.tzinfo is None:
                raise ValueError("Naive timestamps are rejected. Must be timezone-aware.")
        for event in m1_pkg.protocol_events:
            if event.timestamp.tzinfo is None:
                raise ValueError("Naive timestamps are rejected. Must be timezone-aware.")
            
        if m1_pkg.acquisition_id != m2_pkg.acquisition_id:
            raise ValueError(f"Acquisition ID mismatch: M1({m1_pkg.acquisition_id}) != M2({m2_pkg.acquisition_id})")
            
        evidence_index = EvidenceIndex()
        telemetry = TelemetryCapability()
        
        # 1. Map M1 Flows
        for flow in m1_pkg.flows:
            if flow.flow_id in evidence_index.flows:
                raise ValueError(f"Duplicate flow_id detected: {flow.flow_id}")
            evidence_index.flows[flow.flow_id] = flow
            
        # 2. Map M1 Protocol Events & Assess Telemetry Capabilities
        for event in m1_pkg.protocol_events:
            if event.event_id in evidence_index.events:
                raise ValueError(f"Duplicate event_id detected: {event.event_id}")
            evidence_index.events[event.event_id] = event
            if event.protocol == "dns":
                telemetry.dns = True
            elif event.protocol == "http":
                telemetry.http = True
            elif event.protocol in ("tls", "ssl"):
                telemetry.tls = True
                
        # 3. Map M1 Artifacts
        for artifact in m1_pkg.artifacts:
            if artifact.artifact_id in evidence_index.artifacts:
                raise ValueError(f"Duplicate artifact_id detected: {artifact.artifact_id}")
            evidence_index.artifacts[artifact.artifact_id] = artifact
            
        # 4. Map M2 Findings and Check Referential Integrity
        for finding in m2_pkg.findings:
            if finding.finding_id in evidence_index.findings:
                raise ValueError(f"Duplicate finding_id detected: {finding.finding_id}")
            evidence_index.findings[finding.finding_id] = finding
            
            for ref in finding.evidence_references:
                for f_id in ref.flow_ids:
                    if f_id not in evidence_index.flows:
                        raise ValueError(f"Referential integrity failure: flow_id {f_id} not found in M1")
                for e_id in ref.event_ids:
                    if e_id not in evidence_index.events:
                        raise ValueError(f"Referential integrity failure: event_id {e_id} not found in M1")
                for a_id in ref.artifact_ids:
                    if a_id not in evidence_index.artifacts:
                        raise ValueError(f"Referential integrity failure: artifact_id {a_id} not found in M1")
            
        # 5. Construct Canonical M3 Input
        m3_input = M3InvestigationInput(
            acquisition_id=m1_pkg.acquisition_id,
            network_package_id=m1_pkg.package_id,
            findings_package_id=m2_pkg.package_id,
            network_flows=m1_pkg.flows,
            protocol_events=m1_pkg.protocol_events,
            artifacts=m1_pkg.artifacts,
            findings=m2_pkg.findings,
            telemetry_capabilities=telemetry,
            evidence_index=evidence_index
        )
        
        return m3_input
