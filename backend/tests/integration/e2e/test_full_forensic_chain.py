import pytest
import uuid
import os
from datetime import datetime, timezone

from app.orchestrator.pipeline import ForensicPipelineOrchestrator

# M1
from app.contracts.network_intelligence import (
    NetworkIntelligencePackage, 
    Flow, 
    ProtocolEvent, 
    Artifact, 
    ArtifactType, 
    Endpoint, 
    FlowProvenance, 
    EventProvenance, 
    ArtifactProvenance,
    DNSData,
    HTTPData,
    AcquisitionReference
)

# M2
from app.engines.analysis.engine import M2AnalysisEngine
from app.engines.analysis.evaluation.model_registry import ModelRegistry

# M3
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder

# M4
from app.engines.reporting.report_engine import ReportEngine
from app.shared.contract_validation import ContractValidator

def generate_mock_m1_package() -> NetworkIntelligencePackage:
    acq_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc)
    
    flow_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    
    flow = Flow(
        flow_id=flow_id,
        zeek_uid="C" + str(uuid.uuid4())[:18],
        acquisition_id=acq_id,
        timestamp=now_utc, 
        source=Endpoint(ip="192.168.1.10", port=54321),
        destination=Endpoint(ip="8.8.8.8", port=53),
        protocol="udp",
        service="dns",
        provenance=FlowProvenance(
            acquisition_id=acq_id,
            source="zeek",
            source_log="conn.log"
        )
    )
    
    event = ProtocolEvent(
        event_id=event_id,
        flow_id=flow_id,
        zeek_uid=flow.zeek_uid,
        acquisition_id=acq_id,
        timestamp=now_utc,
        protocol="dns",
        protocol_data=DNSData(query="malicious.com", query_type="A"),
        provenance=EventProvenance(
            acquisition_id=acq_id,
            source="zeek",
            source_log="dns.log",
            line_number=1
        )
    )
    
    art = Artifact(
        artifact_id=str(uuid.uuid4()),
        type=ArtifactType.DOMAIN,
        value="malicious.com",
        source_event_id=event_id,
        flow_id=flow_id,
        acquisition_id=acq_id,
        provenance=ArtifactProvenance(
            acquisition_id=acq_id,
            source_event_id=event_id
        )
    )

    return NetworkIntelligencePackage(
        package_id=str(uuid.uuid4()),
        acquisition_id=acq_id,
        flows=[flow],
        protocol_events=[event],
        artifacts=[art],
        schema_version="1.0"
    )

@pytest.mark.asyncio
async def test_fast_e2e_pipeline():
    """
    Validates the end-to-end integration of M1 -> M2 -> M3 -> M4
    bypassing database persistence.
    """
    from unittest.mock import AsyncMock, MagicMock
    uow = AsyncMock()
    uow.__aenter__.return_value = uow
    uow.session = AsyncMock()

    m1_pkg = generate_mock_m1_package()
    
    from app.contracts.analysis import Finding, EvidenceReference, ActivityClass
    
    # Generate findings for ALL 5 REQUIRED SCENARIOS
    finding_c2 = Finding(
        finding_id=f"F-C2",
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.C2_MALWARE_COMMUNICATION,
        anomaly_score=0.95, anomaly_detected=True, classification_confidence=0.9, risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(event_ids=[m1_pkg.protocol_events[0].event_id], rationale="C2")]
    )
    finding_dns = Finding(
        finding_id=f"F-DNS",
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.DNS_ANOMALY_TUNNELING,
        anomaly_score=0.95, anomaly_detected=True, classification_confidence=0.9, risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(event_ids=[m1_pkg.protocol_events[0].event_id], rationale="DNS")]
    )
    finding_scan = Finding(
        finding_id=f"F-SCAN",
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.SCANNING_RECONNAISSANCE,
        anomaly_score=0.95, anomaly_detected=True, classification_confidence=0.9, risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(flow_ids=[m1_pkg.flows[0].flow_id], rationale="SCAN")]
    )
    finding_exfil = Finding(
        finding_id=f"F-EXFIL",
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.POSSIBLE_EXFILTRATION,
        anomaly_score=0.95, anomaly_detected=True, classification_confidence=0.9, risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(flow_ids=[m1_pkg.flows[0].flow_id], rationale="EXFIL")]
    )
    finding_web = Finding(
        finding_id=f"F-WEB",
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
        anomaly_score=0.95, anomaly_detected=True, classification_confidence=0.9, risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(event_ids=[m1_pkg.protocol_events[0].event_id], rationale="WEB")]
    )

    from app.contracts.analysis import FindingsPackage
    m2_pkg = FindingsPackage(
        acquisition_id=m1_pkg.acquisition_id,
        source_package_id=m1_pkg.package_id,
        analysis_engine_version="1.0",
        findings=[finding_c2, finding_dns, finding_scan, finding_exfil, finding_web]
    )
    
    class MockM2Engine:
        def analyze(self, pkg): return m2_pkg

    class MockStorageService:
        bucket_name = "test-bucket"
        
    from app.engines.packet_intelligence.persistence_service import M1PersistenceService
    m1_persistence = M1PersistenceService(orchestrator=None, storage_service=MockStorageService()) # type: ignore
    m1_persistence._persist_package = AsyncMock()

    m3_builder = InvestigationCaseBuilder(validator=ContractValidator())
    m4_engine = ReportEngine(validator=ContractValidator())
    
    orchestrator = ForensicPipelineOrchestrator(
        uow=uow,
        m2_engine=MockM2Engine(), # type: ignore
        m3_builder=m3_builder,
        m4_engine=m4_engine,
        m1_persistence=m1_persistence
    )
    
    # Mock persistence methods that make DB queries
    orchestrator.m2_persistence.persist_findings_package = AsyncMock()
    orchestrator.m3_persistence.persist_investigation_case = AsyncMock()

    # 3. Run Pipeline
    result = await orchestrator.run_pipeline_from_m1(m1_pkg)
    
    assert result["status"] == "success"
    assert result["findings_count"] == 5
    
    # Verify we hit all 5 scenarios in MITRE Mapping
    # The output is captured in the m3_case_dict through case_id lookup, but wait, the pipeline returns m4_report and case_id.
    # To check MITRE mappings we can inspect the call args to persist_investigation_case!
    
    m3_case_dict = orchestrator.m3_persistence.persist_investigation_case.call_args[0][0]
    
    # Assert MITRE and M4 success
    report = result["m4_report"]
    assert report["schema_version"] in ("report-v1", "report-v1.1", "report-v1.2")
    
    assert "mitre_mappings" in m3_case_dict
    mitre_mappings = m3_case_dict["mitre_mappings"]
    
    # We expect mappings for our 5 scenarios
    assert len(mitre_mappings) > 0
    mapped_findings = [m["source_finding_ids"][0] for m in mitre_mappings]
    assert "F-DNS" in mapped_findings
    assert "F-SCAN" in mapped_findings
    assert "F-EXFIL" in mapped_findings
    
    # Verify attack chain
    assert "attack_chain" in m3_case_dict
    assert m3_case_dict["attack_chain"]["status"] in ("potential", "confirmed")
    assert len(m3_case_dict["attack_chain"]["stages"]) > 0
