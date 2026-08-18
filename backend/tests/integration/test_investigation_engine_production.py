import pytest
import uuid
import datetime
import copy
from unittest.mock import AsyncMock, MagicMock
from typing import Dict, Any

from app.orchestrator.pipeline import ForensicPipelineOrchestrator
from app.contracts.network_intelligence import NetworkIntelligencePackage, Flow, Endpoint, FlowProvenance
from app.contracts.analysis import FindingsPackage, Finding, ActivityClass
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator
from app.engines.reporting.report_engine import ReportEngine

def create_mock_m1_package(acq_id: str = "12345678-1234-5678-1234-567812345678") -> NetworkIntelligencePackage:
    flow1 = Flow(
        flow_id="FLOW-1",
        zeek_uid="C" + uuid.uuid4().hex[:17],
        acquisition_id=acq_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        source=Endpoint(ip="192.168.1.10", port=12345),
        destination=Endpoint(ip="10.0.0.5", port=80),
        protocol="tcp",
        orig_bytes=5000,
        provenance=FlowProvenance(source="zeek", source_log="conn.log")
    )
    flow2 = Flow(
        flow_id="FLOW-2",
        zeek_uid="C" + uuid.uuid4().hex[:17],
        acquisition_id=acq_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        source=Endpoint(ip="192.168.1.10", port=12346),
        destination=Endpoint(ip="10.0.0.6", port=443),
        protocol="tcp",
        provenance=FlowProvenance(source="zeek", source_log="conn.log")
    )
    
    from app.contracts.network_intelligence import ProtocolEvent, DNSData, HTTPData, EventProvenance
    
    dns_event = ProtocolEvent(
        event_id="EV-DNS",
        flow_id="FLOW-1",
        zeek_uid=flow1.zeek_uid,
        acquisition_id=acq_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        protocol="dns",
        protocol_data=DNSData(query="malicious.com"),
        provenance=EventProvenance(acquisition_id=acq_id, source="zeek", source_log="dns.log")
    )
    
    http_event = ProtocolEvent(
        event_id="EV-HTTP",
        flow_id="FLOW-1",
        zeek_uid=flow1.zeek_uid,
        acquisition_id=acq_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        protocol="http",
        protocol_data=HTTPData(uri="/malicious"),
        provenance=EventProvenance(acquisition_id=acq_id, source="zeek", source_log="http.log")
    )
    
    return NetworkIntelligencePackage(
        package_id=f"M1-{uuid.uuid4().hex[:6]}",
        schema_version="network-intelligence-v1",
        acquisition_id=acq_id,
        capture_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        sensor_id="sensor-01",
        flows=[flow1, flow2],
        protocol_events=[dns_event, http_event],
        dns_queries=[],
        http_sessions=[],
        tls_sessions=[],
        endpoints=[]
    )

def create_mock_m2_engine(scenario: str, finding_id: str = None) -> MagicMock:
    engine = MagicMock()
    if finding_id is None:
        finding_id = f"F-{uuid.uuid4().hex[:6]}"
    
    # Map scenarios to specific activity classes and severities
    if scenario == "C2_MALWARE_COMMUNICATION":
        act_class = ActivityClass.C2_MALWARE_COMMUNICATION
        risk = 0.95
    elif scenario == "DNS_ANOMALY_TUNNELING":
        act_class = ActivityClass.DNS_ANOMALY_TUNNELING
        risk = 0.85
    elif scenario == "SCANNING_RECONNAISSANCE":
        act_class = ActivityClass.SCANNING_RECONNAISSANCE
        risk = 0.70
    elif scenario == "POSSIBLE_EXFILTRATION":
        act_class = ActivityClass.POSSIBLE_EXFILTRATION
        risk = 0.90
    elif scenario == "SUSPICIOUS_WEB_ACTIVITY":
        act_class = ActivityClass.SUSPICIOUS_WEB_ACTIVITY
        risk = 0.60
    else:
        act_class = ActivityClass.UNKNOWN
        risk = 0.1
        
    # Provide sufficient evidence for validation checks
    flow_ids = []
    event_ids = []
    
    if scenario == "C2_MALWARE_COMMUNICATION":
        flow_ids = ["FLOW-1", "FLOW-2"]
    elif scenario == "DNS_ANOMALY_TUNNELING":
        event_ids = ["EV-DNS"]
    elif scenario == "SCANNING_RECONNAISSANCE":
        flow_ids = ["FLOW-1", "FLOW-2"]
    elif scenario == "POSSIBLE_EXFILTRATION":
        flow_ids = ["FLOW-1"]
    elif scenario == "SUSPICIOUS_WEB_ACTIVITY":
        event_ids = ["EV-HTTP"]
    else:
        flow_ids = ["FLOW-1"]
    
    from app.contracts.analysis import EvidenceReference
    ev_ref = EvidenceReference(flow_ids=flow_ids, event_ids=event_ids, rationale="test rationale")
    
    finding = Finding(
        finding_id=finding_id,
        acquisition_id="12345678-1234-5678-1234-567812345678",
        activity_class=act_class,
        anomaly_score=0.9,
        anomaly_detected=True,
        risk_score=risk,
        classification_confidence=0.8,
        model_version="1.0",
        evidence_references=[ev_ref]
    )
    
    pkg = FindingsPackage(
        source_package_id="12345678-1234-5678-1234-567812345678",
        acquisition_id="12345678-1234-5678-1234-567812345678",
        analysis_engine_version="1.0",
        findings=[finding]
    )
    engine.analyze.return_value = pkg
    return engine

@pytest.fixture
def base_orchestrator():
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(),
        m2_engine=MagicMock(),
        m3_builder=InvestigationCaseBuilder(validator=ContractValidator()),
        m4_engine=ReportEngine(validator=ContractValidator()),
        m1_persistence=AsyncMock()
    )
    orchestrator.m2_persistence = AsyncMock()
    orchestrator.m3_persistence = AsyncMock()
    return orchestrator

@pytest.mark.asyncio
async def test_scenario_c2(base_orchestrator):
    base_orchestrator.m2_engine = create_mock_m2_engine("C2_MALWARE_COMMUNICATION")
    m1_pkg = create_mock_m1_package()
    
    res = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    assert res["status"] == "success"
    
    report = res["m4_report"]
    assert report["schema_version"] == "report-v1.3"
    assert "assessment" in report

@pytest.mark.asyncio
async def test_scenario_dns(base_orchestrator):
    base_orchestrator.m2_engine = create_mock_m2_engine("DNS_ANOMALY_TUNNELING")
    m1_pkg = create_mock_m1_package()
    res = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    assert res["status"] == "success"

@pytest.mark.asyncio
async def test_scenario_scanning(base_orchestrator):
    base_orchestrator.m2_engine = create_mock_m2_engine("SCANNING_RECONNAISSANCE")
    m1_pkg = create_mock_m1_package()
    res = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    assert res["status"] == "success"
    report = res["m4_report"]
    # Scanning without target evidence -> impact remains empty or POTENTIAL
    # Just verify it doesn't crash and generates a V1.3 report
    assert report["schema_version"] == "report-v1.3"

@pytest.mark.asyncio
async def test_scenario_exfiltration(base_orchestrator):
    base_orchestrator.m2_engine = create_mock_m2_engine("POSSIBLE_EXFILTRATION")
    m1_pkg = create_mock_m1_package()
    res = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    assert res["status"] == "success"

@pytest.mark.asyncio
async def test_scenario_web(base_orchestrator):
    base_orchestrator.m2_engine = create_mock_m2_engine("SUSPICIOUS_WEB_ACTIVITY")
    m1_pkg = create_mock_m1_package()
    res = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    assert res["status"] == "success"

@pytest.mark.asyncio
async def test_determinism(base_orchestrator):
    m1_pkg = create_mock_m1_package()
    
    # Reset mocks to avoid any state carrying over (though orchestrator should be stateless across runs)
    # The timestamps generated internally (like `first_seen`) might differ slightly if we don't mock them,
    # but the IDs of hypotheses, validations, etc should be deterministically generated from evidence.
    engine = create_mock_m2_engine("C2_MALWARE_COMMUNICATION", finding_id="F-DETERMINISM-1")
    base_orchestrator.m2_engine = engine
    res1 = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    
    # Run again with same engine (same finding ID)
    res2 = await base_orchestrator.run_pipeline_from_m1(m1_pkg)
    
    assm1 = res1["m4_report"]["assessment"]
    assm2 = res2["m4_report"]["assessment"]
    
    # Assert deterministic equality of complex nested arrays
    def clean_timestamps(assm):
        for h in assm.get("hypothesis_validations", []):
            h["validated_at"] = "FIXED"
    clean_timestamps(assm1)
    clean_timestamps(assm2)
    
    assert assm1 == assm2

@pytest.mark.asyncio
async def test_llm_failure_isolation():
    # Provide a broken LLM service
    broken_llm = MagicMock()
    broken_llm.generate_summary.side_effect = Exception("LLM is down")
    
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(),
        m2_engine=create_mock_m2_engine("C2_MALWARE_COMMUNICATION"),
        m3_builder=InvestigationCaseBuilder(validator=ContractValidator()),
        m4_engine=ReportEngine(validator=ContractValidator()),
        m1_persistence=AsyncMock(),
        llm_service=broken_llm
    )
    orchestrator.m2_persistence = AsyncMock()
    orchestrator.m3_persistence = AsyncMock()
    
    m1_pkg = create_mock_m1_package()
    res = await orchestrator.run_pipeline_from_m1(m1_pkg)
    
    # Must succeed despite LLM failure
    assert res["status"] == "success"
    assert res["m4_report"]["schema_version"] == "report-v1.3"
