import pytest
import uuid
import copy
from typing import Dict, Any
from unittest.mock import AsyncMock

from app.orchestrator.pipeline import ForensicPipelineOrchestrator
from app.engines.llm_assistant.service import LLMAssistantService
from app.engines.llm_assistant.models import LLMResponseStatus
from app.engines.llm_assistant.client import AbstractLLMClient, LLMConnectionError, LLMModelUnavailableError

# M1
from app.contracts.network_intelligence import NetworkIntelligencePackage, Flow, Endpoint, FlowProvenance

# M3
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator

# M4
from app.engines.reporting.report_engine import ReportEngine

class MockClient(AbstractLLMClient):
    def __init__(self, response_text: str = "", exception_to_raise=None):
        self.response_text = response_text
        self.exception_to_raise = exception_to_raise
        self.model = "mock-model"
        
    def generate(self, prompt: str, system_instruction: str) -> str:
        if self.exception_to_raise:
            raise self.exception_to_raise
        return self.response_text

@pytest.fixture
def base_case_dict() -> Dict[str, Any]:
    return {
        "schema_version": "investigation-case-v1.2",
        "case_id": "CASE-123",
        "status": "OPEN",
        "timeline_events": [],
        "findings": [],
        "evidence_references": [],
        "mitre_mappings": [
            {
                "mapping_id": "M-1",
                "technique_id": "T1071.001",
                "technique_name": "Web Traffic",
                "mapping_status": "POTENTIAL",
                "mapping_confidence": 0.5,
                "evidence_ids": ["E-1"],
                "source_finding_ids": ["F-1"]
            }
        ],
        "attack_chain": {
            "status": "potential",
            "stages": []
        }
    }

@pytest.mark.asyncio
async def test_llm_service_absent_preserves_behavior(base_case_dict):
    # 18. LLM service absent (None) preserves previous pipeline behavior.
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(),
        m2_engine=AsyncMock(),
        m3_builder=InvestigationCaseBuilder(validator=ContractValidator()),
        m4_engine=ReportEngine(validator=ContractValidator()),
        m1_persistence=AsyncMock()
    )
    # The default behavior is no LLM calls
    res = orchestrator.generate_llm_summary(base_case_dict, {})
    assert res is None

@pytest.mark.asyncio
async def test_summary_succeeds(base_case_dict):
    # 2. Summary succeeds
    client = MockClient('{"summary": "test summary"}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_summary(base_case_dict, {})
    assert resp.status == LLMResponseStatus.SUCCESS
    assert resp.summary == "test summary"
    
@pytest.mark.asyncio
async def test_mitre_explanation_succeeds(base_case_dict):
    # 3. MITRE explanation succeeds.
    client = MockClient('{"technique_id": "T1071.001", "explanation": "test expl"}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_mitre_explanation(base_case_dict, {}, "T1071.001")
    assert resp.status == LLMResponseStatus.SUCCESS
    assert resp.mitre_explanations[0].explanation == "test expl"

@pytest.mark.asyncio
async def test_mitre_explanation_requested_technique_must_already_exist(base_case_dict):
    # 16. requested technique must already exist.
    client = MockClient('{"technique_id": "T9999", "explanation": "test expl"}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_mitre_explanation(base_case_dict, {}, "T9999")
    assert resp.status == LLMResponseStatus.LLM_INVALID_RESPONSE
    assert len(resp.mitre_explanations) == 0

@pytest.mark.asyncio
async def test_qa_succeeds(base_case_dict):
    # 4. Q&A succeeds.
    client = MockClient('{"question": "test q", "answer": "test answer"}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_qa(base_case_dict, {}, "test q")
    assert resp.status == LLMResponseStatus.SUCCESS
    assert resp.investigator_answers["test q"] == "test answer"

@pytest.mark.asyncio
async def test_unsupported_qa_returns_insufficient_evidence(base_case_dict):
    # 17. unsupported Q&A returns insufficient evidence.
    client = MockClient('{"question": "test q", "answer": "known malicious domain"}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_qa(base_case_dict, {}, "test q")
    assert resp.status == LLMResponseStatus.LLM_UNGROUNDED

@pytest.mark.asyncio
async def test_llm_failures_pipeline_continues(base_case_dict):
    # 5. Ollama unavailable → pipeline continues.
    # 6. Ollama timeout → pipeline continues.
    # 7. Model unavailable → pipeline continues.
    # 8. Invalid LLM response → pipeline continues.
    # 9. Grounding failure → pipeline continues.
    
    scenarios = [
        (MockClient(exception_to_raise=LLMConnectionError("timeout")), LLMResponseStatus.LLM_UNAVAILABLE),
        (MockClient(exception_to_raise=LLMConnectionError("unavailable")), LLMResponseStatus.LLM_UNAVAILABLE),
        (MockClient(exception_to_raise=LLMModelUnavailableError("missing")), LLMResponseStatus.LLM_MODEL_UNAVAILABLE),
        (MockClient('{"wrong": "format"'), LLMResponseStatus.LLM_INVALID_RESPONSE),
        (MockClient('{"summary": "known malicious payload"}'), LLMResponseStatus.LLM_UNGROUNDED),
    ]
    
    for client, expected_status in scenarios:
        service = LLMAssistantService(client)
        orchestrator = ForensicPipelineOrchestrator(
            uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
        )
        resp = orchestrator.generate_llm_summary(base_case_dict, {})
        assert resp.status == expected_status

@pytest.mark.asyncio
async def test_m3_case_unchanged_after_llm_success_or_failure(base_case_dict):
    # 10. M3 case unchanged after LLM failure.
    # 11. M3 case unchanged after LLM success.
    # 12-15. mappings, evidence, attack chain unchanged.
    case_copy = copy.deepcopy(base_case_dict)
    
    client = MockClient('{"technique_id": "T1071.001", "explanation": "test", "mapping_status": "SUPPORTED", "mapping_confidence": 1.0, "evidence_ids": ["FAKE"], "attack_chain": {"status": "confirmed"}}')
    service = LLMAssistantService(client)
    orchestrator = ForensicPipelineOrchestrator(
        uow=AsyncMock(), m2_engine=AsyncMock(), m3_builder=AsyncMock(), m4_engine=AsyncMock(), llm_service=service
    )
    
    resp = orchestrator.generate_llm_mitre_explanation(case_copy, {}, "T1071.001")
    assert resp.status == LLMResponseStatus.SUCCESS
    
    # Check that LLM's returned metadata was ignored and context metadata was reattached
    assert resp.mitre_explanations[0].mapping_status == "POTENTIAL"
    assert resp.mitre_explanations[0].mapping_confidence == 0.5
    assert resp.mitre_explanations[0].evidence_ids == ["E-1"]
    
    # Check that the original case dict was absolutely not modified
    assert case_copy == base_case_dict

@pytest.mark.asyncio
async def test_run_pipeline_from_m1_with_llm(base_case_dict):
    # Test full pipeline logic
    # Import necessary pieces exactly as in test_full_forensic_chain.py
    from app.contracts.network_intelligence import NetworkIntelligencePackage, Flow, Endpoint, FlowProvenance, ProtocolEvent, EventProvenance, DNSData
    from datetime import datetime, timezone

    now_utc = datetime.now(timezone.utc)
    acq_id = str(uuid.uuid4())
    
    event = ProtocolEvent(
        event_id="EV-1",
        flow_id="FLOW-1",
        zeek_uid="C" + str(uuid.uuid4())[:18],
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
    
    m1_pkg = NetworkIntelligencePackage(
        package_id=str(uuid.uuid4()),
        acquisition_id=acq_id,
        flows=[],
        protocol_events=[event],
        artifacts=[],
        schema_version="1.0"
    )

    from app.contracts.analysis import FindingsPackage, Finding, ActivityClass, EvidenceReference
    m2_pkg = FindingsPackage(
        acquisition_id=m1_pkg.acquisition_id,
        source_package_id=m1_pkg.package_id,
        analysis_engine_version="1.0",
        findings=[
            Finding(
                finding_id="F-1",
                acquisition_id=m1_pkg.acquisition_id,
                activity_class=ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
                anomaly_score=0.9,
                anomaly_detected=True,
                classification_confidence=0.9,
                risk_score=0.8,
                model_version="1.0",
                evidence_references=[EvidenceReference(event_ids=["EV-1"], rationale="test")]
            )
        ]
    )
    
    class MockM2Engine:
        def analyze(self, pkg): return m2_pkg

    uow = AsyncMock()
    uow.__aenter__.return_value = uow
    uow.session = AsyncMock()
    
    m1_persistence = AsyncMock()
    m3_builder = InvestigationCaseBuilder(validator=ContractValidator())
    m4_engine = ReportEngine(validator=ContractValidator())
    
    client = MockClient('{"summary": "Test Pipeline Summary"}')
    service = LLMAssistantService(client)
    
    orchestrator = ForensicPipelineOrchestrator(
        uow=uow,
        m2_engine=MockM2Engine(), # type: ignore
        m3_builder=m3_builder,
        m4_engine=m4_engine,
        m1_persistence=m1_persistence, # type: ignore
        llm_service=service
    )
    
    orchestrator.m2_persistence.persist_findings_package = AsyncMock()
    orchestrator.m3_persistence.persist_investigation_case = AsyncMock()
    
    # Run pipeline
    result = await orchestrator.run_pipeline_from_m1(m1_pkg)
    
    # Assert
    assert result["status"] == "success"
    assert "llm_enrichment" in result
    assert result["llm_enrichment"] is not None
    assert result["llm_enrichment"]["summary"] == "Test Pipeline Summary"
    assert result["llm_enrichment"]["status"] == "SUCCESS"
    
    # Ensure M4 report generates properly
    assert "m4_report" in result
    assert result["m4_report"]["schema_version"] in ("report-v1", "report-v1.1", "report-v1.2")
