import pytest
import uuid
import os
from datetime import datetime, timezone

from app.persistence.database import engine
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models import AcquisitionModel, EvidenceModel, UserModel

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
    using a deterministic mock NetworkIntelligencePackage (bypassing real Zeek).
    """
    # 1. Prepare Unit Of Work
    uow = UnitOfWork()

    # Pre-inject identity so foreign keys pass
    sys_user_uuid = uuid.uuid5(uuid.NAMESPACE_OID, "m4-system-user")
    
    async with uow:
        # Check if sys user exists to prevent PK conflict in test reruns
        existing = await uow.session.get(UserModel, sys_user_uuid)
        if not existing:
            sys_user = UserModel(
                user_id=sys_user_uuid,
                username="m4_system_user",
                email="system@netsleuth.ai",
                full_name="System Orchestrator",
                role="admin"
            )
            uow.session.add(sys_user)
            await uow.session.flush()

    # 2. Instantiate Engines
    
    # We must patch M2 AnalysisEngine to return a mocked FindingsPackage because
    # actual ML models would crash if None is passed. 
    # For this E2E *database persistence integration* test, we mock the engine compute boundary.
    m1_pkg = generate_mock_m1_package()
    
    from app.contracts.analysis import Finding, EvidenceReference, ActivityClass
    
    finding_id_str = f"F-{uuid.uuid4().hex[:8].upper()}"
    finding = Finding(
        finding_id=finding_id_str,
        acquisition_id=m1_pkg.acquisition_id,
        activity_class=ActivityClass.C2_MALWARE_COMMUNICATION,
        anomaly_score=0.95,
        anomaly_detected=True,
        classification_confidence=0.9,
        risk_score=0.92,
        model_version="1.0",
        evidence_references=[EvidenceReference(
            event_ids=[m1_pkg.protocol_events[0].event_id],
            rationale="The malicious DNS query event"
        )]
    )
    
    from app.contracts.analysis import FindingsPackage
    m2_pkg = FindingsPackage(
        acquisition_id=m1_pkg.acquisition_id,
        source_package_id=m1_pkg.package_id,
        analysis_engine_version="1.0",
        findings=[finding]
    )
    
    class MockM2Engine:
        def analyze(self, pkg):
            return m2_pkg

    class MockStorageService:
        bucket_name = "test-bucket"
        
    from app.engines.packet_intelligence.persistence_service import M1PersistenceService
    m1_persistence = M1PersistenceService(orchestrator=None, storage_service=MockStorageService()) # type: ignore

    m3_builder = InvestigationCaseBuilder(validator=ContractValidator())
    m4_engine = ReportEngine(validator=ContractValidator())
    
    orchestrator = ForensicPipelineOrchestrator(
        uow=uow,
        m2_engine=MockM2Engine(), # type: ignore
        m3_builder=m3_builder,
        m4_engine=m4_engine,
        m1_persistence=m1_persistence
    )

    # 3. Run Pipeline
    result = await orchestrator.run_pipeline_from_m1(m1_pkg)
    
    assert result["status"] == "success"
    assert result["findings_count"] == 1
    case_id_uuid = uuid.uuid5(uuid.NAMESPACE_OID, f"CASE-{m1_pkg.acquisition_id}")
    
    # 4. Verify Final State
    from app.persistence.models.custody_models import ReportModel
    from app.persistence.models.investigation_models import InvestigationCaseModel
    from app.persistence.models import FlowModel, ProtocolEventModel
    from sqlalchemy import select

    async with uow:
        # Check M1 Flow
        flows = await uow.session.execute(select(FlowModel))
        assert len(flows.scalars().all()) > 0
        
        # Check M3 Case
        db_case = await uow.session.get(InvestigationCaseModel, case_id_uuid)
        assert db_case is not None
        assert db_case.title.startswith("Investigation Case CASE-")
        
        assert result["m4_report"]["case_id"] == result["case_id"]
        

