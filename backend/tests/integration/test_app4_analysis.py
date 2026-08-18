import pytest
import uuid
import asyncio
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from app.persistence.models.investigation_models import InvestigationCaseModel, AnalysisJobModel
from app.persistence.models.acquisition_models import AcquisitionModel, EvidenceModel
from app.api.v1.analysis import inject_analysis_orchestrator
from app.auth.jwt import create_access_token

from .test_app2_cases import setup_users_cases, client, db_session

@pytest.fixture
def get_admin_token(setup_users_cases):
    async def _get_token():
        return create_access_token(subject=str(setup_users_cases["admin"].user_id))
    return _get_token

@pytest.fixture
def mock_orchestrator(monkeypatch):
    """Mocks the AnalysisOrchestratorService dependencies to avoid real Zeek execution."""
    from app.services.analysis_orchestrator import AnalysisOrchestratorService
    from app.persistence.transactions.uow import UnitOfWork
    from app.persistence.repositories.analysis_repository import AnalysisRepository
    from app.persistence.repositories.acquisition_repository import AcquisitionRepository
    from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
    from app.shared.storage.minio_service import EvidenceStorageService
    from app.services.audit_service import log_audit_event

    class MockM1:
        def process_acquisition(self, acq_ref):
            from app.contracts.network_intelligence import NetworkIntelligencePackage
            return NetworkIntelligencePackage(
                package_id=str(uuid.uuid4()),
                acquisition_id=acq_ref.acquisition_id,
                flows=[],
                protocol_events=[],
                artifacts=[],
                packet_references=[]
            )

    class MockPipeline:
        async def run_pipeline_from_m1(self, m1_package):
            return {
                "status": "success",
                "acquisition_id": m1_package.acquisition_id,
                "findings_count": 5
            }
            
    class MockStorage(EvidenceStorageService):
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def download_evidence_temp(self, object_key):
            import tempfile, os
            fd, temp_path = tempfile.mkstemp(prefix="mock_evidence_", suffix=".pcap")
            os.close(fd)
            try:
                yield temp_path
            finally:
                os.remove(temp_path)

    class MockAnalysisOrchestrator(AnalysisOrchestratorService):
        def __init__(self, session):
            super().__init__(
                uow=UnitOfWork(),
                analysis_repo=AnalysisRepository(session),
                acquisition_repo=AcquisitionRepository(session),
                investigation_repo=InvestigationCaseRepository(session),
                storage_service=MockStorage(),
                m1_orchestrator=MockM1(),
                pipeline_orchestrator=MockPipeline()
            )
            self._session = session

        async def start_analysis(self, case_id, acquisition_id, user_id):
            # Check idempotency using our own session
            is_active = await self.analysis_repo.has_active_analysis(acquisition_id)
            if is_active:
                from app.exceptions import ValidationError
                raise ValidationError("An active analysis job already exists for this acquisition.")
            job = await self.analysis_repo.create_job(case_id=case_id, acquisition_id=acquisition_id, created_by=user_id)
            await self._session.flush()  # populate server-side defaults and PK
            analysis_id = job.analysis_id
            await self._session.commit()
            return analysis_id

        async def execute_analysis_background(self, analysis_id, user_id):
            # Simulate instant completion
            await self.analysis_repo.update_status(analysis_id, "completed", stage="COMPLETED", progress=100)
            await self._session.commit()

        async def get_job_status(self, analysis_id):
            job = await self.analysis_repo.get_job(analysis_id)
            if not job:
                return None
            return {
                "analysis_id": job.analysis_id,
                "case_id": job.case_id,
                "acquisition_id": job.acquisition_id,
                "status": job.status,
                "current_stage": job.current_stage,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
                "progress": job.progress,
                "result_available": job.status == "completed",
                "error_code": job.error_code,
                "error_message": job.error_message,
            }

    def get_mocked_orchestrator(session):
        return MockAnalysisOrchestrator(session)
        
    return get_mocked_orchestrator

import pytest_asyncio

@pytest_asyncio.fixture
async def setup_test_data(db_session, setup_users_cases):
    """Sets up a case and acquisition to test analysis against."""
    from sqlalchemy import text
    
    # From setup_users_cases, we have cases. Let's find one.
    result = await db_session.execute(text("SELECT case_id FROM investigation.investigation_cases LIMIT 1"))
    case_id = result.scalar()
    
    if not case_id:
        case_id = uuid.uuid4()
        case = InvestigationCaseModel(
            case_id=case_id,
            title="Analysis Test Case",
            trigger_type="IDS",
            status="open"
        )
        db_session.add(case)
    
    acq_id = uuid.uuid4()
    unique_sha256 = uuid.uuid4().hex + uuid.uuid4().hex  # 64 lowercase hex chars
    acq = AcquisitionModel(
        acquisition_id=acq_id,
        file_name="test.pcap",
        sha256=unique_sha256,
        format="pcap",
        source_type="upload",
        status="complete"
    )
    db_session.add(acq)
    
    evidence = EvidenceModel(
        evidence_id=uuid.uuid4(),
        acquisition_id=acq_id,
        minio_bucket="evidence",
        object_key=f"fake/{acq_id}/test.pcap",  # unique per acq
        sha256=unique_sha256
    )
    db_session.add(evidence)
    
    await db_session.flush()
    
    # Link acquisition to case
    await db_session.execute(
        text(f"INSERT INTO acquisition.case_acquisition_links (case_id, acquisition_id) VALUES ('{case_id}', '{acq_id}')")
    )
    
    await db_session.commit()
    
    return {"case_id": case_id, "acquisition_id": acq_id}


@pytest.mark.asyncio
async def test_start_analysis_success(client: TestClient, setup_test_data, get_admin_token, mock_orchestrator):
    case_id = setup_test_data["case_id"]
    acq_id = setup_test_data["acquisition_id"]
    token = await get_admin_token()
    
    # Create the orchestrator instance now — dependency override bypasses DI
    from app.persistence.database import async_session_factory
    from app.services.analysis_orchestrator import AnalysisOrchestratorService
    from app.persistence.transactions.uow import UnitOfWork
    from app.persistence.repositories.analysis_repository import AnalysisRepository
    from app.persistence.repositories.acquisition_repository import AcquisitionRepository
    from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
    from app.shared.storage.minio_service import EvidenceStorageService

    async def override_orchestrator():
        async with async_session_factory() as session:
            yield mock_orchestrator(session)

    client.app.dependency_overrides[inject_analysis_orchestrator] = override_orchestrator
    
    response = client.post(
        f"/api/v1/cases/{case_id}/analysis",
        headers={"Authorization": f"Bearer {token}"},
        json={"acquisition_id": str(acq_id)}
    )
    
    assert response.status_code == 202, f"422 detail: {response.text}"
    data = response.json()
    assert "analysis_id" in data
    assert data["status"] == "queued"
    
    # Wait slightly to allow background task to advance state
    await asyncio.sleep(1.0)
    
    # Poll status
    status_resp = client.get(
        f"/api/v1/cases/{case_id}/analysis/{data['analysis_id']}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["status"] == "completed"
    assert status_data["current_stage"] == "COMPLETED"
    assert status_data["progress"] == 100
    assert status_data["result_available"] is True

@pytest.mark.asyncio
async def test_duplicate_analysis_rejected(client: TestClient, setup_test_data, get_admin_token, mock_orchestrator):
    case_id = setup_test_data["case_id"]
    acq_id = setup_test_data["acquisition_id"]
    token = await get_admin_token()

    from app.persistence.database import async_session_factory

    async def override_orchestrator():
        async with async_session_factory() as session:
            orchestrator = mock_orchestrator(session)

            # Patch background execution to be a no-op so job stays in 'queued' state
            async def no_op_background(analysis_id, user_id):
                pass  # don't update status so job remains queued

            orchestrator.execute_analysis_background = no_op_background
            yield orchestrator

    client.app.dependency_overrides[inject_analysis_orchestrator] = override_orchestrator

    # First request — creates a queued job
    resp1 = client.post(
        f"/api/v1/cases/{case_id}/analysis",
        headers={"Authorization": f"Bearer {token}"},
        json={"acquisition_id": str(acq_id)}
    )
    assert resp1.status_code == 202, f"First request failed: {resp1.text}"

    # Immediate second request should fail as the first one is still queued
    resp2 = client.post(
        f"/api/v1/cases/{case_id}/analysis",
        headers={"Authorization": f"Bearer {token}"},
        json={"acquisition_id": str(acq_id)}
    )
    assert resp2.status_code == 400, f"Expected 400, got {resp2.status_code}: {resp2.text}"
    assert "active analysis" in resp2.text.lower()
