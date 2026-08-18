import asyncio
import logging
import uuid
from typing import Optional

from sqlalchemy.orm import Session
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.repositories.analysis_repository import AnalysisRepository
from app.persistence.repositories.acquisition_repository import AcquisitionRepository
from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
from app.shared.storage.minio_service import EvidenceStorageService
from app.exceptions import ValidationError

from app.engines.packet_intelligence.orchestrator import M1Orchestrator
from app.orchestrator.pipeline import ForensicPipelineOrchestrator
from app.contracts.network_intelligence import AcquisitionReference
from app.services.audit_service import log_audit_event

logger = logging.getLogger(__name__)

class AnalysisOrchestratorService:
    """Application-level service for Analysis Job Orchestration."""

    def __init__(
        self,
        uow: UnitOfWork,
        analysis_repo: AnalysisRepository,
        acquisition_repo: AcquisitionRepository,
        investigation_repo: InvestigationCaseRepository,
        storage_service: EvidenceStorageService,
        m1_orchestrator: M1Orchestrator,
        pipeline_orchestrator: ForensicPipelineOrchestrator
    ):
        self.uow = uow
        self.analysis_repo = analysis_repo
        self.acquisition_repo = acquisition_repo
        self.investigation_repo = investigation_repo
        self.storage_service = storage_service
        self.m1_orchestrator = m1_orchestrator
        self.pipeline_orchestrator = pipeline_orchestrator

    async def start_analysis(self, case_id: uuid.UUID, acquisition_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
        """Starts an analysis job. Returns the new analysis_id immediately (background execution)."""
        async with self.uow:
            # Idempotency / Concurrency check
            is_active = await self.analysis_repo.has_active_analysis(acquisition_id)
            if is_active:
                raise ValidationError("An active analysis job already exists for this acquisition.")

            # Create analysis job
            job = await self.analysis_repo.create_job(
                case_id=case_id,
                acquisition_id=acquisition_id,
                created_by=user_id
            )
            analysis_id = job.analysis_id

            await log_audit_event(
                db=self.uow.session,
                actor_id=user_id,
                action="ANALYSIS_REQUESTED",
                target_entity_type="analysis_job",
                target_entity_id=str(analysis_id),
                result="success"
            )

        return analysis_id

    async def execute_analysis_background(self, analysis_id: uuid.UUID, user_id: uuid.UUID):
        """
        Background task executing M1->M4.
        Note: FastAPI BackgroundTasks are in-process and NOT crash-durable.
        """
        try:
            # Fetch job details
            async with self.uow:
                job = await self.analysis_repo.get_job(analysis_id)
                if not job:
                    logger.error(f"Analysis job {analysis_id} not found.")
                    return
                
                acquisition_id = job.acquisition_id
                case_id = job.case_id
                await self.analysis_repo.update_status(analysis_id, "running", stage="INITIALIZING", progress=0)

                await log_audit_event(
                    db=self.uow.session,
                    actor_id=user_id,
                    action="ANALYSIS_STARTED",
                    target_entity_type="analysis_job",
                    target_entity_id=str(analysis_id),
                    result="success"
                )

            # Get Acquisition Metadata
            async with self.uow:
                acq = await self.acquisition_repo.get_by_id(acquisition_id)
                if not acq:
                    raise ValueError("Acquisition not found")
                evidence_list = acq.evidence
                if not evidence_list:
                    raise ValueError("No evidence object linked to acquisition")
                evidence = evidence_list[0]

            async with self.uow:
                await self.analysis_repo.update_status(analysis_id, "running", stage="M1_PACKET_INTELLIGENCE", progress=10)

            # --- M1 Phase ---
            # 1. Download evidence to temporary secure file
            async with self.storage_service.download_evidence_temp(evidence.object_key) as temp_pcap_path:
                acq_ref = AcquisitionReference(
                    acquisition_id=str(acquisition_id),
                    evidence_id=str(evidence.evidence_id),
                    file_name=acq.file_name,
                    file_size=acq.file_size,
                    format=acq.format,
                    sha256=acq.sha256,
                    capture_reference=temp_pcap_path
                )

                # 2. Run M1 Orchestrator (Zeek -> Extraction)
                # Note: m1_orchestrator process_acquisition is currently synchronous/blocking the thread.
                # In a real app we'd use run_in_executor, but we'll call it directly here.
                # Wait, zeek_runner.run uses subprocess.run. M1 is entirely synchronous.
                # Run it in an executor to not block the FastAPI async event loop.
                loop = asyncio.get_running_loop()
                m1_package = await loop.run_in_executor(None, self.m1_orchestrator.process_acquisition, acq_ref)

            async with self.uow:
                await self.analysis_repo.update_status(analysis_id, "running", stage="M2_ANALYSIS", progress=40)

            # --- M2 -> M4 Phase ---
            pipeline_result = await self.pipeline_orchestrator.run_pipeline_from_m1(m1_package)
            
            if pipeline_result.get("status") != "success":
                raise RuntimeError("Forensic pipeline reported failure")

            async with self.uow:
                await self.analysis_repo.update_status(analysis_id, "completed", stage="COMPLETED", progress=100)

                await log_audit_event(
                    db=self.uow.session,
                    actor_id=user_id,
                    action="ANALYSIS_COMPLETED",
                    target_entity_type="analysis_job",
                    target_entity_id=str(analysis_id),
                    result="success"
                )

        except Exception as e:
            logger.exception(f"Analysis job {analysis_id} failed.")
            async with self.uow:
                await self.analysis_repo.update_status(
                    analysis_id, 
                    "failed", 
                    stage="FAILED",
                    error_code="ANALYSIS_FAILED", 
                    error_message=str(e)
                )

                # Use a system-level UUID if user_id cannot be tracked safely here
                await log_audit_event(
                    db=self.uow.session,
                    actor_id=user_id,
                    action="ANALYSIS_FAILED",
                    target_entity_type="analysis_job",
                    target_entity_id=str(analysis_id),
                    result="failure"
                )

    async def get_job_status(self, analysis_id: uuid.UUID) -> Optional[dict]:
        async with self.uow:
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
                "error_message": job.error_message
            }

def get_analysis_orchestrator(session: Session) -> AnalysisOrchestratorService:
    from app.persistence.transactions.uow import UnitOfWork
    from app.persistence.repositories.analysis_repository import AnalysisRepository
    from app.persistence.repositories.acquisition_repository import AcquisitionRepository
    from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
    from app.shared.storage.minio_service import EvidenceStorageService

    # Build M1
    from app.engines.packet_intelligence.orchestrator import M1Orchestrator
    from app.engines.packet_intelligence.zeek.runner import ZeekRunner
    from app.engines.packet_intelligence.zeek.reader import ZeekReader
    from app.engines.packet_intelligence.adapters.conn import ConnAdapter
    from app.engines.packet_intelligence.adapters.dns import DNSAdapter
    from app.engines.packet_intelligence.adapters.http import HTTPAdapter
    from app.engines.packet_intelligence.adapters.tls import TLSAdapter
    from app.engines.packet_intelligence.artifacts.extractor import ArtifactExtractor
    from app.engines.packet_intelligence.provenance.validator import ProvenanceValidator
    from app.shared.contract_validation import ContractValidator

    m1_orchestrator = M1Orchestrator(
        zeek_runner=ZeekRunner(),
        zeek_reader=ZeekReader(),
        conn_adapter=ConnAdapter(),
        dns_adapter=DNSAdapter(),
        http_adapter=HTTPAdapter(),
        tls_adapter=TLSAdapter(),
        artifact_extractor=ArtifactExtractor(),
        provenance_validator=ProvenanceValidator()
    )

    # Build M2-M4 Pipeline
    from app.orchestrator.pipeline import ForensicPipelineOrchestrator
    from app.engines.analysis.engine import M2AnalysisEngine
    from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
    from app.engines.reporting.report_engine import ReportEngine

    validator = ContractValidator()
    pipeline_orchestrator = ForensicPipelineOrchestrator(
        uow=UnitOfWork(session_factory=lambda: session),
        m2_engine=M2AnalysisEngine(),
        m3_builder=InvestigationCaseBuilder(validator=validator),
        m4_engine=ReportEngine(validator=validator),
        m1_persistence=None # M1 persistence occurs in M1Orchestrator or isn't needed if pipeline handles it? Wait!
    )
    # The pipeline orchestrator run_pipeline_from_m1 does M1 persistence if m1_persistence is provided.
    # In APP-4, we need M1 persisted.
    from app.engines.packet_intelligence.persistence_service import M1PersistenceService
    pipeline_orchestrator.m1_persistence = M1PersistenceService(UnitOfWork(session_factory=lambda: session))

    return AnalysisOrchestratorService(
        uow=UnitOfWork(session_factory=lambda: session),
        analysis_repo=AnalysisRepository(session),
        acquisition_repo=AcquisitionRepository(session),
        investigation_repo=InvestigationCaseRepository(session),
        storage_service=EvidenceStorageService(),
        m1_orchestrator=m1_orchestrator,
        pipeline_orchestrator=pipeline_orchestrator
    )

