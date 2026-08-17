from typing import Dict, Any, Optional
import logging
import uuid
from app.persistence.transactions.uow import UnitOfWork

# Engine Domains
from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FindingsPackage
from app.engines.reporting.evidence_package import M4EvidencePackage

# M1
from app.engines.packet_intelligence.persistence_service import M1PersistenceService
from app.contracts.network_intelligence import AcquisitionReference

# M2
from app.engines.analysis.engine import M2AnalysisEngine
from app.engines.analysis.persistence_service import M2PersistenceService

# M3
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.persistence_service import M3PersistenceService

# M4
from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.persistence_service import M4PersistenceService

logger = logging.getLogger(__name__)

class ForensicPipelineOrchestrator:
    """
    End-to-End System Integration Orchestrator.
    Manages the deterministic flow of forensic data from M1 -> M2 -> M3 -> M4,
    ensuring each stage is correctly persisted to the PostgreSQL / MinIO boundary.
    """

    def __init__(
        self,
        uow: UnitOfWork,
        m2_engine: M2AnalysisEngine,
        m3_builder: InvestigationCaseBuilder,
        m4_engine: ReportEngine,
        m1_persistence: M1PersistenceService = None # type: ignore
    ):
        self.uow = uow
        self.m2_engine = m2_engine
        self.m3_builder = m3_builder
        self.m4_engine = m4_engine
        
        # Persistence Services
        self.m1_persistence = m1_persistence
        self.m2_persistence = M2PersistenceService()
        self.m3_persistence = M3PersistenceService(uow)
        self.m4_persistence = M4PersistenceService(uow)

    async def run_pipeline_from_m1(self, m1_package: NetworkIntelligencePackage) -> Dict[str, Any]:
        """
        Fast E2E pipeline primarily used for CI tests.
        Bypasses PCAP/Zeek processing (M1 extraction) and begins directly with 
        a validated NetworkIntelligencePackage.
        """
        logger.info(f"Starting E2E Pipeline with M1 Package for Acquisition: {m1_package.acquisition_id}")
        
        # --- 1. M1 Persistence Phase ---
        logger.info("Persisting M1 Package...")
        # We assume M1 data isn't persisted yet in the fast-pipeline test
        acq_ref = AcquisitionReference(
            acquisition_id=m1_package.acquisition_id,
            evidence_id=str(uuid.uuid4()),
            file_name="mock.pcap",
            file_size=1024,
            format="pcap",
            sha256=uuid.uuid4().hex + uuid.uuid4().hex, # 64 chars
            capture_reference="mock.pcap"
        )
        if self.m1_persistence:
            await self.m1_persistence._persist_package(
                acq_ref=acq_ref,
                object_key=f"{m1_package.acquisition_id}/mock.pcap",
                package=m1_package
            )
        logger.info("M1 Persistence Complete.")

        # --- 2. M2 Analysis Phase ---
        logger.info("Executing M2 Analysis Engine...")
        m2_package: FindingsPackage = self.m2_engine.analyze(m1_package)
        
        logger.info(f"Persisting M2 Findings Package ({len(m2_package.findings)} findings)...")
        await self.m2_persistence.persist_findings_package(m2_package)
        logger.info("M2 Persistence Complete.")

        # --- 3. M3 Correlation Phase ---
        logger.info("Executing M3 Correlation Engine...")
        ctx = InvestigationContext(case_id=f"CASE-{m1_package.acquisition_id}")
        from app.engines.correlation.domain.finding import FindingReference
        from app.engines.correlation.domain.timeline import TimelineEvent
        import datetime
        for finding in m2_package.findings:
            ref = FindingReference(
                finding_id=finding.finding_id,
                finding_type=finding.activity_class.value,
                severity="high" if finding.risk_score > 0.8 else "low",
                confidence_score=finding.classification_confidence
            )
            ctx.findings.append(ref)
            ctx.timeline_events.append(TimelineEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                event_type="Finding Triggered",
                description=f"Finding {finding.finding_id} generated",
                finding_ids=[finding.finding_id]
            ))
        
        # Trigger M3 rules/correlation algorithms if applicable
        # (Assuming CaseBuilder does this internally or via another orchestrator)
        m3_case_dict = self.m3_builder.build(ctx)
        case_id = m3_case_dict["case_id"]
        
        logger.info(f"Persisting M3 Investigation Case: {case_id}...")
        async with self.uow:
            # We associate the case with the original M1 acquisition to link custody
            await self.m3_persistence.persist_investigation_case(m3_case_dict, acquisition_id=m1_package.acquisition_id)
        logger.info("M3 Persistence Complete.")

        # --- 4. M4 Reporting Phase ---
        logger.info("Executing M4 Evidence & Reporting Engine...")
        m4_report = self.m4_engine.generate_report(m3_case_dict, [])
        
        # NOTE: M4 persistence service is mocked or not injected here yet,
        # but in a real flow we would call self.m4_persistence.persist_report(m4_report)
        # We'll return m4_report for the test to validate it generated successfully.
        
        logger.info("Forensic Pipeline E2E execution successful.")
        return {
            "status": "success",
            "acquisition_id": m1_package.acquisition_id,
            "case_id": case_id,
            "findings_count": len(m2_package.findings),
            "m4_report": m4_report
        }
