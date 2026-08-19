from typing import Dict, Any, Optional
import logging
import uuid
from app.persistence.transactions.uow import UnitOfWork

# Engine Domains
from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FindingsPackage
from app.engines.reporting.evidence_package import M4EvidencePackage

# LLM Integration
from app.engines.llm_assistant.service import LLMAssistantService
from app.engines.llm_assistant.models import LLMInvestigationResponse, LLMResponseStatus
from app.engines.llm_assistant.context_assembler import ContextAssembler
import copy

# M1
from app.engines.packet_intelligence.persistence_service import M1PersistenceService
from app.contracts.network_intelligence import AcquisitionReference

# M2
from app.engines.analysis.engine import M2AnalysisEngine
from app.engines.analysis.persistence_service import M2PersistenceService

# M3
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.engines.correlation.investigation.hypothesis_generator import HypothesisGenerator
from app.engines.correlation.investigation.hypothesis_validator import HypothesisValidator
from app.engines.correlation.investigation.root_cause_analyzer import RootCauseAnalyzer
from app.engines.correlation.investigation.impact_assessor import ImpactAssessor
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
        m1_persistence: M1PersistenceService = None, # type: ignore
        llm_service: Optional[LLMAssistantService] = None
    ):
        self.uow = uow
        self.m2_engine = m2_engine
        self.m3_builder = m3_builder
        self.m4_engine = m4_engine
        self.llm_service = llm_service
        
        # M3 Investigation Engines
        self.hypothesis_generator = HypothesisGenerator()
        self.hypothesis_validator = HypothesisValidator()
        self.root_cause_analyzer = RootCauseAnalyzer()
        self.impact_assessor = ImpactAssessor()
        
        # Persistence Services
        self.m1_persistence = m1_persistence
        self.m2_persistence = M2PersistenceService()
        self.m3_persistence = M3PersistenceService(uow)
        self.m4_persistence = M4PersistenceService(uow)

    def _get_llm_context(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any]):
        if not self.llm_service:
            return None
        assembler = ContextAssembler()
        return assembler.assemble(case_dict, evidence_map)

    def _run_coro_sync(self, coro):
        import asyncio
        import concurrent.futures
        try:
            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        except RuntimeError:
            return asyncio.run(coro)

    def generate_llm_summary(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any] = None) -> Optional[LLMInvestigationResponse]:
        if not self.llm_service:
            return None
        try:
            # Take a validated snapshot to guarantee immutability of original data
            case_snapshot = copy.deepcopy(case_dict)
            ctx = self._get_llm_context(case_snapshot, evidence_map or {})
            return self._run_coro_sync(self.llm_service.generate_summary(ctx))
        except Exception as e:
            logger.error(f"Optional LLM Summary generation failed: {e}")
            return LLMInvestigationResponse(
                request_id=str(uuid.uuid4()),
                case_id=case_dict.get("case_id", "unknown"),
                status=LLMResponseStatus.LLM_INVALID_RESPONSE,
                provenance={}
            )

    def generate_llm_mitre_explanation(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any], technique_id: str) -> Optional[LLMInvestigationResponse]:
        if not self.llm_service:
            return None
        try:
            case_snapshot = copy.deepcopy(case_dict)
            
            # Requested technique must already exist
            mappings = case_snapshot.get("mitre_mappings", [])
            exists = any(m.get("technique_id") == technique_id for m in mappings)
            if not exists:
                return LLMInvestigationResponse(
                    request_id=str(uuid.uuid4()),
                    case_id=case_dict.get("case_id", "unknown"),
                    status=LLMResponseStatus.LLM_INVALID_RESPONSE,
                    provenance={}
                )

            ctx = self._get_llm_context(case_snapshot, evidence_map or {})
            return self._run_coro_sync(self.llm_service.generate_mitre_explanation(ctx, technique_id))
        except Exception as e:
            logger.error(f"Optional LLM MITRE explanation generation failed: {e}")
            return LLMInvestigationResponse(
                request_id=str(uuid.uuid4()),
                case_id=case_dict.get("case_id", "unknown"),
                status=LLMResponseStatus.LLM_INVALID_RESPONSE,
                provenance={}
            )

    def generate_llm_qa(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any], question: str) -> Optional[LLMInvestigationResponse]:
        if not self.llm_service:
            return None
        try:
            case_snapshot = copy.deepcopy(case_dict)
            ctx = self._get_llm_context(case_snapshot, evidence_map or {})
            return self._run_coro_sync(self.llm_service.generate_qa(ctx, question))
        except Exception as e:
            logger.error(f"Optional LLM Q&A generation failed: {e}")
            return LLMInvestigationResponse(
                request_id=str(uuid.uuid4()),
                case_id=case_dict.get("case_id", "unknown"),
                status=LLMResponseStatus.LLM_INVALID_RESPONSE,
                provenance={}
            )

    async def run_pipeline_from_m1(self, m1_package: NetworkIntelligencePackage, case_id: str = None) -> Dict[str, Any]:
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
        
        # 3a. M3 Canonical Input Assembly
        from app.engines.correlation.adapters.m3_input_adapter import M3InputAdapter
        m3_adapter = M3InputAdapter()
        m3_input = m3_adapter.adapt(m1_package.model_dump(mode="json"), m2_package.model_dump(mode="json"))

        ctx = InvestigationContext(case_id=case_id if case_id else f"CASE-{m1_package.acquisition_id}", acquisition_id=m1_package.acquisition_id)
        from app.engines.correlation.domain.finding import FindingReference
        from app.engines.correlation.domain.timeline import TimelineEvent
        from app.engines.correlation.domain.entity import Entity
        from app.engines.correlation.domain.evidence import EvidenceReference as DomainEvidenceReference
        import datetime

        # 1. Map all M1 Evidence References (flows, events, artifacts) for strict referential integrity
        declared_ev_ids = set()
        for flow in m1_package.flows:
            if flow.flow_id not in declared_ev_ids:
                ctx.evidence_references.append(DomainEvidenceReference(evidence_id=flow.flow_id, evidence_type="flow", source_id=flow.flow_id))
                declared_ev_ids.add(flow.flow_id)
        for event in m1_package.protocol_events:
            if event.event_id not in declared_ev_ids:
                ctx.evidence_references.append(DomainEvidenceReference(evidence_id=event.event_id, evidence_type="session", source_id=event.event_id))
                declared_ev_ids.add(event.event_id)
        for art in m1_package.artifacts:
            if art.artifact_id not in declared_ev_ids:
                ctx.evidence_references.append(DomainEvidenceReference(evidence_id=art.artifact_id, evidence_type="artifact", source_id=art.artifact_id))
                declared_ev_ids.add(art.artifact_id)

        # 2. Extract Real Domain Entities from M1 Network Intelligence & M2 Findings
        seen_entity_ids = set()
        for flow in m1_package.flows:
            src_ip = str(flow.source.ip)
            dst_ip = str(flow.destination.ip)
            src_ent_id = f"ip:{src_ip}"
            dst_ent_id = f"ip:{dst_ip}"
            if src_ent_id not in seen_entity_ids:
                ctx.entities.append(Entity(entity_id=src_ent_id, entity_type="ip", value=src_ip, first_seen=flow.timestamp, last_seen=flow.timestamp))
                seen_entity_ids.add(src_ent_id)
            if dst_ent_id not in seen_entity_ids:
                ctx.entities.append(Entity(entity_id=dst_ent_id, entity_type="ip", value=dst_ip, first_seen=flow.timestamp, last_seen=flow.timestamp))
                seen_entity_ids.add(dst_ent_id)

        for evt in m1_package.protocol_events:
            p_data = evt.protocol_data.model_dump() if hasattr(evt.protocol_data, "model_dump") else (evt.protocol_data if isinstance(evt.protocol_data, dict) else {})
            
            if evt.protocol == "dns" and p_data:
                q = getattr(evt.protocol_data, "query", None) or p_data.get("query")
                if q:
                    dom_ent_id = f"domain:{q}"
                    if dom_ent_id not in seen_entity_ids:
                        ctx.entities.append(Entity(entity_id=dom_ent_id, entity_type="domain", value=q, first_seen=evt.timestamp, last_seen=evt.timestamp))
                        seen_entity_ids.add(dom_ent_id)
            elif evt.protocol == "tls" and p_data:
                sni = getattr(evt.protocol_data, "server_name", None) or p_data.get("server_name")
                if sni:
                    dom_ent_id = f"domain:{sni}"
                    if dom_ent_id not in seen_entity_ids:
                        ctx.entities.append(Entity(entity_id=dom_ent_id, entity_type="domain", value=sni, first_seen=evt.timestamp, last_seen=evt.timestamp))
                        seen_entity_ids.add(dom_ent_id)

        for art in m1_package.artifacts:
            art_ent_id = f"artifact:{art.artifact_id}"
            if art_ent_id not in seen_entity_ids:
                ctx.entities.append(Entity(entity_id=art_ent_id, entity_type="artifact", value=art.value, attributes={"source_event_id": art.source_event_id, "flow_id": art.flow_id}))
                seen_entity_ids.add(art_ent_id)

        for finding in m2_package.findings:
            f_ent_id = f"finding:{finding.finding_id}"
            if f_ent_id not in seen_entity_ids:
                ctx.entities.append(Entity(entity_id=f_ent_id, entity_type="finding", value=finding.activity_class.value, attributes={"risk_score": finding.risk_score, "confidence": finding.classification_confidence}))
                seen_entity_ids.add(f_ent_id)

        # 3. Extract Findings References (for M3 input)
        for finding in m2_package.findings:
            ref = FindingReference(
                finding_id=finding.finding_id,
                finding_type=finding.activity_class.value,
                severity="high" if finding.risk_score > 0.8 else "low",
                confidence_score=finding.classification_confidence
            )
            ctx.findings.append(ref)

        # 4. Reconstruct Semantic Timeline
        from app.engines.correlation.timeline.builder import TimelineReconstructor
        timeline_reconstructor = TimelineReconstructor()
        ctx.timeline_events = timeline_reconstructor.reconstruct(ctx, m1_package, m2_package)

        # 3b. M3 Deterministic Correlation
        from app.engines.correlation.correlation.correlation_engine import CorrelationEngine
        correlation_engine = CorrelationEngine()
        ctx = correlation_engine.correlate(ctx)
        
        # 3c. MITRE Mapping
        from app.engines.correlation.mitre.repository import MitreKnowledgeRepository
        from app.engines.correlation.mitre.mapper import MitreMapper
        repo = MitreKnowledgeRepository()
        mapper = MitreMapper(repo)
        
        ctx.mitre_mappings = []
        for finding in m2_package.findings:
            mappings = mapper.map_finding(m3_input, finding.finding_id)
            ctx.mitre_mappings.extend(mappings)
        
        # 3d. Investigation Engine
        ctx.hypotheses = self.hypothesis_generator.generate(ctx, m3_input)
        ctx.hypothesis_validations = self.hypothesis_validator.validate(ctx, m3_input)
        ctx.root_causes = self.root_cause_analyzer.analyze(ctx, m3_input)
        ctx.impact_assessments = self.impact_assessor.analyze(ctx, m3_input)
        
        # 3e. Investigation Case Builder (Attack Chain & Formatting)
        m3_case_dict = self.m3_builder.build(ctx)
        case_id = m3_case_dict["case_id"]
        
        logger.info(f"Persisting M3 Investigation Case: {case_id}...")
        async with self.uow:
            # We associate the case with the original M1 acquisition to link custody
            await self.m3_persistence.persist_investigation_case(m3_case_dict, acquisition_id=m1_package.acquisition_id)
        logger.info("M3 Persistence Complete.")

        # --- 3.5. Optional LLM Assistant Phase ---
        logger.info("Executing Optional LLM Assistant Phase...")
        llm_enrichment = None
        if self.llm_service:
            llm_enrichment = self.generate_llm_summary(m3_case_dict, {})

        # --- 4. M4 Reporting Phase ---
        logger.info("Executing M4 Evidence & Reporting Engine...")
        llm_dict = llm_enrichment.model_dump(mode="json") if llm_enrichment else None
        m4_report = self.m4_engine.generate_report(m3_case_dict, [], llm_enrichment=llm_dict)

        # Persist M4 report metadata to PostgreSQL
        try:
            logger.info("Persisting M4 Report...")
            async with self.uow:
                report_title = m4_report.get("title", f"Investigation Report — {case_id}")
                report_sha256 = m4_report.get("integrity", {}).get("sha256") or "0" * 64
                report_schema = m4_report.get("schema_version", "report-v1.3")
                await self.m4_persistence.persist_report(
                    case_id=str(case_id),
                    title=report_title,
                    report_type="forensic_investigation",
                    format="json",
                    minio_bucket="netsleuth-reports",
                    object_key=f"{case_id}/report.json",
                    hash_sha256=report_sha256,
                    generator_id="m4-report-engine"
                )
            logger.info("M4 Persistence Complete.")
        except Exception as m4_err:
            # M4 persistence failure must NOT erase already-persisted M3 forensic data.
            # Log and continue — analysis is still complete from a forensic standpoint.
            logger.warning(f"M4 report persistence failed (non-fatal): {m4_err}")

        logger.info("Forensic Pipeline E2E execution successful.")
        return {
            "status": "success",
            "acquisition_id": m1_package.acquisition_id,
            "case_id": case_id,
            "findings_count": len(m2_package.findings),
            "m4_report": m4_report,
            "llm_enrichment": llm_enrichment.model_dump() if llm_enrichment else None
        }
