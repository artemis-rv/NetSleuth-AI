import uuid
import json
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request

from app.engines.llm_assistant.service import LLMAssistantService
from app.engines.llm_assistant.client import OllamaClient
from app.engines.llm_assistant.context_assembler import ContextAssembler
from app.engines.llm_assistant.models import LLMInvestigationResponse
from app.services.audit_service import log_audit_event, get_client_ip
from app.services.investigation_service import InvestigationService
from app.services.findings_service import FindingsService
from app.persistence.models.identity_models import UserModel

class CopilotOrchestrator:
    def __init__(self, db: AsyncSession, llm_service: Optional[LLMAssistantService] = None):
        self.db = db
        self.client = llm_service.client if (llm_service and hasattr(llm_service, "client")) else OllamaClient()
        self.llm_service = llm_service or LLMAssistantService(self.client)
        self.context_assembler = ContextAssembler()
        self.investigation_service = InvestigationService(db)
        self.findings_service = FindingsService(db)

    async def _build_case_dict(self, case_id: uuid.UUID) -> Dict[str, Any]:
        entities = await self.investigation_service.entity_repo.list_by_case(case_id, skip=0, limit=1000)
        relationships = await self.investigation_service.relationship_repo.list_by_case(case_id, skip=0, limit=1000)
        timeline = await self.investigation_service.timeline_repo.list_by_case(case_id, skip=0, limit=1000)
        mitre_mappings = await self.investigation_service.mitre_repo.list_by_case(case_id, skip=0, limit=1000)
        attack_chain = await self.investigation_service.attack_chain_repo.get_by_case(case_id)
        findings = await self.findings_service.repository.list_by_case(case_id=case_id, skip=0, limit=1000)
        
        # V1.3 assessment objects
        hypotheses_objs = await self.investigation_service.hypothesis_repo.list_by_case(case_id, skip=0, limit=1000) if hasattr(self.investigation_service, 'hypothesis_repo') else []
        root_causes_objs = await self.investigation_service.root_cause_repo.list_by_case(case_id, skip=0, limit=1000) if hasattr(self.investigation_service, 'root_cause_repo') else []
        impacts_objs = await self.investigation_service.impact_repo.list_by_case(case_id, skip=0, limit=1000) if hasattr(self.investigation_service, 'impact_repo') else []
        
        from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
        case_obj = await InvestigationCaseRepository(self.db).get(case_id)
        case_title = case_obj.title if case_obj else "Investigation Case"
        case_status = case_obj.status if case_obj else "OPEN"

        case_dict = {
            "schema_version": "investigation-case-v1.3",
            "case_id": str(case_id),
            "case_metadata": {
                "title": case_title,
                "status": case_status,
            },
            "findings": [
                {
                    "finding_id": str(f.finding_id),
                    "activity": f.activity,
                    "risk_score": f.risk_score,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "decision_state": f.decision_state,
                    "rationale": f.rationale,
                    "feature_attribution": f.feature_attribution,
                    "evidence_ids": [f"ev-{f.finding_id}"]
                } for f in findings
            ],
            "entities": [
                {
                    "entity_id": str(e.entity_id),
                    "entity_type": e.entity_type,
                    "label": e.label,
                    "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                    "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                } for e in entities
            ],
            "timeline": [
                {
                    "event_id": str(t.timeline_event_id),
                    "timestamp": t.event_timestamp.isoformat() if t.event_timestamp else None,
                    "event_type": t.event_type,
                    "description": t.description,
                    "evidence_ids": t.attributes.get("evidence_ids", []) if t.attributes else []
                } for t in timeline
            ],
            "relationships": [
                {
                    "relationship_id": str(r.relationship_id),
                    "source_entity_id": str(r.source_entity_id),
                    "target_entity_id": str(r.target_entity_id),
                    "relationship_type": r.relationship_type,
                    "confidence": r.strength,
                    "evidence_ids": r.attributes.get("evidence_ids", []) if r.attributes else []
                } for r in relationships
            ],
            "evidence_references": [],
            "mitre_mappings": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic_id": m.tactic,
                    "tactic_name": m.tactic,
                    "mapping_status": "SUPPORTED",
                    "mapping_confidence": float(m.confidence) if m.confidence is not None else 0.95,
                    "rationale": m.justification,
                    "evidence_ids": [f"ev-{m.technique_id}"],
                } for m in mitre_mappings
            ],
            "hypotheses": [
                {
                    "hypothesis_id": str(h.hypothesis_id),
                    "statement": h.statement,
                    "hypothesis_type": getattr(h, 'hypothesis_type', None),
                    "status": h.status,
                    "confidence": h.confidence,
                    "supporting_evidence": h.supporting_evidence or [],
                    "supporting_findings": h.supporting_findings or [],
                    "reasons": h.reasons or [],
                    "missing_evidence": h.missing_evidence or []
                } for h in hypotheses_objs
            ],
            "root_causes": [
                {
                    "root_cause_id": str(rc.root_cause_id),
                    "statement": rc.statement,
                    "status": rc.status,
                    "confidence": rc.confidence,
                    "supporting_hypotheses": rc.supporting_hypotheses or [],
                    "supporting_evidence": rc.supporting_evidence or [],
                    "rationale": getattr(rc, 'rationale', None),
                    "missing_evidence": rc.missing_evidence or []
                } for rc in root_causes_objs
            ],
            "impacts": [
                {
                    "impact_id": str(imp.impact_id),
                    "category": imp.category,
                    "statement": imp.statement,
                    "status": imp.status,
                    "confidence": imp.confidence,
                    "evidence": imp.evidence or [],
                    "affected_entities": imp.affected_entities or [],
                    "rationale": getattr(imp, 'rationale', None),
                    "missing_evidence": imp.missing_evidence or []
                } for imp in impacts_objs
            ]
        }
        
        if attack_chain and attack_chain.stages:
            if isinstance(attack_chain.stages, dict):
                case_dict["attack_chain"] = attack_chain.stages
            else:
                case_dict["attack_chain"] = {
                    "status": "potential",
                    "stages": attack_chain.stages
                }
            
        return case_dict

    async def _build_evidence_map(self, case_id: uuid.UUID) -> Dict[str, Any]:
        return {}

    async def _get_context(self, case_id: uuid.UUID) -> Any:
        case_dict = await self._build_case_dict(case_id)
        evidence_map = await self._build_evidence_map(case_id)
        return self.context_assembler.assemble(case_dict, evidence_map)

    async def generate_summary(self, case_id: uuid.UUID, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_summary(ctx)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_SUMMARY_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req)
        )
        await self.db.commit()
        return resp

    async def generate_finding_explanation(self, case_id: uuid.UUID, finding_id: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_finding_explanation(ctx, finding_id)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_FINDING_EXPLANATION_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"finding_id": finding_id}
        )
        await self.db.commit()
        return resp

    async def generate_mitre_explanation(self, case_id: uuid.UUID, technique_id: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_mitre_explanation(ctx, technique_id)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_MITRE_EXPLANATION_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"technique_id": technique_id}
        )
        await self.db.commit()
        return resp

    async def generate_hypothesis_explanation(self, case_id: uuid.UUID, hypothesis_id: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_hypothesis_explanation(ctx, hypothesis_id)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_HYPOTHESIS_EXPLANATION_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"hypothesis_id": hypothesis_id}
        )
        await self.db.commit()
        return resp

    async def generate_root_cause_explanation(self, case_id: uuid.UUID, root_cause_id: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_root_cause_explanation(ctx, root_cause_id)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_ROOT_CAUSE_EXPLANATION_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"root_cause_id": root_cause_id}
        )
        await self.db.commit()
        return resp

    async def generate_impact_explanation(self, case_id: uuid.UUID, impact_id: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_impact_explanation(ctx, impact_id)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_IMPACT_EXPLANATION_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"impact_id": impact_id}
        )
        await self.db.commit()
        return resp

    async def generate_qa(self, case_id: uuid.UUID, question: str, user: UserModel, req: Request) -> LLMInvestigationResponse:
        ctx = await self._get_context(case_id)
        resp = await self.llm_service.generate_qa(ctx, question)
        
        await log_audit_event(
            db=self.db,
            action="COPILOT_QA_GENERATED",
            target_entity_type="investigation_case",
            target_entity_id=str(case_id),
            result="success" if resp.status == "SUCCESS" else "failure",
            actor_id=user.user_id,
            actor_name=user.username,
            source_ip=get_client_ip(req),
            metadata={"question": question}
        )
        await self.db.commit()
        return resp
