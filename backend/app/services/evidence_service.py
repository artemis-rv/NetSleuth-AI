from typing import Optional
from uuid import UUID
from fastapi import Request

from app.contracts.api.evidence import EvidenceResponse, EvidenceListResponse, EvidenceVerificationResponse
from app.persistence.repositories.acquisition_repository import EvidenceRepository
from app.persistence.models.identity_models import UserModel
from app.shared.storage.minio_service import EvidenceStorageService
from app.services.audit_service import log_audit_event, get_client_ip
from app.exceptions import NotFoundError, InfrastructureError

from sqlalchemy.ext.asyncio import AsyncSession

class EvidenceService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.ev_repo = EvidenceRepository(db)
        self.storage = EvidenceStorageService()

    async def list_evidence(
        self, 
        case_id: UUID, 
        current_user: UserModel,
        page: int = 1,
        page_size: int = 25
    ) -> EvidenceListResponse:
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        skip = (page - 1) * page_size
        
        items, total = await self.ev_repo.list_by_case(case_id, skip, page_size)
        
        return EvidenceListResponse(
            items=[EvidenceResponse.model_validate(item) for item in items],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_evidence(self, evidence_id: UUID, current_user: UserModel, http_request: Request) -> EvidenceResponse:
        ev = await self.ev_repo.get(evidence_id)
        if not ev:
            raise NotFoundError("Evidence not found")
            
        actor_id = current_user.user_id
        actor_name = current_user.username
        
        await log_audit_event(
            db=self.db,
            action="EVIDENCE_VIEWED",
            target_entity_type="evidence",
            target_entity_id=str(evidence_id),
            result="success",
            actor_id=actor_id,
            actor_name=actor_name,
            source_ip=get_client_ip(http_request)
        )
        await self.db.commit()
            
        return EvidenceResponse.model_validate(ev)

    async def verify_integrity(self, evidence_id: UUID, current_user: UserModel, http_request: Request) -> EvidenceVerificationResponse:
        ev = await self.ev_repo.get(evidence_id)
        if not ev:
            raise NotFoundError("Evidence not found")
            
        is_verified, observed_hash = await self.storage.verify_evidence_integrity(ev.object_key, ev.sha256)
        
        if observed_hash is None:
            status = "missing"
        else:
            status = "verified" if is_verified else "mismatch"
            
        actor_id = current_user.user_id
        actor_name = current_user.username
        expected_sha256 = ev.sha256
        
        await log_audit_event(
            db=self.db,
            action="EVIDENCE_INTEGRITY_VERIFIED",
            target_entity_type="evidence",
            target_entity_id=str(evidence_id),
            result="success" if is_verified else "failure",
            actor_id=actor_id,
            actor_name=actor_name,
            source_ip=get_client_ip(http_request),
            metadata={"status": status, "expected_sha256": expected_sha256, "observed_sha256": observed_hash}
        )
        await self.db.commit()
        
        return EvidenceVerificationResponse(
            evidence_id=evidence_id,
            expected_sha256=expected_sha256,
            observed_sha256=observed_hash,
            integrity_status=status
        )
