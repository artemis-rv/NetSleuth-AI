import os
import uuid
import tempfile
import aiofiles
from typing import Optional, Tuple
from uuid import UUID
from fastapi import Request, UploadFile

from app.engines.acquisition import AcquisitionService, AcquisitionError
from app.contracts.api.acquisitions import AcquisitionUploadResponse, AcquisitionResponse, AcquisitionListResponse
from app.persistence.repositories.acquisition_repository import AcquisitionRepository, EvidenceRepository
from app.persistence.repositories.investigation_repository import InvestigationCaseRepository
from app.persistence.models.acquisition_models import AcquisitionModel, EvidenceModel
from app.persistence.models.identity_models import UserModel
from app.shared.storage.minio_service import EvidenceStorageService
from app.services.audit_service import log_audit_event, get_client_ip
from app.exceptions import NotFoundError, ForbiddenError, InfrastructureError, ApplicationError, ValidationError

from sqlalchemy.ext.asyncio import AsyncSession
import logging

logger = logging.getLogger(__name__)

class AppAcquisitionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.acq_repo = AcquisitionRepository(db)
        self.ev_repo = EvidenceRepository(db)
        self.case_repo = InvestigationCaseRepository(db)
        self.storage = EvidenceStorageService()
        self.engine = AcquisitionService()  # M1 Acquisition Engine

    async def upload_evidence(
        self, 
        case_id: UUID, 
        current_user: UserModel, 
        file: UploadFile, 
        http_request: Request
    ) -> AcquisitionUploadResponse:
        if current_user.role == "analyst":
            raise ForbiddenError("Analysts are not permitted to upload evidence.")
            
        case = await self.case_repo.get(case_id)
        if not case:
            raise NotFoundError("Investigation case not found")

        # Create temporary file
        fd, temp_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        
        object_key = None
        acquisition_ref = None

        try:
            # 1. Write uploaded bytes to temp file safely
            async with aiofiles.open(temp_path, 'wb') as out_file:
                while content := await file.read(1024 * 1024):  # 1MB chunks
                    await out_file.write(content)

            # 2. Run M1 Acquisition Engine for validation and SHA-256
            try:
                acquisition_ref = self.engine.acquire(temp_path)
            except AcquisitionError as e:
                raise ValidationError(f"Evidence validation failed: {str(e)}")

            # 3. Deterministic object key (User requested: evidence/{acquisition_id}/{safe_filename})
            object_key = f"evidence/{acquisition_ref.acquisition_id}/{acquisition_ref.file_name}"
            
            # Check for existing acquisition by SHA256 to avoid UniqueViolationError
            existing_acq = await self.acq_repo.get_by_sha256(acquisition_ref.sha256)
            if existing_acq:
                ev = existing_acq.evidence[0] if existing_acq.evidence else None
                target_key = ev.object_key if (ev and ev.object_key) else object_key
                
                # Always upload to ensure the file physically exists in MinIO
                try:
                    await self.storage.upload_evidence(temp_path, target_key)
                except Exception as e:
                    logger.warning(f"Could not upload to MinIO key {target_key}: {e}")

                if not ev:
                    ev = EvidenceModel(
                        evidence_id=uuid.UUID(acquisition_ref.evidence_id),
                        acquisition_id=existing_acq.acquisition_id,
                        minio_bucket=self.storage.bucket_name,
                        object_key=target_key,
                        sha256=existing_acq.sha256,
                        size_bytes=existing_acq.file_size,
                        content_type="application/vnd.tcpdump.pcap"
                    )
                    await self.ev_repo.create(ev)

                # Link existing acquisition to the new case
                await self.acq_repo.link_to_case(case_id, existing_acq.acquisition_id)
                await self.db.commit()
                
                return AcquisitionUploadResponse(
                    acquisition_id=existing_acq.acquisition_id,
                    evidence_id=ev.evidence_id,
                    case_id=case_id,
                    file_name=existing_acq.file_name,
                    format=existing_acq.format,
                    size_bytes=existing_acq.file_size,
                    sha256=existing_acq.sha256,
                    status=existing_acq.status,
                    created_at=existing_acq.ingested_at
                )

            # 4. Upload to authoritative MinIO storage
            try:
                await self.storage.upload_evidence(temp_path, object_key)
            except Exception as e:
                raise InfrastructureError(f"Storage upload failed: {str(e)}")

            # 5. Persist metadata transactionally
            try:
                acq_model = AcquisitionModel(
                    acquisition_id=uuid.UUID(acquisition_ref.acquisition_id),
                    file_name=file.filename or acquisition_ref.file_name,
                    file_size=acquisition_ref.file_size,
                    sha256=acquisition_ref.sha256,
                    format=acquisition_ref.format,
                    source_type="pcap",
                    status="complete"
                )
                await self.acq_repo.create(acq_model)

                ev_model = EvidenceModel(
                    evidence_id=uuid.UUID(acquisition_ref.evidence_id),
                    acquisition_id=uuid.UUID(acquisition_ref.acquisition_id),
                    minio_bucket=self.storage.bucket_name,
                    object_key=object_key,
                    sha256=acquisition_ref.sha256,
                    size_bytes=acquisition_ref.file_size,
                    content_type="application/vnd.tcpdump.pcap"
                )
                await self.ev_repo.create(ev_model)

                # Link to case
                await self.acq_repo.link_to_case(case_id, uuid.UUID(acquisition_ref.acquisition_id))

                # 6. Audit Success
                await log_audit_event(
                    db=self.db,
                    action="ACQUISITION_CREATED",
                    target_entity_type="acquisition",
                    target_entity_id=str(acq_model.acquisition_id),
                    result="success",
                    actor_id=current_user.user_id,
                    actor_name=current_user.username,
                    source_ip=get_client_ip(http_request),
                    metadata={"case_id": str(case_id)}
                )
                await log_audit_event(
                    db=self.db,
                    action="EVIDENCE_STORED",
                    target_entity_type="evidence",
                    target_entity_id=str(ev_model.evidence_id),
                    result="success",
                    actor_id=current_user.user_id,
                    actor_name=current_user.username,
                    source_ip=get_client_ip(http_request),
                    metadata={"sha256": acquisition_ref.sha256, "object_key": object_key}
                )

                # Commit all metadata and audit events
                await self.db.commit()

            except Exception as e:
                # Rollback Postgres metadata
                await self.db.rollback()
                
                # EMIT ORPHANED AUDIT LOG
                logger.error(f"Postgres persistence failed after MinIO upload! Orphan object: {object_key}. Error: {e}")
                
                await log_audit_event(
                    db=self.db,
                    action="EVIDENCE_ORPHANED",
                    target_entity_type="minio_object",
                    target_entity_id=object_key,
                    result="failure",
                    actor_id=current_user.user_id,
                    actor_name=current_user.username,
                    source_ip=get_client_ip(http_request),
                    metadata={"error": str(e), "acquisition_id": acquisition_ref.acquisition_id}
                )
                await self.db.commit() # Ensure audit log gets committed
                raise InfrastructureError("Evidence stored in MinIO but metadata persistence failed. Object left for reconciliation.")

            return AcquisitionUploadResponse(
                acquisition_id=acq_model.acquisition_id,
                evidence_id=ev_model.evidence_id,
                case_id=case_id,
                file_name=acq_model.file_name,
                format=acq_model.format,
                size_bytes=acq_model.file_size,
                sha256=acq_model.sha256,
                status=acq_model.status,
                created_at=ev_model.registered_at
            )

        finally:
            # 7. Always clean up temporary file
            try:
                os.remove(temp_path)
            except OSError:
                pass

    async def list_acquisitions(
        self, 
        case_id: UUID, 
        current_user: UserModel,
        page: int = 1,
        page_size: int = 25,
        status: Optional[str] = None,
        format: Optional[str] = None
    ) -> AcquisitionListResponse:
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        skip = (page - 1) * page_size
        
        items, total = await self.acq_repo.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            status=status,
            format=format
        )
        
        return AcquisitionListResponse(
            items=[AcquisitionResponse.model_validate(item) for item in items],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_acquisition(self, acquisition_id: UUID, current_user: UserModel) -> AcquisitionResponse:
        acq = await self.acq_repo.get(acquisition_id)
        if not acq:
            raise NotFoundError("Acquisition not found")
        return AcquisitionResponse.model_validate(acq)
