import hashlib
import uuid
from uuid import UUID
from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.models.custody_models import ReportModel
from app.persistence.models.identity_models import UserModel
from app.persistence.repositories.custody_repository import ReportRepository
from app.persistence.repositories.investigation_repository import (
    InvestigationCaseRepository, EntityRepository, RelationshipRepository,
    BehaviorRepository, TimelineEventRepository, MitreMappingRepository
)
from app.contracts.api.reports import ReportListResponse, ReportResponse
from app.engines.reporting.report_engine import ReportEngine
from app.engines.reporting.html_renderer import HTMLReportRenderer
from app.engines.reporting.pdf_renderer import PDFReportRenderer
from app.engines.reporting.report_exporter import ReportExporter
from app.shared.contract_validation import ContractValidator
from app.shared.storage.minio_service import ReportStorageService
from app.services.audit_service import log_audit_event, get_client_ip
from app.auth.dependencies import verify_case_access_direct
from app.exceptions import NotFoundError, ForbiddenError, ConflictError, ValidationError, InfrastructureError

class ReportsService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.report_repo = ReportRepository(db)
        self.case_repo = InvestigationCaseRepository(db)
        self.storage_service = ReportStorageService()
        self.validator = ContractValidator()
        self.report_engine = ReportEngine(self.validator)

    async def list_reports_by_case(self, case_id: UUID, page: int, page_size: int) -> ReportListResponse:
        skip = (page - 1) * page_size
        reports = await self.report_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.report_repo.count_by_case(case_id=case_id)
        
        return ReportListResponse(
            items=[ReportResponse.model_validate(r) for r in reports],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_report(self, report_id: UUID) -> ReportResponse:
        report = await self.report_repo.get(report_id)
        if not report:
            raise NotFoundError(f"Report {report_id} not found")
        return ReportResponse.model_validate(report)

    async def generate_report(
        self,
        case_id: UUID,
        current_user: UserModel,
        format: str = "pdf",
        title: Optional[str] = None,
        http_request: Optional[Request] = None
    ) -> ReportResponse:
        fmt = format.lower()
        if fmt not in ("pdf", "html", "json"):
            raise ValidationError(f"Unsupported report format '{format}'. Supported formats: pdf, html, json.")

        await verify_case_access_direct(case_id, current_user, self.db)

        case = await self.case_repo.get(case_id)
        if not case:
            raise NotFoundError(f"Case {case_id} not found")

        # Fetch case investigation sub-items
        entity_repo = EntityRepository(self.db)
        rel_repo = RelationshipRepository(self.db)
        timeline_repo = TimelineEventRepository(self.db)
        behavior_repo = BehaviorRepository(self.db)

        entities = await entity_repo.list_by_case(case_id=case_id, skip=0, limit=500)
        relationships = await rel_repo.list_by_case(case_id=case_id, skip=0, limit=500)
        timeline_events = await timeline_repo.list_by_case(case_id=case_id, skip=0, limit=500)
        behaviors = await behavior_repo.list_by_case(case_id=case_id, skip=0, limit=500)

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Build investigation case dictionary conforming to investigation-case-v1.1
        case_dict = {
            "schema_version": "investigation-case-v1.1",
            "case_id": f"CASE-{case_id}",
            "created_at": case.opened_at.isoformat().replace("+00:00", "Z") if getattr(case, "opened_at", None) else now_iso,
            "updated_at": case.updated_at.isoformat().replace("+00:00", "Z") if getattr(case, "updated_at", None) else now_iso,
            "title": case.title,
            "description": case.description or "Forensic Investigation Report",
            "status": case.status,
            "severity": "medium",
            "investigator": {
                "investigator_id": str(current_user.user_id),
                "name": current_user.full_name or current_user.username
            },
            "evidence_references": [],
            "findings": [
                {
                    "finding_id": str(b.behavior_id),
                    "title": b.behavior_type,
                    "severity": b.severity,
                    "confidence": b.confidence,
                    "description": f"Observed behavior: {b.behavior_type}"
                } for b in behaviors
            ],
            "timeline": [
                {
                    "event_id": str(te.event_id),
                    "timestamp": te.timestamp.isoformat().replace("+00:00", "Z") if te.timestamp else now_iso,
                    "title": te.title or f"Timeline Event {te.event_id}",
                    "description": te.description
                } for te in timeline_events
            ],
            "entities": [
                {
                    "entity_id": str(e.entity_id),
                    "entity_type": e.entity_type if e.entity_type in ("ip", "domain", "url", "session", "flow", "protocol_event", "ioc", "artifact", "finding") else "artifact",
                    "value": e.value
                } for e in entities
            ],
            "relationships": [
                {
                    "relationship_id": str(r.relationship_id),
                    "source_entity_id": str(r.source_entity_id),
                    "target_entity_id": str(r.target_entity_id),
                    "relationship_type": r.relationship_type
                } for r in relationships
            ]
        }

        # Generate report payload using ReportEngine
        report_payload = self.report_engine.generate_report(case_dict, [])

        # Render format artifact bytes
        if fmt == "html":
            artifact_str = HTMLReportRenderer(self.validator).render(report_payload)
            artifact_bytes = artifact_str.encode("utf-8")
        elif fmt == "pdf":
            artifact_bytes = PDFReportRenderer(self.validator).render(report_payload)
        else:  # json
            artifact_str = ReportExporter(self.validator).export_json(report_payload)
            artifact_bytes = artifact_str.encode("utf-8")

        hash_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        report_id = uuid.uuid4()
        object_key = f"reports/{case_id}/draft/{report_id}.{fmt}"

        # Upload to MinIO netsleuth-reports bucket
        await self.storage_service.upload_report_bytes(artifact_bytes, object_key)

        report_title = title or f"{case.title} - Forensic Report ({fmt.upper()})"
        bucket_name = self.storage_service.bucket_name

        report_model = ReportModel(
            report_id=report_id,
            case_id=case_id,
            report_type="draft",
            version=1,
            title=report_title,
            minio_bucket=bucket_name,
            object_key=object_key,
            sha256=hash_sha256,
            format=fmt,
            generated_by=current_user.user_id
        )
        self.db.add(report_model)
        await self.db.flush()

        ip = get_client_ip(http_request) if http_request else "127.0.0.1"
        await log_audit_event(
            db=self.db,
            action="REPORT_GENERATED",
            target_entity_type="report",
            target_entity_id=str(report_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=ip,
            metadata={"sha256": hash_sha256, "format": fmt}
        )
        await self.db.commit()

        return ReportResponse.model_validate(report_model)

    async def finalize_report(
        self,
        report_id: UUID,
        current_user: UserModel,
        http_request: Optional[Request] = None
    ) -> ReportResponse:
        if current_user.role == "analyst":
            raise ForbiddenError("Analysts are not permitted to finalize reports.")

        report = await self.report_repo.get(report_id)
        if not report:
            raise NotFoundError(f"Report {report_id} not found")

        await verify_case_access_direct(report.case_id, current_user, self.db)

        if report.report_type == "final":
            raise ConflictError(f"Report {report_id} is already finalized and immutable.")

        # Move/copy draft object to final path in MinIO
        draft_key = report.object_key
        final_key = f"reports/{report.case_id}/final/{report_id}.{report.format}"

        try:
            await self.storage_service.copy_report(draft_key, final_key)
        except Exception:
            pass

        report.report_type = "final"
        report.object_key = final_key
        report.version += 1
        await self.db.flush()

        ip = get_client_ip(http_request) if http_request else "127.0.0.1"
        await log_audit_event(
            db=self.db,
            action="REPORT_FINALIZED",
            target_entity_type="report",
            target_entity_id=str(report_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=ip,
            metadata={"case_id": str(report.case_id)}
        )
        await self.db.commit()

        return ReportResponse.model_validate(report)

    async def export_report(
        self,
        report_id: UUID,
        current_user: UserModel,
        http_request: Optional[Request] = None
    ) -> Tuple[bytes, str, str]:
        if current_user.role == "analyst":
            raise ForbiddenError("Analysts are not permitted to export court reports.")

        report = await self.report_repo.get(report_id)
        if not report:
            raise NotFoundError(f"Report {report_id} not found")

        await verify_case_access_direct(report.case_id, current_user, self.db)

        if report.report_type != "final":
            raise ConflictError("Only finalized reports can be exported as official court reports.")

        artifact_bytes = await self.storage_service.get_report_bytes(report.object_key)
        observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()

        if observed_sha256.lower() != report.sha256.lower():
            raise InfrastructureError("Report artifact SHA-256 integrity verification failed.")

        ip = get_client_ip(http_request) if http_request else "127.0.0.1"
        await log_audit_event(
            db=self.db,
            action="REPORT_EXPORTED",
            target_entity_type="report",
            target_entity_id=str(report_id),
            result="success",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=ip,
            metadata={"sha256": report.sha256, "format": report.format}
        )
        await self.db.commit()

        media_types = {
            "pdf": "application/pdf",
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8"
        }
        media_type = media_types.get(report.format, "application/octet-stream")
        safe_title = (report.title or f"report_{report_id}").replace(" ", "_")
        filename = f"{safe_title}.{report.format}"

        return artifact_bytes, media_type, filename
