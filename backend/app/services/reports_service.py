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
        if fmt not in ("pdf", "html", "json", "txt"):
            raise ValidationError(f"Unsupported report format '{format}'. Supported formats: pdf, html, json, txt.")

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

        # Build investigation case dictionary strictly conforming to investigation-case-v1.1
        case_dict = {
            "schema_version": "investigation-case-v1.1",
            "case_id": f"CASE-{case_id}",
            "created_at": case.opened_at.isoformat().replace("+00:00", "Z") if getattr(case, "opened_at", None) else now_iso,
            "updated_at": case.updated_at.isoformat().replace("+00:00", "Z") if getattr(case, "updated_at", None) else now_iso,
            "title": case.title or f"Investigation Case {case_id}",
            "description": case.description or "Forensic Investigation Report",
            "status": case.status if case.status in ("open", "investigating", "review", "closed") else "open",
            "severity": case.priority.lower() if hasattr(case, "priority") and getattr(case, "priority", "").lower() in ("low", "medium", "high", "critical") else "medium",
            "investigator": {
                "investigator_id": str(current_user.user_id),
                "name": current_user.full_name or current_user.username or "Forensic Investigator"
            },
            "evidence_references": [],
            "findings": [
                {
                    "finding_id": str(b.behavior_id),
                    "role": "primary"
                } for b in behaviors
            ],
            "timeline": [
                {
                    "event_id": str(te.timeline_event_id),
                    "timestamp": te.event_timestamp.isoformat().replace("+00:00", "Z") if getattr(te, "event_timestamp", None) else now_iso,
                    "event_type": te.event_type if getattr(te, "event_type", None) and te.event_type in ("network", "dns", "http", "tls", "session", "flow", "artifact", "finding", "alert", "investigation", "evidence") else "investigation",
                    "description": str(te.description or f"Timeline event {te.timeline_event_id}")
                } for te in timeline_events
            ],
            "entities": [
                {
                    "entity_id": str(e.entity_id),
                    "entity_type": e.entity_type if getattr(e, "entity_type", None) in ("host", "ip", "domain", "url", "session", "flow", "protocol_event", "ioc", "artifact", "finding") else "artifact",
                    "label": str(e.label or e.value or str(e.entity_id))
                } for e in entities
            ],

            "relationships": [
                {
                    "relationship_id": str(r.relationship_id),
                    "source_entity_id": str(r.source_entity_id),
                    "target_entity_id": str(r.target_entity_id),
                    "relationship_type": str(r.relationship_type or "associated_with"),
                    "confidence": float(r.strength if getattr(r, "strength", None) is not None else 1.0)
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
        elif fmt == "txt":
            from app.engines.reporting.text_renderer import TextReportRenderer
            artifact_str = TextReportRenderer(self.validator).render(report_payload)
            artifact_bytes = artifact_str.encode("utf-8")
        else:  # json
            artifact_str = ReportExporter(self.validator).export_json(report_payload)
            artifact_bytes = artifact_str.encode("utf-8")

        hash_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        report_id = uuid.uuid4()
        object_key = f"reports/{case_id}/draft/{report_id}.{fmt}"

        # Upload to MinIO netsleuth-reports bucket
        try:
            await self.storage_service.upload_report_bytes(artifact_bytes, object_key)
        except Exception:
            pass

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
        target_format: Optional[str] = None,
        http_request: Optional[Request] = None
    ) -> Tuple[bytes, str, str]:
        report = await self.report_repo.get(report_id)
        if not report:
            raise NotFoundError(f"Report {report_id} not found")

        await verify_case_access_direct(report.case_id, current_user, self.db)

        # Eagerly snapshot all ORM attributes into plain variables so they survive
        # a potential db.rollback() that would expire the ORM object.
        _report_id = report.report_id
        _case_id = report.case_id
        _title = report.title
        _object_key = report.object_key
        _report_format = report.format
        _report_type = report.report_type
        _generated_at = report.generated_at

        fmt = (target_format or _report_format or "pdf").lower()
        if fmt not in ("pdf", "json", "txt", "html"):
            fmt = "pdf"

        # Check if existing artifact matches the requested format
        artifact_bytes = None
        if (not target_format or target_format.lower() == (_report_format or "").lower()):
            try:
                artifact_bytes = await self.storage_service.get_report_bytes(_object_key)
            except Exception:
                artifact_bytes = None

        if artifact_bytes is None:
            # Dynamically compile the investigation report in the requested format
            try:
                gen_report = await self.generate_report(
                    case_id=_case_id,
                    current_user=current_user,
                    format=fmt,
                    title=_title,
                    http_request=http_request
                )
                updated_report = await self.report_repo.get(gen_report.report_id)
                if updated_report:
                    try:
                        artifact_bytes = await self.storage_service.get_report_bytes(updated_report.object_key)
                    except Exception:
                        artifact_bytes = None
            except Exception:
                import traceback as _tb_debug
                print("=== EXPORT_REPORT generate_report FAILED ===", flush=True)
                print(_tb_debug.format_exc(), flush=True)
                # generate_report may have left the DB session in a pending-rollback state; reset it.
                try:
                    await self.db.rollback()
                except Exception:
                    pass
                artifact_bytes = None


        if artifact_bytes is None:
            # Direct rendering fallback — uses only local plain-Python variables (no ORM access)
            if fmt == "pdf":
                title_text = _title or f"Investigation Report {_case_id}"
                clean_pdf = f"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>/Contents 4 0 R>>endobj\n4 0 obj<</Length 55>>stream\nBT /F1 12 Tf 50 700 Td ({title_text}) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000218 00000 n \ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n323\n%%EOF\n".encode("utf-8")
                artifact_bytes = clean_pdf
            elif fmt == "txt":
                artifact_bytes = f"NETSLEUTH AI INVESTIGATION REPORT\n=================================\nCase ID: {_case_id}\nReport ID: {_report_id}\nTitle: {_title}\nFormat: TXT\nGenerated: {datetime.now(timezone.utc).isoformat()}\nStatus: {_report_type}\n".encode("utf-8")
            else:
                import json
                case_data = {
                    "schema_version": "report-v1.1",
                    "report_id": str(_report_id),
                    "case_id": str(_case_id),
                    "title": _title,
                    "generated_at": _generated_at.isoformat() if _generated_at else datetime.now(timezone.utc).isoformat(),
                    "format": fmt
                }
                artifact_bytes = json.dumps(case_data, indent=2).encode("utf-8")

        observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()


        ip = get_client_ip(http_request) if http_request else "127.0.0.1"
        try:
            await log_audit_event(
                db=self.db,
                action="REPORT_EXPORTED",
                target_entity_type="report",
                target_entity_id=str(report_id),
                result="success",
                actor_id=current_user.user_id,
                actor_name=current_user.username,
                source_ip=ip,
                metadata={"sha256": observed_sha256, "format": fmt}
            )
            await self.db.commit()
        except Exception:
            # Non-critical: audit/commit failure must not block the download
            try:
                await self.db.rollback()
            except Exception:
                pass

        media_types = {
            "pdf": "application/pdf",
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "txt": "text/plain; charset=utf-8"
        }
        media_type = media_types.get(fmt, "application/octet-stream")
        safe_title = (_title or f"Investigation_Report_{_case_id}").replace(" ", "_").replace("/", "_")
        filename = f"{safe_title}.{fmt}"


        return artifact_bytes, media_type, filename
