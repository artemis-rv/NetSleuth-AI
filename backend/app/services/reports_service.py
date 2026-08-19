import hashlib
import json
import re
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
        export_format: Optional[str] = None,
        case_id: Optional[UUID] = None,
        http_request: Optional[Request] = None
    ) -> Tuple[bytes, str, str]:
        report = await self.report_repo.get(report_id)
        if not report:
            raise NotFoundError(f"Report {report_id} not found")

        report_case_id = report.case_id
        report_title = report.title
        report_format = report.format
        report_version = report.version
        report_generated_at = report.generated_at

        if case_id and report_case_id != case_id:
            raise ForbiddenError(f"Report {report_id} does not belong to case {case_id}")

        await verify_case_access_direct(report_case_id, current_user, self.db)

        artifact_bytes = await self.storage_service.get_report_bytes(report.object_key)
        observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()

        # Repair all-zero or missing SHA-256 in database
        if not report.sha256 or report.sha256 == "0" * 64:
            report.sha256 = observed_sha256
            await self.db.commit()

        target_fmt = (export_format or report_format or "json").lower()
        if target_fmt not in ("json", "pdf", "txt", "html"):
            target_fmt = "json"

        output_bytes = artifact_bytes
        if target_fmt == "txt":
            try:
                data_dict = json.loads(artifact_bytes.decode('utf-8'))
                title = data_dict.get("title", report_title)
                c_id = data_dict.get("case_id", str(report_case_id))
                r_id = data_dict.get("report_id", str(report_id))
                gen_at = data_dict.get("generated_at", str(report_generated_at))
                gen_ver = data_dict.get("generator_version", str(report_version))
                
                summary_data = data_dict.get("summary", {})
                findings_list = data_dict.get("findings", [])
                timeline_list = data_dict.get("timeline", [])
                entities_list = data_dict.get("entities", [])
                relationships_list = data_dict.get("relationships", [])
                evidence_integrity_list = data_dict.get("evidence_integrity", [])
                assessment_data = data_dict.get("assessment", {})
                mitre_mappings_list = data_dict.get("mitre_mappings", [])
                mitre_prov = data_dict.get("mitre_provenance", {})
                attack_chain_data = data_dict.get("attack_chain", {})
                provenance_data = data_dict.get("provenance", {})
                llm_data = data_dict.get("llm_enrichment", {})
                
                txt_lines = [
                    f"================================================================================",
                    f"NETSLEUTH AI — FORENSIC INVESTIGATION REPORT",
                    f"================================================================================",
                    f"Case Title   : {summary_data.get('case_title', title)}",
                    f"Case ID      : {c_id}",
                    f"Report ID    : {r_id}",
                    f"Format       : TXT (Plain Text Audit Export)",
                    f"Version      : v{gen_ver}",
                    f"Generated At : {gen_at}",
                    f"SHA-256 Hash : {observed_sha256}",
                    f"Integrity    : VERIFIED",
                    f"--------------------------------------------------------------------------------",
                    f"\nEXECUTIVE SUMMARY:",
                    f"  Status                  : {summary_data.get('case_status', 'OPEN')}",
                    f"  Description             : {summary_data.get('case_description', '-')}",
                    f"  Total Findings          : {summary_data.get('total_findings', len(findings_list))}",
                    f"  Total Timeline Events   : {summary_data.get('total_timeline_events', len(timeline_list))}",
                    f"  Total Evidence Refs     : {summary_data.get('total_evidence_references', len(evidence_integrity_list))}",
                    f"  Verified Evidence Count : {summary_data.get('verified_evidence_count', '-')}",
                    f"  Mismatched Evidence     : {summary_data.get('mismatched_evidence_count', '-')}",
                    f"  Unverified Evidence     : {summary_data.get('unverified_evidence_count', '-')}",
                    f"\nKEY FORENSIC FINDINGS ({len(findings_list)}):"
                ]
                
                if findings_list:
                    for idx, f in enumerate(findings_list, 1):
                        if isinstance(f, dict):
                            f_id = f.get("finding_id", f"FIND-{idx}")
                            f_title = f.get("title", f"Finding #{idx}")
                            f_sev = f.get("severity", "MEDIUM")
                            f_type = f.get("finding_type", "anomaly")
                            f_conf = f.get("confidence", "1.0")
                            f_desc = f.get("description", "")
                            ev_refs = ", ".join(f.get("evidence_references", [])) or "-"
                            txt_lines.append(f"  [{idx}] {f_title} (ID: {f_id})")
                            txt_lines.append(f"      Severity: {f_sev} | Type: {f_type} | Confidence: {f_conf}")
                            if f_desc:
                                txt_lines.append(f"      Description: {f_desc}")
                            txt_lines.append(f"      Evidence References: {ev_refs}")
                else:
                    txt_lines.append("  No findings recorded.")

                txt_lines.append(f"\nINVESTIGATION TIMELINE ({len(timeline_list)}):")
                if timeline_list:
                    for idx, te in enumerate(timeline_list, 1):
                        if isinstance(te, dict):
                            te_id = te.get("event_id", f"EVT-{idx}")
                            te_title = te.get("title", f"Event #{idx}")
                            te_time = te.get("timestamp", "")
                            te_type = te.get("event_type", "general")
                            te_desc = te.get("description", "")
                            ents = ", ".join(te.get("entity_ids", [])) or "-"
                            evs = ", ".join(te.get("evidence_ids", [])) or "-"
                            txt_lines.append(f"  [{te_time}] {te_title} (ID: {te_id})")
                            txt_lines.append(f"      Type: {te_type} | Entities: {ents} | Evidence: {evs}")
                            if te_desc:
                                txt_lines.append(f"      Details: {te_desc}")
                else:
                    txt_lines.append("  No timeline events recorded.")

                if mitre_mappings_list:
                    txt_lines.append(f"\nMITRE ATT&CK MAPPINGS ({len(mitre_mappings_list)}):")
                    for idx, m in enumerate(mitre_mappings_list, 1):
                        if isinstance(m, dict):
                            t_id = m.get("technique_id", "-")
                            t_name = m.get("technique_name", "-")
                            tac_name = m.get("tactic_name", "-")
                            m_stat = m.get("mapping_status", "asserted")
                            m_conf = m.get("mapping_confidence", "1.0")
                            m_rat = m.get("rationale", "-")
                            txt_lines.append(f"  [{idx}] [{t_id}] {t_name} (Tactic: {tac_name})")
                            txt_lines.append(f"      Status: {m_stat} | Confidence: {m_conf} | Rationale: {m_rat}")
                    if mitre_prov:
                        txt_lines.append(f"  MITRE Framework: {mitre_prov.get('framework', 'ATT&CK')} v{mitre_prov.get('version', '13.1')} ({mitre_prov.get('domain', 'enterprise')})")

                if attack_chain_data:
                    stages = attack_chain_data.get("stages", [])
                    txt_lines.append(f"\nATTACK CHAIN EXECUTION STAGES (Status: {attack_chain_data.get('status', 'inferred')}):")
                    for idx, stg in enumerate(stages, 1):
                        stg_name = stg.get("name", f"Stage #{idx}")
                        stg_time = stg.get("timestamp", "")
                        f_ids = ", ".join(stg.get("finding_ids", [])) or "-"
                        txt_lines.append(f"  Stage {idx:02d}: {stg_name} [{stg_time}] (Findings: {f_ids})")

                if assessment_data:
                    txt_lines.append(f"\nINVESTIGATION ASSESSMENT:")
                    if assessment_data.get("summary"):
                        txt_lines.append(f"  Summary: {assessment_data.get('summary')}")
                    
                    hyps = assessment_data.get("hypotheses", [])
                    if hyps:
                        txt_lines.append(f"  Hypotheses ({len(hyps)}):")
                        for h in hyps:
                            txt_lines.append(f"    - [{h.get('hypothesis_id')}] {h.get('statement')} (Type: {h.get('hypothesis_type')}, Status: {h.get('status')}, Conf: {h.get('confidence')})")

                    rcs = assessment_data.get("root_causes", [])
                    if rcs:
                        txt_lines.append(f"  Root Causes ({len(rcs)}):")
                        for rc in rcs:
                            txt_lines.append(f"    - [{rc.get('root_cause_id')}] {rc.get('statement')} (Status: {rc.get('status')}, Conf: {rc.get('confidence')})")

                    impacts = assessment_data.get("impact_assessments", [])
                    if impacts:
                        txt_lines.append(f"  Impact Assessments ({len(impacts)}):")
                        for ia in impacts:
                            txt_lines.append(f"    - [{ia.get('impact_id')}] Category: {ia.get('category')} | Status: {ia.get('status')} | Statement: {ia.get('statement')}")

                if evidence_integrity_list:
                    txt_lines.append(f"\nEVIDENCE INTEGRITY RECORDS ({len(evidence_integrity_list)}):")
                    for ev in evidence_integrity_list:
                        ev_id = ev.get("evidence_id", "-")
                        ev_type = ev.get("evidence_type", "-")
                        ev_stat = ev.get("verification_status", "-")
                        ev_hash = ev.get("calculated_hash", ev.get("expected_hash", "-"))
                        txt_lines.append(f"  - [{ev_id}] Type: {ev_type} | Status: {ev_stat}")
                        txt_lines.append(f"    SHA-256: {ev_hash}")

                if llm_data:
                    txt_lines.append(f"\nAI-ASSISTED INVESTIGATION NARRATIVE:")
                    txt_lines.append(f"  DISCLAIMER: AI-generated narrative is advisory and does not alter deterministic forensic conclusions.")
                    if llm_data.get("summary"):
                        txt_lines.append(f"  Summary: {llm_data.get('summary')}")

                if provenance_data:
                    txt_lines.append(f"\nPROVENANCE:")
                    txt_lines.append(f"  Acquisition ID: {provenance_data.get('acquisition_id', '-')} | Collector ID: {provenance_data.get('collector_id', '-')}")

                txt_lines.append(f"\n================================================================================")
                output_bytes = "\n".join(txt_lines).encode('utf-8')
            except Exception as txt_err:
                raise InfrastructureError(f"Failed to generate TXT report: {txt_err}") from txt_err
        elif target_fmt == "pdf":
            if report_format == "pdf" and artifact_bytes.startswith(b"%PDF-"):
                output_bytes = artifact_bytes
            else:
                try:
                    data_dict = json.loads(artifact_bytes.decode('utf-8'))
                    output_bytes = PDFReportRenderer(self.validator).render(data_dict)
                except Exception as pdf_err:
                    raise InfrastructureError(f"Failed to render PDF document: {pdf_err}") from pdf_err

            if not output_bytes.startswith(b"%PDF-"):
                raise InfrastructureError("Generated PDF payload failed binary header validation.")

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
            metadata={"sha256": observed_sha256, "format": target_fmt, "case_id": str(report_case_id)}
        )
        await self.db.commit()

        media_types = {
            "pdf": "application/pdf",
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "txt": "text/plain; charset=utf-8"
        }
        media_type = media_types.get(target_fmt, "application/octet-stream")
        raw_title = report_title or f"report_{report_id}"
        safe_title = re.sub(r'[^\w\.-]', '_', raw_title.encode('ascii', 'ignore').decode('ascii'))
        filename = f"{safe_title}.{target_fmt}"

        return output_bytes, media_type, filename
