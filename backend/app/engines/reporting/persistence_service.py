import uuid
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert

from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models.custody_models import EvidenceItemModel, CustodyEventModel, ReportModel
from app.engines.reporting.evidence_package import M4EvidencePackage
from app.engines.reporting.chain_of_custody import parse_iso_timestamp

# DB-6 physically allowed evidence types for custody
ALLOWED_PHYSICAL_TYPES = {'pcap', 'pcapng', 'log_file', 'report', 'exported_session', 'analyst_note'}

class M4PersistenceService:
    """
    Persists M4 Evidence Package, Reports, and Chain of Custody objects into DB-8 schema.
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def _to_uuid(self, id_str: str) -> uuid.UUID:
        try:
            return uuid.UUID(str(id_str))
        except (ValueError, AttributeError):
            return uuid.uuid5(uuid.NAMESPACE_OID, str(id_str))

    async def persist_evidence_package(self, package: M4EvidencePackage) -> None:
        """
        Persists physical evidence items and custody events within a single transaction.
        """
        case_uuid = self._to_uuid(package.case_id)

        evidence_records = []
        custody_records = []

        # Default system user UUID for missing/automated custodians
        system_user_id = uuid.uuid5(uuid.NAMESPACE_OID, "m4-system-user")

        for ev_ref in package.case_evidence_package.evidence_references:
            # Skip logical references that don't belong in physical custody schema
            if ev_ref.evidence_type not in ALLOWED_PHYSICAL_TYPES:
                continue

            item_uuid = uuid.uuid5(uuid.NAMESPACE_OID, ev_ref.evidence_id)
            
            # Map evidence_id upstream to acquisition.evidence if it came from acquisition
            acq_evidence_uuid = None
            if ev_ref.source_id and ev_ref.evidence_type in {'pcap', 'pcapng'}:
                acq_evidence_uuid = uuid.uuid5(uuid.NAMESPACE_OID, ev_ref.source_id)

            evidence_records.append({
                "evidence_item_id": item_uuid,
                "case_id": case_uuid,
                "evidence_id": acq_evidence_uuid,
                "label": f"Evidence {ev_ref.evidence_id}",
                "description": f"{ev_ref.evidence_type.capitalize()} evidence {ev_ref.evidence_id}",
                "evidence_type": ev_ref.evidence_type,
                "minio_bucket": "netsleuth-evidence",
                "object_key": f"{package.case_id}/{ev_ref.evidence_id}",
                "sha256": ev_ref.hash,
                "registered_at": datetime.utcnow(),
                "registered_by": system_user_id
            })

            # Process custody logs for this physical evidence
            if ev_ref.evidence_id in package.custody_logs:
                chain = package.custody_logs[ev_ref.evidence_id]
                for entry in chain._entries:
                    event_uuid = uuid.uuid4()
                    user_uuid = uuid.uuid5(uuid.NAMESPACE_OID, entry.custodian_id) if entry.custodian_id else system_user_id
                    
                    # Store extra M4 data in JSONB
                    meta = {}
                    if getattr(entry, "signature", None):
                        meta["signature"] = entry.signature

                    custody_records.append({
                        "custody_event_id": event_uuid,
                        "evidence_item_id": item_uuid,
                        "action": entry.action,
                        "actor_id": user_uuid,
                        "actor_name": entry.custodian_id,
                        "occurred_at": parse_iso_timestamp(entry.timestamp) if entry.timestamp else datetime.utcnow(),
                        "notes": getattr(entry, "reason", None),
                        "event_metadata": meta
                    })

        if evidence_records:
            await self.uow.session.execute(insert(EvidenceItemModel).values(evidence_records))
            await self.uow.session.flush()

        if custody_records:
            await self.uow.session.execute(insert(CustodyEventModel).values(custody_records))

    async def persist_report(
        self,
        case_id: str,
        title: str,
        report_type: str,
        format: str,
        minio_bucket: str,
        object_key: str,
        hash_sha256: str,
        generator_id: str = "m4-report-engine"
    ) -> uuid.UUID:
        """
        Persists a newly generated report document.
        """
        report_uuid = uuid.uuid4()
        case_uuid = self._to_uuid(case_id)
        user_uuid = self._to_uuid(generator_id)

        report = ReportModel(
            report_id=report_uuid,
            case_id=case_uuid,
            generated_by=user_uuid,
            title=title,
            report_type=report_type,
            format=format,
            minio_bucket=minio_bucket,
            object_key=object_key,
            sha256=hash_sha256
        )
        self.uow.session.add(report)
        return report_uuid
