import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from app.persistence.transactions.uow import UnitOfWork
from app.engines.reporting.persistence_service import M4PersistenceService
from app.engines.reporting.evidence_package import M4EvidencePackage
from app.engines.reporting.evidence_model import M4CaseEvidencePackage, M4EvidenceReference
from app.engines.reporting.chain_of_custody import ChainOfCustody
from app.shared.contract_validation import ContractValidator

from app.persistence.models.custody_models import EvidenceItemModel, CustodyEventModel, ReportModel
from app.persistence.models.identity_models import UserModel
from app.persistence.models.investigation_models import InvestigationCaseModel

@pytest.mark.asyncio
async def test_db12_m4_persistence_flow():
    """
    Validates that M4 Persistence correctly stores physical Evidence Items,
    Custody Events, and Reports to PostgreSQL DB-6 custody schema.
    """
    uow = UnitOfWork()

    # Pre-inject identities and cases so Foreign Keys pass
    rand_suffix = uuid.uuid4().hex[:6]
    system_user_uuid = uuid.uuid5(uuid.NAMESPACE_OID, f"m4-system-user-{rand_suffix}")
    case_str_id = f"CASE-999-{rand_suffix}"
    case_uuid = uuid.uuid5(uuid.NAMESPACE_OID, case_str_id)

    async with uow:
        # Minimal User
        sys_user = UserModel(
            user_id=system_user_uuid,
            username=f"system_user_{rand_suffix}",
            email=f"system_{rand_suffix}@netsleuth.ai",
            full_name="System User",
            role="analyst"
        )
        uow.session.add(sys_user)

        # Minimal Investigation Case
        case_model = InvestigationCaseModel(
            case_id=case_uuid,
            title="M4 Integration Test Case",
            status="open",
            priority="high",
            trigger_type="correlation_engine"
        )
        uow.session.add(case_model)
    
    # Construct M4 Domain Objects manually
    case_ev_pkg = M4CaseEvidencePackage(
        case_id=case_str_id,
        schema_version="1.0",
        created_at=datetime.utcnow().isoformat(),
        updated_at=datetime.utcnow().isoformat(),
        evidence_references=[
            # This is a physical report being tracked in custody
            M4EvidenceReference(
                evidence_id=f"EV-REPORT-001-{rand_suffix}",
                evidence_type="report",
                source_id="REP-123",
                hash="a" * 64,
                hash_algorithm="sha256"
            ),
            # This is a finding (logical), so the persistence service should skip inserting it to evidence_items
            M4EvidenceReference(
                evidence_id="EV-FINDING-001",
                evidence_type="finding",
                source_id="F-12345",
                hash="findinghash",
                hash_algorithm="sha256"
            )
        ]
    )

    validator = ContractValidator()
    package = M4EvidencePackage(
        case_id=case_str_id,
        case_evidence_package=case_ev_pkg,
        validator=validator,
        raw_case_payload={}
    )

    chain = ChainOfCustody(f"EV-REPORT-001-{rand_suffix}")
    chain.record_action(custodian_id=f"m4-system-user-{rand_suffix}", action="verify")
    package.custody_logs[f"EV-REPORT-001-{rand_suffix}"] = chain

    svc = M4PersistenceService(uow)

    async with uow:
        await svc.persist_evidence_package(package)
        
        await svc.persist_report(
            case_id=case_str_id,
            title="Final Investigation Report",
            report_type="executive",
            format="pdf",
            minio_bucket="netsleuth-reports",
            object_key=f"{case_str_id}/final.pdf",
            hash_sha256="deadbeefdeadbeef",
            generator_id=f"m4-system-user-{rand_suffix}"
        )

    # Verify in DB
    async with uow:
        # 1. Evidence Items - Only the 'report' should be saved
        item_res = await uow.session.execute(select(EvidenceItemModel).where(EvidenceItemModel.case_id == case_uuid))
        items = item_res.scalars().all()
        assert len(items) == 1
        assert items[0].evidence_type == "report"
        assert items[0].sha256 == "a" * 64
        item_uuid = items[0].evidence_item_id

        # 2. Custody Events
        ev_res = await uow.session.execute(select(CustodyEventModel).where(CustodyEventModel.evidence_item_id == item_uuid))
        events = ev_res.scalars().all()
        assert len(events) == 1
        assert events[0].action == "verify"
        assert events[0].actor_name == f"m4-system-user-{rand_suffix}"

        # 3. Reports
        rep_res = await uow.session.execute(select(ReportModel).where(ReportModel.case_id == case_uuid))
        reports = rep_res.scalars().all()
        assert len(reports) == 1
        assert reports[0].format == "pdf"
        assert reports[0].title == "Final Investigation Report"
