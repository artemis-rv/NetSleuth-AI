import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from app.persistence.transactions.uow import UnitOfWork
from app.engines.correlation.persistence_service import M3PersistenceService
from app.persistence.models.investigation_models import (
    InvestigationCaseModel, EntityModel, RelationshipModel, TimelineEventModel
)
from app.persistence.models.analytics_models import FindingModel, FindingsPackageModel
from app.persistence.models.acquisition_models import AcquisitionModel

@pytest.mark.asyncio
async def test_db11_m3_persistence_full_case():
    """
    Validates that M3 Persistence correctly stores an InvestigationCase
    with Entities, Relationships, and Timeline Events mapped to PostgreSQL.
    """
    uow = UnitOfWork()
    
    # Pre-inject an acquisition and finding so Foreign Keys pass
    acq_uuid = uuid.uuid4()
    rand_suffix = uuid.uuid4().hex[:6]
    f_str_id = f"F-{rand_suffix}"
    f_uuid = uuid.uuid5(uuid.NAMESPACE_OID, f_str_id)
    
    async with uow:
        # Create minimal acquisition to satisfy DB constraints
        acq = AcquisitionModel(
            acquisition_id=acq_uuid,
            file_name="test.pcap",
            file_size=1024,
            sha256=uuid.uuid4().hex + uuid.uuid4().hex,
            format="pcap",
            source_type="test",
            status="complete"
        )
        uow.session.add(acq)
        
        # Create minimal finding package
        pkg_uuid = uuid.uuid4()
        pkg = FindingsPackageModel(
            package_id=pkg_uuid,
            acquisition_id=acq_uuid,
            source_package_id="test_pkg",
            analysis_engine_version="1.0",
            findings_count=1
        )
        uow.session.add(pkg)
        
        # Create minimal finding
        f_model = FindingModel(
            finding_id=f_uuid,
            package_id=pkg_uuid,
            acquisition_id=acq_uuid,
            activity="Test finding",
            severity="low",
            confidence=0.9,
            anomaly_detected=False,
            decision_state="SUSPICIOUS_ACTIVITY",
            detection_method="test"
        )
        uow.session.add(f_model)
        
    # M3 Payload
    case_dict = {
        "schema_version": "investigation-case-v1.1",
        "case_id": f"CASE-{rand_suffix}",
        "title": "Lateral Movement Detected",
        "description": "Suspicious RDP behavior.",
        "status": "open",
        "severity": "high",
        "created_at": "2024-01-01T12:00:00Z",
        "updated_at": "2024-01-01T12:30:00Z",
        "entities": [
            {
                "entity_id": "ip:192.168.1.100",
                "entity_type": "ip",
                "value": "192.168.1.100",
                "first_seen": "2024-01-01T12:00:00Z",
                "last_seen": "2024-01-01T12:05:00Z"
            },
            {
                "entity_id": "ip:10.0.0.5",
                "entity_type": "ip",
                "value": "10.0.0.5"
            }
        ],
        "relationships": [
            {
                "relationship_id": "REL-001",
                "source_entity_id": "ip:192.168.1.100",
                "target_entity_id": "ip:10.0.0.5",
                "relationship_type": "communicated_with",
                "confidence": 0.95,
                "first_seen": "2024-01-01T12:01:00Z",
                "last_seen": "2024-01-01T12:02:00Z"
            }
        ],
        "timeline": [
            {
                "event_id": "EV-100",
                "timestamp": "2024-01-01T12:01:30Z",
                "event_type": "network",
                "description": "RDP connection initiated.",
                "source_entity_id": "ip:192.168.1.100"
            }
        ],
        "findings": [
            {
                "finding_id": f_str_id,
                "role": "primary"
            }
        ],
        "evidence_references": [
            {
                "evidence_id": f_str_id,
                "evidence_type": "finding",
                "source_id": "REL-001"
            }
        ]
    }
    
    uow = UnitOfWork()
    svc = M3PersistenceService(uow)
    
    async with uow:
        case_uuid = await svc.persist_investigation_case(case_dict, acquisition_id=acq_uuid)
        
    # Verify in PostgreSQL
    async with uow:
        # Case
        case_res = await uow.session.execute(select(InvestigationCaseModel).where(InvestigationCaseModel.case_id == case_uuid))
        case = case_res.scalar_one()
        assert case.title == "Lateral Movement Detected"
        assert case.priority == "high" # Verified severity -> priority mapping
        
        # Entities
        ent_res = await uow.session.execute(select(EntityModel).where(EntityModel.case_id == case_uuid))
        entities = ent_res.scalars().all()
        assert len(entities) == 2
        ip1 = next(e for e in entities if e.value == "192.168.1.100")
        assert ip1.first_seen is not None
        
        # Relationships
        rel_res = await uow.session.execute(select(RelationshipModel).where(RelationshipModel.case_id == case_uuid))
        rels = rel_res.scalars().all()
        assert len(rels) == 1
        r = rels[0]
        assert r.relationship_type == "communicated_with"
        assert r.first_seen is not None
        assert r.last_seen is not None
        
        # Timeline
        tl_res = await uow.session.execute(select(TimelineEventModel).where(TimelineEventModel.case_id == case_uuid))
        tls = tl_res.scalars().all()
        assert len(tls) == 1
        t = tls[0]
        assert t.description == "RDP connection initiated."
