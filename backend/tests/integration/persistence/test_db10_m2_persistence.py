import pytest
import uuid
import asyncio
from datetime import datetime, timezone
from sqlalchemy import select

from app.contracts.analysis import (
    FindingsPackage,
    Finding,
    ActivityClass,
    EvidenceReference,
    ClassificationResult,
    AnomalyResult
)
from app.engines.analysis.persistence_service import M2PersistenceService
from app.persistence.database import engine
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models import (
    AcquisitionModel,
    FlowModel,
    ProtocolEventModel,
    ArtifactModel
)
from app.persistence.models.analytics_models import (
    FindingsPackageModel,
    FindingModel,
    finding_flow_links
)

@pytest.mark.asyncio
async def test_m2_persistence_pipeline():
    # 1. Setup Mock M1 Data in DB
    uow = UnitOfWork()
    acq_id = uuid.uuid4()
    flow_id = uuid.uuid4()
    
    async with uow:
        # Insert minimal M1 requirements to satisfy Foreign Keys
        acq = AcquisitionModel(
            acquisition_id=acq_id,
            file_name="test.pcap",
            file_size=1024,
            sha256=uuid.uuid4().hex + uuid.uuid4().hex,
            format="pcap",
            source_type="test",
            status="complete"
        )
        uow.session.add(acq)
        
        flow = FlowModel(
            flow_id=flow_id,
            acquisition_id=acq_id,
            zeek_uid="C123456789",
            timestamp=datetime.now(timezone.utc),
            src_ip="1.1.1.1",
            src_port=80,
            dst_ip="2.2.2.2",
            dst_port=8080,
            protocol="tcp",
            service="http"
        )
        uow.session.add(flow)
        await uow.session.commit()
    
    # 2. Create M2 FindingsPackage Contract Object
    now_utc = datetime.now(timezone.utc)
    finding_id_str = f"F-{uuid.uuid4().hex[:12].upper()}"
    
    classification_res = ClassificationResult(
        activity_class=ActivityClass.C2_MALWARE_COMMUNICATION,
        confidence=0.95,
        class_probabilities={
            "C2_MALWARE_COMMUNICATION": 0.95,
            "BENIGN": 0.05
        },
        model_id="cls-v1",
        model_version="1.0"
    )
    
    anomaly_res = AnomalyResult(
        anomaly_detected=True,
        score=0.88,
        threshold=0.80,
        model_id="anom-v1",
        model_version="1.0",
        contributing_features=["byte_ratio", "duration"]
    )
    
    finding = Finding(
        finding_id=finding_id_str,
        acquisition_id=str(acq_id),
        activity_class=ActivityClass.C2_MALWARE_COMMUNICATION,
        anomaly_score=0.88,
        anomaly_detected=True,
        classification_confidence=0.95,
        risk_score=0.92,
        evidence_references=[
            EvidenceReference(
                flow_ids=[str(flow_id)],
                rationale="Anomalous high-entropy payload connected to known malicious behavioral cluster."
            )
        ],
        feature_snapshot={"byte_ratio": 0.99},
        classification_result=classification_res,
        anomaly_result=anomaly_res,
        model_version="M2-Core-1.0",
        feature_schema_version="1.0",
        created_at=now_utc
    )
    
    pkg = FindingsPackage(
        package_id=f"FP-{uuid.uuid4().hex[:12].upper()}",
        acquisition_id=str(acq_id),
        source_package_id="test_pkg_1",
        findings=[finding],
        analysis_engine_version="1.0",
        analysed_at=now_utc
    )
    
    # 3. Execute Persistence Service
    service = M2PersistenceService()
    await service.persist_findings_package(pkg)
    
    # 4. Verify DB-10 Persistence
    async with uow:
        # Check Package
        stmt = select(FindingsPackageModel).where(FindingsPackageModel.acquisition_id == acq_id)
        db_pkg = (await uow.session.execute(stmt)).scalar_one_or_none()
        assert db_pkg is not None
        assert db_pkg.findings_count == 1
        
        # Check Finding
        stmt = select(FindingModel).where(FindingModel.package_id == db_pkg.package_id)
        db_finding = (await uow.session.execute(stmt)).scalar_one_or_none()
        assert db_finding is not None
        assert db_finding.activity == "C2_MALWARE_COMMUNICATION"
        assert db_finding.severity == "low"  # Defaulting correctly
        assert db_finding.detection_method == "hybrid"
        assert db_finding.rationale == "Anomalous high-entropy payload connected to known malicious behavioral cluster."
        assert db_finding.classification_probabilities["C2_MALWARE_COMMUNICATION"] == 0.95
        
        # Check Many-to-Many evidence links
        stmt = select(finding_flow_links).where(finding_flow_links.c.finding_id == db_finding.finding_id)
        links = (await uow.session.execute(stmt)).all()
        assert len(links) == 1
        assert links[0].flow_id == flow_id
