import pytest
import os
import uuid
from pathlib import Path
import asyncio
from datetime import datetime, timezone

from app.engines.packet_intelligence.persistence_service import M1PersistenceService
from app.shared.storage.minio_service import EvidenceStorageService
from app.contracts.network_intelligence import (
    NetworkIntelligencePackage, 
    Flow, 
    ProtocolEvent, 
    Artifact, 
    ArtifactType, 
    Endpoint, 
    FlowProvenance, 
    EventProvenance, 
    ArtifactProvenance,
    DNSData
)
from app.persistence.database import engine
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models import AcquisitionModel, EvidenceModel, FlowModel, ProtocolEventModel, ArtifactModel

# Mock M1Orchestrator to avoid needing Zeek on Windows for this test
class MockM1Orchestrator:
    def process_acquisition(self, acquisition) -> NetworkIntelligencePackage:
        flow_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        
        now_utc = datetime.now(timezone.utc)
        
        flow = Flow(
            flow_id=flow_id,
            zeek_uid="C" + str(uuid.uuid4())[:18],
            acquisition_id=acquisition.acquisition_id,
            timestamp=acquisition.acquired_at or now_utc, 
            source=Endpoint(ip="192.168.1.10", port=54321),
            destination=Endpoint(ip="8.8.8.8", port=53),
            protocol="udp",
            service="dns",
            provenance=FlowProvenance(
                acquisition_id=acquisition.acquisition_id,
                source="zeek",
                source_log="conn.log"
            )
        )
        
        event = ProtocolEvent(
            event_id=event_id,
            flow_id=flow_id,
            zeek_uid=flow.zeek_uid,
            acquisition_id=acquisition.acquisition_id,
            timestamp=flow.timestamp,
            protocol="dns",
            protocol_data=DNSData(query="example.com", query_type="A"),
            provenance=EventProvenance(
                acquisition_id=acquisition.acquisition_id,
                source="zeek",
                source_log="dns.log"
            )
        )
        
        artifact = Artifact(
            artifact_id=str(uuid.uuid4()),
            type=ArtifactType.DOMAIN,
            value="example.com",
            source_event_id=event_id,
            flow_id=flow_id,
            acquisition_id=acquisition.acquisition_id,
            provenance=ArtifactProvenance(
                acquisition_id=acquisition.acquisition_id,
                source_event_id=event_id
            )
        )
        
        return NetworkIntelligencePackage(
            package_id=str(uuid.uuid4()),
            acquisition_id=acquisition.acquisition_id,
            flows=[flow],
            protocol_events=[event],
            artifacts=[artifact]
        )


@pytest.mark.asyncio
async def test_m1_persistence_pipeline(tmp_path):
    # Create dummy PCAP
    pcap_path = Path(tmp_path) / "sample.pcap"
    pcap_path.write_bytes(b"dummy pcap data for testing M1 pipeline")
    
    storage = EvidenceStorageService()
    orchestrator = MockM1Orchestrator()
    service = M1PersistenceService(orchestrator, storage)
    
    # 1. Run Pipeline
    package = await service.ingest_pcap(pcap_path)
    
    # 2. Verify Cleanup
    assert not pcap_path.exists(), "Local PCAP should be deleted after processing"
    
    uow = UnitOfWork()
    async with uow:
        # 3. Verify PostgreSQL Data
        acq = await uow.session.get(AcquisitionModel, uuid.UUID(package.acquisition_id))
        assert acq is not None
        assert acq.status == "complete"
        assert acq.sha256 is not None
        
        # Verify MinIO Storage Record
        from sqlalchemy import select
        stmt = select(EvidenceModel).where(EvidenceModel.acquisition_id == uuid.UUID(package.acquisition_id))
        evidence = (await uow.session.execute(stmt)).scalar_one_or_none()
        assert evidence is not None
        assert evidence.object_key.startswith(package.acquisition_id)
        
        # Verify Flows
        stmt = select(FlowModel).where(FlowModel.acquisition_id == uuid.UUID(package.acquisition_id))
        flows = (await uow.session.execute(stmt)).scalars().all()
        assert len(flows) == 1
        assert str(flows[0].src_ip) == "192.168.1.10"
        
        # Verify Events
        stmt = select(ProtocolEventModel).where(ProtocolEventModel.acquisition_id == uuid.UUID(package.acquisition_id))
        events = (await uow.session.execute(stmt)).scalars().all()
        assert len(events) == 1
        assert events[0].protocol == "dns"
        
        # Verify Artifacts
        stmt = select(ArtifactModel).where(ArtifactModel.acquisition_id == uuid.UUID(package.acquisition_id))
        artifacts = (await uow.session.execute(stmt)).scalars().all()
        assert len(artifacts) == 1
        assert artifacts[0].value == "example.com"
        assert artifacts[0].type == "DOMAIN"
        
    # 4. Verify MinIO Download
    async with storage.get_client() as s3:
        response = await s3.get_object(Bucket=storage.bucket_name, Key=evidence.object_key)
        data = await response['Body'].read()
        assert data == b"dummy pcap data for testing M1 pipeline"
