import os
import uuid
import hashlib
import aiofiles
from pathlib import Path
from typing import Optional

from app.contracts.network_intelligence import AcquisitionReference, NetworkIntelligencePackage
from app.engines.packet_intelligence.orchestrator import M1Orchestrator
from app.shared.storage.minio_service import EvidenceStorageService

from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models import AcquisitionModel, EvidenceModel, FlowModel, ProtocolEventModel, ArtifactModel
from app.persistence.repositories import AcquisitionRepository, EvidenceRepository, FlowRepository, ProtocolEventRepository, ArtifactRepository

class M1PersistenceService:
    def __init__(self, orchestrator: M1Orchestrator, storage_service: EvidenceStorageService):
        self.orchestrator = orchestrator
        self.storage = storage_service

    async def compute_sha256(self, file_path: Path) -> str:
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, "rb") as f:
            while chunk := await f.read(8192):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    async def ingest_pcap(self, pcap_path: Path) -> NetworkIntelligencePackage:
        """
        1. Compute SHA-256 of PCAP.
        2. Upload to MinIO.
        3. Run M1 extraction.
        4. Persist everything transactionally.
        5. Clean up local PCAP.
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        # 1. Compute Hash
        file_hash = await self.compute_sha256(pcap_path)
        file_size = pcap_path.stat().st_size
        
        acquisition_id = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())
        object_key = f"{acquisition_id}/{pcap_path.name}"

        # 2. Upload to MinIO
        await self.storage.upload_evidence(str(pcap_path), object_key)

        # 3. Form Acquisition Reference and Run Zeek
        acquisition_ref = AcquisitionReference(
            acquisition_id=acquisition_id,
            evidence_id=evidence_id,
            file_name=pcap_path.name,
            file_size=file_size,
            format="pcap" if pcap_path.suffix == ".pcap" else "pcapng",
            sha256=file_hash,
            capture_reference=str(pcap_path)  # Local path for Zeek
        )

        package = self.orchestrator.process_acquisition(acquisition_ref)

        # 4. Persist to DB-8 transactionally
        await self._persist_package(acquisition_ref, object_key, package)

        # 5. Cleanup
        try:
            os.remove(pcap_path)
        except OSError:
            pass # Non-fatal if we can't remove temp file
            
        return package

    async def _persist_package(self, acq_ref: AcquisitionReference, object_key: str, package: NetworkIntelligencePackage):
        uow = UnitOfWork()
        async with uow:
            # Insert Acquisition
            acq_repo = uow.get_repository(AcquisitionRepository)
            await acq_repo.create(AcquisitionModel(
                acquisition_id=uuid.UUID(acq_ref.acquisition_id),
                file_name=acq_ref.file_name,
                file_size=acq_ref.file_size,
                sha256=acq_ref.sha256,
                format=acq_ref.format,
                source_type="pcap",
                status="complete"
            ))

            # Insert Evidence
            ev_repo = uow.get_repository(EvidenceRepository)
            await ev_repo.create(EvidenceModel(
                evidence_id=uuid.UUID(acq_ref.evidence_id),
                acquisition_id=uuid.UUID(acq_ref.acquisition_id),
                minio_bucket=self.storage.bucket_name,
                object_key=object_key,
                sha256=acq_ref.sha256,
                size_bytes=acq_ref.file_size,
                content_type="application/vnd.tcpdump.pcap"
            ))

            # Insert Flows
            flow_repo = uow.get_repository(FlowRepository)
            flow_models = [
                FlowModel(
                    flow_id=uuid.UUID(f.flow_id),
                    zeek_uid=f.zeek_uid,
                    acquisition_id=uuid.UUID(f.acquisition_id),
                    evidence_id=uuid.UUID(f.evidence_id) if f.evidence_id else None,
                    timestamp=f.timestamp,
                    start_time=f.start_time,
                    end_time=f.end_time,
                    src_ip=f.source.ip,
                    src_port=f.source.port,
                    dst_ip=f.destination.ip,
                    dst_port=f.destination.port,
                    protocol=f.protocol,
                    service=f.service,
                    duration=f.duration,
                    orig_bytes=f.orig_bytes,
                    resp_bytes=f.resp_bytes,
                    orig_packets=f.orig_packets,
                    resp_packets=f.resp_packets,
                    connection_state=f.connection_state,
                    provenance=f.provenance.model_dump(mode="json") if f.provenance else None
                ) for f in package.flows
            ]
            if flow_models:
                await flow_repo.bulk_create(flow_models)

            # Insert Events
            event_repo = uow.get_repository(ProtocolEventRepository)
            event_models = [
                ProtocolEventModel(
                    event_id=uuid.UUID(e.event_id),
                    flow_id=uuid.UUID(e.flow_id),
                    zeek_uid=e.zeek_uid,
                    acquisition_id=uuid.UUID(e.acquisition_id),
                    evidence_id=uuid.UUID(e.evidence_id) if e.evidence_id else None,
                    protocol=e.protocol,
                    timestamp=e.timestamp,
                    protocol_data=e.protocol_data.model_dump(mode="json") if hasattr(e.protocol_data, "model_dump") else e.protocol_data,
                    provenance=e.provenance.model_dump(mode="json") if e.provenance else None
                ) for e in package.protocol_events
            ]
            if event_models:
                await event_repo.bulk_create(event_models)

            # Insert Artifacts
            artifact_repo = uow.get_repository(ArtifactRepository)
            artifact_models = [
                ArtifactModel(
                    artifact_id=uuid.UUID(a.artifact_id),
                    type=a.type,
                    value=a.value,
                    source_event_id=uuid.UUID(a.source_event_id) if a.source_event_id else None,
                    flow_id=uuid.UUID(a.flow_id) if a.flow_id else None,
                    acquisition_id=uuid.UUID(a.acquisition_id),
                    evidence_id=uuid.UUID(a.evidence_id) if a.evidence_id else None,
                    first_seen=a.first_seen,
                    last_seen=a.last_seen,
                    provenance=a.provenance.model_dump(mode="json") if a.provenance else None
                ) for a in package.artifacts
            ]
            if artifact_models:
                await artifact_repo.bulk_create(artifact_models)
