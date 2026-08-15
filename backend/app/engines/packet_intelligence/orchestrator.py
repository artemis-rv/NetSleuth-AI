"""
backend/app/engines/packet_intelligence/orchestrator.py
-------------------------------------------------------
Orchestrates M1 Packet Intelligence extraction pipeline to assemble the NetworkIntelligencePackage.
"""

import uuid
from typing import Any

from backend.app.contracts.network_intelligence import (
    AcquisitionReference,
    Artifact,
    Flow,
    NetworkIntelligencePackage,
    ProtocolEvent,
)
from backend.app.engines.packet_intelligence.adapters.conn import ConnAdapter
from backend.app.engines.packet_intelligence.adapters.dns import DNSAdapter
from backend.app.engines.packet_intelligence.adapters.http import HTTPAdapter
from backend.app.engines.packet_intelligence.adapters.tls import TLSAdapter
from backend.app.engines.packet_intelligence.artifacts.extractor import ArtifactExtractor
from backend.app.engines.packet_intelligence.provenance.validator import ProvenanceValidator
from backend.app.engines.packet_intelligence.zeek.reader import RawZeekErrorRecord, ZeekReader
from backend.app.engines.packet_intelligence.zeek.runner import ZeekRunner

from .errors import PackageAssemblyError, PackageAssemblyErrorCode


class M1Orchestrator:
    """Assembles a valid NetworkIntelligencePackage from raw evidence."""

    def __init__(
        self,
        zeek_runner: ZeekRunner,
        zeek_reader: ZeekReader,
        conn_adapter: ConnAdapter,
        dns_adapter: DNSAdapter,
        http_adapter: HTTPAdapter,
        tls_adapter: TLSAdapter,
        artifact_extractor: ArtifactExtractor,
        provenance_validator: ProvenanceValidator,
    ):
        """Initialise with all dependent canonical mapping components."""
        self.zeek_runner = zeek_runner
        self.zeek_reader = zeek_reader
        self.conn_adapter = conn_adapter
        self.dns_adapter = dns_adapter
        self.http_adapter = http_adapter
        self.tls_adapter = tls_adapter
        self.artifact_extractor = artifact_extractor
        self.provenance_validator = provenance_validator

    def process_acquisition(self, acquisition: AcquisitionReference) -> NetworkIntelligencePackage:
        """Run the full extraction pipeline for a single acquisition."""
        
        # 1. Run Zeek to generate logs
        runner_result = self.zeek_runner.run(acquisition)

        # We will collect canonical objects
        flows: list[Flow] = []
        flow_index: dict[str, str] = {}  # zeek_uid -> flow_id
        protocol_events: list[ProtocolEvent] = []
        artifacts: list[Artifact] = []

        # 2. First pass: extract Flows from conn.log to build flow_index
        # We read all logs, but only process 'conn' for the first pass
        for record in self.zeek_reader.read(runner_result):
            if isinstance(record, RawZeekErrorRecord):
                continue
            
            if record.log_type == "conn":
                flow_or_err = self.conn_adapter.convert(record)
                if isinstance(flow_or_err, Flow):
                    flows.append(flow_or_err)
                    flow_index[flow_or_err.zeek_uid] = flow_or_err.flow_id

        # 3. Second pass: extract ProtocolEvents and Artifacts
        for record in self.zeek_reader.read(runner_result):
            if isinstance(record, RawZeekErrorRecord):
                continue

            event: ProtocolEvent | Any = None
            
            if record.log_type == "dns":
                event = self.dns_adapter.convert(record, flow_index)
            elif record.log_type == "http":
                event = self.http_adapter.convert(record, flow_index)
            elif record.log_type == "ssl":
                event = self.tls_adapter.convert(record, flow_index)

            # If an event was successfully extracted
            if isinstance(event, ProtocolEvent):
                protocol_events.append(event)
                
                # 4. Extract artifacts
                extracted_artifacts = self.artifact_extractor.extract(event)
                for art in extracted_artifacts:
                    # 5. Validate provenance immediately
                    self.provenance_validator.validate_artifact_provenance(art, event)
                    
                    if art.acquisition_id != acquisition.acquisition_id:
                        raise PackageAssemblyError(
                            code=PackageAssemblyErrorCode.ACQUISITION_MISMATCH,
                            message=f"Artifact {art.artifact_id} acquisition mismatch.",
                            acquisition_id=acquisition.acquisition_id,
                        )
                        
                    artifacts.append(art)

        # 6. Relational Integrity Checks before Assembly
        for flow in flows:
            if flow.acquisition_id != acquisition.acquisition_id:
                raise PackageAssemblyError(
                    code=PackageAssemblyErrorCode.ACQUISITION_MISMATCH,
                    message=f"Flow {flow.flow_id} acquisition mismatch.",
                    acquisition_id=acquisition.acquisition_id,
                )

        valid_flow_ids = {f.flow_id for f in flows}
        for event in protocol_events:
            if event.acquisition_id != acquisition.acquisition_id:
                raise PackageAssemblyError(
                    code=PackageAssemblyErrorCode.ACQUISITION_MISMATCH,
                    message=f"Event {event.event_id} acquisition mismatch.",
                    acquisition_id=acquisition.acquisition_id,
                )
            if event.flow_id not in valid_flow_ids:
                raise PackageAssemblyError(
                    code=PackageAssemblyErrorCode.BROKEN_FLOW_REFERENCE,
                    message=f"Event {event.event_id} points to missing flow {event.flow_id}.",
                    acquisition_id=acquisition.acquisition_id,
                )

        valid_event_ids = {e.event_id for e in protocol_events}
        for art in artifacts:
            if art.source_event_id and art.source_event_id not in valid_event_ids:
                raise PackageAssemblyError(
                    code=PackageAssemblyErrorCode.BROKEN_EVENT_REFERENCE,
                    message=f"Artifact {art.artifact_id} points to missing event {art.source_event_id}.",
                    acquisition_id=acquisition.acquisition_id,
                )
            if art.flow_id and art.flow_id not in valid_flow_ids:
                raise PackageAssemblyError(
                    code=PackageAssemblyErrorCode.BROKEN_FLOW_REFERENCE,
                    message=f"Artifact {art.artifact_id} points to missing flow {art.flow_id}.",
                    acquisition_id=acquisition.acquisition_id,
                )

        # 7. Construct Final Package
        package = NetworkIntelligencePackage(
            package_id=str(uuid.uuid4()),
            acquisition_id=acquisition.acquisition_id,
            flows=flows,
            protocol_events=protocol_events,
            artifacts=artifacts,
            packet_references=[],  # Not provided by Phase 3/4 pipeline natively currently
        )

        return package
