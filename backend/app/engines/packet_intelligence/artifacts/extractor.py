"""
backend/app/engines/packet_intelligence/artifacts/extractor.py
--------------------------------------------------------------
Extracts canonical Artifact objects from M1 ProtocolEvents.
"""

import ipaddress
import uuid
from typing import Any

from app.contracts.network_intelligence import (
    Artifact,
    ArtifactProvenance,
    ArtifactType,
    DNSData,
    HTTPData,
    ProtocolEvent,
    TLSData,
)

from .errors import ArtifactExtractionError, ArtifactExtractionErrorCode


class ArtifactExtractor:
    """Extracts Artifact objects from canonical ProtocolEvents."""

    def extract(self, event: ProtocolEvent) -> list[Artifact]:
        """Extract artifacts based on the underlying protocol_data.

        Parameters:
            event: A canonical ProtocolEvent produced by an adapter.

        Returns:
            A list of isolated Artifact objects derived from the event.
        """
        if isinstance(event.protocol_data, DNSData):
            return self._extract_dns(event, event.protocol_data)
        if isinstance(event.protocol_data, HTTPData):
            return self._extract_http(event, event.protocol_data)
        if isinstance(event.protocol_data, TLSData):
            return self._extract_tls(event, event.protocol_data)

        # Skip unknown or un-modeled protocol data (e.g. dict passthrough)
        return []

    def _extract_dns(self, event: ProtocolEvent, data: DNSData) -> list[Artifact]:
        artifacts = []

        if data.query:
            artifacts.append(self._build_artifact(event, ArtifactType.DOMAIN, data.query))

        for answer in data.answers:
            if not answer:
                continue
            
            try:
                # If it's a valid IP, map as IP
                _ = ipaddress.ip_address(answer)
                artifacts.append(self._build_artifact(event, ArtifactType.IP, answer))
            except ValueError:
                # Otherwise map as DOMAIN (e.g. CNAMEs)
                artifacts.append(self._build_artifact(event, ArtifactType.DOMAIN, answer))

        return artifacts

    def _extract_http(self, event: ProtocolEvent, data: HTTPData) -> list[Artifact]:
        artifacts = []

        if data.host:
            artifacts.append(self._build_artifact(event, ArtifactType.DOMAIN, data.host))

        if data.user_agent:
            artifacts.append(self._build_artifact(event, ArtifactType.USER_AGENT, data.user_agent))

        return artifacts

    def _extract_tls(self, event: ProtocolEvent, data: TLSData) -> list[Artifact]:
        artifacts = []

        if data.server_name:
            artifacts.append(self._build_artifact(event, ArtifactType.DOMAIN, data.server_name))

        # Certificate fields are skipped intentionally to abide by the boundary 
        # (TLSData has no stable unique identifier for a CERTIFICATE artifact).
        return artifacts

    def _build_artifact(self, event: ProtocolEvent, art_type: ArtifactType, value: str) -> Artifact:
        """Helper to consistently construct an Artifact linked back to its source event."""
        provenance = ArtifactProvenance(
            acquisition_id=event.acquisition_id,
            evidence_id=event.evidence_id,
            source_event_id=event.event_id,
            derived_from="extracted from protocol data",
        )

        return Artifact(
            artifact_id=str(uuid.uuid4()),
            type=art_type,
            value=value,
            source_event_id=event.event_id,
            flow_id=event.flow_id,
            acquisition_id=event.acquisition_id,
            evidence_id=event.evidence_id,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            provenance=provenance,
        )
