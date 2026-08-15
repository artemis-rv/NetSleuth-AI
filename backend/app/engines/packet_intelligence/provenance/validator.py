"""
backend/app/engines/packet_intelligence/provenance/validator.py
---------------------------------------------------------------
Validates the provenance chain of generated canonical objects.
"""

from backend.app.contracts.network_intelligence import Artifact, ProtocolEvent

from .errors import ProvenanceError, ProvenanceErrorCode


class ProvenanceValidator:
    """Verifies provenance relationships between canonical M1 objects."""

    def validate_artifact_provenance(self, artifact: Artifact, source_event: ProtocolEvent) -> None:
        """Verify an artifact correctly references its source event.

        Raises:
            ProvenanceError: If the artifact references conflict with the source event.
        """
        if not artifact.source_event_id:
            raise ProvenanceError(
                code=ProvenanceErrorCode.MISSING_REQUIRED_REFERENCE,
                message="Artifact is missing source_event_id",
                artifact_id=artifact.artifact_id,
                source_event_id=source_event.event_id,
            )

        if artifact.source_event_id != source_event.event_id:
            raise ProvenanceError(
                code=ProvenanceErrorCode.MISMATCHED_EVENT_ID,
                message=f"Artifact source_event_id {artifact.source_event_id} != {source_event.event_id}",
                artifact_id=artifact.artifact_id,
                source_event_id=source_event.event_id,
            )

        if artifact.flow_id != source_event.flow_id:
            raise ProvenanceError(
                code=ProvenanceErrorCode.MISMATCHED_FLOW_ID,
                message=f"Artifact flow_id {artifact.flow_id} != {source_event.flow_id}",
                artifact_id=artifact.artifact_id,
                source_event_id=source_event.event_id,
            )

        if artifact.acquisition_id != source_event.acquisition_id:
            raise ProvenanceError(
                code=ProvenanceErrorCode.MISMATCHED_ACQUISITION_ID,
                message=f"Artifact acquisition_id {artifact.acquisition_id} != {source_event.acquisition_id}",
                artifact_id=artifact.artifact_id,
                source_event_id=source_event.event_id,
            )
