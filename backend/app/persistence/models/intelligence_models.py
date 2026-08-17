import uuid
from sqlalchemy import Column, String, BigInteger, Integer, Float, text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB, INET
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class FlowModel(Base):
    __tablename__ = "flows"
    __table_args__ = {"schema": "intelligence"}

    flow_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    zeek_uid = Column(String, nullable=False)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.evidence.evidence_id", ondelete="RESTRICT"), nullable=True)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False)
    start_time = Column(TIMESTAMP(timezone=True), nullable=True)
    end_time = Column(TIMESTAMP(timezone=True), nullable=True)
    src_ip = Column(INET, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(INET, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    service = Column(String, nullable=False)
    duration = Column(Float, nullable=True)
    orig_bytes = Column(BigInteger, nullable=True)
    resp_bytes = Column(BigInteger, nullable=True)
    orig_packets = Column(Integer, nullable=True)
    resp_packets = Column(Integer, nullable=True)
    connection_state = Column(String, nullable=True)
    pcap_frame_start = Column(BigInteger, nullable=True)
    pcap_frame_end = Column(BigInteger, nullable=True)
    pcap_byte_offset = Column(BigInteger, nullable=True)
    pcap_timestamp_start = Column(TIMESTAMP(timezone=True), nullable=True)
    pcap_timestamp_end = Column(TIMESTAMP(timezone=True), nullable=True)
    provenance = Column(JSONB, nullable=True)

    protocol_events = relationship("ProtocolEventModel", back_populates="flow")
    artifacts = relationship("ArtifactModel", back_populates="flow")

class ProtocolEventModel(Base):
    __tablename__ = "protocol_events"
    __table_args__ = {"schema": "intelligence"}

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("intelligence.flows.flow_id", ondelete="RESTRICT"), nullable=False)
    zeek_uid = Column(String, nullable=False)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.evidence.evidence_id", ondelete="RESTRICT"), nullable=True)
    protocol = Column(String, nullable=False)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False)
    protocol_data = Column(JSONB, nullable=False)
    provenance = Column(JSONB, nullable=True)

    flow = relationship("FlowModel", back_populates="protocol_events")
    artifacts = relationship("ArtifactModel", back_populates="source_event")

class ArtifactModel(Base):
    __tablename__ = "artifacts"
    __table_args__ = {"schema": "intelligence"}

    artifact_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source_event_id = Column(UUID(as_uuid=True), ForeignKey("intelligence.protocol_events.event_id", ondelete="RESTRICT"), nullable=True)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("intelligence.flows.flow_id", ondelete="RESTRICT"), nullable=True)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.evidence.evidence_id", ondelete="RESTRICT"), nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    provenance = Column(JSONB, nullable=True)

    source_event = relationship("ProtocolEventModel", back_populates="artifacts")
    flow = relationship("FlowModel", back_populates="artifacts")
