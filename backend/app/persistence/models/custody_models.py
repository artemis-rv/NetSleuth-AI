import uuid
from sqlalchemy import Column, String, Integer, text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class EvidenceItemModel(Base):
    __tablename__ = "evidence_items"
    __table_args__ = {"schema": "custody"}

    evidence_item_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.evidence.evidence_id", ondelete="RESTRICT"), nullable=True)
    label = Column(String, nullable=False)
    description = Column(String, nullable=True)
    evidence_type = Column(String, nullable=False)
    minio_bucket = Column(String, nullable=True)
    object_key = Column(String, nullable=True)
    sha256 = Column(String(64), nullable=True)
    registered_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    registered_by = Column(UUID(as_uuid=True), nullable=True)

class CustodyEventModel(Base):
    __tablename__ = "custody_events"
    __table_args__ = {"schema": "custody"}

    custody_event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_item_id = Column(UUID(as_uuid=True), ForeignKey("custody.evidence_items.evidence_item_id", ondelete="RESTRICT"), nullable=False)
    action = Column(String, nullable=False)
    actor_id = Column(UUID(as_uuid=True), nullable=True)
    actor_name = Column(String, nullable=True)
    occurred_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    notes = Column(String, nullable=True)
    event_metadata = Column("metadata", JSONB, nullable=True)

class ReportModel(Base):
    __tablename__ = "reports"
    __table_args__ = {"schema": "custody"}

    report_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    report_type = Column(String, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    title = Column(String, nullable=True)
    minio_bucket = Column(String, nullable=False)
    object_key = Column(String, nullable=False, unique=True)
    sha256 = Column(String(64), nullable=False)
    format = Column(String, nullable=False)
    generated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    generated_by = Column(UUID(as_uuid=True), nullable=True)
