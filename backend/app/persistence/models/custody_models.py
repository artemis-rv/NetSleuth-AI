import uuid
from sqlalchemy import Column, String, text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class EvidenceItemModel(Base):
    __tablename__ = "evidence_items"
    __table_args__ = {"schema": "custody"}

    item_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), nullable=True)
    artifact_id = Column(UUID(as_uuid=True), ForeignKey("intelligence.artifacts.artifact_id", ondelete="RESTRICT"), nullable=True)
    description = Column(String, nullable=False)
    collected_by = Column(UUID(as_uuid=True), ForeignKey("identity.users.user_id", ondelete="RESTRICT"), nullable=False)
    collected_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    hash_sha256 = Column(String(64), nullable=True)
    status = Column(String, nullable=False, default="collected")
    attributes = Column(JSONB, nullable=True)

class CustodyEventModel(Base):
    __tablename__ = "custody_events"
    __table_args__ = {"schema": "custody"}

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id = Column(UUID(as_uuid=True), ForeignKey("custody.evidence_items.item_id", ondelete="RESTRICT"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("identity.users.user_id", ondelete="RESTRICT"), nullable=False)
    action = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    signature = Column(String, nullable=True)

class ReportModel(Base):
    __tablename__ = "reports"
    __table_args__ = {"schema": "custody"}

    report_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("identity.users.user_id", ondelete="RESTRICT"), nullable=False)
    title = Column(String, nullable=False)
    format = Column(String, nullable=False)
    content_uri = Column(String, nullable=False)
    hash_sha256 = Column(String(64), nullable=False)
    generated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
