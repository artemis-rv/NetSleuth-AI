import uuid
from sqlalchemy import Column, String, text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB, INET

from app.persistence.models.base import Base

class AuditEventModel(Base):
    __tablename__ = "audit_events"
    __table_args__ = {"schema": "audit"}

    audit_event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id = Column(UUID(as_uuid=True), nullable=True)
    actor_name = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target_entity_type = Column(String, nullable=True)
    target_entity_id = Column(String, nullable=True)
    occurred_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    source_ip = Column(INET, nullable=True)
    session_id = Column(String, nullable=True)
    result = Column(String, nullable=False)
    metadata_ = Column("metadata", JSONB, nullable=True)
