import uuid
from sqlalchemy import Column, String, text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB, INET

from app.persistence.models.base import Base

class AuditEventModel(Base):
    __tablename__ = "audit_events"
    __table_args__ = {"schema": "audit"}

    audit_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id = Column(UUID(as_uuid=True), nullable=True)  # Soft reference to identity.users
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    ip_address = Column(INET, nullable=True)
    details = Column(JSONB, nullable=True)
