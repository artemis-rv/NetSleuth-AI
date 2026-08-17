import uuid
from sqlalchemy import Column, String, Boolean, text, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class UserModel(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "identity"}

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="analyst")
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class CaseAccessModel(Base):
    __tablename__ = "case_access"
    __table_args__ = {"schema": "identity"}

    access_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("identity.users.user_id", ondelete="CASCADE"), nullable=False)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="CASCADE"), nullable=False)
    access_level = Column(String, nullable=False)
    granted_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    granted_by = Column(UUID(as_uuid=True), ForeignKey("identity.users.user_id", ondelete="RESTRICT"), nullable=True)
