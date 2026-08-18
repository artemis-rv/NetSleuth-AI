import uuid
from sqlalchemy import Column, String, BigInteger, text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class AcquisitionModel(Base):
    __tablename__ = "acquisitions"
    __table_args__ = {"schema": "acquisition"}

    acquisition_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_name = Column(String, nullable=False)
    file_size = Column(BigInteger, nullable=True)
    sha256 = Column(String(64), nullable=False, unique=True)
    format = Column(String, nullable=False)
    source_type = Column(String, nullable=False)
    capture_interface = Column(String, nullable=True)
    capture_filter = Column(String, nullable=True)
    source_environment = Column(String, nullable=True)
    capture_started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    capture_ended_at = Column(TIMESTAMP(timezone=True), nullable=True)
    ingested_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    status = Column(String, nullable=False)

    evidence = relationship("EvidenceModel", back_populates="acquisition")


class EvidenceModel(Base):
    __tablename__ = "evidence"
    __table_args__ = {"schema": "acquisition"}

    evidence_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    minio_bucket = Column(String, nullable=False)
    object_key = Column(String, nullable=False, unique=True)
    sha256 = Column(String(64), nullable=False)
    size_bytes = Column(BigInteger, nullable=True)
    content_type = Column(String, nullable=True)
    packet_refs = Column(JSONB, nullable=True)
    integrity_status = Column(String, nullable=False, default="pending")
    registered_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    acquisition = relationship("AcquisitionModel", back_populates="evidence")

    @property
    def file_name(self) -> str:
        return self.acquisition.file_name if self.acquisition else ""

    @property
    def format(self) -> str:
        return self.acquisition.format if self.acquisition else ""

    @property
    def status(self) -> str:
        return self.acquisition.status if self.acquisition else ""

