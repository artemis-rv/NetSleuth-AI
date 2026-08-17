import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, text, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class ModelRegistryModel(Base):
    __tablename__ = "model_registry"
    __table_args__ = {"schema": "analytics"}

    model_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_name = Column(String, nullable=False)
    model_type = Column(String, nullable=False)
    version = Column(String, nullable=False)
    feature_schema_version = Column(String, nullable=True)
    training_dataset_version = Column(String, nullable=True)
    artifact_object_key = Column(String, nullable=True)
    artifact_sha256 = Column(String, nullable=True)
    metrics = Column(JSONB, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class FindingsPackageModel(Base):
    __tablename__ = "findings_packages"
    __table_args__ = {"schema": "analytics"}

    package_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    source_package_id = Column(String, nullable=False)
    analysis_engine_version = Column(String, nullable=False)
    feature_schema_version = Column(String, nullable=True)
    anomaly_model_version = Column(String, nullable=True)
    classifier_model_version = Column(String, nullable=True)
    findings_count = Column(Integer, nullable=False, default=0)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    findings = relationship("FindingModel", back_populates="package")

# Many-to-Many link tables
finding_flow_links = Table(
    "finding_flow_links",
    Base.metadata,
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    Column("flow_id", UUID(as_uuid=True), ForeignKey("intelligence.flows.flow_id", ondelete="RESTRICT"), primary_key=True),
    schema="analytics"
)

finding_event_links = Table(
    "finding_event_links",
    Base.metadata,
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    Column("event_id", UUID(as_uuid=True), ForeignKey("intelligence.protocol_events.event_id", ondelete="RESTRICT"), primary_key=True),
    schema="analytics"
)

finding_artifact_links = Table(
    "finding_artifact_links",
    Base.metadata,
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    Column("artifact_id", UUID(as_uuid=True), ForeignKey("intelligence.artifacts.artifact_id", ondelete="RESTRICT"), primary_key=True),
    schema="analytics"
)

class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = {"schema": "analytics"}

    finding_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    package_id = Column(UUID(as_uuid=True), ForeignKey("analytics.findings_packages.package_id", ondelete="RESTRICT"), nullable=False)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    activity = Column(String, nullable=False)
    decision_state = Column(String, nullable=False)
    risk_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    anomaly_detected = Column(Boolean, nullable=False, default=False)
    severity = Column(String, nullable=False)
    risk_policy_version = Column(String, nullable=True)
    classification_probabilities = Column(JSONB, nullable=True)
    feature_attribution = Column(JSONB, nullable=True)
    rationale = Column(String, nullable=True)
    model_version = Column(String, nullable=True)
    feature_schema_version = Column(String, nullable=True)
    detection_method = Column(String, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    supersedes_id = Column(UUID(as_uuid=True), nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    detected_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    package = relationship("FindingsPackageModel", back_populates="findings")
    flows = relationship("FlowModel", secondary=finding_flow_links)
    events = relationship("ProtocolEventModel", secondary=finding_event_links)
    artifacts = relationship("ArtifactModel", secondary=finding_artifact_links)
