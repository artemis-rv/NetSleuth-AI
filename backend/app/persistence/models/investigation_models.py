import uuid
from sqlalchemy import Column, String, Float, text, ForeignKey, Table, JSON
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB, ARRAY
from sqlalchemy.orm import relationship

from app.persistence.models.base import Base

class InvestigationCaseModel(Base):
    __tablename__ = "investigation_cases"
    __table_args__ = {"schema": "investigation"}

    case_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(String, nullable=False, default="open")
    priority = Column(String, nullable=True)
    trigger_type = Column(String, nullable=False)
    trigger_description = Column(String, nullable=True)
    external_case_id = Column(String, nullable=True)
    external_system = Column(String, nullable=True)
    reported_by = Column(String, nullable=True)
    investigation_goals = Column(ARRAY(String), nullable=True)
    opened_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    closed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    entities = relationship("EntityModel", back_populates="case")

class EntityModel(Base):
    __tablename__ = "entities"
    __table_args__ = {"schema": "investigation"}

    entity_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    entity_type = Column(String, nullable=False)
    label = Column(String, nullable=False)
    value = Column(String, nullable=True)
    attributes = Column(JSONB, nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    case = relationship("InvestigationCaseModel", back_populates="entities")

class RelationshipModel(Base):
    __tablename__ = "relationships"
    __table_args__ = {"schema": "investigation"}

    relationship_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    source_entity_id = Column(UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), nullable=False)
    target_entity_id = Column(UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), nullable=False)
    relationship_type = Column(String, nullable=False)
    strength = Column(Float, nullable=True)
    attributes = Column(JSONB, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class BehaviorModel(Base):
    __tablename__ = "behaviors"
    __table_args__ = {"schema": "investigation"}

    behavior_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    behavior_type = Column(String, nullable=False)
    label = Column(String, nullable=False)
    confidence = Column(Float, nullable=True)
    attributes = Column(JSONB, nullable=True)
    first_observed = Column(TIMESTAMP(timezone=True), nullable=True)
    last_observed = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class AttackChainModel(Base):
    __tablename__ = "attack_chains"
    __table_args__ = {"schema": "investigation"}

    attack_chain_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False, unique=True)
    title = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    stages = Column(JSONB, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    finalized_at = Column(TIMESTAMP(timezone=True), nullable=True)

class MitreMappingModel(Base):
    __tablename__ = "mitre_mappings"
    __table_args__ = {"schema": "investigation"}

    mitre_mapping_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    attack_chain_id = Column(UUID(as_uuid=True), ForeignKey("investigation.attack_chains.attack_chain_id", ondelete="RESTRICT"), nullable=True)
    technique_id = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    technique_name = Column(String, nullable=True)
    attack_version = Column(String, nullable=True)
    justification = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    mapped_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class TimelineEventModel(Base):
    __tablename__ = "timeline_events"
    __table_args__ = {"schema": "investigation"}

    timeline_event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    event_timestamp = Column(TIMESTAMP(timezone=True), nullable=False)
    event_type = Column(String, nullable=False)
    description = Column(String, nullable=True)
    entity_id = Column(UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), nullable=True)
    behavior_id = Column(UUID(as_uuid=True), ForeignKey("investigation.behaviors.behavior_id", ondelete="RESTRICT"), nullable=True)
    finding_id = Column(UUID(as_uuid=True), nullable=True)  # No hard FK across schema for this specific optional link in timeline, wait, in DB-6 is it an FK? Let's check. DB-6 didn't list it as an FK for timeline events finding_id, but it is conceptually linked. Actually, I didn't add the constraint in Alembic. Let's leave as UUID.
    attributes = Column(JSONB, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

# Investigation Link Tables
relationship_finding_links = Table(
    "relationship_finding_links", Base.metadata,
    Column("relationship_id", UUID(as_uuid=True), ForeignKey("investigation.relationships.relationship_id", ondelete="RESTRICT"), primary_key=True),
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    schema="investigation"
)

entity_artifact_links = Table(
    "entity_artifact_links", Base.metadata,
    Column("entity_id", UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), primary_key=True),
    Column("artifact_id", UUID(as_uuid=True), ForeignKey("intelligence.artifacts.artifact_id", ondelete="RESTRICT"), primary_key=True),
    schema="investigation"
)

behavior_finding_links = Table(
    "behavior_finding_links", Base.metadata,
    Column("behavior_id", UUID(as_uuid=True), ForeignKey("investigation.behaviors.behavior_id", ondelete="RESTRICT"), primary_key=True),
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    schema="investigation"
)

mitre_finding_links = Table(
    "mitre_finding_links", Base.metadata,
    Column("mitre_mapping_id", UUID(as_uuid=True), ForeignKey("investigation.mitre_mappings.mitre_mapping_id", ondelete="RESTRICT"), primary_key=True),
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    schema="investigation"
)

case_finding_links = Table(
    "case_finding_links", Base.metadata,
    Column("case_id", UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), primary_key=True),
    Column("finding_id", UUID(as_uuid=True), ForeignKey("analytics.findings.finding_id", ondelete="RESTRICT"), primary_key=True),
    Column("role", String, nullable=True),
    Column("added_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    schema="analytics"
)

case_acquisition_links = Table(
    "case_acquisition_links", Base.metadata,
    Column("case_id", UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), primary_key=True),
    Column("acquisition_id", UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), primary_key=True),
    Column("added_at", TIMESTAMP, nullable=False, server_default=text("now()")),
    schema="acquisition"
)
