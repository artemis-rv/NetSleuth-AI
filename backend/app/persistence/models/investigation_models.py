import uuid
from sqlalchemy import Column, String, Float, Integer, text, ForeignKey, Table, JSON, CheckConstraint
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
    investigation_goals = Column(JSONB, nullable=True)
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

    relationship_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    source_entity_id = Column(UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), nullable=False)
    target_entity_id = Column(UUID(as_uuid=True), ForeignKey("investigation.entities.entity_id", ondelete="RESTRICT"), nullable=False)
    relationship_type = Column(String, nullable=False)
    strength = Column(Float, nullable=True)
    attributes = Column(JSONB, nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

    __table_args__ = (
        CheckConstraint("last_seen >= first_seen", name="ck_rel__time"),
        {"schema": "investigation"}
    )

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
    status = Column(String, nullable=False, default="none")
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
    behavior_id = Column(UUID(as_uuid=True), ForeignKey("investigation.behaviors.behavior_id", ondelete="RESTRICT"), nullable=True)
    technique_id = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    tactic_id = Column(String, nullable=True)
    technique_name = Column(String, nullable=True)
    mapping_status = Column(String, nullable=True)
    attack_version = Column(String, nullable=True)
    justification = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    evidence_ids = Column(ARRAY(String), nullable=True)
    source_finding_ids = Column(ARRAY(String), nullable=True)
    detection_strategy_ids = Column(ARRAY(String), nullable=True)
    analytic_ids = Column(ARRAY(String), nullable=True)
    data_component_ids = Column(ARRAY(String), nullable=True)
    channels = Column(ARRAY(String), nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    mapped_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))


class AnalysisJobModel(Base):
    __tablename__ = "analysis_jobs"
    __table_args__ = {"schema": "investigation"}

    analysis_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    acquisition_id = Column(UUID(as_uuid=True), ForeignKey("acquisition.acquisitions.acquisition_id", ondelete="RESTRICT"), nullable=False)
    status = Column(String, nullable=False)
    current_stage = Column(String, nullable=True)
    progress = Column(Integer, nullable=True)
    error_code = Column(String, nullable=True)
    error_message = Column(String, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    created_by = Column(UUID(as_uuid=True), nullable=True)


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

# ─────────────────────────────────────────────
# V1.3 Assessment Models
# ─────────────────────────────────────────────

class HypothesisModel(Base):
    __tablename__ = "hypotheses"
    __table_args__ = {"schema": "investigation"}

    hypothesis_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    statement = Column(String, nullable=False)
    hypothesis_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="POTENTIAL")
    confidence = Column(Float, nullable=False)
    supporting_evidence_ids = Column(ARRAY(String), nullable=False)
    supporting_finding_ids = Column(ARRAY(String), nullable=True)
    related_entity_ids = Column(ARRAY(String), nullable=True)
    related_mitre_mapping_ids = Column(ARRAY(String), nullable=True)
    first_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen = Column(TIMESTAMP(timezone=True), nullable=True)
    supporting_reasons = Column(ARRAY(String), nullable=True)
    missing_evidence = Column(ARRAY(String), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class HypothesisValidationModel(Base):
    __tablename__ = "hypothesis_validations"
    __table_args__ = {"schema": "investigation"}

    validation_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    hypothesis_id = Column(UUID(as_uuid=True), ForeignKey("investigation.hypotheses.hypothesis_id", ondelete="RESTRICT"), nullable=False)
    validation_status = Column(String, nullable=False)
    supporting_evidence_ids = Column(ARRAY(String), nullable=True)
    contradicting_evidence_ids = Column(ARRAY(String), nullable=True)
    supporting_reasons = Column(ARRAY(String), nullable=True)
    contradicting_reasons = Column(ARRAY(String), nullable=True)
    missing_evidence = Column(ARRAY(String), nullable=True)
    confidence = Column(Float, nullable=False)
    validated_at = Column(TIMESTAMP(timezone=True), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class RootCauseModel(Base):
    __tablename__ = "root_causes"
    __table_args__ = {"schema": "investigation"}

    root_cause_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    statement = Column(String, nullable=False)
    status = Column(String, nullable=False, default="POTENTIAL")
    confidence = Column(Float, nullable=False)
    supporting_hypothesis_ids = Column(ARRAY(String), nullable=True)
    supporting_evidence_ids = Column(ARRAY(String), nullable=False)
    supporting_finding_ids = Column(ARRAY(String), nullable=True)
    rationale = Column(ARRAY(String), nullable=True)
    missing_evidence = Column(ARRAY(String), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))

class ImpactAssessmentModel(Base):
    __tablename__ = "impact_assessments"
    __table_args__ = {"schema": "investigation"}

    impact_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation.investigation_cases.case_id", ondelete="RESTRICT"), nullable=False)
    category = Column(String, nullable=False)
    statement = Column(String, nullable=False)
    status = Column(String, nullable=False, default="POTENTIAL")
    confidence = Column(Float, nullable=False)
    supporting_evidence_ids = Column(ARRAY(String), nullable=False)
    supporting_finding_ids = Column(ARRAY(String), nullable=True)
    affected_entity_ids = Column(ARRAY(String), nullable=True)
    rationale = Column(ARRAY(String), nullable=True)
    missing_evidence = Column(ARRAY(String), nullable=True)
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
