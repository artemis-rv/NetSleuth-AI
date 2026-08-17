from app.persistence.models.base import Base
from app.persistence.models.acquisition_models import AcquisitionModel, EvidenceModel
from app.persistence.models.intelligence_models import FlowModel, ProtocolEventModel, ArtifactModel
from app.persistence.models.analytics_models import (
    ModelRegistryModel, 
    FindingsPackageModel, 
    FindingModel,
    finding_flow_links,
    finding_event_links,
    finding_artifact_links,
)
from app.persistence.models.investigation_models import (
    InvestigationCaseModel,
    EntityModel,
    RelationshipModel,
    BehaviorModel,
    AttackChainModel,
    MitreMappingModel,
    TimelineEventModel,
    relationship_finding_links,
    entity_artifact_links,
    behavior_finding_links,
    mitre_finding_links,
    case_finding_links,
    case_acquisition_links,
)
from app.persistence.models.identity_models import UserModel, CaseAccessModel
from app.persistence.models.custody_models import EvidenceItemModel, CustodyEventModel, ReportModel
from app.persistence.models.audit_models import AuditEventModel

# This explicitly registers all tables with the declarative base metadata
__all__ = [
    "Base",
    "AcquisitionModel", "EvidenceModel",
    "FlowModel", "ProtocolEventModel", "ArtifactModel",
    "ModelRegistryModel", "FindingsPackageModel", "FindingModel",
    "InvestigationCaseModel", "EntityModel", "RelationshipModel", 
    "BehaviorModel", "AttackChainModel", "MitreMappingModel", "TimelineEventModel",
    "UserModel", "CaseAccessModel",
    "EvidenceItemModel", "CustodyEventModel", "ReportModel",
    "AuditEventModel",
    # Link tables
    "finding_flow_links", "finding_event_links", "finding_artifact_links",
    "relationship_finding_links", "entity_artifact_links", 
    "behavior_finding_links", "mitre_finding_links", "case_finding_links",
    "case_acquisition_links"
]
