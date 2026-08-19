from pydantic import BaseModel, ConfigDict, field_validator
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime


# ─────────────────────────────────────────────
# Entity
# ─────────────────────────────────────────────

class EntityBase(BaseModel):
    entity_type: str
    risk_score: Optional[float] = None
    properties: Optional[Dict[str, Any]] = None

class EntityResponse(EntityBase):
    entity_id: UUID
    case_id: UUID
    # V1.3 contract uses 'label' — aligned to contract
    label: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        """Override to map DB column names to API field names."""
        if hasattr(obj, '__dict__') or hasattr(obj, '_sa_instance_state'):
            data = {
                'entity_id': obj.entity_id,
                'case_id': obj.case_id,
                'label': getattr(obj, 'label', None),
                'entity_type': obj.entity_type,
                'risk_score': None,
                'properties': getattr(obj, 'attributes', None),
                'first_seen': getattr(obj, 'first_seen', None),
                'last_seen': getattr(obj, 'last_seen', None),
                'created_at': obj.created_at,
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)

class EntityListResponse(BaseModel):
    items: List[EntityResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# Relationship
# ─────────────────────────────────────────────

class RelationshipBase(BaseModel):
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: str
    confidence: Optional[float] = None
    properties: Optional[Dict[str, Any]] = None

class RelationshipResponse(RelationshipBase):
    relationship_id: UUID
    case_id: UUID
    created_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            data = {
                'relationship_id': obj.relationship_id,
                'case_id': obj.case_id,
                'source_entity_id': obj.source_entity_id,
                'target_entity_id': obj.target_entity_id,
                'relationship_type': obj.relationship_type,
                # DB column is 'strength' — expose as 'confidence' per V1.3 contract
                'confidence': getattr(obj, 'strength', None),
                'properties': getattr(obj, 'attributes', None),
                'created_at': obj.created_at,
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)

class RelationshipListResponse(BaseModel):
    items: List[RelationshipResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# Behavior
# ─────────────────────────────────────────────

class BehaviorBase(BaseModel):
    # V1.3 contract uses 'label' — aligned to contract
    label: Optional[str] = None
    description: Optional[str] = None
    # V1.3 contract uses 'behavior_type' — aligned to contract
    behavior_type: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None

class BehaviorResponse(BehaviorBase):
    behavior_id: UUID
    case_id: UUID
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            data = {
                'behavior_id': obj.behavior_id,
                'case_id': obj.case_id,
                'label': getattr(obj, 'label', None),
                'description': None,
                'behavior_type': getattr(obj, 'behavior_type', None),
                'severity': None,
                'confidence': getattr(obj, 'confidence', None),
                'first_observed': getattr(obj, 'first_observed', None),
                'last_observed': getattr(obj, 'last_observed', None),
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)

class BehaviorListResponse(BaseModel):
    items: List[BehaviorResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# Timeline
# ─────────────────────────────────────────────

class TimelineEventBase(BaseModel):
    event_type: str
    title: Optional[str] = None
    description: Optional[str] = None
    event_timestamp: datetime
    source_id: Optional[UUID] = None
    attributes: Optional[Dict[str, Any]] = None

class TimelineEventResponse(TimelineEventBase):
    timeline_event_id: UUID
    case_id: UUID
    created_at: datetime
    
    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            data = {
                'timeline_event_id': obj.timeline_event_id,
                'case_id': obj.case_id,
                'event_type': obj.event_type,
                'title': obj.attributes.get("title") if obj.attributes else None,
                'description': obj.description,
                'event_timestamp': obj.event_timestamp,
                'source_id': None, # Adjust if needed
                'attributes': obj.attributes,
                'created_at': obj.created_at
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)

class TimelineEventListResponse(BaseModel):
    items: List[TimelineEventResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# MITRE — V1.3 contract-aligned
# ─────────────────────────────────────────────

class MitreMappingBase(BaseModel):
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    technique_id: str
    technique_name: Optional[str] = None
    mapping_status: Optional[str] = None
    confidence: Optional[float] = None
    behavior_id: Optional[UUID] = None
    evidence_ids: Optional[List[str]] = None
    source_finding_ids: Optional[List[str]] = None
    detection_strategy_ids: Optional[List[str]] = None
    analytic_ids: Optional[List[str]] = None
    data_component_ids: Optional[List[str]] = None
    channels: Optional[List[str]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

class MitreMappingResponse(MitreMappingBase):
    mitre_mapping_id: UUID
    case_id: UUID
    mapped_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            tactic = getattr(obj, 'tactic', None)
            data = {
                'mitre_mapping_id': obj.mitre_mapping_id,
                'case_id': obj.case_id,
                # Prefer dedicated tactic_id column; fall back to tactic (name)
                'tactic_id': getattr(obj, 'tactic_id', None) or tactic or '',
                'tactic_name': tactic,
                'technique_id': obj.technique_id,
                'technique_name': getattr(obj, 'technique_name', None),
                'mapping_status': getattr(obj, 'mapping_status', None),
                'confidence': getattr(obj, 'confidence', None),
                'behavior_id': getattr(obj, 'behavior_id', None),
                'evidence_ids': getattr(obj, 'evidence_ids', None),
                'source_finding_ids': getattr(obj, 'source_finding_ids', None),
                'detection_strategy_ids': getattr(obj, 'detection_strategy_ids', None),
                'analytic_ids': getattr(obj, 'analytic_ids', None),
                'data_component_ids': getattr(obj, 'data_component_ids', None),
                'channels': getattr(obj, 'channels', None),
                'first_seen': getattr(obj, 'first_seen', None),
                'last_seen': getattr(obj, 'last_seen', None),
                'mapped_at': obj.mapped_at,
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)

class MitreMappingListResponse(BaseModel):
    items: List[MitreMappingResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# Attack Chain — V1.3 contract-aligned
# ─────────────────────────────────────────────

class AttackChainResponse(BaseModel):
    # M3-005 FIX: Use DB column name 'attack_chain_id' instead of 'chain_id'
    attack_chain_id: UUID
    case_id: UUID
    # M3-008 FIX: Expose status field
    status: Optional[str] = None
    title: Optional[str] = None
    summary: Optional[str] = None
    # M3-006 FIX: stages is a List (array), not a Dict
    stages: Optional[List[Dict[str, Any]]] = None
    confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            raw_stages = getattr(obj, 'stages', None)
            # Normalize: if stages is stored as JSONB object with nested 'stages' key, unwrap
            if isinstance(raw_stages, dict) and 'stages' in raw_stages:
                stages_list = raw_stages.get('stages', [])
            elif isinstance(raw_stages, list):
                stages_list = raw_stages
            else:
                stages_list = []

            data = {
                'attack_chain_id': obj.attack_chain_id,
                'case_id': obj.case_id,
                'status': getattr(obj, 'status', None),
                'title': getattr(obj, 'title', None),
                'summary': getattr(obj, 'summary', None),
                'stages': stages_list,
                'confidence': None,
                'created_at': obj.created_at,
                'updated_at': obj.updated_at,
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────────
# Graph
# ─────────────────────────────────────────────

class GraphResponse(BaseModel):
    nodes: List[EntityResponse]
    edges: List[RelationshipResponse]


# ─────────────────────────────────────────────
# V1.3 Assessment — Hypothesis
# ─────────────────────────────────────────────

class HypothesisResponse(BaseModel):
    hypothesis_id: UUID
    case_id: UUID
    statement: str
    hypothesis_type: str
    status: str
    confidence: float
    supporting_evidence_ids: List[str]
    supporting_finding_ids: Optional[List[str]] = None
    related_entity_ids: Optional[List[str]] = None
    related_mitre_mapping_ids: Optional[List[str]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    supporting_reasons: Optional[List[str]] = None
    missing_evidence: Optional[List[str]] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class HypothesisListResponse(BaseModel):
    items: List[HypothesisResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# V1.3 Assessment — Hypothesis Validation
# ─────────────────────────────────────────────

class HypothesisValidationResponse(BaseModel):
    validation_id: UUID
    case_id: UUID
    hypothesis_id: UUID
    validation_status: str
    supporting_evidence_ids: Optional[List[str]] = None
    contradicting_evidence_ids: Optional[List[str]] = None
    supporting_reasons: Optional[List[str]] = None
    contradicting_reasons: Optional[List[str]] = None
    missing_evidence: Optional[List[str]] = None
    confidence: float
    validated_at: datetime
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class HypothesisValidationListResponse(BaseModel):
    items: List[HypothesisValidationResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# V1.3 Assessment — Root Cause
# ─────────────────────────────────────────────

class RootCauseResponse(BaseModel):
    root_cause_id: UUID
    case_id: UUID
    statement: str
    status: str
    confidence: float
    supporting_hypothesis_ids: Optional[List[str]] = None
    supporting_evidence_ids: List[str]
    supporting_finding_ids: Optional[List[str]] = None
    rationale: Optional[List[str]] = None
    missing_evidence: Optional[List[str]] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class RootCauseListResponse(BaseModel):
    items: List[RootCauseResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# V1.3 Assessment — Impact Assessment
# ─────────────────────────────────────────────

class ImpactAssessmentResponse(BaseModel):
    impact_id: UUID
    case_id: UUID
    category: str
    statement: str
    status: str
    confidence: float
    supporting_evidence_ids: List[str]
    supporting_finding_ids: Optional[List[str]] = None
    affected_entity_ids: Optional[List[str]] = None
    rationale: Optional[List[str]] = None
    missing_evidence: Optional[List[str]] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ImpactAssessmentListResponse(BaseModel):
    items: List[ImpactAssessmentResponse]
    total: int
    page: int
    page_size: int
