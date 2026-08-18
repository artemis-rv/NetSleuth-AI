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
    # DB column is 'label' — expose as 'name' to the frontend
    name: Optional[str] = None
    created_at: datetime

    @field_validator('name', mode='before')
    @classmethod
    def _coerce_name(cls, v):
        return v  # populated via model_validator below

    @classmethod
    def model_validate(cls, obj, **kwargs):
        """Override to map DB column names to API field names."""
        if hasattr(obj, '__dict__') or hasattr(obj, '_sa_instance_state'):
            data = {
                'entity_id': obj.entity_id,
                'case_id': obj.case_id,
                'name': getattr(obj, 'label', None),
                'entity_type': obj.entity_type,
                'risk_score': None,
                'properties': getattr(obj, 'attributes', None),
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
                # DB column is 'strength' — expose as 'confidence'
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
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    # severity is not in the DB behaviors table — optional
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
                # DB column is 'label' — expose as 'name'
                'name': getattr(obj, 'label', None),
                'description': None,
                # DB column is 'behavior_type' — expose as 'category'
                'category': getattr(obj, 'behavior_type', None),
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
    # Nullable in DB — must be Optional here
    description: Optional[str] = None
    event_timestamp: datetime
    source_id: Optional[UUID] = None

class TimelineEventResponse(TimelineEventBase):
    timeline_event_id: UUID
    case_id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TimelineEventListResponse(BaseModel):
    items: List[TimelineEventResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────
# MITRE
# ─────────────────────────────────────────────

class MitreMappingBase(BaseModel):
    # DB has a single 'tactic' column that stores the tactic name
    # Expose as both tactic_id (empty fallback) and tactic_name for UI compat
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    technique_id: str
    technique_name: Optional[str] = None
    confidence: Optional[float] = None

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
                'tactic_id': tactic or '',
                'tactic_name': tactic,
                'technique_id': obj.technique_id,
                'technique_name': getattr(obj, 'technique_name', None),
                'confidence': getattr(obj, 'confidence', None),
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
# Attack Chain
# ─────────────────────────────────────────────

class AttackChainResponse(BaseModel):
    # DB column is 'attack_chain_id' — expose consistently
    chain_id: UUID
    case_id: UUID
    title: Optional[str] = None
    summary: Optional[str] = None
    stages: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        if hasattr(obj, '_sa_instance_state'):
            data = {
                # DB column is 'attack_chain_id' — map to 'chain_id' for API
                'chain_id': obj.attack_chain_id,
                'case_id': obj.case_id,
                'title': getattr(obj, 'title', None),
                'summary': getattr(obj, 'summary', None),
                'stages': getattr(obj, 'stages', None) or {},
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
