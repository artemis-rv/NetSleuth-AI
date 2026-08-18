from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

class EntityBase(BaseModel):
    name: str
    entity_type: str
    risk_score: Optional[float] = None
    properties: Optional[Dict[str, Any]] = None

class EntityResponse(EntityBase):
    entity_id: UUID
    case_id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class EntityListResponse(BaseModel):
    items: List[EntityResponse]
    total: int
    page: int
    page_size: int

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
    model_config = ConfigDict(from_attributes=True)

class RelationshipListResponse(BaseModel):
    items: List[RelationshipResponse]
    total: int
    page: int
    page_size: int

class BehaviorBase(BaseModel):
    name: str
    description: Optional[str] = None
    category: str
    severity: str
    confidence: Optional[float] = None

class BehaviorResponse(BehaviorBase):
    behavior_id: UUID
    case_id: UUID
    first_observed: datetime
    last_observed: datetime
    model_config = ConfigDict(from_attributes=True)

class BehaviorListResponse(BaseModel):
    items: List[BehaviorResponse]
    total: int
    page: int
    page_size: int

class TimelineEventBase(BaseModel):
    event_type: str
    description: str
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

class MitreMappingBase(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    confidence: Optional[float] = None

class MitreMappingResponse(MitreMappingBase):
    mitre_mapping_id: UUID
    case_id: UUID
    mapped_at: datetime
    model_config = ConfigDict(from_attributes=True)

class MitreMappingListResponse(BaseModel):
    items: List[MitreMappingResponse]
    total: int
    page: int
    page_size: int

class AttackChainResponse(BaseModel):
    chain_id: UUID
    case_id: UUID
    stages: Dict[str, Any]
    confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class GraphResponse(BaseModel):
    nodes: List[EntityResponse]
    edges: List[RelationshipResponse]
