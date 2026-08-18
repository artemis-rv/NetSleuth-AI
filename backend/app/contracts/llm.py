from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class LLMMitreMapping(BaseModel):
    model_config = ConfigDict(frozen=True)
    technique_id: str
    technique_name: str
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    behavior_id: Optional[str] = None
    mapping_status: str
    mapping_confidence: float
    rationale: Optional[str] = None
    source_finding_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    detection_strategy_ids: List[str] = Field(default_factory=list)
    analytic_ids: List[str] = Field(default_factory=list)
    data_component_ids: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default_factory=list)

class LLMEvidenceData(BaseModel):
    text: str
    content_type: str = "evidence"

class LLMEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    evidence_id: str
    evidence_type: str
    source_id: Optional[str] = None
    relationship_to_case: Optional[str] = None
    status: Optional[str] = None
    timestamp: Optional[str] = None
    evidence_data: LLMEvidenceData

class LLMAttackChainStage(BaseModel):
    model_config = ConfigDict(frozen=True)
    stage_id: str
    name: str
    timestamp: Optional[str] = None
    event_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)

class LLMAttackChain(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: str
    stages: List[LLMAttackChainStage] = Field(default_factory=list)

class LLMInvestigationContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")
    schema_version: str = "llm-context-v1.0"
    case_id: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_mappings: List[LLMMitreMapping] = Field(default_factory=list)
    mitre_provenance: Optional[Dict[str, Any]] = None
    attack_chain: Optional[LLMAttackChain] = None
    evidence_context: List[LLMEvidence] = Field(default_factory=list)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
