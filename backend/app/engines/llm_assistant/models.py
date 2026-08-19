from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class LLMResponseStatus(str, Enum):
    SUCCESS = "SUCCESS"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    LLM_MODEL_UNAVAILABLE = "LLM_MODEL_UNAVAILABLE"
    LLM_INVALID_RESPONSE = "LLM_INVALID_RESPONSE"
    LLM_UNGROUNDED = "LLM_UNGROUNDED"

class LLMMitreExplanation(BaseModel):
    technique_id: str
    technique_name: str
    mapping_status: str
    mapping_confidence: float
    evidence_ids: List[str] = Field(default_factory=list)
    explanation: str

class LLMFindingExplanation(BaseModel):
    finding_id: str
    explanation: str

class LLMHypothesisExplanation(BaseModel):
    hypothesis_id: str
    explanation: str

class LLMRootCauseExplanation(BaseModel):
    root_cause_id: str
    explanation: str

class LLMImpactExplanation(BaseModel):
    impact_id: str
    explanation: str

class LLMInvestigationResponse(BaseModel):
    status: LLMResponseStatus = LLMResponseStatus.SUCCESS
    request_id: str
    case_id: str
    summary: Optional[str] = None
    explanation: Optional[str] = None
    finding_explanations: List[LLMFindingExplanation] = Field(default_factory=list)
    mitre_explanations: List[LLMMitreExplanation] = Field(default_factory=list)
    hypothesis_explanations: List[LLMHypothesisExplanation] = Field(default_factory=list)
    root_cause_explanations: List[LLMRootCauseExplanation] = Field(default_factory=list)
    impact_explanations: List[LLMImpactExplanation] = Field(default_factory=list)
    investigator_answers: Dict[str, str] = Field(default_factory=dict)
    limitations: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
