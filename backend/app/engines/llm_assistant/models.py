from enum import Enum
from typing import List, Dict, Optional
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

class LLMInvestigationResponse(BaseModel):
    status: LLMResponseStatus = LLMResponseStatus.SUCCESS
    request_id: str
    case_id: str
    summary: Optional[str] = None
    explanation: Optional[str] = None
    mitre_explanations: List[LLMMitreExplanation] = Field(default_factory=list)
    investigator_answers: Dict[str, str] = Field(default_factory=dict)
    limitations: Optional[str] = None
    provenance: Dict[str, str] = Field(default_factory=dict)
