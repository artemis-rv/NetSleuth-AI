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

class CopilotPoint(BaseModel):
    title: str = Field(description="Forensic title of this observation or signal")
    explanation: str = Field(description="1-3 sentences concise explanation of the finding, signal, or recommendation")
    evidence_ids: List[str] = Field(default_factory=list, description="Forensic evidence IDs from the case context that support this point")
    finding_ids: List[str] = Field(default_factory=list, description="Authoritative M3 finding IDs associated with this point")
    technique_ids: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs associated with this point")
    status: Optional[str] = Field(default=None, description="Authoritative status of the evidence or mapping if applicable")
    confidence: Optional[float] = Field(default=None, description="Confidence score associated with the mapping or finding if applicable")

class CopilotStructuredResponse(BaseModel):
    summary: str = Field(description="Short 1-3 sentences executive summary of the overall answer")
    points: List[CopilotPoint] = Field(default_factory=list, description="List of structured forensic points representing key observations or architecture blocks")
    confirmed: List[str] = Field(default_factory=list, description="Observed facts or behaviors that have been fully confirmed by evidence")
    unconfirmed: List[str] = Field(default_factory=list, description="Still unconfirmed hypotheses, missing evidence, or telemetry limitations")
    recommendations: List[str] = Field(default_factory=list, description="Advisory recommended next steps or actions for containment, remediation, or further investigation")
    limitations: List[str] = Field(default_factory=list, description="Limitations of current forensic evidence or visibility boundaries")
    raw_unstructured: Optional[str] = Field(default=None, description="Preserved legacy unstructured output representation")

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
    copilot_response: Optional[CopilotStructuredResponse] = None
