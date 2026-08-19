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

class LLMHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True)
    hypothesis_id: str
    statement: str
    hypothesis_type: Optional[str] = None
    status: str
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)
    supporting_findings: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)

class LLMValidation(BaseModel):
    model_config = ConfigDict(frozen=True)
    validation_id: str
    hypothesis_id: str
    status: str
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)

class LLMRootCause(BaseModel):
    model_config = ConfigDict(frozen=True)
    root_cause_id: str
    statement: str
    status: str
    confidence: float
    supporting_hypotheses: List[str] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    missing_evidence: List[str] = Field(default_factory=list)

class LLMImpact(BaseModel):
    model_config = ConfigDict(frozen=True)
    impact_id: str
    category: str
    statement: str
    status: str
    confidence: float
    evidence: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    missing_evidence: List[str] = Field(default_factory=list)

class LLMReportRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    report_id: str
    report_version: str = "v1.3"
    provenance: Dict[str, Any] = Field(default_factory=dict)

class LLMSystemKnowledge(BaseModel):
    model_config = ConfigDict(frozen=True)
    m1_description: str = "M1 handles evidence acquisition, packet intelligence, flow metrics, protocol events, and raw PCAP/PCAPNG ingestion."
    m2_description: str = "M2 handles Machine Learning activity classification, anomaly detection scoring, risk assignment, and evidence attribution."
    m3_description: str = "M3 handles deterministic DFIR correlation, entity graph construction, timeline alignment, MITRE ATT&CK mapping, attack chains, hypothesis validation, root cause analysis, and impact assessment."
    m4_description: str = "M4 handles InvestigationCase V1.3 state management, multi-format report generation (JSON, HTML, PDF), cryptographic SHA-256 evidence integrity, and chain of custody preservation."
    llm_boundary: str = "LLM acts as a read-only, advisory DFIR assistant. LLM explains findings and recommends actions but MUST NOT alter authoritative M3 state, risk scores, or mapping status."
    storage_architecture: str = "PostgreSQL stores operational/investigation metadata, users, cases, and correlation graphs. MinIO stores raw PCAP captures, evidence artifacts, and exported report files."
    api_boundary: str = "FastAPI backend exposes REST endpoints under /api/v1 for authentication, cases, evidence, analysis, investigation, reports, and copilot."

class LLMInvestigationContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")
    schema_version: str = "llm-context-v1.3"
    case_id: str
    case_metadata: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_mappings: List[LLMMitreMapping] = Field(default_factory=list)
    mitre_provenance: Optional[Dict[str, Any]] = None
    attack_chain: Optional[LLMAttackChain] = None
    evidence_context: List[LLMEvidence] = Field(default_factory=list)
    hypotheses: List[LLMHypothesis] = Field(default_factory=list)
    validations: List[LLMValidation] = Field(default_factory=list)
    root_causes: List[LLMRootCause] = Field(default_factory=list)
    impacts: List[LLMImpact] = Field(default_factory=list)
    reports: List[LLMReportRef] = Field(default_factory=list)
    system_knowledge: LLMSystemKnowledge = Field(default_factory=LLMSystemKnowledge)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
