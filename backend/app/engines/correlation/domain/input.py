from pydantic import BaseModel, Field
from typing import Dict, List

from app.contracts.network_intelligence import Flow, ProtocolEvent, Artifact
from app.contracts.analysis import Finding

class TelemetryCapability(BaseModel):
    """Profile of available telemetry in the input package."""
    network_flow: bool = True
    dns: bool = False
    http: bool = False
    tls: bool = False

class EvidenceIndex(BaseModel):
    """Deterministic lookup for O(1) evidence retrieval by M3 engines."""
    flows: Dict[str, Flow] = Field(default_factory=dict)
    events: Dict[str, ProtocolEvent] = Field(default_factory=dict)
    artifacts: Dict[str, Artifact] = Field(default_factory=dict)
    findings: Dict[str, Finding] = Field(default_factory=dict)

class M3InvestigationInput(BaseModel):
    """Authoritative immutable canonical input object for M3.
    
    Contains everything M3 needs for correlation, behavior extraction, 
    evidence validation, MITRE ATT&CK mapping, and attack-chain construction.
    """
    acquisition_id: str
    network_package_id: str
    findings_package_id: str
    
    # Lossless underlying records
    network_flows: List[Flow] = Field(default_factory=list)
    protocol_events: List[ProtocolEvent] = Field(default_factory=list)
    artifacts: List[Artifact] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    
    # Computed metadata for M3
    telemetry_capabilities: TelemetryCapability
    evidence_index: EvidenceIndex
    
    model_config = {"frozen": True}
