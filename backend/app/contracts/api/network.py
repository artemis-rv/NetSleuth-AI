from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

class FlowListItem(BaseModel):
    flow_id: UUID
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    @field_validator('src_ip', 'dst_ip', mode='before')
    @classmethod
    def cast_ip_to_str(cls, v):
        return str(v) if v is not None else v
    protocol: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    connection_state: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class FlowDetailResponse(FlowListItem):
    acquisition_id: UUID
    zeek_uid: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    orig_packets: Optional[int] = None
    resp_packets: Optional[int] = None
    pcap_frame_start: Optional[int] = None
    pcap_frame_end: Optional[int] = None
    pcap_byte_offset: Optional[int] = None
    pcap_timestamp_start: Optional[datetime] = None
    pcap_timestamp_end: Optional[datetime] = None
    provenance: Optional[Dict[str, Any]] = None

class FlowListResponse(BaseModel):
    items: List[FlowListItem]
    total: int
    page: int
    page_size: int

class ProtocolEventResponse(BaseModel):
    event_id: UUID
    flow_id: UUID
    zeek_uid: str
    protocol: str
    timestamp: datetime
    protocol_data: Dict[str, Any]
    provenance: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

class ProtocolEventListResponse(BaseModel):
    items: List[ProtocolEventResponse]
    total: int
    page: int
    page_size: int

class ArtifactResponse(BaseModel):
    artifact_id: UUID
    type: str
    value: str
    source_event_id: Optional[UUID] = None
    flow_id: Optional[UUID] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    provenance: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

class ArtifactListResponse(BaseModel):
    items: List[ArtifactResponse]
    total: int
    page: int
    page_size: int

class IPEntityResponse(BaseModel):
    ip: str
    classification: str  # "PRIVATE/INTERNAL", "PUBLIC/EXTERNAL", "LOOPBACK", "LINK_LOCAL", "MULTICAST", "UNKNOWN"
    role: str  # "SOURCE", "DESTINATION", "BOTH"
    related_domains: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    flow_count: int = 0
    event_count: int = 0
    finding_count: int = 0
    flow_ids: List[UUID] = Field(default_factory=list)
    event_ids: List[UUID] = Field(default_factory=list)
    artifact_ids: List[UUID] = Field(default_factory=list)
    finding_ids: List[UUID] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)

class IPEntityListResponse(BaseModel):
    items: List[IPEntityResponse]
    total: int
    internal_count: int
    external_count: int

# =====================================================================
# DYNAMIC ENDPOINT FORENSIC CONTEXT MODELS (READ-ONLY PRESENTATION)
# =====================================================================

class CommunicationProfile(BaseModel):
    total_flows: int = 0
    unique_sources: List[str] = Field(default_factory=list)
    unique_destinations: List[str] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    destination_ports: List[int] = Field(default_factory=list)
    source_ports: List[int] = Field(default_factory=list)
    connection_states: List[str] = Field(default_factory=list)
    total_active_duration: float = 0.0

class TrafficProfile(BaseModel):
    bytes_sent: int = 0  # OUTBOUND
    bytes_received: int = 0  # INBOUND
    packets_sent: int = 0
    packets_received: int = 0
    total_bytes: int = 0
    total_packets: int = 0
    avg_flow_duration: float = 0.0

class DNSProtocolProfile(BaseModel):
    query_count: int = 0
    unique_queries: List[str] = Field(default_factory=list)
    answers_count: int = 0
    response_codes: List[str] = Field(default_factory=list)

class HTTPProtocolProfile(BaseModel):
    request_count: int = 0
    methods: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    uris: List[str] = Field(default_factory=list)
    status_codes: List[int] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)

class TLSProtocolProfile(BaseModel):
    session_count: int = 0
    versions: List[str] = Field(default_factory=list)
    ciphers: List[str] = Field(default_factory=list)
    server_names: List[str] = Field(default_factory=list)

class ProtocolProfile(BaseModel):
    dns: DNSProtocolProfile = Field(default_factory=DNSProtocolProfile)
    http: HTTPProtocolProfile = Field(default_factory=HTTPProtocolProfile)
    tls: TLSProtocolProfile = Field(default_factory=TLSProtocolProfile)

class ArtifactSummaryItem(BaseModel):
    artifact_id: UUID
    type: str
    value: str
    source_event_id: Optional[UUID] = None
    flow_id: Optional[UUID] = None
    acquisition_id: Optional[UUID] = None
    evidence_id: Optional[str] = None

class SeverityBreakdown(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class M2FindingSummaryItem(BaseModel):
    finding_id: UUID
    activity: str
    severity: str
    risk_score: float
    confidence: float
    anomaly_score: Optional[float] = None
    decision_state: str
    rationale: str

class M2FindingsSummary(BaseModel):
    finding_count: int = 0
    highest_severity: Optional[str] = None
    max_risk_score: float = 0.0
    max_anomaly_score: float = 0.0
    avg_confidence: float = 0.0
    activity_classes: List[str] = Field(default_factory=list)
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    items: List[M2FindingSummaryItem] = Field(default_factory=list)

class TemporalSummary(BaseModel):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    active_duration_seconds: float = 0.0
    connection_rate_per_min: float = 0.0

class EvidenceTraceabilityItem(BaseModel):
    flow_id: UUID
    zeek_uid: str
    acquisition_id: UUID
    pcap_frame_start: Optional[int] = None
    pcap_frame_end: Optional[int] = None
    pcap_byte_offset: Optional[int] = None
    pcap_timestamp_start: Optional[datetime] = None
    pcap_timestamp_end: Optional[datetime] = None
    has_packet_reference: bool = False

class EvidenceSummary(BaseModel):
    flow_count: int = 0
    protocol_event_count: int = 0
    artifact_count: int = 0
    has_packet_references: bool = False
    traceability_items: List[EvidenceTraceabilityItem] = Field(default_factory=list)

class NetworkEndpointContextResponse(BaseModel):
    ip: str
    ip_version: int = 4
    role: str  # "SOURCE", "DESTINATION", "BOTH"
    network_scope: str  # "PRIVATE/INTERNAL", "PUBLIC/EXTERNAL", "LOOPBACK", "LINK_LOCAL", "MULTICAST", "UNKNOWN"
    hostname: Optional[str] = None
    associated_domain: Optional[str] = None
    resolved_dns_names: List[str] = Field(default_factory=list)
    
    communication: CommunicationProfile = Field(default_factory=CommunicationProfile)
    traffic: TrafficProfile = Field(default_factory=TrafficProfile)
    protocol_activity: ProtocolProfile = Field(default_factory=ProtocolProfile)
    artifacts: List[ArtifactSummaryItem] = Field(default_factory=list)
    m2_findings: M2FindingsSummary = Field(default_factory=M2FindingsSummary)
    temporal: TemporalSummary = Field(default_factory=TemporalSummary)
    evidence: EvidenceSummary = Field(default_factory=EvidenceSummary)
    
    flow_ids: List[UUID] = Field(default_factory=list)
    event_ids: List[UUID] = Field(default_factory=list)
    
    model_config = ConfigDict(from_attributes=True)

class NetworkEndpointContextListResponse(BaseModel):
    items: List[NetworkEndpointContextResponse]
    total: int
    page: int
    page_size: int
    internal_count: int
    external_count: int
