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
