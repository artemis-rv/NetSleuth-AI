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
    protocol: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    connection_state: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def convert_ip(cls, v: Any) -> str:
        return str(v) if v is not None else ""

class FlowDetailResponse(FlowListItem):
    acquisition_id: UUID
    zeek_uid: Optional[str] = None
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
    zeek_uid: Optional[str] = None
    protocol: str
    timestamp: datetime
    protocol_data: Optional[Dict[str, Any]] = None
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
