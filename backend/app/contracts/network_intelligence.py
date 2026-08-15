"""
network_intelligence.py
-----------------------
M1 V1 Contract: NetworkIntelligencePackage and all canonical M1 objects.

This module defines the authoritative Python-typed representation of the
M1 output contract.  It is the SHARED INTERFACE between M1 and M2.

OWNERSHIP:
  - Contract definition: shared (all members)
  - Implementation: M1 (packet intelligence engine)

CONTRACT VERSION: 1.0

Canonical JSON schema: docs/contracts/network-intelligence-v1.json

Do NOT add detection, scoring, severity, MITRE, risk, or any downstream
analysis concepts to this file.  This contract represents observations
only — "what happened on the wire."

Do NOT modify another member's contract fields without a team interface
discussion and explicit agreement.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# CONTRACT VERSION
# ---------------------------------------------------------------------------

CONTRACT_VERSION = "1.0"


# ---------------------------------------------------------------------------
# ENUMERATIONS
# ---------------------------------------------------------------------------


class ArtifactType(str, Enum):
    """V1 supported artifact types.  Do not expand without explicit instruction."""

    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE = "FILE"
    FILE_HASH = "FILE_HASH"
    CERTIFICATE = "CERTIFICATE"
    USER_AGENT = "USER_AGENT"


class Protocol(str, Enum):
    """V1 supported protocols."""

    # Network foundation
    ETHERNET = "ethernet"
    ARP = "arp"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"

    # Application protocols
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    SSL = "ssl"  # Zeek uses 'ssl' for TLS sessions

    # Unknown / other (pass-through, not enumerated)
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# PROVENANCE
# ---------------------------------------------------------------------------


class FlowProvenance(BaseModel):
    """Provenance carried on a Flow object.

    Preserves the Zeek source and log file so the origin of every
    field is traceable back to a specific Zeek log record.
    """

    acquisition_id: Optional[str] = None
    evidence_id: Optional[str] = None
    zeek_uid: Optional[str] = None
    source: str = Field(..., description="Producing tool, e.g. 'zeek'")
    source_log: str = Field(..., description="Source Zeek log file, e.g. 'conn.log'")
    processed_at: Optional[datetime] = None
    processor_version: Optional[str] = None

    model_config = {"frozen": True}


class EventProvenance(BaseModel):
    """Provenance carried on a ProtocolEvent object."""

    acquisition_id: str
    evidence_id: Optional[str] = None
    zeek_uid: Optional[str] = None
    source: str = Field(..., description="Producing tool, e.g. 'zeek'")
    source_log: str = Field(..., description="Source Zeek log file, e.g. 'dns.log'")
    processed_at: Optional[datetime] = None
    processor_version: Optional[str] = None

    model_config = {"frozen": True}


class ArtifactProvenance(BaseModel):
    """Provenance carried on an Artifact object."""

    acquisition_id: str
    evidence_id: Optional[str] = None
    source_event_id: Optional[str] = None
    derived_from: Optional[str] = Field(
        None,
        description="Free-text description of how this artifact was derived",
    )

    model_config = {"frozen": True}


class Provenance(BaseModel):
    """General-purpose provenance block.

    Used by AcquisitionReference and PacketReference where the
    specialised per-object provenance types are not required.
    """

    acquisition_id: Optional[str] = None
    evidence_id: Optional[str] = None
    source: Optional[str] = None
    source_log: Optional[str] = None
    zeek_uid: Optional[str] = None
    processed_at: Optional[datetime] = None
    processor_version: Optional[str] = None

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# ACQUISITION REFERENCE
# ---------------------------------------------------------------------------


class AcquisitionReference(BaseModel):
    """Record of a PCAP/PCAPNG evidence file that has been ingested.

    Created once per evidence file by the acquisition engine.
    Immutable after creation.
    """

    acquisition_id: str = Field(..., description="Unique acquisition identifier")
    evidence_id: str = Field(..., description="Unique evidence file identifier")
    file_name: str = Field(..., description="Original file name (not a full path)")
    file_size: int = Field(..., ge=0, description="File size in bytes")
    format: str = Field(..., description="Capture format: 'pcap' or 'pcapng'")
    sha256: str = Field(..., description="SHA-256 hex digest of the evidence file")
    capture_reference: str = Field(
        ...,
        description="Location of the evidence file.  Local path for independent dev.",
    )
    acquired_at: Optional[datetime] = None
    provenance: Optional[Provenance] = None

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# ENDPOINT
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    """Source or destination endpoint of a network flow."""

    ip: str = Field(..., description="IP address as a string")
    port: int = Field(..., ge=0, le=65535, description="Port number")

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# FLOW
# ---------------------------------------------------------------------------


class Flow(BaseModel):
    """A network connection/session derived from Zeek conn.log.

    One Flow corresponds to one Zeek connection record (one UID).
    Many packets -> one Flow.

    Do NOT invent field values.  Use None for any value not present
    in the upstream Zeek record.
    """

    object_type: str = Field(default="flow", description="Constant discriminator")
    flow_id: str = Field(..., description="M1-generated unique flow identifier")
    zeek_uid: str = Field(..., description="Original Zeek connection UID")
    acquisition_id: str
    evidence_id: Optional[str] = None
    timestamp: datetime = Field(..., description="Connection start timestamp (UTC)")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source: Endpoint
    destination: Endpoint
    protocol: str = Field(..., description="Transport protocol, e.g. 'tcp'")
    service: Optional[str] = Field(
        None, description="Application service identified by Zeek, e.g. 'ssl'"
    )
    duration: Optional[float] = Field(None, ge=0.0)
    orig_bytes: Optional[int] = Field(None, ge=0)
    resp_bytes: Optional[int] = Field(None, ge=0)
    orig_packets: Optional[int] = Field(None, ge=0)
    resp_packets: Optional[int] = Field(None, ge=0)
    connection_state: Optional[str] = Field(
        None, description="Zeek connection state code, e.g. 'SF'"
    )
    provenance: FlowProvenance

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# PROTOCOL EVENT DATA
# ---------------------------------------------------------------------------


class DNSData(BaseModel):
    """DNS-specific protocol data extracted from Zeek dns.log."""

    query: Optional[str] = None
    query_type: Optional[str] = None
    answers: list[str] = Field(default_factory=list)
    response_code: Optional[str] = None

    model_config = {"frozen": True, "extra": "forbid"}


class HTTPData(BaseModel):
    """HTTP-specific protocol data extracted from Zeek http.log."""

    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    request_body_len: Optional[int] = None
    response_body_len: Optional[int] = None

    model_config = {"frozen": True, "extra": "forbid"}


class TLSData(BaseModel):
    """TLS-specific protocol data extracted from Zeek ssl.log.

    Only observable metadata is captured.  Encrypted content is NOT
    accessible and must NOT be invented or inferred.
    """

    version: Optional[str] = None
    server_name: Optional[str] = Field(None, description="SNI from ClientHello")
    cipher: Optional[str] = None
    subject: Optional[str] = Field(None, description="Certificate subject (if logged)")
    issuer: Optional[str] = Field(None, description="Certificate issuer (if logged)")
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None

    model_config = {"frozen": True, "extra": "forbid"}


# ---------------------------------------------------------------------------
# PROTOCOL EVENT
# ---------------------------------------------------------------------------


class ProtocolEvent(BaseModel):
    """Application-layer protocol activity associated with a Flow.

    Derived from Zeek protocol-specific logs (dns.log, http.log, ssl.log).
    Joined to its parent Flow via zeek_uid.

    protocol_data holds one of DNSData | HTTPData | TLSData | dict.
    Using dict allows pass-through for edge cases without breaking the
    contract when unexpected fields appear in Zeek output.
    """

    event_id: str = Field(..., description="M1-generated unique event identifier")
    flow_id: str = Field(..., description="Parent flow identifier")
    zeek_uid: str = Field(..., description="Zeek UID linking to conn.log and Flow")
    acquisition_id: str
    evidence_id: Optional[str] = None
    timestamp: datetime
    protocol: str = Field(..., description="Application protocol, e.g. 'dns'")
    protocol_data: DNSData | HTTPData | TLSData | dict[str, Any] = Field(
        ...,
        description="Protocol-specific observed data.  Never invented.",
    )
    provenance: EventProvenance

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# ARTIFACT
# ---------------------------------------------------------------------------


class Artifact(BaseModel):
    """An observable indicator extracted from protocol events.

    V1 types: IP, DOMAIN, URL, FILE, FILE_HASH, CERTIFICATE, USER_AGENT.

    Artifacts are derived from actual observed data.  Never synthesised.
    """

    artifact_id: str = Field(..., description="M1-generated unique artifact identifier")
    type: ArtifactType
    value: str = Field(..., description="The observable value")
    source_event_id: Optional[str] = Field(
        None, description="ProtocolEvent that produced this artifact"
    )
    flow_id: Optional[str] = None
    acquisition_id: str
    evidence_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    provenance: ArtifactProvenance

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# PACKET REFERENCE
# ---------------------------------------------------------------------------


class PacketReference(BaseModel):
    """Forensic traceability reference into the original PCAP.

    Does NOT copy packet data.  References byte offsets / frame ranges
    so the original evidence file remains the authoritative source.
    """

    evidence_id: Optional[str] = None
    acquisition_id: Optional[str] = None
    packet_start: Optional[int] = Field(None, description="First frame number")
    packet_end: Optional[int] = Field(None, description="Last frame number")
    timestamp_start: Optional[datetime] = None
    timestamp_end: Optional[datetime] = None
    byte_offset: Optional[int] = Field(
        None, description="Byte offset into the PCAP file where evidence begins"
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# NETWORK INTELLIGENCE PACKAGE
# ---------------------------------------------------------------------------


class NetworkIntelligencePackage(BaseModel):
    """The final M1 output.

    Consumed by M2 (Analysis Engine).

    This package contains all M1 canonical objects for one acquisition.
    It does NOT contain:
      - malicious / risk_score / severity / attack_type
      - MITRE mapping
      - detection results
      - AI or ML conclusions

    Those are strictly downstream (M2+) concepts.
    """

    package_id: str = Field(..., description="Unique package identifier")
    contract_version: str = Field(
        default=CONTRACT_VERSION,
        description="Contract version this package conforms to",
    )
    acquisition_id: str
    flows: list[Flow] = Field(default_factory=list)
    protocol_events: list[ProtocolEvent] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    packet_references: list[PacketReference] = Field(default_factory=list)

    model_config = {"frozen": True}
