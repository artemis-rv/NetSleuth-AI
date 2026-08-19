import pytest
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from app.services.network_service import NetworkIntelligenceService
from app.contracts.api.network import (
    NetworkEndpointContextListResponse, NetworkEndpointContextResponse,
    CommunicationProfile, TrafficProfile, ProtocolProfile
)

@pytest.mark.asyncio
async def test_endpoint_context_aggregation_basic():
    db_mock = AsyncMock()
    service = NetworkIntelligenceService(db_mock)

    # Mock flow objects
    f1 = MagicMock()
    f1.flow_id = uuid.uuid4()
    f1.src_ip = "192.168.1.100"
    f1.src_port = 54321
    f1.dst_ip = "93.184.216.34"
    f1.dst_port = 443
    f1.protocol = "tcp"
    f1.service = "tls"
    f1.connection_state = "SF"
    f1.duration = 10.5
    f1.orig_bytes = 1024
    f1.resp_bytes = 2048
    f1.timestamp = datetime(2026, 8, 19, 10, 0, 0)
    f1.zeek_uid = "C12345"
    f1.acquisition_id = uuid.uuid4()
    f1.pcap_frame_start = 100
    f1.pcap_frame_end = 200
    f1.pcap_byte_offset = 4096
    f1.pcap_timestamp_start = datetime(2026, 8, 19, 10, 0, 0)
    f1.pcap_timestamp_end = datetime(2026, 8, 19, 10, 0, 10)

    service.flow_repo.list_by_case = AsyncMock(return_value=[f1])
    service.artifact_repo.list_by_case = AsyncMock(return_value=[])
    service.finding_repo.list_by_case = AsyncMock(return_value=[])
    service.event_repo.list_by_flow = AsyncMock(return_value=[])

    case_id = uuid.uuid4()
    res = await service.list_endpoint_contexts_by_case(case_id=case_id)

    assert isinstance(res, NetworkEndpointContextListResponse)
    assert res.total == 2
    
    internal_ep = next(item for item in res.items if item.ip == "192.168.1.100")
    external_ep = next(item for item in res.items if item.ip == "93.184.216.34")

    # Scenario 1-3: Role & Classification
    assert internal_ep.network_scope == "PRIVATE/INTERNAL"
    assert internal_ep.role == "SOURCE"
    assert external_ep.network_scope == "PUBLIC/EXTERNAL"
    assert external_ep.role == "DESTINATION"

    # Scenario 4-8: Communication & Traffic Profile
    assert internal_ep.communication.total_flows == 1
    assert "TCP" in internal_ep.communication.protocols
    assert "TLS" in internal_ep.communication.services
    assert 443 in internal_ep.communication.destination_ports

    assert internal_ep.traffic.bytes_sent == 1024  # OUTBOUND
    assert internal_ep.traffic.bytes_received == 2048  # INBOUND
    assert external_ep.traffic.bytes_sent == 2048
    assert external_ep.traffic.bytes_received == 1024

    # Scenario 9-10: Temporal & Evidence Traceability
    assert internal_ep.evidence.has_packet_references is True
    assert internal_ep.evidence.traceability_items[0].pcap_frame_start == 100

@pytest.mark.asyncio
async def test_endpoint_context_m2_finding_association():
    db_mock = AsyncMock()
    service = NetworkIntelligenceService(db_mock)

    f1 = MagicMock()
    f1.flow_id = uuid.uuid4()
    f1.src_ip = "192.168.1.105"
    f1.src_port = 49152
    f1.dst_ip = "93.184.216.34"
    f1.dst_port = 8080
    f1.protocol = "tcp"
    f1.service = "http"
    f1.connection_state = "SF"
    f1.duration = 5.0
    f1.orig_bytes = 500
    f1.resp_bytes = 1000
    f1.timestamp = datetime(2026, 8, 19, 10, 0, 0)
    f1.zeek_uid = "C9999"
    f1.acquisition_id = uuid.uuid4()
    f1.pcap_frame_start = None
    f1.pcap_byte_offset = None

    finding = MagicMock()
    finding.finding_id = uuid.uuid4()
    finding.activity = "c2_beaconing"
    finding.severity = "HIGH"
    finding.risk_score = 0.95
    finding.confidence = 0.90
    finding.decision_state = "confirmed"
    finding.rationale = "Periodic HTTP beaconing from 192.168.1.105 to 93.184.216.34"
    finding.feature_attribution = {"anomaly_score": 0.88}

    service.flow_repo.list_by_case = AsyncMock(return_value=[f1])
    service.artifact_repo.list_by_case = AsyncMock(return_value=[])
    service.finding_repo.list_by_case = AsyncMock(return_value=[finding])
    service.event_repo.list_by_flow = AsyncMock(return_value=[])

    res = await service.list_endpoint_contexts_by_case(case_id=uuid.uuid4())
    ep = next(item for item in res.items if item.ip == "192.168.1.105")

    # Scenario 11-15: M2 Findings aggregation
    assert ep.m2_findings.finding_count == 1
    assert ep.m2_findings.highest_severity == "HIGH"
    assert ep.m2_findings.max_risk_score == 0.95
    assert ep.m2_findings.max_anomaly_score == 0.88
    assert "c2_beaconing" in ep.m2_findings.activity_classes

@pytest.mark.asyncio
async def test_endpoint_context_filtering_and_sorting():
    db_mock = AsyncMock()
    service = NetworkIntelligenceService(db_mock)

    f1 = MagicMock()
    f1.flow_id = uuid.uuid4()
    f1.src_ip = "10.0.0.5"
    f1.src_port = 1234
    f1.dst_ip = "1.1.1.1"
    f1.dst_port = 53
    f1.protocol = "udp"
    f1.service = "dns"
    f1.connection_state = "SF"
    f1.duration = 1.0
    f1.orig_bytes = 100
    f1.resp_bytes = 200
    f1.timestamp = datetime(2026, 8, 19, 10, 0, 0)
    f1.zeek_uid = "C8888"
    f1.acquisition_id = uuid.uuid4()
    f1.pcap_frame_start = None
    f1.pcap_byte_offset = None

    service.flow_repo.list_by_case = AsyncMock(return_value=[f1])
    service.artifact_repo.list_by_case = AsyncMock(return_value=[])
    service.finding_repo.list_by_case = AsyncMock(return_value=[])
    service.event_repo.list_by_flow = AsyncMock(return_value=[])

    case_id = uuid.uuid4()

    # Test IP search filter
    res = await service.list_endpoint_contexts_by_case(case_id=case_id, search_ip="10.0.0.5")
    assert res.total == 1
    assert res.items[0].ip == "10.0.0.5"

    # Test Scope filter
    res_ext = await service.list_endpoint_contexts_by_case(case_id=case_id, network_scope="PUBLIC/EXTERNAL")
    assert res_ext.total == 1
    assert res_ext.items[0].ip == "1.1.1.1"
