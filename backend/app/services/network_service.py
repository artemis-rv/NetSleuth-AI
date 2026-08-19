from uuid import UUID
from typing import Optional, List, Dict, Any
import ipaddress
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.intelligence_repository import FlowRepository, ProtocolEventRepository, ArtifactRepository
from app.persistence.repositories.analytics_repository import FindingRepository
from app.contracts.api.network import (
    FlowDetailResponse, FlowListResponse, FlowListItem,
    ProtocolEventResponse, ProtocolEventListResponse,
    ArtifactResponse, ArtifactListResponse,
    NetworkEndpointContextResponse, NetworkEndpointContextListResponse,
    CommunicationProfile, TrafficProfile, ProtocolProfile,
    DNSProtocolProfile, HTTPProtocolProfile, TLSProtocolProfile,
    ArtifactSummaryItem, M2FindingsSummary, M2FindingSummaryItem, SeverityBreakdown,
    TemporalSummary, EvidenceSummary, EvidenceTraceabilityItem
)

class NetworkIntelligenceService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.flow_repo = FlowRepository(db)
        self.event_repo = ProtocolEventRepository(db)
        self.artifact_repo = ArtifactRepository(db)
        self.finding_repo = FindingRepository(db)

    async def list_flows_by_case(
        self,
        case_id: UUID,
        page: int,
        page_size: int,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None
    ) -> FlowListResponse:
        skip = (page - 1) * page_size
        flows = await self.flow_repo.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol
        )
        total = await self.flow_repo.count_by_case(
            case_id=case_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol
        )

        return FlowListResponse(
            items=[FlowListItem.model_validate(f) for f in flows],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_flow(self, flow_id: UUID) -> FlowDetailResponse:
        flow = await self.flow_repo.get(flow_id)
        if not flow:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flow not found")
        return FlowDetailResponse.model_validate(flow)

    async def list_events_by_flow(self, flow_id: UUID, page: int, page_size: int) -> ProtocolEventListResponse:
        skip = (page - 1) * page_size
        events = await self.event_repo.list_by_flow(flow_id=flow_id, skip=skip, limit=page_size)
        total = await self.event_repo.count_by_flow(flow_id=flow_id)
        
        return ProtocolEventListResponse(
            items=[ProtocolEventResponse.model_validate(e) for e in events],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_event(self, event_id: UUID) -> ProtocolEventResponse:
        event = await self.event_repo.get(event_id)
        if not event:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
        return ProtocolEventResponse.model_validate(event)

    async def list_artifacts_by_case(
        self,
        case_id: UUID,
        page: int,
        page_size: int,
        artifact_type: Optional[str] = None
    ) -> ArtifactListResponse:
        skip = (page - 1) * page_size
        artifacts = await self.artifact_repo.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            artifact_type=artifact_type
        )
        total = await self.artifact_repo.count_by_case(case_id=case_id, artifact_type=artifact_type)
        
        return ArtifactListResponse(
            items=[ArtifactResponse.model_validate(a) for a in artifacts],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_artifact(self, artifact_id: UUID) -> ArtifactResponse:
        artifact = await self.artifact_repo.get(artifact_id)
        if not artifact:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
        return ArtifactResponse.model_validate(artifact)

    async def get_case_id_for_acquisition(self, acquisition_id: UUID) -> Optional[UUID]:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import select
        
        stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == acquisition_id)
        result = await self.db.execute(stmt)
        row = result.first()
        if row:
            return row[0]
        return None

    def _classify_ip(self, ip_str: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback: return "LOOPBACK"
            if ip_obj.is_link_local: return "LINK_LOCAL"
            if ip_obj.is_multicast: return "MULTICAST"
            if ip_obj.is_private: return "PRIVATE/INTERNAL"
            if ip_obj.is_global: return "PUBLIC/EXTERNAL"
            return "UNKNOWN"
        except ValueError:
            return "UNKNOWN"

    async def list_endpoint_contexts_by_case(
        self,
        case_id: UUID,
        page: int = 1,
        page_size: int = 50,
        search_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        service: Optional[str] = None,
        port: Optional[int] = None,
        network_scope: Optional[str] = None,
        severity: Optional[str] = None,
        min_risk: Optional[float] = None,
        min_anomaly: Optional[float] = None,
        sort_by: Optional[str] = "risk_score"
    ) -> NetworkEndpointContextListResponse:
        
        flows = await self.flow_repo.list_by_case(case_id=case_id, skip=0, limit=2000)
        artifacts = await self.artifact_repo.list_by_case(case_id=case_id, skip=0, limit=2000)
        findings = await self.finding_repo.list_by_case(case_id=case_id, skip=0, limit=2000)

        # Build Flow map
        flow_map = {f.flow_id: f for f in flows}
        flow_ids = list(flow_map.keys())

        # Build events per flow
        events_by_flow: Dict[UUID, List[Any]] = {}
        for fid in flow_ids[:500]:  # batch lookup
            evs = await self.event_repo.list_by_flow(flow_id=fid, skip=0, limit=100)
            events_by_flow[fid] = evs

        # Map artifacts by flow/event
        artifacts_by_ip: Dict[str, List[ArtifactSummaryItem]] = {}
        for a in artifacts:
            matched_ip = None
            if a.type == "ip":
                matched_ip = a.value
            elif a.flow_id and a.flow_id in flow_map:
                matched_ip = str(flow_map[a.flow_id].dst_ip)

            if matched_ip:
                if matched_ip not in artifacts_by_ip:
                    artifacts_by_ip[matched_ip] = []
                artifacts_by_ip[matched_ip].append(ArtifactSummaryItem(
                    artifact_id=a.artifact_id,
                    type=a.type,
                    value=a.value,
                    source_event_id=a.source_event_id,
                    flow_id=a.flow_id,
                    acquisition_id=a.acquisition_id
                ))

        # Map endpoints
        endpoints_data: Dict[str, Dict[str, Any]] = {}

        for flow in flows:
            src_str = str(flow.src_ip)
            dst_str = str(flow.dst_ip)

            for ip_str, is_src in [(src_str, True), (dst_str, False)]:
                if search_ip and search_ip.lower() not in ip_str.lower():
                    continue

                if ip_str not in endpoints_data:
                    ip_ver = 6 if ":" in ip_str else 4
                    endpoints_data[ip_str] = {
                        "ip": ip_str,
                        "ip_version": ip_ver,
                        "network_scope": self._classify_ip(ip_str),
                        "roles": set(),
                        "unique_sources": set(),
                        "unique_destinations": set(),
                        "protocols": set(),
                        "services": set(),
                        "dest_ports": set(),
                        "src_ports": set(),
                        "connection_states": set(),
                        "bytes_sent": 0,
                        "bytes_received": 0,
                        "packets_sent": 0,
                        "packets_received": 0,
                        "total_duration": 0.0,
                        "first_seen": flow.timestamp,
                        "last_seen": flow.timestamp,
                        "flow_ids": [],
                        "events": [],
                        "resolved_dns_names": set(),
                        "hostnames": set(),
                        "traceability": []
                    }

                ep = endpoints_data[ip_str]
                ep["roles"].add("SOURCE" if is_src else "DESTINATION")
                if is_src:
                    ep["unique_destinations"].add(dst_str)
                    ep["bytes_sent"] += (flow.orig_bytes or 0)
                    ep["bytes_received"] += (flow.resp_bytes or 0)
                    ep["src_ports"].add(flow.src_port)
                    ep["dest_ports"].add(flow.dst_port)
                else:
                    ep["unique_sources"].add(src_str)
                    ep["bytes_received"] += (flow.orig_bytes or 0)
                    ep["bytes_sent"] += (flow.resp_bytes or 0)
                    ep["src_ports"].add(flow.dst_port)
                    ep["dest_ports"].add(flow.src_port)

                if flow.protocol: ep["protocols"].add(flow.protocol.upper())
                if flow.service: ep["services"].add(flow.service.upper())
                if flow.connection_state: ep["connection_states"].add(flow.connection_state)

                if flow.duration:
                    ep["total_duration"] += float(flow.duration)

                if flow.timestamp:
                    if not ep["first_seen"] or flow.timestamp < ep["first_seen"]:
                        ep["first_seen"] = flow.timestamp
                    if not ep["last_seen"] or flow.timestamp > ep["last_seen"]:
                        ep["last_seen"] = flow.timestamp

                ep["flow_ids"].append(flow.flow_id)

                # Traceability item
                has_pkt_ref = bool(flow.pcap_frame_start or flow.pcap_byte_offset)
                ep["traceability"].append(EvidenceTraceabilityItem(
                    flow_id=flow.flow_id,
                    zeek_uid=flow.zeek_uid,
                    acquisition_id=flow.acquisition_id,
                    pcap_frame_start=flow.pcap_frame_start,
                    pcap_frame_end=flow.pcap_frame_end,
                    pcap_byte_offset=flow.pcap_byte_offset,
                    pcap_timestamp_start=flow.pcap_timestamp_start,
                    pcap_timestamp_end=flow.pcap_timestamp_end,
                    has_packet_reference=has_pkt_ref
                ))

                # Process flow events if present
                if flow.flow_id in events_by_flow:
                    for ev in events_by_flow[flow.flow_id]:
                        ep["events"].append(ev)
                        p_data = ev.protocol_data or {}
                        if "query" in p_data: ep["resolved_dns_names"].add(str(p_data["query"]))
                        if "host" in p_data: ep["hostnames"].add(str(p_data["host"]))

        # Build responses
        items: List[NetworkEndpointContextResponse] = []
        internal_cnt = 0
        external_cnt = 0

        for ip_str, ep in endpoints_data.items():
            if protocol and protocol.upper() not in [p.upper() for p in ep["protocols"]]:
                continue
            if service and service.upper() not in [s.upper() for s in ep["services"]]:
                continue
            if port and (port not in ep["dest_ports"] and port not in ep["src_ports"]):
                continue
            if network_scope and ep["network_scope"] != network_scope:
                continue

            if ep["network_scope"] == "PRIVATE/INTERNAL":
                internal_cnt += 1
            else:
                external_cnt += 1

            # Aggregate protocol profiles
            dns_prof = DNSProtocolProfile()
            http_prof = HTTPProtocolProfile()
            tls_prof = TLSProtocolProfile()

            for ev in ep["events"]:
                p_lower = ev.protocol.lower()
                data = ev.protocol_data or {}
                if p_lower == "dns":
                    dns_prof.query_count += 1
                    if "query" in data: dns_prof.unique_queries.append(str(data["query"]))
                elif p_lower in ("http", "https"):
                    http_prof.request_count += 1
                    if "method" in data: http_prof.methods.append(str(data["method"]))
                    if "host" in data: http_prof.hosts.append(str(data["host"]))
                    if "uri" in data: http_prof.uris.append(str(data["uri"]))
                    if "status_code" in data and isinstance(data["status_code"], int): http_prof.status_codes.append(data["status_code"])
                    if "user_agent" in data: http_prof.user_agents.append(str(data["user_agent"]))
                elif p_lower == "tls":
                    tls_prof.session_count += 1
                    if "server_name" in data: tls_prof.server_names.append(str(data["server_name"]))
                    if "version" in data: tls_prof.versions.append(str(data["version"]))
                    if "cipher" in data: tls_prof.ciphers.append(str(data["cipher"]))

            dns_prof.unique_queries = list(set(dns_prof.unique_queries))
            http_prof.methods = list(set(http_prof.methods))
            http_prof.hosts = list(set(http_prof.hosts))
            http_prof.uris = list(set(http_prof.uris))
            http_prof.status_codes = list(set(http_prof.status_codes))
            http_prof.user_agents = list(set(http_prof.user_agents))
            tls_prof.server_names = list(set(tls_prof.server_names))
            tls_prof.versions = list(set(tls_prof.versions))
            tls_prof.ciphers = list(set(tls_prof.ciphers))

            # Match M2 Findings for endpoint
            ep_findings = []
            for f in findings:
                # Match if finding is linked or rationale mentions IP
                if ip_str in f.rationale or (f.feature_attribution and ip_str in str(f.feature_attribution)):
                    ep_findings.append(f)

            if severity and not any(f.severity.upper() == severity.upper() for f in ep_findings):
                continue
            if min_risk is not None and not any(f.risk_score >= min_risk for f in ep_findings):
                continue

            sev_breakdown = SeverityBreakdown()
            max_risk = 0.0
            max_anomaly = 0.0
            conf_sum = 0.0
            act_classes = set()
            m2_items = []

            for f in ep_findings:
                s_lower = f.severity.lower()
                if s_lower == "high" or s_lower == "critical": sev_breakdown.high += 1
                elif s_lower == "medium": sev_breakdown.medium += 1
                elif s_lower == "low": sev_breakdown.low += 1
                else: sev_breakdown.info += 1

                max_risk = max(max_risk, f.risk_score)
                conf_sum += f.confidence
                act_classes.add(f.activity)

                anom = None
                if f.feature_attribution and isinstance(f.feature_attribution, dict):
                    anom = f.feature_attribution.get("anomaly_score")
                    if anom: max_anomaly = max(max_anomaly, float(anom))

                m2_items.append(M2FindingSummaryItem(
                    finding_id=f.finding_id,
                    activity=f.activity,
                    severity=f.severity,
                    risk_score=f.risk_score,
                    confidence=f.confidence,
                    anomaly_score=anom,
                    decision_state=f.decision_state,
                    rationale=f.rationale
                ))

            if min_anomaly is not None and max_anomaly < min_anomaly:
                continue

            avg_conf = (conf_sum / len(ep_findings)) if ep_findings else 0.0
            highest_sev = "CRITICAL" if sev_breakdown.high > 0 and any(f.severity == "CRITICAL" for f in ep_findings) else ("HIGH" if sev_breakdown.high > 0 else ("MEDIUM" if sev_breakdown.medium > 0 else ("LOW" if sev_breakdown.low > 0 else None)))

            m2_summary = M2FindingsSummary(
                finding_count=len(ep_findings),
                highest_severity=highest_sev,
                max_risk_score=max_risk,
                max_anomaly_score=max_anomaly,
                avg_confidence=avg_conf,
                activity_classes=sorted(list(act_classes)),
                severity_breakdown=sev_breakdown,
                items=m2_items
            )

            # Communication & Traffic Profiles
            roles_set = ep["roles"]
            role_str = "BOTH" if len(roles_set) > 1 else (list(roles_set)[0] if roles_set else "UNKNOWN")

            comm_profile = CommunicationProfile(
                total_flows=len(ep["flow_ids"]),
                unique_sources=sorted(list(ep["unique_sources"])),
                unique_destinations=sorted(list(ep["unique_destinations"])),
                protocols=sorted(list(ep["protocols"])),
                services=sorted(list(ep["services"])),
                destination_ports=sorted(list(ep["dest_ports"])),
                source_ports=sorted(list(ep["src_ports"])),
                connection_states=sorted(list(ep["connection_states"])),
                total_active_duration=ep["total_duration"]
            )

            traffic_profile = TrafficProfile(
                bytes_sent=ep["bytes_sent"],
                bytes_received=ep["bytes_received"],
                packets_sent=ep["packets_sent"],
                packets_received=ep["packets_received"],
                total_bytes=ep["bytes_sent"] + ep["bytes_received"],
                total_packets=ep["packets_sent"] + ep["packets_received"],
                avg_flow_duration=(ep["total_duration"] / len(ep["flow_ids"])) if ep["flow_ids"] else 0.0
            )

            active_dur = 0.0
            if ep["first_seen"] and ep["last_seen"]:
                active_dur = (ep["last_seen"] - ep["first_seen"]).total_seconds()

            temporal_summary = TemporalSummary(
                first_seen=ep["first_seen"],
                last_seen=ep["last_seen"],
                active_duration_seconds=active_dur,
                connection_rate_per_min=(len(ep["flow_ids"]) / (max(active_dur, 60.0) / 60.0))
            )

            ep_artifacts = artifacts_by_ip.get(ip_str, [])
            has_pkt_refs = any(t.has_packet_reference for t in ep["traceability"])

            evidence_summary = EvidenceSummary(
                flow_count=len(ep["flow_ids"]),
                protocol_event_count=len(ep["events"]),
                artifact_count=len(ep_artifacts),
                has_packet_references=has_pkt_refs,
                traceability_items=ep["traceability"]
            )

            assoc_dom = list(ep["resolved_dns_names"])[0] if ep["resolved_dns_names"] else (list(ep["hostnames"])[0] if ep["hostnames"] else None)

            items.append(NetworkEndpointContextResponse(
                ip=ip_str,
                ip_version=ep["ip_version"],
                role=role_str,
                network_scope=ep["network_scope"],
                hostname=list(ep["hostnames"])[0] if ep["hostnames"] else None,
                associated_domain=assoc_dom,
                resolved_dns_names=sorted(list(ep["resolved_dns_names"])),
                communication=comm_profile,
                traffic=traffic_profile,
                protocol_activity=ProtocolProfile(dns=dns_prof, http=http_prof, tls=tls_prof),
                artifacts=ep_artifacts,
                m2_findings=m2_summary,
                temporal=temporal_summary,
                evidence=evidence_summary,
                flow_ids=ep["flow_ids"],
                event_ids=[ev.event_id for ev in ep["events"]]
            ))

        # Sorting
        if sort_by == "risk_score":
            items.sort(key=lambda x: x.m2_findings.max_risk_score, reverse=True)
        elif sort_by == "findings":
            items.sort(key=lambda x: x.m2_findings.finding_count, reverse=True)
        elif sort_by == "anomaly_score":
            items.sort(key=lambda x: x.m2_findings.max_anomaly_score, reverse=True)
        elif sort_by == "bytes":
            items.sort(key=lambda x: x.traffic.total_bytes, reverse=True)
        elif sort_by == "flow_count":
            items.sort(key=lambda x: x.communication.total_flows, reverse=True)
        elif sort_by == "first_seen":
            items.sort(key=lambda x: x.temporal.first_seen or datetime.min)
        elif sort_by == "last_seen":
            items.sort(key=lambda x: x.temporal.last_seen or datetime.min, reverse=True)

        total_cnt = len(items)
        skip = (page - 1) * page_size
        paginated_items = items[skip:skip + page_size]

        return NetworkEndpointContextListResponse(
            items=paginated_items,
            total=total_cnt,
            page=page,
            page_size=page_size,
            internal_count=internal_cnt,
            external_count=external_cnt
        )

    async def get_endpoint_context_detail(self, case_id: UUID, ip: str) -> NetworkEndpointContextResponse:
        res = await self.list_endpoint_contexts_by_case(case_id=case_id, search_ip=ip, page_size=100)
        target = next((item for item in res.items if item.ip == ip), None)
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Endpoint '{ip}' not found in case context.")
        return target
