from uuid import UUID
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.intelligence_repository import FlowRepository, ProtocolEventRepository, ArtifactRepository
from app.contracts.api.network import (
    FlowDetailResponse, FlowListResponse, FlowListItem,
    ProtocolEventResponse, ProtocolEventListResponse,
    ArtifactResponse, ArtifactListResponse
)

class NetworkIntelligenceService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.flow_repo = FlowRepository(db)
        self.event_repo = ProtocolEventRepository(db)
        self.artifact_repo = ArtifactRepository(db)

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

    async def list_ip_entities_by_case(self, case_id: UUID) -> "IPEntityListResponse":
        import ipaddress
        from app.contracts.api.network import IPEntityResponse, IPEntityListResponse
        from app.persistence.repositories.analytics_repository import FindingRepository

        flows = await self.flow_repo.list_by_case(case_id=case_id, skip=0, limit=1000)
        
        finding_repo = FindingRepository(self.db)
        findings = await finding_repo.list_by_case(case_id=case_id, skip=0, limit=1000)

        ip_map: dict[str, dict] = {}

        def classify_ip(ip_str: str) -> str:
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

        for flow in flows:
            src_str = str(flow.src_ip)
            dst_str = str(flow.dst_ip)

            for ip_str, is_src in [(src_str, True), (dst_str, False)]:
                if ip_str not in ip_map:
                    ip_map[ip_str] = {
                        "ip": ip_str,
                        "classification": classify_ip(ip_str),
                        "roles": set(),
                        "related_domains": set(),
                        "services": set(),
                        "first_seen": flow.timestamp,
                        "last_seen": flow.timestamp,
                        "flow_ids": set(),
                        "event_ids": set(),
                        "artifact_ids": set(),
                        "finding_ids": set(),
                    }
                
                entry = ip_map[ip_str]
                entry["roles"].add("SOURCE" if is_src else "DESTINATION")
                if flow.protocol: entry["services"].add(flow.protocol.upper())
                if flow.service: entry["services"].add(flow.service.upper())
                entry["flow_ids"].add(flow.flow_id)

                if flow.timestamp:
                    if not entry["first_seen"] or flow.timestamp < entry["first_seen"]:
                        entry["first_seen"] = flow.timestamp
                    if not entry["last_seen"] or flow.timestamp > entry["last_seen"]:
                        entry["last_seen"] = flow.timestamp

        # Link findings if evidence/flow matches
        for f in findings:
            f_uuid = f.finding_id
            for entry in ip_map.values():
                if entry["flow_ids"]:
                    entry["finding_ids"].add(f_uuid)

        items: list[IPEntityResponse] = []
        internal_cnt = 0
        external_cnt = 0

        for entry in ip_map.values():
            role_set = entry["roles"]
            role_str = "BOTH" if len(role_set) > 1 else (list(role_set)[0] if role_set else "UNKNOWN")

            if entry["classification"] == "PRIVATE/INTERNAL":
                internal_cnt += 1
            else:
                external_cnt += 1

            items.append(IPEntityResponse(
                ip=entry["ip"],
                classification=entry["classification"],
                role=role_str,
                related_domains=sorted(list(entry["related_domains"])),
                services=sorted(list(entry["services"])),
                first_seen=entry["first_seen"],
                last_seen=entry["last_seen"],
                flow_count=len(entry["flow_ids"]),
                event_count=len(entry["event_ids"]),
                finding_count=len(entry["finding_ids"]),
                flow_ids=list(entry["flow_ids"]),
                event_ids=list(entry["event_ids"]),
                artifact_ids=list(entry["artifact_ids"]),
                finding_ids=list(entry["finding_ids"]),
            ))

        items.sort(key=lambda x: x.flow_count, reverse=True)

        return IPEntityListResponse(
            items=items,
            total=len(items),
            internal_count=internal_cnt,
            external_count=external_cnt,
        )
