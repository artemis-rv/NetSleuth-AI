from datetime import datetime, timezone
from typing import Dict, Any

from src.m3_correlation.domain.investigation import InvestigationContext
from src.m3_correlation.domain.entity import Entity
from src.m3_correlation.domain.timeline import TimelineEvent
from src.m3_correlation.domain.evidence import EvidenceReference
from src.shared.contract_validation import ContractValidator

class M1Adapter:
    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def _parse_timestamp(self, ts_str: str) -> datetime:
        try:
            # Handle ISO-8601 with Z indicating UTC
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                raise ValueError("Timestamp must be timezone-aware.")
            return dt.astimezone(timezone.utc)
        except Exception as e:
            raise ValueError(f"Invalid timestamp format: {ts_str}") from e

    def adapt(self, m1_payload: Dict[str, Any]) -> InvestigationContext:
        self.validator.validate("network-intelligence-v1.json", m1_payload)
        
        ctx = InvestigationContext(acquisition_id=m1_payload.get("acquisition_id"))
        
        # Process flows
        for flow in m1_payload.get("flows", []):
            self._map_flow(flow, ctx)
            
        # Process protocol events
        for event in m1_payload.get("protocol_events", []):
            self._map_protocol_event(event, ctx)
            
        # Process artifacts
        for artifact in m1_payload.get("artifacts", []):
            self._map_artifact(artifact, ctx)
            
        return ctx
        
    def _map_flow(self, flow: Dict[str, Any], ctx: InvestigationContext):
        ts = self._parse_timestamp(flow["timestamp"])
        
        src_ip = flow["source"]["ip"]
        dst_ip = flow["destination"]["ip"]
        flow_id = flow["flow_id"]
        
        src_ent = Entity(
            entity_id=f"ip:{src_ip}",
            entity_type="ip",
            value=src_ip,
            first_seen=ts,
            last_seen=ts
        )
        dst_ent = Entity(
            entity_id=f"ip:{dst_ip}",
            entity_type="ip",
            value=dst_ip,
            first_seen=ts,
            last_seen=ts
        )
        flow_ent = Entity(
            entity_id=f"flow:{flow_id}",
            entity_type="flow",
            value=flow_id,
            first_seen=ts,
            last_seen=ts,
            attributes={
                "protocol": flow.get("protocol"),
                "service": flow.get("service"),
                "source_port": flow["source"]["port"],
                "destination_port": flow["destination"]["port"],
                "connection_state": flow.get("connection_state"),
                "zeek_uid": flow.get("zeek_uid"),
                "provenance": flow.get("provenance")
            }
        )
        ctx.add_entity(src_ent)
        ctx.add_entity(dst_ent)
        ctx.add_entity(flow_ent)

        ev_id = f"ev-{flow_id}"
        if not any(e.evidence_id == ev_id for e in ctx.evidence_references):
            ctx.evidence_references.append(EvidenceReference(
                evidence_id=ev_id,
                evidence_type="flow",
                source_id=flow_id
            ))

    def _map_protocol_event(self, event: Dict[str, Any], ctx: InvestigationContext):
        ts = self._parse_timestamp(event["timestamp"])
        event_id = event["event_id"]
        protocol = event.get("protocol")
        protocol_data = event.get("protocol_data") or event.get("data", {})
        
        # 1. Create Protocol Event Entity
        evt_ent = Entity(
            entity_id=f"protocol_event:{event_id}",
            entity_type="protocol_event",
            value=event_id,
            first_seen=ts,
            last_seen=ts,
            attributes={
                "protocol": protocol,
                "data": protocol_data,
                "provenance": event.get("provenance"),
                "zeek_uid": event.get("zeek_uid"),
                "flow_id": event.get("flow_id")
            }
        )
        ctx.add_entity(evt_ent)
        
        evidence_type = "log"
        if protocol == "dns":
            evidence_type = "dns"
            data = protocol_data
            query = data.get("query")
            if query:
                domain_ent = Entity(
                    entity_id=f"domain:{query}",
                    entity_type="domain",
                    value=query,
                    first_seen=ts,
                    last_seen=ts
                )
                ctx.add_entity(domain_ent)
            
            for ans in data.get("answers", []):
                ans_ent = Entity(
                    entity_id=f"ip:{ans}",
                    entity_type="ip",
                    value=ans,
                    first_seen=ts,
                    last_seen=ts
                )
                ctx.add_entity(ans_ent)
        elif protocol in ["http", "tls"]:
            evidence_type = protocol
        
        # 2. TimelineEvent
        evidence_ref_id = f"ev-{event_id}"
        related_entities = [evt_ent.entity_id]
        if event.get("flow_id"):
            related_entities.append(f"flow:{event['flow_id']}")
            
        tl_event = TimelineEvent(
            event_id=event_id,
            timestamp=ts,
            event_type=protocol or "unknown",
            description=f"Protocol event for {protocol}",
            entity_ids=related_entities,
            evidence_ids=[evidence_ref_id],
            source_reference=event_id
        )
        ctx.timeline_events.append(tl_event)
        
        # 3. EvidenceReference
        if not any(e.evidence_id == evidence_ref_id for e in ctx.evidence_references):
            ev_ref = EvidenceReference(
                evidence_id=evidence_ref_id,
                evidence_type=evidence_type,
                source_id=event_id
            )
            ctx.evidence_references.append(ev_ref)

    def _map_artifact(self, artifact: Dict[str, Any], ctx: InvestigationContext):
        art_id = artifact["artifact_id"]
        art_type = artifact["type"].lower()
        val = artifact["value"]
        
        ent = Entity(
            entity_id=f"{art_type}:{val}",
            entity_type=art_type,
            value=val,
            attributes={
                "artifact_id": art_id,
                "source_event_id": artifact.get("source_event_id"),
                "flow_id": artifact.get("flow_id"),
                "provenance": artifact.get("provenance")
            }
        )
        ctx.add_entity(ent)

        art_ev_id = f"ev-{art_id}"
        if not any(e.evidence_id == art_ev_id for e in ctx.evidence_references):
            ctx.evidence_references.append(EvidenceReference(
                evidence_id=art_ev_id,
                evidence_type="artifact",
                source_id=art_id
            ))
