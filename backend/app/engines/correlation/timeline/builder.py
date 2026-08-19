from typing import List, Optional, Set
import uuid
from datetime import datetime, timezone

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.timeline import TimelineEvent
from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FindingsPackage

class TimelineReconstructor:
    """M3 Phase: Reconstructs a chronologically and semantically meaningful timeline from M1 and M2 evidence."""
    
    def reconstruct(
        self, 
        ctx: InvestigationContext, 
        m1_package: NetworkIntelligencePackage, 
        m2_package: FindingsPackage
    ) -> List[TimelineEvent]:
        
        events: List[TimelineEvent] = []
        
        # 1. Map M2 Findings
        for finding in m2_package.findings:
            finding_ts = datetime.now(timezone.utc)
            # Try to inherit timestamp from the earliest referenced flow if possible
            if finding.evidence_references:
                ev_flow_ids = set()
                for er in finding.evidence_references:
                    if er.flow_ids:
                        ev_flow_ids.update(er.flow_ids)
                if ev_flow_ids:
                    earliest = None
                    for flow in m1_package.flows:
                        if flow.flow_id in ev_flow_ids:
                            if earliest is None or flow.timestamp < earliest:
                                earliest = flow.timestamp
                    if earliest:
                        finding_ts = earliest

            events.append(TimelineEvent(
                event_id=str(uuid.uuid4()),
                timestamp=finding_ts,
                event_type="finding",
                title=f"Finding: {finding.activity_class.value}",
                description=f"Automated analysis identified {finding.activity_class.value} with {int(finding.classification_confidence * 100)}% confidence.",
                finding_ids=[finding.finding_id],
                evidence_ids=[],
                source_reference=f"m2-finding:{finding.finding_id}"
            ))

        # 2. Map Semantic Protocol Events (DNS, HTTP, TLS, etc.)
        used_flow_ids = set()
        
        for event in m1_package.protocol_events:
            p_data = event.protocol_data.model_dump() if hasattr(event.protocol_data, "model_dump") else (event.protocol_data if isinstance(event.protocol_data, dict) else {})
            
            title = f"{event.protocol.upper()} Event"
            desc = ""
            
            if event.protocol == "dns" and p_data:
                q = p_data.get("query") or getattr(event.protocol_data, "query", None)
                if q:
                    title = "DNS Query"
                    desc = f"DNS query for {q}"
            elif event.protocol == "http" and p_data:
                method = p_data.get("method") or getattr(event.protocol_data, "method", "")
                uri = p_data.get("uri") or getattr(event.protocol_data, "uri", "")
                if method or uri:
                    title = f"HTTP {method}".strip()
                    desc = uri
            elif event.protocol == "tls" and p_data:
                sni = p_data.get("server_name") or getattr(event.protocol_data, "server_name", None)
                if sni:
                    title = "TLS Connection"
                    desc = f"SNI: {sni}"

            events.append(TimelineEvent(
                event_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                event_type=event.protocol.lower(),
                title=title,
                description=desc,
                entity_ids=[f"protocol_event:{event.event_id}"],
                protocol_event_ids=[event.event_id],
                flow_ids=[event.flow_id] if event.flow_id else [],
                source_reference=f"m1-event:{event.event_id}"
            ))
            if event.flow_id:
                used_flow_ids.add(event.flow_id)

        # 3. Map File Artifacts
        for art in m1_package.artifacts:
            events.append(TimelineEvent(
                event_id=str(uuid.uuid4()),
                timestamp=art.timestamp if hasattr(art, 'timestamp') and art.timestamp else datetime.now(timezone.utc),
                event_type="artifact",
                title="File Observed",
                description=f"Artifact extracted: {art.type.value if hasattr(art.type, 'value') else str(art.type)} ({art.value})",
                artifact_ids=[art.artifact_id],
                protocol_event_ids=[art.source_event_id] if art.source_event_id else [],
                flow_ids=[art.flow_id] if art.flow_id else [],
                source_reference=f"m1-artifact:{art.artifact_id}"
            ))
            if art.flow_id:
                used_flow_ids.add(art.flow_id)

        # 4. Map Remaining Raw Flows (Only those involved in findings but have no protocol events, or just a sample to avoid UI spam)
        # We will only include flows that are explicitly part of a finding if they aren't already represented by a protocol event.
        finding_flow_ids = set()
        for finding in m2_package.findings:
            if finding.evidence_references:
                for er in finding.evidence_references:
                    if er.flow_ids:
                        finding_flow_ids.update(er.flow_ids)
                        
        for flow in m1_package.flows:
            if flow.flow_id in finding_flow_ids and flow.flow_id not in used_flow_ids:
                events.append(TimelineEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=flow.timestamp,
                    event_type="network",
                    title=f"Network Flow {flow.protocol.upper()}",
                    description=f"{flow.source.ip}:{flow.source.port} -> {flow.destination.ip}:{flow.destination.port}",
                    entity_ids=[f"ip:{flow.source.ip}", f"ip:{flow.destination.ip}"],
                    flow_ids=[flow.flow_id],
                    source_reference=f"m1-flow:{flow.flow_id}"
                ))

        # 5. Deterministic sorting
        # Primary: timestamp ascending
        # Secondary: event_type priority
        # Tertiary: source_reference or event_id for stable tie-breaking
        
        priority_map = {
            "finding": 1,
            "artifact": 2,
            "http": 3,
            "dns": 4,
            "tls": 5,
            "network": 9
        }
        
        def sort_key(e: TimelineEvent):
            pri = priority_map.get(e.event_type, 10)
            return (e.timestamp.timestamp(), pri, e.source_reference or e.event_id)
            
        events.sort(key=sort_key)
        
        return events
