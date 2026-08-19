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
        
        # 1. Map M2 Findings (Investigation-Significant)
        for finding in m2_package.findings:
            finding_ts = datetime.now(timezone.utc)
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
                event_id=f"evt-finding-{finding.finding_id}",
                timestamp=finding_ts,
                event_type="finding",
                title=f"Finding: {finding.activity_class.value}",
                description=f"Automated threat model identified {finding.activity_class.value} ({int(finding.classification_confidence * 100)}% confidence). Risk score: {finding.risk_score:.2f}.",
                finding_ids=[finding.finding_id],
                evidence_ids=[],
                source_reference=f"m2-finding:{finding.finding_id}"
            ))

        # 2. Map Payload-Bearing Protocol Events (Deduplicated)
        seen_proto_keys = set()

        for event in m1_package.protocol_events:
            p_data = event.protocol_data.model_dump() if hasattr(event.protocol_data, "model_dump") else (event.protocol_data if isinstance(event.protocol_data, dict) else {})
            
            title = ""
            desc = ""
            ref_entities = []
            dedupe_key = ""
            
            if event.protocol == "dns" and p_data:
                q = p_data.get("query") or getattr(event.protocol_data, "query", None)
                if q:
                    dedupe_key = f"dns:{q}"
                    if dedupe_key not in seen_proto_keys:
                        title = "DNS Query Observed"
                        desc = f"DNS resolution query for {q} — external domain look-up"
                        ref_entities.append(f"domain:{q}")
                        seen_proto_keys.add(dedupe_key)
            elif event.protocol == "http" and p_data:
                method = p_data.get("method") or getattr(event.protocol_data, "method", "")
                uri = p_data.get("uri") or getattr(event.protocol_data, "uri", "")
                if method or uri:
                    dedupe_key = f"http:{method}:{uri}"
                    if dedupe_key not in seen_proto_keys:
                        title = f"HTTP {method} Communication".strip()
                        desc = f"HTTP {method} request to {uri} — application traffic"
                        seen_proto_keys.add(dedupe_key)
            elif event.protocol == "tls" and p_data:
                sni = p_data.get("server_name") or getattr(event.protocol_data, "server_name", None)
                if sni:
                    dedupe_key = f"tls:{sni}"
                    if dedupe_key not in seen_proto_keys:
                        title = "TLS Encrypted Session"
                        desc = f"TLS session established with SNI {sni} — encrypted connection"
                        ref_entities.append(f"domain:{sni}")
                        seen_proto_keys.add(dedupe_key)

            if title and desc:
                events.append(TimelineEvent(
                    event_id=f"evt-proto-{event.event_id}",
                    timestamp=event.timestamp,
                    event_type=event.protocol.lower(),
                    title=title,
                    description=desc,
                    entity_ids=ref_entities,
                    protocol_event_ids=[event.event_id],
                    flow_ids=[event.flow_id] if event.flow_id else [],
                    source_reference=f"m1-event:{event.event_id}"
                ))

        # 3. Map Extracted File Artifacts
        for art in m1_package.artifacts:
            events.append(TimelineEvent(
                event_id=f"evt-artifact-{art.artifact_id}",
                timestamp=art.timestamp if hasattr(art, 'timestamp') and art.timestamp else datetime.now(timezone.utc),
                event_type="artifact",
                title="File Artifact Extracted",
                description=f"File artifact extracted from stream: {art.type.value if hasattr(art.type, 'value') else str(art.type)} ({art.value})",
                entity_ids=[f"artifact:{art.artifact_id}"],
                artifact_ids=[art.artifact_id],
                protocol_event_ids=[art.source_event_id] if art.source_event_id else [],
                flow_ids=[art.flow_id] if art.flow_id else [],
                source_reference=f"m1-artifact:{art.artifact_id}"
            ))

        # 4. Chronological sorting
        priority_map = {
            "finding": 1,
            "artifact": 2,
            "http": 3,
            "dns": 4,
            "tls": 5,
        }
        
        def sort_key(e: TimelineEvent):
            pri = priority_map.get(e.event_type, 10)
            return (e.timestamp.timestamp(), pri, e.source_reference or e.event_id)
            
        events.sort(key=sort_key)
        return events
