from typing import List
import ipaddress
from dataclasses import replace

from backend.app.engines.correlation.domain.investigation import InvestigationContext
from backend.app.engines.correlation.domain.relationship import Relationship

def apply_rules(ctx: InvestigationContext) -> None:
    new_rels = []

    def relation_exists(src: str, tgt: str, rel_type: str) -> bool:
        for r in ctx.relationships:
            if r.source_entity_id == src and r.target_entity_id == tgt and r.relationship_type == rel_type:
                return True
        for r in new_rels:
            if r.source_entity_id == src and r.target_entity_id == tgt and r.relationship_type == rel_type:
                return True
        return False

    def add_rel(src: str, tgt: str, rel_type: str, reason: str, ev_ids: List[str] = None):
        if not relation_exists(src, tgt, rel_type):
            rel = Relationship(
                relationship_id=f"rel-{src}-{rel_type}-{tgt}",
                source_entity_id=src,
                relationship_type=rel_type,
                target_entity_id=tgt,
                confidence=1.0,
                evidence_ids=ev_ids or [],
                reason=reason
            )
            new_rels.append(rel)

    entities_by_id = {e.entity_id: e for e in ctx.entities}
    
    for ent in ctx.entities:
        # Rule 1, 2, 3: Protocol Events
        if ent.entity_type == "protocol_event":
            flow_id = ent.attributes.get("flow_id")
            if flow_id:
                flow_ent_id = f"flow:{flow_id}"
                if flow_ent_id in entities_by_id:
                    add_rel(
                        ent.entity_id, 
                        flow_ent_id, 
                        "observed_in", 
                        "Protocol event explicitly references flow."
                    )
            
            protocol = ent.attributes.get("protocol")
            if protocol == "dns":
                data = ent.attributes.get("data", {})
                
                # Rule 3: DNS Query
                query = data.get("query")
                if query:
                    domain_id = f"domain:{query}"
                    if domain_id in entities_by_id:
                        add_rel(
                            ent.entity_id,
                            domain_id,
                            "queried",
                            "DNS query exactly matches observed domain."
                        )
                
                # Rule 2: DNS Answer
                answers = data.get("answers", [])
                for ans in answers:
                    try:
                        # Proper IP parsing checks if it is truly an IP
                        ipaddress.ip_address(ans)
                        ip_id = f"ip:{ans}"
                        if ip_id in entities_by_id:
                            add_rel(
                                ent.entity_id,
                                ip_id,
                                "resolved_to",
                                "DNS answer explicitly matches observed IP."
                            )
                    except ValueError:
                        # Not an IP address
                        pass

        # Rule 4 & 5: Artifacts
        elif ent.entity_type in ["domain", "ip", "url", "hash", "artifact"]: 
            src_evt_id = ent.attributes.get("source_event_id")
            if src_evt_id:
                evt_id = f"protocol_event:{src_evt_id}"
                if evt_id in entities_by_id:
                    add_rel(
                        ent.entity_id,
                        evt_id,
                        "derived_from",
                        "Artifact explicitly references source protocol event."
                    )
            
            flow_id = ent.attributes.get("flow_id")
            if flow_id:
                f_id = f"flow:{flow_id}"
                if f_id in entities_by_id:
                    add_rel(
                        ent.entity_id,
                        f_id,
                        "associated_with",
                        "Artifact explicitly references flow."
                    )

    # Rule 6: Finding <-> Explicit Evidence
    # Note: 'finding:...' is currently a temporary graph anchor Entity. 
    # The actual finding data belongs in FindingReference.
    final_rels = []
    for r in ctx.relationships:
        if r.relationship_type == "explicit_reference" and r.source_entity_id.startswith("finding:"):
            new_r = replace(
                r, 
                relationship_type="supported_by", 
                reason="M2 Finding explicitly references an evidence object",
            )
            final_rels.append(new_r)
        else:
            final_rels.append(r)
            
    final_rels.extend(new_rels)
    ctx.relationships = final_rels

    # Rule 7: Temporal Order
    ctx.timeline_events.sort(key=lambda x: x.timestamp)
