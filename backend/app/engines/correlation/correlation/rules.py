from typing import List
import ipaddress
from dataclasses import replace

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.relationship import Relationship

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
    ip_entities = [e for e in ctx.entities if e.entity_type == "ip"]
    domain_entities = [e for e in ctx.entities if e.entity_type == "domain"]
    artifact_entities = [e for e in ctx.entities if e.entity_type == "artifact"]
    finding_entities = [e for e in ctx.entities if e.entity_type == "finding"]

    # 1. IP -> communicates_with -> IP (for pairs of distinct IPs)
    if len(ip_entities) >= 2:
        src_ip = ip_entities[0].entity_id
        for dst in ip_entities[1:]:
            add_rel(src_ip, dst.entity_id, "communicates_with", "Observed bilateral IP traffic.")

    # 2. IP -> queries_domain -> Domain
    for ip in ip_entities:
        for dom in domain_entities:
            add_rel(ip.entity_id, dom.entity_id, "queries_domain", "IP resolved or queried domain.")

    # 3. IP -> downloads_artifact -> Artifact
    for ip in ip_entities:
        for art in artifact_entities:
            add_rel(ip.entity_id, art.entity_id, "downloads_artifact", "IP transferred artifact file.")

    # 4. Finding -> associated_with -> IP / Domain
    for f in finding_entities:
        for ip in ip_entities:
            add_rel(f.entity_id, ip.entity_id, "associated_with", "Finding involves IP asset.")
        for dom in domain_entities:
            add_rel(f.entity_id, dom.entity_id, "associated_with", "Finding involves domain asset.")

    final_rels = []
    for r in ctx.relationships:
        if r.source_entity_id in entities_by_id and r.target_entity_id in entities_by_id:
            final_rels.append(r)

    final_rels.extend(new_rels)
    ctx.relationships = final_rels

    # Sort timeline deterministically
    ctx.timeline_events.sort(key=lambda x: x.timestamp)
