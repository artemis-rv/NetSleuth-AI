import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert, update

from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models.investigation_models import (
    InvestigationCaseModel, EntityModel, RelationshipModel, TimelineEventModel,
    AttackChainModel, MitreMappingModel, BehaviorModel,
    case_finding_links, case_acquisition_links, mitre_finding_links, relationship_finding_links
)
from app.persistence.models.analytics_models import FindingModel

class M3PersistenceService:
    """
    Persists the M3 InvestigationCase V1.x JSON payload into the PostgreSQL schema.

    IMPORTANT — case_id contract:
    The case_id in the M3 case_doc MUST be the real PostgreSQL UUID string of the
    investigation_cases row created by the user. This service will use it directly
    (uuid.UUID(case_id_str)) so that timeline events, entities, etc. are linked to
    the correct existing case row.

    It does NOT hash case_id through uuid5 — that was the root cause of the empty
    timeline bug where events were stored under a ghost UUID.
    """
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
        
    def _parse_time(self, t_str: str) -> Optional[datetime]:
        if not t_str:
            return None
        if t_str.endswith("Z"):
            t_str = t_str[:-1] + "+00:00"
        return datetime.fromisoformat(t_str)

    def _to_uuid(self, id_str: str) -> uuid.UUID:
        """
        Convert an ID string to a UUID.
        If the string is already a valid UUID, use it directly.
        Otherwise derive a deterministic UUID5 from it (for M3-internal IDs like entity IDs).
        """
        try:
            return uuid.UUID(id_str)
        except (ValueError, AttributeError):
            return uuid.uuid5(uuid.NAMESPACE_OID, str(id_str))

    async def persist_investigation_case(self, case_doc: Dict[str, Any], acquisition_id: Optional[uuid.UUID] = None) -> uuid.UUID:
        """
        Persists an InvestigationCase dict within a transactional UnitOfWork.
        The case_doc['case_id'] MUST be the real UUID of the existing investigation_cases row.
        """
        if case_doc.get("schema_version") not in ("investigation-case-v1.1", "investigation-case-v1.2", "investigation-case-v1.3"):
            raise ValueError(f"Unsupported case schema version: {case_doc.get('schema_version')}")
            
        case_id_str = case_doc["case_id"]

        # Use the real UUID directly — DO NOT hash through uuid5.
        # The investigation_cases row was already created by the user via POST /cases.
        case_uuid = self._to_uuid(case_id_str)
        
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        # 1. Upsert the Investigation Case (update M3-enriched fields on existing row)
        stmt = pg_insert(InvestigationCaseModel).values(
            case_id=case_uuid,
            title=case_doc.get("title", f"Investigation {case_id_str}"),
            description=case_doc.get("description"),
            status=case_doc.get("status", "open"),
            priority=case_doc.get("severity"),
            trigger_type="correlation_engine",
            opened_at=self._parse_time(case_doc.get("created_at")),
            updated_at=self._parse_time(case_doc.get("updated_at"))
        ).on_conflict_do_update(
            index_elements=["case_id"],
            set_={
                "status": case_doc.get("status", "open"),
                "priority": case_doc.get("severity"),
                "updated_at": self._parse_time(case_doc.get("updated_at")),
                "description": case_doc.get("description"),
            }
        )
        await self.uow.session.execute(stmt)
        await self.uow.session.flush()
        
        # 2. Persist Entities
        entity_uuid_map = {}
        entities = case_doc.get("entities", [])
        if entities:
            entity_records = []
            for e in entities:
                e_id_str = e["entity_id"]
                # Entity IDs from M3 are internal strings like "ip:1.2.3.4" — derive UUID
                e_uuid = self._to_uuid(e_id_str)
                entity_uuid_map[e_id_str] = e_uuid
                
                e_val = e.get("value")
                label = e_val if e_val else e_id_str.split(":")[-1]
                
                raw_type = e.get("entity_type", "network")
                type_map = {
                    "ip": "external_ip",
                    "url": "service",
                    "session": "network",
                    "flow": "network",
                    "protocol_event": "network",
                    "ioc": "domain",
                    "artifact": "service",
                    "finding": "service"
                }
                db_type = type_map.get(raw_type, raw_type)
                
                entity_records.append({
                    "entity_id": e_uuid,
                    "case_id": case_uuid,
                    "entity_type": db_type,
                    "label": label,
                    "value": e_val,
                    "attributes": e.get("attributes"),
                    "first_seen": self._parse_time(e.get("first_seen")),
                    "last_seen": self._parse_time(e.get("last_seen"))
                })
            await self.uow.session.execute(
                pg_insert(EntityModel).values(entity_records).on_conflict_do_nothing()
            )
            
        # 3. Persist Relationships
        relationships = case_doc.get("relationships", [])
        rel_uuid_map = {}
        if relationships:
            rel_records = []
            for r in relationships:
                r_id_str = r["relationship_id"]
                r_uuid = self._to_uuid(r_id_str)
                rel_uuid_map[r_id_str] = r_uuid
                
                src_uuid = entity_uuid_map.get(r["source_entity_id"])
                tgt_uuid = entity_uuid_map.get(r["target_entity_id"])
                
                if src_uuid and tgt_uuid:
                    rel_records.append({
                        "relationship_id": r_uuid,
                        "case_id": case_uuid,
                        "source_entity_id": src_uuid,
                        "target_entity_id": tgt_uuid,
                        "relationship_type": r.get("relationship_type", "linked"),
                        "strength": r.get("confidence", 0.5),
                        "attributes": {"reason": r.get("reason")} if r.get("reason") else None,
                        "first_seen": self._parse_time(r.get("first_seen")),
                        "last_seen": self._parse_time(r.get("last_seen"))
                    })
            if rel_records:
                await self.uow.session.execute(
                    pg_insert(RelationshipModel).values(rel_records).on_conflict_do_nothing()
                )
                
        # 4. Persist Timeline Events
        timeline = case_doc.get("timeline", [])
        if timeline:
            timeline_records = []
            for t in timeline:
                t_id_str = t["event_id"]
                t_uuid = self._to_uuid(t_id_str)
                
                t_entity_uuid = None
                if "source_entity_id" in t:
                    t_entity_uuid = entity_uuid_map.get(t["source_entity_id"])
                    
                attributes = {}
                if t.get("evidence_ids"): attributes["evidence_ids"] = t.get("evidence_ids")
                if t.get("flow_ids"): attributes["flow_ids"] = t.get("flow_ids")
                if t.get("protocol_event_ids"): attributes["protocol_event_ids"] = t.get("protocol_event_ids")
                if t.get("artifact_ids"): attributes["artifact_ids"] = t.get("artifact_ids")
                if t.get("title"): attributes["title"] = t.get("title")

                timeline_records.append({
                    "timeline_event_id": t_uuid,
                    "case_id": case_uuid,
                    "event_timestamp": self._parse_time(t.get("timestamp")),
                    "event_type": t.get("event_type", "network"),
                    "description": t.get("description"),
                    "entity_id": t_entity_uuid,
                    "attributes": attributes if attributes else None
                })
            await self.uow.session.execute(
                pg_insert(TimelineEventModel).values(timeline_records).on_conflict_do_nothing()
            )
            
        # 5. Persist Case-to-Finding and Case-to-Acquisition Links
        findings = case_doc.get("findings", [])
        if findings:
            cf_links = []
            for f in findings:
                # Finding IDs from M3 may be internal strings — derive UUID
                f_uuid = self._to_uuid(f["finding_id"])
                cf_links.append({
                    "case_id": case_uuid,
                    "finding_id": f_uuid,
                    "role": f.get("role", "primary")
                })
            await self.uow.session.execute(
                pg_insert(case_finding_links).values(cf_links).on_conflict_do_nothing()
            )
            
        if acquisition_id:
            await self.uow.session.execute(
                pg_insert(case_acquisition_links).values({
                    "case_id": case_uuid,
                    "acquisition_id": acquisition_id
                }).on_conflict_do_nothing()
            )

        # 6. Persist Attack Chain (P2 — previously missing)
        attack_chain = case_doc.get("attack_chain")
        if attack_chain:
            ac_uuid = uuid.uuid4()
            ac_status = attack_chain.get("status", "unknown")
            ac_stages = attack_chain.get("stages", [])
            ac_title = f"Attack Chain — {ac_status}"
            await self.uow.session.execute(
                pg_insert(AttackChainModel).values({
                    "attack_chain_id": ac_uuid,
                    "case_id": case_uuid,
                    "title": ac_title,
                    "summary": f"Correlation engine produced {len(ac_stages)} stage(s). Status: {ac_status}.",
                    "stages": {"status": ac_status, "stages": ac_stages},
                }).on_conflict_do_update(
                    index_elements=["case_id"],
                    set_={
                        "stages": {"status": ac_status, "stages": ac_stages},
                        "title": ac_title,
                        "updated_at": datetime.utcnow(),
                    }
                )
            )

        # 7. Persist MITRE Mappings (P2 — previously missing)
        mitre_mappings = case_doc.get("mitre_mappings", [])
        if mitre_mappings:
            mitre_records = []
            mitre_finding_link_records = []
            for m in mitre_mappings:
                m_id_str = m.get("mapping_id") or m.get("technique_id", "")
                m_uuid = self._to_uuid(f"{case_id_str}:{m_id_str}") if m_id_str else uuid.uuid4()
                
                mitre_records.append({
                    "mitre_mapping_id": m_uuid,
                    "case_id": case_uuid,
                    "technique_id": m.get("technique_id", ""),
                    "tactic": m.get("tactic", m.get("tactic_name", "")),
                    "technique_name": m.get("technique_name"),
                    "attack_version": m.get("attack_version", "19.2"),
                    "justification": m.get("justification"),
                    "confidence": m.get("confidence"),
                })
                # Link to findings referenced by this mapping
                for f_id in m.get("finding_ids", []):
                    f_uuid = self._to_uuid(f_id)
                    mitre_finding_link_records.append({
                        "mitre_mapping_id": m_uuid,
                        "finding_id": f_uuid,
                    })
            if mitre_records:
                await self.uow.session.execute(
                    pg_insert(MitreMappingModel).values(mitre_records).on_conflict_do_nothing()
                )
            if mitre_finding_link_records:
                await self.uow.session.execute(
                    pg_insert(mitre_finding_links).values(mitre_finding_link_records).on_conflict_do_nothing()
                )

        # 8. Persist Behaviors from Findings
        findings_list = case_doc.get("findings", [])
        behaviors = []
        for finding in findings_list:
            f_id = finding.get("finding_id")
            if f_id:
                b_uuid = self._to_uuid(f"behavior:{f_id}")
                b_type = finding.get("activity", finding.get("finding_type", "suspicious_activity"))
                b_label = b_type.replace("_", " ").title()
                behaviors.append({
                    "behavior_id": b_uuid,
                    "case_id": case_uuid,
                    "behavior_type": b_type,
                    "label": b_label,
                    "confidence": finding.get("confidence_score", 0.8),
                    "attributes": finding,
                    "first_observed": None,
                    "last_observed": None
                })
        if behaviors:
            await self.uow.session.execute(
                pg_insert(BehaviorModel).values(behaviors).on_conflict_do_nothing()
            )
            
        # 9. M3 evidence_references — relationship and artifact links
        evidences = case_doc.get("evidence_references", [])
        
        rel_finding_links_data = []
        ent_artifact_links_data = []
        beh_finding_links_data = []
        
        for ev in evidences:
            ev_id_str = ev["evidence_id"]
            src_id_str = ev.get("source_id")
            if not src_id_str:
                continue
                
            ev_type = ev.get("evidence_type")
            ev_uuid = self._to_uuid(ev_id_str)
            src_uuid = self._to_uuid(src_id_str)
            
            if ev_type == "finding":
                if src_id_str.startswith("REL-") or src_id_str in rel_uuid_map:
                    rel_finding_links_data.append({
                        "relationship_id": src_uuid,
                        "finding_id": ev_uuid
                    })
                elif src_id_str.startswith("BEH-"):
                    beh_finding_links_data.append({
                        "behavior_id": src_uuid,
                        "finding_id": ev_uuid
                    })
                    
            elif ev_type == "artifact":
                if src_id_str in entity_uuid_map or src_id_str.startswith("ip:") or src_id_str.startswith("domain:"):
                    ent_artifact_links_data.append({
                        "entity_id": src_uuid,
                        "artifact_id": ev_uuid
                    })

        if rel_finding_links_data:
            await self.uow.session.execute(
                pg_insert(relationship_finding_links).values(rel_finding_links_data).on_conflict_do_nothing()
            )
        if ent_artifact_links_data:
            from app.persistence.models.investigation_models import entity_artifact_links
            await self.uow.session.execute(
                pg_insert(entity_artifact_links).values(ent_artifact_links_data).on_conflict_do_nothing()
            )
        if beh_finding_links_data:
            from app.persistence.models.investigation_models import behavior_finding_links
            await self.uow.session.execute(
                pg_insert(behavior_finding_links).values(beh_finding_links_data).on_conflict_do_nothing()
            )

        return case_uuid
