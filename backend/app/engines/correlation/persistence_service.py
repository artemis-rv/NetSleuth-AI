import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert

from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models.investigation_models import (
    InvestigationCaseModel, EntityModel, RelationshipModel, TimelineEventModel,
    case_finding_links, case_acquisition_links, mitre_finding_links, relationship_finding_links
)
from app.persistence.models.analytics_models import FindingModel

class M3PersistenceService:
    """
    Persists the M3 InvestigationCase V1.1 JSON payload into the DB-8 PostgreSQL schema.
    Uses UUID5 for deterministic mapping of M3's string-based IDs to PostgreSQL UUIDs,
    ensuring traceability and referential integrity with M2 findings and M1 acquisitions.
    """
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
        
    def _parse_time(self, t_str: str) -> Optional[datetime]:
        if not t_str:
            return None
        # Handle 'Z' suffix to standard offset
        if t_str.endswith("Z"):
            t_str = t_str[:-1] + "+00:00"
        return datetime.fromisoformat(t_str)

    async def persist_investigation_case(self, case_doc: Dict[str, Any], acquisition_id: Optional[uuid.UUID] = None) -> uuid.UUID:
        """
        Persists an InvestigationCase dict within a transactional UnitOfWork.
        """
        if case_doc.get("schema_version") not in ("investigation-case-v1.1", "investigation-case-v1.2", "investigation-case-v1.3"):
            raise ValueError(f"Unsupported case schema version: {case_doc.get('schema_version')}")
            
        case_id_str = case_doc["case_id"]
        # Deterministic UUID for the Case itself
        case_uuid = uuid.uuid5(uuid.NAMESPACE_OID, case_id_str)
        
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        # 1. Persist the Investigation Case
        stmt = pg_insert(InvestigationCaseModel).values(
            case_id=case_uuid,
            title=case_doc.get("title", f"Investigation {case_id_str}"),
            description=case_doc.get("description"),
            status=case_doc.get("status", "open"),
            priority=case_doc.get("severity"),
            trigger_type="correlation_engine",
            opened_at=self._parse_time(case_doc.get("created_at")),
            updated_at=self._parse_time(case_doc.get("updated_at"))
        ).on_conflict_do_nothing()
        await self.uow.session.execute(stmt)
        await self.uow.session.flush()
        
        # 2. Persist Entities
        entity_uuid_map = {}
        entities = case_doc.get("entities", [])
        if entities:
            entity_records = []
            for e in entities:
                e_id_str = e["entity_id"]
                e_uuid = uuid.uuid5(uuid.NAMESPACE_OID, e_id_str)
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
            await self.uow.session.execute(pg_insert(EntityModel).values(entity_records).on_conflict_do_nothing())
            
        # 3. Persist Relationships
        relationships = case_doc.get("relationships", [])
        rel_uuid_map = {}
        if relationships:
            rel_records = []
            for r in relationships:
                r_id_str = r["relationship_id"]
                r_uuid = uuid.uuid5(uuid.NAMESPACE_OID, r_id_str)
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
                await self.uow.session.execute(pg_insert(RelationshipModel).values(rel_records).on_conflict_do_nothing())
                
        # 4. Persist Timeline Events
        timeline = case_doc.get("timeline", [])
        if timeline:
            timeline_records = []
            for t in timeline:
                t_id_str = t["event_id"]
                t_uuid = uuid.uuid5(uuid.NAMESPACE_OID, t_id_str)
                
                t_entity_uuid = None
                if "source_entity_id" in t:
                    t_entity_uuid = entity_uuid_map.get(t["source_entity_id"])
                    
                timeline_records.append({
                    "timeline_event_id": t_uuid,
                    "case_id": case_uuid,
                    "event_timestamp": self._parse_time(t.get("timestamp")),
                    "event_type": t.get("event_type", "network"),
                    "description": t.get("description"),
                    "entity_id": t_entity_uuid,
                    "attributes": {"evidence_ids": t.get("evidence_ids")} if t.get("evidence_ids") else None
                })
            await self.uow.session.execute(pg_insert(TimelineEventModel).values(timeline_records).on_conflict_do_nothing())
            
        # 5. Persist Case-to-Finding and Case-to-Acquisition Links
        findings = case_doc.get("findings", [])
        if findings:
            cf_links = []
            for f in findings:
                f_uuid = uuid.uuid5(uuid.NAMESPACE_OID, f["finding_id"])
                cf_links.append({
                    "case_id": case_uuid,
                    "finding_id": f_uuid,
                    "role": f.get("role", "primary")
                })
            await self.uow.session.execute(pg_insert(case_finding_links).values(cf_links).on_conflict_do_nothing())
            
        if acquisition_id:
            await self.uow.session.execute(pg_insert(case_acquisition_links).values({
                "case_id": case_uuid,
                "acquisition_id": acquisition_id
            }).on_conflict_do_nothing())
            
        # 6. M3 evidence_references parsing. 
        evidences = case_doc.get("evidence_references", [])
        
        rel_finding_links = []
        ent_artifact_links = []
        beh_finding_links = []
        
        for ev in evidences:
            ev_id_str = ev["evidence_id"]
            src_id_str = ev.get("source_id")
            if not src_id_str:
                continue
                
            ev_type = ev.get("evidence_type")
            
            ev_uuid = uuid.uuid5(uuid.NAMESPACE_OID, ev_id_str)
            src_uuid = uuid.uuid5(uuid.NAMESPACE_OID, src_id_str)
            
            if ev_type == "finding":
                if src_id_str.startswith("REL-") or src_id_str in rel_uuid_map:
                    rel_finding_links.append({
                        "relationship_id": src_uuid,
                        "finding_id": ev_uuid
                    })
                elif src_id_str.startswith("BEH-"):
                    beh_finding_links.append({
                        "behavior_id": src_uuid,
                        "finding_id": ev_uuid
                    })
                    
            elif ev_type == "artifact":
                if src_id_str in entity_uuid_map or src_id_str.startswith("ip:") or src_id_str.startswith("domain:"):
                    ent_artifact_links.append({
                        "entity_id": src_uuid,
                        "artifact_id": ev_uuid
                    })

        if rel_finding_links:
            await self.uow.session.execute(pg_insert(relationship_finding_links).values(rel_finding_links).on_conflict_do_nothing())
        if ent_artifact_links:
            from app.persistence.models.investigation_models import entity_artifact_links
            await self.uow.session.execute(pg_insert(entity_artifact_links).values(ent_artifact_links).on_conflict_do_nothing())
        if beh_finding_links:
            from app.persistence.models.investigation_models import behavior_finding_links
            await self.uow.session.execute(pg_insert(behavior_finding_links).values(beh_finding_links).on_conflict_do_nothing())

        return case_uuid
