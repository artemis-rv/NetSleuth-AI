from dataclasses import dataclass, field, replace
from typing import List, Optional

from .entity import Entity
from .relationship import Relationship
from .timeline import TimelineEvent
from .finding import FindingReference
from .evidence import EvidenceReference

@dataclass
class InvestigationContext:
    acquisition_id: Optional[str] = None
    case_id: Optional[str] = None
    
    entities: List[Entity] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    timeline_events: List[TimelineEvent] = field(default_factory=list)
    findings: List[FindingReference] = field(default_factory=list)
    evidence_references: List[EvidenceReference] = field(default_factory=list)

    def add_entity(self, entity: Entity):
        """Adds a new entity or updates the temporal bounds of an existing entity."""
        for i, existing in enumerate(self.entities):
            if existing.entity_id == entity.entity_id:
                new_first = existing.first_seen
                if entity.first_seen:
                    new_first = min(new_first, entity.first_seen) if new_first else entity.first_seen
                    
                new_last = existing.last_seen
                if entity.last_seen:
                    new_last = max(new_last, entity.last_seen) if new_last else entity.last_seen
                
                self.entities[i] = replace(existing, first_seen=new_first, last_seen=new_last)
                return
        self.entities.append(entity)
