from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass(frozen=True)
class Entity:
    entity_id: str
    entity_type: str
    value: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.entity_id:
            raise ValueError("Entity ID cannot be empty.")
        if ":" not in self.entity_id:
            raise ValueError(f"Entity ID must follow namespace:value convention, got '{self.entity_id}'")
        ns, val = self.entity_id.split(":", 1)
        if not ns or not val:
            raise ValueError(f"Entity ID must have non-empty namespace and value, got '{self.entity_id}'")
