from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from src.shared.contract_validation import ContractValidator

ALLOWED_CUSTODY_ACTIONS = {"ingest", "verify", "export", "transfer", "inspect", "archive"}

def parse_iso_timestamp(ts_str: str) -> datetime:
    """Helper to parse ISO-8601 timestamp and ensure timezone awareness."""
    if not isinstance(ts_str, str) or not ts_str.strip():
        raise ValueError("Timestamp must be a non-empty string.")
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            raise ValueError("Timestamp must be timezone-aware.")
        return dt.astimezone(timezone.utc)
    except Exception as e:
        raise ValueError(f"Invalid date-time timestamp format: '{ts_str}'") from e

@dataclass(frozen=True)
class CustodyEntry:
    """Immutable representation of a single chain of custody event."""
    custodian_id: str
    action: str
    timestamp: str
    signature: Optional[str] = None

    def __post_init__(self):
        if not self.custodian_id or not isinstance(self.custodian_id, str) or not self.custodian_id.strip():
            raise ValueError("Custody entry missing required 'custodian_id'.")
        if not self.action or not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("Custody entry missing required 'action'.")
        if self.action not in ALLOWED_CUSTODY_ACTIONS:
            raise ValueError(f"Custody action '{self.action}' is not one of the allowed contract actions: {sorted(list(ALLOWED_CUSTODY_ACTIONS))}")

        # Validate timestamp format
        parse_iso_timestamp(self.timestamp)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to contract-compliant dictionary representation."""
        return {
            "custodian_id": self.custodian_id,
            "action": self.action,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

class ChainOfCustody:
    """
    M4 Chain of Custody manager.
    Maintains an auditable, ordered, and deterministic log of custody events for evidence.
    Does NOT calculate hashes, alter evidence bytes, or fabricate signatures.
    """

    def __init__(self, evidence_id: Optional[str] = None, validator: Optional[ContractValidator] = None):
        self.evidence_id = evidence_id
        self.validator = validator
        self._entries: List[CustodyEntry] = []

    def record_action(
        self,
        custodian_id: str,
        action: str,
        timestamp: Optional[str] = None,
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Records a new custody action entry in chronological order.

        :param custodian_id: Identifier of the custodian performing the action.
        :param action: Action performed (e.g. 'ingest', 'verify', 'export', 'transfer').
        :param timestamp: Optional ISO-8601 UTC timestamp string. Generated if None.
        :param signature: Optional signature string or None. Never fabricated.
        :return: Dict representation of the recorded custody entry.
        """
        if timestamp is None:
            ts_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        else:
            # Parse to ensure valid timestamp format
            dt = parse_iso_timestamp(timestamp)
            ts_str = dt.isoformat().replace("+00:00", "Z")

        entry = CustodyEntry(
            custodian_id=custodian_id,
            action=action,
            timestamp=ts_str,
            signature=signature
        )

        # Handle duplicate entries deterministically
        if not any(
            e.custodian_id == entry.custodian_id and
            e.action == entry.action and
            e.timestamp == entry.timestamp and
            e.signature == entry.signature
            for e in self._entries
        ):
            self._entries.append(entry)
            # Sort entries chronologically by parsed timestamp
            self._entries.sort(key=lambda e: parse_iso_timestamp(e.timestamp))

        return entry.to_dict()

    def get_entries(self) -> List[Dict[str, Any]]:
        """Returns chronologically ordered list of custody entry dictionaries."""
        return [entry.to_dict() for entry in self._entries]
