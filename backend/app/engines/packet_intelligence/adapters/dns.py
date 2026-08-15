"""
backend/app/engines/packet_intelligence/adapters/dns.py
-------------------------------------------------------
Adapter for converting Zeek dns.log records into canonical ProtocolEvent objects.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.app.contracts.network_intelligence import DNSData, EventProvenance, ProtocolEvent
from backend.app.engines.packet_intelligence.zeek.reader import RawZeekRecord

from .errors import AdapterError, AdapterErrorCode


class DNSAdapter:
    """Converts RawZeekRecord objects from dns.log into canonical ProtocolEvent objects."""

    def convert(self, record: RawZeekRecord, flow_index: dict[str, str]) -> ProtocolEvent | AdapterError:
        """Convert a raw Zeek dns.log record into a ProtocolEvent.

        Parameters:
            record: The raw Zeek record yielded by ZeekReader.
            flow_index: Dictionary mapping Zeek UIDs to canonical flow IDs.

        Returns:
            A canonical ProtocolEvent object on success.
            An AdapterError on deterministic mapping failure.
        """
        if record.log_type not in ("dns", "dns.log"):
            return self._build_error(
                record,
                AdapterErrorCode.UNSUPPORTED_LOG_TYPE,
                f"DNSAdapter cannot process log_type '{record.log_type}'",
            )

        data = record.record

        # 1. Extract required correlation UID
        zeek_uid = data.get("uid")
        if not zeek_uid:
            return self._build_error(
                record,
                AdapterErrorCode.MISSING_REQUIRED_FIELD,
                "Missing required field: uid",
            )

        # 2. Lookup Flow ID
        flow_id = flow_index.get(zeek_uid)
        if not flow_id:
            return self._build_error(
                record,
                AdapterErrorCode.UNKNOWN_UID,
                f"Zeek UID '{zeek_uid}' not found in flow_index",
            )

        # 3. Extract required timestamp
        ts_val = data.get("ts")
        if not ts_val:
            return self._build_error(
                record,
                AdapterErrorCode.MISSING_REQUIRED_FIELD,
                "Missing required field: ts",
            )

        try:
            timestamp = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
        except (ValueError, TypeError) as exc:
            return self._build_error(
                record,
                AdapterErrorCode.INVALID_TYPE,
                f"Type conversion failed for timestamp: {exc}",
            )

        # 4. Extract DNS specific fields
        query = data.get("query")
        if query == "-":
            query = None

        query_type = data.get("qtype_name") or data.get("qtype")
        if query_type == "-":
            query_type = None
            
        # Zeek might represent answers as a list, a comma-separated string, or "-"
        raw_answers = data.get("answers")
        answers: list[str] = []
        if isinstance(raw_answers, list):
            answers = [str(a) for a in raw_answers if a and a != "-"]
        elif isinstance(raw_answers, str) and raw_answers != "-":
            answers = [a.strip() for a in raw_answers.split(",") if a.strip()]

        response_code = data.get("rcode_name") or data.get("rcode")
        if response_code == "-":
            response_code = None

        # 5. Construct DNSData
        try:
            dns_data = DNSData(
                query=str(query) if query is not None else None,
                query_type=str(query_type) if query_type is not None else None,
                answers=answers,
                response_code=str(response_code) if response_code is not None else None,
            )
        except Exception as exc:
            return self._build_error(
                record,
                AdapterErrorCode.MALFORMED_RECORD,
                f"DNSData contract validation failed: {exc}",
            )

        # 6. Construct Provenance
        provenance = EventProvenance(
            acquisition_id=record.acquisition_id,
            evidence_id=None,  # Not available from Phase 4 pipeline
            zeek_uid=zeek_uid,
            source="zeek",
            source_log=record.source_log,
            processed_at=datetime.now(timezone.utc),
            processor_version="1.0",
        )

        # 7. Construct ProtocolEvent
        event_id = str(uuid.uuid4())

        try:
            event = ProtocolEvent(
                event_id=event_id,
                flow_id=flow_id,
                zeek_uid=zeek_uid,
                acquisition_id=record.acquisition_id,
                evidence_id=None,
                timestamp=timestamp,
                protocol="dns",
                protocol_data=dns_data,
                provenance=provenance,
            )
            return event
        except Exception as exc:
            return self._build_error(
                record,
                AdapterErrorCode.MALFORMED_RECORD,
                f"ProtocolEvent contract validation failed: {exc}",
            )

    def _build_error(
        self, record: RawZeekRecord, code: AdapterErrorCode, message: str
    ) -> AdapterError:
        """Helper to build an AdapterError from a RawZeekRecord."""
        return AdapterError(
            code=code,
            message=message,
            source_log=record.source_log,
            line_number=record.line_number,
            raw_record=record.record,
        )
