"""
backend/app/engines/packet_intelligence/adapters/http.py
--------------------------------------------------------
Adapter for converting Zeek http.log records into canonical ProtocolEvent objects.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from backend.app.contracts.network_intelligence import EventProvenance, HTTPData, ProtocolEvent
from backend.app.engines.packet_intelligence.zeek.reader import RawZeekRecord

from .errors import AdapterError, AdapterErrorCode


class HTTPAdapter:
    """Converts RawZeekRecord objects from http.log into canonical ProtocolEvent objects."""

    def convert(self, record: RawZeekRecord, flow_index: dict[str, str]) -> ProtocolEvent | AdapterError:
        """Convert a raw Zeek http.log record into a ProtocolEvent.

        Parameters:
            record: The raw Zeek record yielded by ZeekReader.
            flow_index: Dictionary mapping Zeek UIDs to canonical flow IDs.

        Returns:
            A canonical ProtocolEvent object on success.
            An AdapterError on deterministic mapping failure.
        """
        if record.log_type not in ("http", "http.log"):
            return self._build_error(
                record,
                AdapterErrorCode.UNSUPPORTED_LOG_TYPE,
                f"HTTPAdapter cannot process log_type '{record.log_type}'",
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

        # 4. Extract HTTP specific fields safely
        try:
            status_code = self._parse_int(data.get("status_code"))
            req_size = self._parse_int(data.get("request_body_len"))
            resp_size = self._parse_int(data.get("response_body_len"))
        except (ValueError, TypeError) as exc:
            return self._build_error(
                record,
                AdapterErrorCode.INVALID_TYPE,
                f"Type conversion failed for numeric fields: {exc}",
            )

        # 5. Construct HTTPData
        try:
            http_data = HTTPData(
                method=self._parse_string(data.get("method")),
                host=self._parse_string(data.get("host")),
                uri=self._parse_string(data.get("uri")),
                status_code=status_code,
                user_agent=self._parse_string(data.get("user_agent")),
                request_body_len=req_size,
                response_body_len=resp_size,
            )
        except Exception as exc:
            return self._build_error(
                record,
                AdapterErrorCode.MALFORMED_RECORD,
                f"HTTPData contract validation failed: {exc}",
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
                protocol="http",
                protocol_data=http_data,
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

    def _parse_int(self, val: Any) -> int | None:
        """Parse an optional integer, mapping absent markers ('-') to None."""
        if val is None or val == "-":
            return None
        return int(val)

    def _parse_string(self, val: Any) -> str | None:
        """Parse an optional string, mapping absent markers ('-') to None."""
        if val is None or val == "-":
            return None
        return str(val)
