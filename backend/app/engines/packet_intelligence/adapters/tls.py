"""
backend/app/engines/packet_intelligence/adapters/tls.py
-------------------------------------------------------
Adapter for converting Zeek ssl.log records into canonical ProtocolEvent objects.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from backend.app.contracts.network_intelligence import EventProvenance, ProtocolEvent, TLSData
from backend.app.engines.packet_intelligence.zeek.reader import RawZeekRecord

from .errors import AdapterError, AdapterErrorCode


class TLSAdapter:
    """Converts RawZeekRecord objects from ssl.log into canonical ProtocolEvent objects."""

    def convert(self, record: RawZeekRecord, flow_index: dict[str, str]) -> ProtocolEvent | AdapterError:
        """Convert a raw Zeek ssl.log record into a ProtocolEvent.

        Parameters:
            record: The raw Zeek record yielded by ZeekReader.
            flow_index: Dictionary mapping Zeek UIDs to canonical flow IDs.

        Returns:
            A canonical ProtocolEvent object on success.
            An AdapterError on deterministic mapping failure.
        """
        if record.log_type not in ("ssl", "ssl.log"):
            return self._build_error(
                record,
                AdapterErrorCode.UNSUPPORTED_LOG_TYPE,
                f"TLSAdapter cannot process log_type '{record.log_type}'",
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

        # 4. Extract TLS specific fields safely
        try:
            tls_data = TLSData(
                version=self._parse_string(data.get("version")),
                server_name=self._parse_string(data.get("server_name")),
                cipher=self._parse_string(data.get("cipher")),
                subject=self._parse_string(data.get("subject")),
                issuer=self._parse_string(data.get("issuer")),
                # not_valid_before and not_valid_after are generally in x509.log,
                # but we will extract them if they happen to be present.
                not_valid_before=self._parse_datetime(data.get("not_valid_before")),
                not_valid_after=self._parse_datetime(data.get("not_valid_after")),
            )
        except Exception as exc:
            return self._build_error(
                record,
                AdapterErrorCode.MALFORMED_RECORD,
                f"TLSData contract validation failed: {exc}",
            )

        # 5. Construct Provenance
        provenance = EventProvenance(
            acquisition_id=record.acquisition_id,
            evidence_id=None,  # Not available from Phase 4 pipeline
            zeek_uid=zeek_uid,
            source="zeek",
            source_log=record.source_log,
            processed_at=datetime.now(timezone.utc),
            processor_version="1.0",
        )

        # 6. Construct ProtocolEvent
        event_id = str(uuid.uuid4())

        try:
            event = ProtocolEvent(
                event_id=event_id,
                flow_id=flow_id,
                zeek_uid=zeek_uid,
                acquisition_id=record.acquisition_id,
                evidence_id=None,
                timestamp=timestamp,
                protocol="tls",
                protocol_data=tls_data,
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

    def _parse_string(self, val: Any) -> str | None:
        """Parse an optional string, mapping absent markers ('-') to None."""
        if val is None or val == "-":
            return None
        return str(val)

    def _parse_datetime(self, val: Any) -> datetime | None:
        """Parse an optional Zeek timestamp float into a UTC datetime."""
        if val is None or val == "-":
            return None
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except (ValueError, TypeError):
            return None
