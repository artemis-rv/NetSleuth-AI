"""
backend/app/engines/packet_intelligence/adapters/conn.py
--------------------------------------------------------
Adapter for converting Zeek conn.log records into canonical Flow objects.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.contracts.network_intelligence import Endpoint, Flow, FlowProvenance
from app.engines.packet_intelligence.zeek.reader import RawZeekRecord

from .errors import AdapterError, AdapterErrorCode


class ConnAdapter:
    """Converts RawZeekRecord objects from conn.log into canonical Flow objects."""

    def convert(self, record: RawZeekRecord) -> Flow | AdapterError:
        """Convert a raw Zeek conn.log record into a Flow.

        Parameters:
            record: The raw Zeek record yielded by ZeekReader.

        Returns:
            A canonical Flow object on success.
            An AdapterError on deterministic mapping failure.
        """
        if record.log_type != "conn":
            return self._build_error(
                record,
                AdapterErrorCode.UNSUPPORTED_LOG_TYPE,
                f"ConnAdapter cannot process log_type '{record.log_type}'",
            )

        data = record.record

        # 1. Extract required fields
        required_keys = [
            "ts",
            "uid",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
        ]
        for key in required_keys:
            if key not in data:
                return self._build_error(
                    record,
                    AdapterErrorCode.MISSING_REQUIRED_FIELD,
                    f"Missing required field: {key}",
                )

        try:
            timestamp = datetime.fromtimestamp(float(data["ts"]), tz=timezone.utc)
            orig_p = int(data["id.orig_p"])
            resp_p = int(data["id.resp_p"])
        except (ValueError, TypeError) as exc:
            return self._build_error(
                record,
                AdapterErrorCode.INVALID_TYPE,
                f"Type conversion failed for required fields: {exc}",
            )

        # 2. Extract and sanitize optional fields
        duration = self._parse_float(data.get("duration"))
        orig_bytes = self._parse_int(data.get("orig_bytes"))
        resp_bytes = self._parse_int(data.get("resp_bytes"))
        orig_packets = self._parse_int(data.get("orig_pkts"))
        resp_packets = self._parse_int(data.get("resp_pkts"))

        service = data.get("service")
        if service == "-":
            service = None
        elif isinstance(service, str) and "," in service:
             # Zeek can log multiple services separated by commas, e.g. "dns,mdns"
             # The contract specifies `service: Optional[str]`, so we can pass it as is.
             pass

        conn_state = data.get("conn_state")
        if conn_state == "-":
            conn_state = None

        # 3. Construct Provenance
        provenance = FlowProvenance(
            acquisition_id=record.acquisition_id,
            evidence_id=None,  # Not available from Phase 4 pipeline
            zeek_uid=data["uid"],
            source="zeek",
            source_log=record.source_log,
            processed_at=datetime.now(timezone.utc),
            processor_version="1.0",
        )

        # 4. Construct Flow
        flow_id = str(uuid.uuid4())

        try:
            flow = Flow(
                flow_id=flow_id,
                zeek_uid=data["uid"],
                acquisition_id=record.acquisition_id,
                evidence_id=None,
                timestamp=timestamp,
                start_time=timestamp, # Conceptually, Zeek's ts is the start_time
                end_time=None,        # Not silently deriving end_time to preserve observed data
                source=Endpoint(ip=str(data["id.orig_h"]), port=orig_p),
                destination=Endpoint(ip=str(data["id.resp_h"]), port=resp_p),
                protocol=str(data["proto"]),
                service=service if isinstance(service, str) else None,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_packets=orig_packets,
                resp_packets=resp_packets,
                connection_state=conn_state if isinstance(conn_state, str) else None,
                provenance=provenance,
            )
            return flow
        except Exception as exc:
            # Catch Pydantic validation errors (e.g. invalid port ranges)
            return self._build_error(
                record,
                AdapterErrorCode.MALFORMED_RECORD,
                f"Flow contract validation failed: {exc}",
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
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def _parse_float(self, val: Any) -> float | None:
        """Parse an optional float, mapping absent markers ('-') to None."""
        if val is None or val == "-":
            return None
        try:
            return float(val)
        except (ValueError, TypeError):
            return None
