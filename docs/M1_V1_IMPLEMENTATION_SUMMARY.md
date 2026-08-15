# NetSleuth-AI: M1 V1 Implementation Summary

## 1. Executive Summary

The M1 Packet Intelligence Engine is the first stage in the NetSleuth-AI pipeline. It observes network traffic ("What happened on the wire?") and normalizes it into a canonical format for downstream analysis. M1 strictly deals with observed data and does not perform threat detection, risk scoring, or any investigation logic.

M1 V1 implements the core contracts and canonical models that represent this observed data. The authoritative output of M1 is the `NetworkIntelligencePackage`, which is consumed by M2 (Analysis Engine) and eventually M3 (Correlation Engine).

## 2. M1 Responsibility

M1 is responsible for:
- Acquiring and validating PCAP/PCAPNG evidence.
- Invoking Zeek via an official Docker container to analyze the PCAP.
- Reading and normalizing Zeek's output logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
- Creating canonical `Flow` and `ProtocolEvent` objects.
- Extracting observable `Artifact` indicators (IP, DOMAIN, URL, CERTIFICATE, etc.).
- Maintaining strict data provenance linking every field back to its Zeek source log.
- Enforcing immutable data models (frozen Pydantic models).
- Passing the final `NetworkIntelligencePackage` downstream.

M1 operates purely on structured inputs from Zeek and does not perform any external lookups, threat intelligence matching, or AI-based conclusions.

## 3. Implemented Components (Phase 1)

Phase 1 focuses exclusively on the contract and canonical model definitions.

### 3.1. Contract Implementation
- **File**: `backend/app/contracts/network_intelligence.py`
- **Technology**: Pydantic v2
- **Key Models**:
  - `NetworkIntelligencePackage`: Top-level package.
  - `Flow`: Represents a network connection (from Zeek `conn.log`).
  - `ProtocolEvent`: Represents application-layer activity (DNS, HTTP, TLS).
  - `Artifact`: Extracted observable indicators.
  - `AcquisitionReference`: Record of the ingested PCAP.
  - `PacketReference`: Traceability reference to the original PCAP frame/byte offsets.
  - `Provenance`: Detailed tracking of the origin of the data.
- **Key Features**: 
  - All models are frozen (`model_config = {"frozen": True}`).
  - Protocol data models use `extra="forbid"` to ensure proper union fallback behavior.
  - Does NOT contain downstream fields like `malicious`, `risk_score`, or `severity`.

### 3.2. Fixtures
- **File**: `fixtures/network_intelligence/network-intelligence-v1-m1-phase1.json`
- Represents a complete, valid M1 output package with flows, DNS/TLS events, and extracted artifacts.

### 3.3. Tests
- **File**: `backend/tests/unit/test_network_intelligence_contract.py`
- Comprehensive test suite (78 tests) covering:
  - Valid and malformed inputs.
  - Boundary cases.
  - Contract compliance.
  - Deterministic output.
  - Provenance preservation.
  - Referential integrity between Flows, Events, and Artifacts.
  - Fixture round-trip serialization.

### 3.4. Phase 2 (Acquisition Engine Implementation)
Phase 2 establishes a trustworthy, validated identity for evidence files (`.pcap` / `.pcapng`) prior to downstream processing.

- **Files**:
  - `backend/app/engines/acquisition/__init__.py`: Package entry point.
  - `backend/app/engines/acquisition/errors.py`: Domain exception `AcquisitionError` and `AcquisitionErrorCode` enum (`FILE_NOT_FOUND`, `NOT_A_FILE`, `UNSUPPORTED_FORMAT`, `EMPTY_FILE`, `UNREADABLE_FILE`, `INVALID_CAPTURE`, `HASH_FAILURE`).
  - `backend/app/engines/acquisition/validator.py`: Path traversal guard via `Path.resolve()`, extension filtering, and 4-byte magic byte detection for PCAP/PCAPNG.
  - `backend/app/engines/acquisition/hasher.py`: Streamed SHA-256 computation in 64 KiB chunks using Python `hashlib`.
  - `backend/app/engines/acquisition/service.py`: `AcquisitionService.acquire()` orchestrating validation, hashing, and returning an immutable `AcquisitionReference`.
- **Tests**:
  - `backend/tests/unit/test_acquisition.py`: 25 unit and benchmark tests covering all error conditions, contract compliance, forensic integrity, and performance SLAs.
- **Key Features & Guarantees**:
  - **Security & Safety**: Zero subprocess/shell execution, strict path canonicalization.
  - **Forensic Integrity**: Byte-for-byte read-only operation; original evidence file remains unmodified.
  - **Performance SLAs**: SHA-256 throughput $\ge 50$ MB/s, 1 MB acquisition execution $\le 200$ ms, validation rejection $\le 5$ ms.
  - **Memory Efficiency**: Memory footprint bounded to 64 KiB regardless of file size.

## 4. Total Test Suite Status

- **Contract Tests (Phase 1)**: 78 tests passing
- **Acquisition Engine Tests (Phase 2)**: 25 tests passing
- **Total M1 Unit Tests**: 103 tests passing

## 5. Next Phases (Roadmap)

- **Phase 3 (Zeek Runner)**: Docker-based Zeek execution.
- **Phase 4 (Zeek Reader)**: Reading JSON logs and handling missing/malformed records.
- **Phases 5-8 (Adapters)**: Converting `conn.log`, `dns.log`, `http.log`, and `ssl.log` into M1 models.
- **Phases 9-10 (Provenance & Package)**: Assembling the final package and preserving source traceability.

