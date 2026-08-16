# M4 Evidence + Reporting Engine - Final Handoff Documentation

## 1. M4 Responsibilities
The NetSleuth-AI **M4 Evidence + Reporting Engine** is responsible for:
- Enforcing forensic evidence integrity and non-duplicating chain of custody across network investigation cases.
- Validating byte-level cryptographic hashes (SHA-256, SHA-512, MD5) for raw network evidence against expected upstream context.
- Packaging evidence integrity records into schema-validated `evidence-integrity-v1` models without modifying upstream investigation case payloads.
- Synthesizing contract-compliant `report-v1` dictionaries from correlated `investigation-case-v1.1` data and `evidence-integrity-v1` records.
- Exporting and rendering reports deterministically into JSON (sorted keys, UTF-8), HTML (self-contained, responsive, dark-mode, XSS-escaped), and PDF (pure Python standard library `%PDF-1.4`).

---

## 2. Data Classification Boundary

### OBSERVED DATA (Immutable Upstream Facts)
- Raw packet captures (PCAPs), network flow logs, protocol sessions, DNS queries, HTTP headers, TLS records, and system artifacts.
- Upstream timestamps (`collected_at`, `ingested_at`, `timestamp`).
- Upstream identifiers (`case_id`, `finding_id`, `event_id`, `entity_id`, `relationship_id`, `evidence_id`, `source_id`).
- Upstream declared expected byte hashes (`hash` / `expected_hash`).
- Upstream provenance metadata (`collector_id`, `acquisition_id`).

### M4-DERIVED DATA (Integrity & Reporting Projections)
- Calculated byte hashes (`calculated_hash`) derived by `IntegrityVerifier` via cryptographic digest of raw payload bytes.
- Verification status (`verification_status`: `"verified"`, `"mismatch"`, `"unverified"`).
- Execution-aware verification timestamps (`verified_at` generated strictly upon actual byte verification).
- Non-duplicating chain-of-custody event log (`chain_of_custody` entries with action, timestamp, custodian ID, signature).
- Deterministic report ID (`report_id = "RPT-{case_id}"`).
- Report summary counters (`total_findings`, `total_timeline_events`, `total_evidence_references`, `verified_evidence_count`, `mismatched_evidence_count`, `unverified_evidence_count`).
- Projected report components (`findings`, `timeline`, `entities`, `relationships`).

---

## 3. M4 Architecture
```
M1 (Packet Intel) → M2 (Analysis) → M3 (Correlation Case V1.1)
                                           │
                                           ▼
                                 M3ToM4EvidenceAdapter
                                           │
                                           ▼
                                  IntegrityVerifier
                                           │
                                           ▼
                                    ChainOfCustody
                                           │
                                           ▼
                                  M4EvidencePackage
                                           │
                                           ▼
                                      ReportEngine
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
              ReportExporter       HTMLReportRenderer     PDFReportRenderer
               (JSON String)           (HTML Doc)            (PDF Bytes)
```

---

## 4. M3 → M4 Evidence Boundary
- Maintained by [`M3ToM4EvidenceAdapter`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/case_adapter.py).
- Extracts declared `evidence_references` from `investigation-case-v1.1` payloads without altering case structure.
- Ensures evidence ID preservation, exact type mapping (`pcap`, `flow`, `session`, `dns`, `http`, `tls`, `artifact`, `log`, `finding`), and source ID alignment.

---

## 5. Evidence Integrity V1 & IntegrityVerifier
- Schema contract: [`docs/contracts/evidence-integrity-v1.json`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/docs/contracts/evidence-integrity-v1.json) (`schema_version: "evidence-integrity-v1"`).
- Class [`IntegrityVerifier`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/integrity_verifier.py):
  - Calculates SHA-256, SHA-512, and MD5 hashes of evidence byte streams.
  - Classifies verification as `"verified"` (calculated matches expected), `"mismatch"` (calculated differs from expected), or `"unverified"` (expected hash or evidence bytes missing).
  - Emits UTC ISO-8601 aware `verified_at` timestamp ONLY upon execution.

---

## 6. ChainOfCustody
- Class [`ChainOfCustody`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/chain_of_custody.py):
  - Records non-duplicating custody actions: `ingest`, `verify`, `export`, `transfer`, `inspect`, `archive`.
  - Enforces chronological ordering and non-duplicate event logging.
  - Prevents signature fabrication (`signature = None` unless explicitly signed by custodian).

---

## 7. M4EvidencePackage & Builder
- Classes [`M4EvidencePackage`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/evidence_package.py) and [`M4EvidencePackageBuilder`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/evidence_package.py):
  - Orchestrates adapter extraction, verifier execution, custody logging, and schema validation.
  - Validates referential integrity (verifying timeline events and relationships do not reference undeclared evidence IDs).

---

## 8. Evidence Lineage Verification
- Verified end-to-end evidence tracing across M1 → M2 → M3 → M4.
- Zero evidence invention, zero ID mutation, zero evidence-type mutation, zero source mutation, zero expected-hash mutation, zero provenance loss, and zero fabricated timestamps or signatures.

---

## 9. Report V1 & ReportEngine
- Schema contract: [`docs/contracts/report-v1.json`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/docs/contracts/report-v1.json) (`schema_version: "report-v1"`).
- Class [`ReportEngine`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/report_engine.py):
  - Derives deterministic `report_id = "RPT-{case_id}"`.
  - Calculates summary counters accurately (`verified_evidence_count`, `mismatched_evidence_count`, `unverified_evidence_count`).
  - Projects findings, timeline events, entities, and relationships into contract-compliant representations.

---

## 10. Report Exporters & Renderers
- [`ReportExporter`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/report_exporter.py): Exports `Report V1` dictionaries into schema-validated, sorted-key UTF-8 JSON strings.
- [`HTMLReportRenderer`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/html_renderer.py): Renders self-contained responsive HTML documents with strict HTML escaping on all dynamic text fields to eliminate XSS risks.
- [`PDFReportRenderer`](file:///c:/Users/Janki%20Panchal/OneDrive/Desktop/NetSleuth-AI/src/m4_evidence/pdf_renderer.py): Renders binary `%PDF-1.4` PDF documents using pure Python standard library (0 third-party dependencies).

---

## 11. Authoritative Frozen Contracts

| Contract Name | Path | Version | Status | Owner |
|---|---|---|---|---|
| InvestigationCase | `docs/contracts/investigation-case-v1.1.json` | V1.1 | FROZEN | M3 Correlation Engine |
| EvidenceIntegrity | `docs/contracts/evidence-integrity-v1.json` | V1 | FROZEN | M4 Evidence Engine |
| Report | `docs/contracts/report-v1.json` | V1 | FROZEN | M4 Reporting Engine |

---

## 12. Complete Test Suite Summary
- Total Tests: 266
- Passed: 266
- Failed: 0

### Unit & Integration Test Breakdown
- Contract Validation Tests: 34 tests
- M4 Evidence Boundary & Adapter Tests: 18 tests
- Integrity Verifier Tests: 22 tests
- Chain of Custody Tests: 22 tests
- M4 Evidence Package Builder Tests: 25 tests
- Evidence Lineage Integration Tests: 15 tests
- Report Engine Tests: 18 tests
- Report Exporter (JSON) Tests: 15 tests
- HTML Renderer Tests: 26 tests (24 unit + 2 integration)
- PDF Renderer Tests: 26 tests (24 unit + 2 integration)
- Full End-to-End Pipeline Integration Tests: 30 tests (`test_m4_full_pipeline.py`)
- M3 Core & Adapter Baseline Tests: 15 tests

---

## 13. Known Limitations
- The PDF renderer formats text sequentially in single-page media boxes (A4/Letter). Multi-page flow layout and custom TTF embedded fonts are reserved for downstream presentation enhancements if needed.
- Evidence byte verification requires in-memory byte arrays or byte stream streams. Streamed disk chunk verification can be wrapped via custom byte iterators if handling multi-gigabyte PCAPs.

---

## 14. Explicit Out-of-Scope Functionality
- Machine learning/AI anomaly detection logic (owned by M2/M3).
- Threat intelligence or MITRE ATT&CK external web APIs (owned by M2/M3).
- Database persistence or ORM models (downstream integration).
- Cloud storage/S3 bucket uploaders (downstream integration).
- Web application framework routing or API endpoints (downstream integration).

---

## 15. M4 → Downstream Handoff Requirements
- Downstream CLI commands or Web API endpoints must ingest binary outputs (`bytes` for PDF, `str` for HTML/JSON) directly without modifying `report_id`, `case_id`, or `evidence_integrity` records.
- Any downstream storage or transfer layer must append an `export` or `transfer` entry to `ChainOfCustody` using `ChainOfCustody.record_action()`.
