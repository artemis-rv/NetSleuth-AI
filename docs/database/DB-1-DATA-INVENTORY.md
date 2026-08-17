# DB-1: Complete Data Inventory

This document inventories every object produced/consumed across the NetSleuth-AI pipeline. It defines exactly what is persisted, referenced, derived, or discarded before designing business entities and tables.

The core question driving persistence decisions is: **"What investigative capability do we lose if we don't store it?"**

---

## 1. M1 — Packet Intelligence

### `AcquisitionReference`
*   **Owner / Producer:** M1 / Acquisition Engine
*   **Consumers:** M1, M2, M3, M4
*   **Source:** Physical PCAP ingestion
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `acquisition_id` (Parent: none)
*   **Retention:** Case lifetime / legal hold
*   **Regenerable?** NO
*   **Why persist?** Root identity that ties all downstream intelligence and findings back to the original physical evidence file.

### `Provenance` (Hash verification chain)
*   **Owner / Producer:** M1 / Provenance Validator
*   **Consumers:** M1, M3, M4
*   **Source:** Validation steps on PCAP/Logs
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** (Implicit tied to `acquisition_id` and `event_id`)
*   **Retention:** Case lifetime / legal hold
*   **Regenerable?** YES (by rerunning validation), but crucial to retain for audit.
*   **Why persist?** Ensures chain of custody and forensic integrity can be proven in court without reprocessing original PCAPs.

### `Flow` & `ProtocolEvent` (including DNSData, HTTPData, TLSData)
*   **Owner / Producer:** M1 / Zeek Adapters
*   **Consumers:** M2, M3
*   **Source:** Zeek `conn.log`, `dns.log`, `http.log`, `ssl.log`
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `flow_id`, `event_id` (Parent: `acquisition_id`, `flow_id`)
*   **Retention:** Standard investigation lifetime
*   **Regenerable?** YES (from PCAP)
*   **Why persist?** If discarded, M3 cannot reconstruct attack context, timelines, or behaviors without re-parsing PCAPs, destroying query performance. (Note: Specific data like DNS/HTTP/TLS will likely share a polymorphic `ProtocolEvent` table with JSONB payloads).

### `Artifact` (Observables like IPs, domains, hashes)
*   **Owner / Producer:** M1 / Artifact Extractor
*   **Consumers:** M2, M3
*   **Source:** Extracted from Flows and ProtocolEvents
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `artifact_id` (Parent: `event_id`, `flow_id`)
*   **Retention:** Standard investigation lifetime
*   **Regenerable?** YES (from events)
*   **Why persist?** Enables fast pivoting during investigation (e.g., "Find all acquisitions where this IP appeared").

### `PacketReference`
*   **Owner / Producer:** M1 / Acquisition Engine
*   **Consumers:** M4 (for evidence export)
*   **Source:** Offset/byte markers in PCAP
*   **Persist? / Storage:** **YES** (selectively) / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** N/A (Parent: `flow_id` or `event_id`)
*   **Retention:** Standard investigation lifetime
*   **Regenerable?** YES
*   **Why persist?** Needed for extracting specific raw packets for evidence presentation without scanning gigabytes of PCAP.

### `NetworkIntelligencePackage`
*   **Owner / Producer:** M1 / Orchestrator
*   **Consumers:** M2, M3
*   **Source:** Aggregation of all M1 outputs
*   **Persist? / Storage:** **NO** / Transient
*   **Why persist?** It is persisted *logically* via its canonical parts in PostgreSQL. Persisting it as a massive JSON blob ruins relational query capabilities.

---

## 2. M2 — Analysis Engine

### `FeatureVector` / `UnsupervisedResult` / `ClassificationResult`
*   **Owner / Producer:** M2 / ML Pipeline
*   **Consumers:** M2 (internal), M3 (conditionally)
*   **Source:** Extracted from M1 intelligence
*   **Persist? / Storage:** **CONDITIONAL** / PostgreSQL (or MinIO for bulk datasets)
*   **Immutable? / Large?** YES / Medium
*   **IDs:** `analysis_id`
*   **Retention:** Transient unless flagged
*   **Regenerable?** YES
*   **Why persist?** Only persist specific feature vectors/snapshots when required for finding reproducibility, model audits, or evaluation experiments. Otherwise, they consume too much storage.

### `Finding`
*   **Owner / Producer:** M2 / Analysis Engine
*   **Consumers:** M3, M4
*   **Source:** Result of ML models / heuristics
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `finding_id` (Parent: `acquisition_id`, `flow_id`)
*   **Retention:** Case lifetime
*   **Regenerable?** YES (by rerunning models, though model drift may change outcomes)
*   **Why persist?** The core analytic output of the system. M3 relies on these to build correlations.

### `FindingsPackage`
*   **Owner / Producer:** M2 / Analysis Orchestrator
*   **Consumers:** M3
*   **Source:** Aggregation of Findings
*   **Persist? / Storage:** **NO** / Transient
*   **Why persist?** Like the M1 package, findings are persisted as individual relational records.

### `ModelRun` & `ModelArtifactMetadata`
*   **Owner / Producer:** M2
*   **Consumers:** M2, M4
*   **Source:** Model execution and training
*   **Persist? / Storage:** **YES** / PostgreSQL (Metadata), MinIO (Actual models)
*   **Immutable? / Large?** YES / Models are Large
*   **IDs:** `model_id`, `run_id`
*   **Retention:** Long-term audit
*   **Regenerable?** NO (historical model weights must be preserved)
*   **Why persist?** Necessary to prove *why* the system generated a finding at a specific point in time (explainability in court).

---

## 3. M3 — Correlation & Investigation

### `InvestigationCase`
*   **Owner / Producer:** M3 / Analyst or automated trigger
*   **Consumers:** M3, M4
*   **Source:** Grouping of findings and acquisitions
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** NO (mutable state: open/closed) / NO
*   **IDs:** `case_id`
*   **Retention:** Permanent / Legal hold
*   **Regenerable?** NO
*   **Why persist?** The root object for human interaction and final reporting.

### `Entity`, `Relationship`, `Behavior`, `TimelineEvent`
*   **Owner / Producer:** M3 / Correlation Engine
*   **Consumers:** M3, M4
*   **Source:** Derived from M1 Artifacts, Events, and M2 Findings
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `entity_id`, `relationship_id`, `behavior_id`, `timeline_event_id` (Parent: `case_id`)
*   **Retention:** Case lifetime
*   **Regenerable?** YES* (Can be rebuilt from logic, but computationally expensive)
*   **Why persist?** These represent the context assembly and investigation graph. Regenerating them on the fly for every UI view or report would be too slow.

### `MITREMapping` & `AttackChain`
*   **Owner / Producer:** M3 / Correlation Engine
*   **Consumers:** M4 (Reporting)
*   **Source:** Mapping behaviors to ATT&CK matrix
*   **Persist? / Storage:** **YES** / PostgreSQL (Mappings), MinIO (Matrix Snapshots)
*   **Immutable? / Large?** YES / NO
*   **IDs:** `mitre_mapping_id`, `attack_chain_id`
*   **Retention:** Case lifetime
*   **Regenerable?** YES
*   **Why persist?** The attack chain is the narrative core of the forensic report. Persisting it caches the investigation results.

---

## 4. M4 — Evidence & Reporting

### `EvidenceItem` & `ChainOfCustodyEvent`
*   **Owner / Producer:** M4 / Evidence Engine
*   **Consumers:** Auditors, External parties
*   **Source:** User actions, system lifecycle events
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `evidence_id`, `custody_event_id` (Parent: `case_id`)
*   **Retention:** Permanent / Legal hold
*   **Regenerable?** NO
*   **Why persist?** Absolute legal requirement for forensics. Without chain of custody, the evidence is inadmissible.

### `Report` & `ReportArtifact` & `Export`
*   **Owner / Producer:** M4 / Reporting Engine
*   **Consumers:** Human analysts
*   **Source:** Aggregation of M3 investigation
*   **Persist? / Storage:** **YES** / PostgreSQL (Metadata), MinIO (PDF/JSON files)
*   **Immutable? / Large?** YES / YES (Large files)
*   **IDs:** `report_id` (Parent: `case_id`)
*   **Retention:** Permanent
*   **Regenerable?** YES (though historical point-in-time reports are usually frozen)
*   **Why persist?** Tangible deliverables to stakeholders.

### `AuditEvent`
*   **Owner / Producer:** M4 (or global infrastructure)
*   **Consumers:** Security/Compliance
*   **Source:** System access, queries, data exports
*   **Persist? / Storage:** **YES** / PostgreSQL
*   **Immutable? / Large?** YES / NO
*   **IDs:** `audit_event_id`
*   **Retention:** Regulatory minimums (e.g., 7 years)
*   **Regenerable?** NO
*   **Why persist?** Compliance, tracking who viewed what evidence and when.

---

## 5. Persistence Matrix

| Object | Store | Persistent? | Authoritative? | Regenerable? |
| :--- | :--- | :--- | :--- | :--- |
| **PCAP** | MinIO | YES | YES | NO |
| **Acquisition** | PostgreSQL | YES | YES | NO |
| **Flow** | PostgreSQL | YES | YES | YES* |
| **Protocol Event (DNS, HTTP)** | PostgreSQL | YES | YES | YES* |
| **RawZeekRecord** | *transient* | NO | NO | YES |
| **NetworkIntelligencePackage** | *transient* | NO | NO | YES |
| **FeatureVector** | PostgreSQL | CONDITIONAL | M2 | YES |
| **ML Model** | MinIO | YES | M2 | NO |
| **Finding** | PostgreSQL | YES | M2 | YES* (Model Drift risk) |
| **FindingsPackage** | *transient* | NO | NO | YES |
| **InvestigationCase** | PostgreSQL | YES | M3 | NO |
| **Entity / Relationship** | PostgreSQL | YES | M3 | YES* |
| **Behavior / Timeline** | PostgreSQL | YES | M3 | YES* |
| **MITRE Snapshot** | MinIO | YES | M3 | YES |
| **AttackChain** | PostgreSQL | YES | M3 | YES* |
| **Evidence / Chain of Custody** | PostgreSQL | YES | M4 | NO |
| **Report Metadata** | PostgreSQL | YES | M4 | NO |
| **Report PDF / Export** | MinIO | YES | M4 | YES |

*\* = Derivable from retained source evidence, but persistence is strictly justified to maintain investigation performance, provenance, and point-in-time explainability.*
