# DB-2: Lifecycle & Persistence Policy

This document translates the DB-1 inventory into an explicit lifecycle and persistence policy. It defines when objects are created, their mutability, versioning, retention rules, and critically, how cascade and deletion behavior is handled to protect the forensic trail.

---

## 1. Core Policies

### 1.1 Source Retention Policy
*   **Original PCAP:** Permanent / Forensic retention in MinIO.
*   **Zeek Logs:** Retained in MinIO as derived evidence to support deep inspection.
*   **M1 Canonical Objects:** Retained in PostgreSQL for the lifetime of the investigation to support high-performance relational querying.

### 1.2 Derived-Data Retention Policy
*   **Raw Parser State (e.g., RawZeekRecord):** Discard immediately after processing.
*   **Temporary Feature Matrices:** Discard.
*   **Feature Snapshot (tied to a Finding):** Retain to ensure explainability and auditability of model decisions.
*   **Model Artifacts:** Retain historical versions permanently to prevent model drift from breaking historical auditability.

### 1.3 Versioning Policy
*   **Original Evidence:** Immutable and versioned at the object-storage bucket level.
*   **M1 Observations:** Versioned only when the underlying schema or output extraction changes.
*   **M2 Findings:** Strictly model- and version-aware. A finding is tied to the specific model version that generated it.
*   **M3 Investigation:** Case-history and audit aware. Changes to the case state generate audit history.
*   **M4 Reports:** Finalized versions are completely immutable.

### 1.4 Cascade Behavior Policy
**CRITICAL:** Cascade delete is strictly FORBIDDEN for forensic data.
*   Never allow `DELETE Acquisition -> CASCADE DELETE Evidence`.
*   Instead of destructive deletes, the system employs explicit archival/restriction behaviors (e.g., soft deletes or status flagging) governed by Evidence Custody policies.

---

## 2. Object Lifecycle Matrix

### M1 (Packet Intelligence)

**Original PCAP**
*   **Created by:** Acquisition
*   **Depends on:** Physical ingest action
*   **Storage:** MinIO
*   **Mutable / Immutable:** Immutable
*   **Versioning:** YES (bucket level)
*   **Regenerable?** NO
*   **Retention:** Evidence policy (permanent / legal hold)
*   **Deletion/Archive:** Restricted (requires specific lifecycle expiry or authorization)
*   **Upstream Ref:** None
*   **Downstream Consumers:** M1, M4
*   **Integrity Req:** SHA-256
*   **Loss Impact:** Destroys original evidence; chain of custody fundamentally broken.

**RawZeekRecord**
*   **Created by:** ZeekReader
*   **Depends on:** Zeek logs (MinIO)
*   **Storage:** Transient (memory/processing only)
*   **Regenerable?** YES
*   **Retention:** None
*   **Deletion/Archive:** Immediately after processing
*   **Upstream Ref:** Zeek Logs
*   **Downstream Consumers:** Zeek Adapters
*   **Loss Impact:** None. Transient processing state.

**AcquisitionReference**
*   **Created by:** Acquisition Engine
*   **Depends on:** Original PCAP
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Immutable
*   **Regenerable?** NO
*   **Retention:** Case lifetime / Legal hold
*   **Deletion/Archive:** Archive / Restrict only. Never cascade delete.
*   **Upstream Ref:** PCAP (MinIO)
*   **Downstream Consumers:** M1 events, M2 findings, M3 case
*   **Integrity Req:** Hash matching
*   **Loss Impact:** Disconnects all downstream findings from the physical source evidence.

**Flow / ProtocolEvent / Artifact**
*   **Created by:** M1 Adapters / Extractors
*   **Depends on:** AcquisitionReference
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Immutable
*   **Regenerable?** YES (by reprocessing PCAP)
*   **Retention:** Investigation lifetime
*   **Deletion/Archive:** Archive with case.
*   **Upstream Ref:** Acquisition
*   **Downstream Consumers:** M2, M3
*   **Integrity Req:** Provenance lineage
*   **Loss Impact:** Breaks immediate querying and correlation capabilities. Requires computationally expensive reprocessing to restore.

### M2 (Analysis Engine)

**FeatureVector (Transient)**
*   **Created by:** M2 ML Pipeline
*   **Storage:** Transient
*   **Regenerable?** YES
*   **Retention:** Discard
*   **Loss Impact:** None.

**FeatureVector (Snapshot)**
*   **Created by:** M2 ML Pipeline
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Immutable
*   **Regenerable?** YES
*   **Retention:** Retained with tied Finding
*   **Upstream Ref:** M1 Observations
*   **Loss Impact:** Inability to explain in court *why* a model generated a specific finding.

**M2 Finding**
*   **Created by:** M2 Analysis Engine
*   **Depends on:** M1 ProtocolEvents / Flow / Artifacts
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Immutable analytical version
*   **Versioning:** Model- and version-aware
*   **Regenerable?** Potentially (but susceptible to model drift)
*   **Retention:** Case lifetime
*   **Deletion/Archive:** Archive with case
*   **Upstream Ref:** M1 Canonical IDs, Model ID
*   **Downstream Consumers:** M3 Correlation
*   **Integrity Req:** Provenance + Model metadata
*   **Loss Impact:** Destroys automated threat detection insights for the case.

**Model Artifact**
*   **Created by:** M2 Training Pipeline
*   **Storage:** MinIO (metadata in PostgreSQL)
*   **Mutable / Immutable:** Immutable
*   **Regenerable?** NO
*   **Retention:** Long-term audit
*   **Loss Impact:** Cannot reproduce historical model behavior, breaking historical auditability.

### M3 (Correlation & Investigation)

**InvestigationCase**
*   **Created by:** M3 / Analyst or trigger
*   **Depends on:** Findings, Acquisitions
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Mutable (state changes like open/closed)
*   **Versioning:** Audit/History aware
*   **Regenerable?** NO
*   **Retention:** Permanent / Legal hold
*   **Deletion/Archive:** Restrict / Soft-delete only
*   **Upstream Ref:** M1, M2 Canonical IDs
*   **Downstream Consumers:** M4 Reports
*   **Integrity Req:** Complete Audit log
*   **Loss Impact:** Destroys analyst work, case state, and investigation grouping context.

**Entity / Relationship / Behavior / TimelineEvent / AttackChain**
*   **Created by:** M3 Correlation Engine / Analyst
*   **Depends on:** M1 Artifacts, Events, M2 Findings
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Mutable (during open case), Immutable (once finalized)
*   **Regenerable?** YES (mostly, via complex logic rebuild)
*   **Retention:** Case lifetime
*   **Deletion/Archive:** Archive with case
*   **Loss Impact:** Destroys the investigative narrative and correlation graph. Would require manual or computationally heavy rebuilding.

### M4 (Evidence & Reporting)

**EvidenceItem / ChainOfCustodyEvent**
*   **Created by:** M4 Evidence Engine
*   **Depends on:** InvestigationCase, Acquisition
*   **Storage:** PostgreSQL
*   **Mutable / Immutable:** Immutable
*   **Regenerable?** NO
*   **Retention:** Permanent / Legal hold
*   **Deletion/Archive:** Never delete
*   **Upstream Ref:** Case ID, Acquisition ID
*   **Integrity Req:** Cryptographic hash and signature validation
*   **Loss Impact:** Evidence becomes legally inadmissible; forensic trail is permanently broken.

**Report (PDF/JSON)**
*   **Created by:** M4 Reporting Engine
*   **Depends on:** InvestigationCase
*   **Storage:** MinIO (metadata in PostgreSQL)
*   **Mutable / Immutable:** Immutable finalized version
*   **Regenerable?** YES (though point-in-time exact matches may vary if data shifted)
*   **Retention:** Permanent
*   **Loss Impact:** Loss of official stakeholder deliverables and historical point-in-time records.
