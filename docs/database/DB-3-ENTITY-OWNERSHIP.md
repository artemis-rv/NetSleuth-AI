# DB-3: Entity Ownership

This document defines which engine creates, modifies, and reads each business entity.

**Rule:** An entity has exactly one owner. Downstream engines may read but must not silently overwrite upstream entities. Cross-engine writes require explicit, audited operations.

---

## 1. Ownership Map

### `acquisition` schema

**`Acquisition`**
- **Owner (writes):** M1 / Acquisition Engine
- **Readers:** M1, M2, M3, M4
- **Created when:** PCAP is ingested and validated
- **Modified by:** No one. Immutable after creation.
- **Deleted by:** Forbidden. Archived under evidence lifecycle policy only.

**`Evidence`**
- **Owner (writes):** M1 (creates MinIO reference), M4 (adds custody linkage)
- **Readers:** M1, M3, M4
- **Created when:** PCAP is stored in MinIO and the object reference is registered
- **Modified by:** M4 adds custody metadata. Core hash fields are immutable.
- **Deleted by:** Forbidden.

---

### `intelligence` schema

**`Flow`**
- **Owner (writes):** M1 / Conn Adapter
- **Readers:** M2, M3
- **Created when:** Zeek conn.log is parsed and normalised
- **Modified by:** No one. Immutable after creation.
- **Deleted by:** Archived with Acquisition under evidence lifecycle policy.

**`ProtocolEvent`**
- **Owner (writes):** M1 / DNS, HTTP, TLS Adapters
- **Readers:** M2, M3
- **Created when:** Protocol-specific Zeek logs are parsed
- **Modified by:** No one. Immutable after creation. `protocol_data` is JSONB.
- **Deleted by:** Archived with Acquisition.

**`Artifact`**
- **Owner (writes):** M1 / Artifact Extractor
- **Readers:** M2, M3
- **Created when:** Observables are extracted from ProtocolEvents
- **Modified by:** No one. Immutable after creation.
- **Deleted by:** Archived with Acquisition.

---

### `analytics` schema

**`Finding`**
- **Owner (writes):** M2 / Analysis Engine
- **Readers:** M3
- **Created when:** An ML model or heuristic produces a detection result
- **Modified by:** No one. A revised finding creates a new versioned record referencing the previous. The old finding is retained.
- **Deleted by:** Never. Archived with case.

**`ModelRun`**
- **Owner (writes):** M2 / ML Pipeline
- **Readers:** M2 (audit), M4 (reporting)
- **Created when:** A model is executed against M1 intelligence
- **Modified by:** No one. Immutable.
- **Deleted by:** Never. Long-term audit retention.

---

### `investigation` schema

**`InvestigationCase`**
- **Owner (writes):** M3 (creates and manages state), Analyst (via M3 API)
- **Readers:** M3, M4
- **Created when:** An investigation is opened (manually or triggered by M2 findings)
- **Modified by:** M3 / Analyst — status transitions (open → investigating → review → closed). All changes are audit-logged.
- **Deleted by:** Never. Soft-close/archive only.

**`Entity`**
- **Owner (writes):** M3 / Correlation Engine or Analyst
- **Readers:** M3, M4
- **Created when:** An actor (host, service, user) is identified in the investigation
- **Modified by:** M3 / Analyst during open case. Immutable once case is finalised.

**`Relationship`**
- **Owner (writes):** M3 / Correlation Engine
- **Readers:** M3, M4
- **Created when:** A directed link between two Entities is established
- **Modified by:** M3 during open case.

**`Behavior`**
- **Owner (writes):** M3 / Correlation Engine
- **Readers:** M3, M4
- **Created when:** A correlated pattern of activity is identified
- **Modified by:** M3 during open case.

**`TimelineEvent`**
- **Owner (writes):** M3 / Correlation Engine
- **Readers:** M3, M4
- **Created when:** A significant timestamped event is assembled during correlation
- **Modified by:** No one. Immutable once written.

**`MITREMapping`**
- **Owner (writes):** M3 / MITRE Mapper
- **Readers:** M3, M4
- **Created when:** A Behavior or Finding is mapped to an ATT&CK technique
- **Modified by:** No one. Versioned — updated mapping creates a new record.

**`AttackChain`**
- **Owner (writes):** M3 / Correlation Engine or Analyst
- **Readers:** M3, M4
- **Created when:** An ordered sequence of TTPs is established
- **Modified by:** M3 / Analyst during open case.

---

### `custody` schema

**`EvidenceItem`**
- **Owner (writes):** M4 / Evidence Engine
- **Readers:** M4, Auditors
- **Created when:** Evidence is formally registered for a case
- **Modified by:** No one. Immutable. Additional custody events are appended separately.
- **Deleted by:** Never.

**`ChainOfCustodyEvent`**
- **Owner (writes):** M4 / Evidence Engine, System actions
- **Readers:** M4, Auditors
- **Created when:** Any custody action occurs (ingest, verify, transfer, export)
- **Modified by:** No one. Append-only log.
- **Deleted by:** Never.

**`Report`**
- **Owner (writes):** M4 / Reporting Engine
- **Readers:** M4, Human Analysts
- **Created when:** A report is generated for a case
- **Modified by:** No one. A new version creates a new record. Prior versions retained.
- **Deleted by:** Never.

---

### `audit` schema

**`AuditEvent`**
- **Owner (writes):** Shared infrastructure (all engines, system layer)
- **Readers:** Security/Compliance
- **Created when:** Any access, export, or state-change action occurs
- **Modified by:** No one. Append-only.
- **Deleted by:** Never. Regulatory retention minimum applies.
