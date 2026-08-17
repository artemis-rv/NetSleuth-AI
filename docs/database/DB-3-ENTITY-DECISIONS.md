# DB-3: Entity Decisions

This document records the explicit reasoning for every entity-status decision.
It answers the six qualification questions:

1. Is this a true business entity?
2. Is it identified independently?
3. Does it have its own lifecycle?
4. Does it need independent queries?
5. Does it have relationships to multiple other entities?
6. Is it immutable or stateful?

---

## M1 — Packet Intelligence Entities

### `Acquisition` → **ENTITY ✅**
1. **Business entity?** YES — the root record of all work done in the system.
2. **Identified independently?** YES — `acquisition_id`, globally unique.
3. **Own lifecycle?** YES — exists from ingest, archived under evidence policy.
4. **Independent queries?** YES — "show all flows for acquisition X", "show all findings for acquisition X".
5. **Multiple relationships?** YES — has many Flows, Events, Artifacts, Findings.
6. **Immutable or stateful?** Immutable.

### `Evidence` → **ENTITY ✅**
1. **Business entity?** YES — the formal database record of the PCAP object stored in MinIO.
2. **Identified independently?** YES — `evidence_id`, separate from `acquisition_id`.
3. **Own lifecycle?** YES — MinIO object key, hash, custody start.
4. **Independent queries?** YES — "verify the SHA-256 of evidence X", "find all custody events for evidence X".
5. **Multiple relationships?** YES — linked to Acquisition and ChainOfCustodyEvents.
6. **Immutable or stateful?** Immutable core fields. M4 appends custody linkage only.

### `Flow` → **ENTITY ✅**
1. **Business entity?** YES — the fundamental network observation unit.
2. **Identified independently?** YES — `flow_id` (wraps Zeek UID).
3. **Own lifecycle?** YES — created at M1 parse time, retained for investigation lifetime.
4. **Independent queries?** YES — "show all flows between IP A and IP B", "show all TLS flows in acquisition X".
5. **Multiple relationships?** YES — has many ProtocolEvents and Artifacts; belongs to Acquisition.
6. **Immutable or stateful?** Immutable.

### `ProtocolEvent` → **ENTITY ✅** (with JSONB payload)
1. **Business entity?** YES — distinct application-layer observation on a Flow.
2. **Identified independently?** YES — `event_id`.
3. **Own lifecycle?** YES — immutable, retained with Acquisition.
4. **Independent queries?** YES — "show all DNS events for acquisition X", "show all events on flow Y".
5. **Multiple relationships?** YES — belongs to Flow and Acquisition; source of Artifacts.
6. **Immutable or stateful?** Immutable.
- **Key decision:** `DNSData`, `HTTPData`, `TLSData` are **NOT** separate entities. They are protocol-specific payloads stored as `JSONB` on `ProtocolEvent` and discriminated by a `protocol` column. This avoids a three-table join for a common query pattern.

### `Artifact` → **ENTITY ✅**
1. **Business entity?** YES — a persisted observable indicator with cross-case investigative value.
2. **Identified independently?** YES — `artifact_id`.
3. **Own lifecycle?** YES — created by M1, consumed by M2 and M3.
4. **Independent queries?** YES — "find all acquisitions where domain X appeared", "pivot on IP address Y".
5. **Multiple relationships?** YES — linked to ProtocolEvent, Flow, Acquisition.
6. **Immutable or stateful?** Immutable.

### `Endpoint` → **VALUE OBJECT ❌**
- Source/destination IP+port embedded directly in `Flow`.
- Not independently queried or managed.
- No `endpoint_id`. Not an entity.

### `Provenance` variants (`FlowProvenance`, `EventProvenance`, `ArtifactProvenance`) → **EMBEDDED ❌**
- Stored as JSONB provenance block on their parent entity.
- Never queried in isolation.
- Not entities.

### `PacketReference` → **EMBEDDED ❌**
- Byte-offset forensic pointer. Stored as nullable columns on `Evidence` or `Flow`.
- No independent lifecycle. Not an entity.

### `NetworkIntelligencePackage` → **TRANSIENT ❌**
- Aggregation of M1 entities. Never persisted as a unit.

---

## M2 — Analysis Entities

### `Finding` → **ENTITY ✅**
1. **Business entity?** YES — the core M2 output, consumed by M3 and visible in reports.
2. **Identified independently?** YES — `finding_id`.
3. **Own lifecycle?** YES — created by M2, versioned, retained for case lifetime.
4. **Independent queries?** YES — "show all findings of type dns_exfiltration", "show all findings for acquisition X".
5. **Multiple relationships?** YES — linked to Acquisition, Flow, ModelRun; consumed by InvestigationCase.
6. **Immutable or stateful?** Append-only versioning (new version creates new row, old row retained).

### `ModelRun` → **ENTITY ✅**
1. **Business entity?** YES — records that a specific model version ran against specific data.
2. **Identified independently?** YES — `run_id`.
3. **Own lifecycle?** YES — immutable audit record.
4. **Independent queries?** YES — "which model produced finding X?", "which runs used model version 2?".
5. **Multiple relationships?** YES — linked to Findings; references MinIO model artifact.
6. **Immutable or stateful?** Immutable.

### `FeatureVector` (transient) → **DISCARDED ❌**
- Never persisted. Processing-only.

### `FeatureVector` (snapshot for finding audit) → **STORED ARTIFACT ⚠️ (not an entity)**
- Retained as a JSONB or small PostgreSQL row attached to a `Finding`.
- Not independently queried. Has no separate lifecycle.
- Not a business entity; a persistence artifact.

### `FindingsPackage` → **TRANSIENT ❌**
- Aggregation. Not persisted as a unit.

---

## M3 — Investigation Entities

### `InvestigationCase` → **ENTITY ✅**
1. **Business entity?** YES — the primary object human analysts interact with.
2. **Identified independently?** YES — `case_id`.
3. **Own lifecycle?** YES — stateful (open → investigating → review → closed).
4. **Independent queries?** YES — "show all open cases", "show case summary for CASE-001".
5. **Multiple relationships?** YES — aggregates Findings, Entities, Timeline, Reports.
6. **Immutable or stateful?** Stateful (mutable status, immutable history).

### `Entity` → **ENTITY ✅**
1. **Business entity?** YES — an investigative actor (host, user, service).
2. **Identified independently?** YES — `entity_id`.
3. **Own lifecycle?** YES — created during correlation, exists within case.
4. **Independent queries?** YES — "show all cases involving IP X".
5. **Multiple relationships?** YES — involved in Relationships, Behaviors, Timeline events.
6. **Immutable or stateful?** Mutable during open case, immutable once finalised.

### `Relationship` → **ENTITY ✅**
1. **Business entity?** YES — a directed, typed link between two Entities that has independent meaning.
2. **Identified independently?** YES — `relationship_id`.
3. **Own lifecycle?** YES — derived during correlation.
4. **Independent queries?** YES — "show all lateral movement relationships in case X".
5. **Multiple relationships?** YES — links two Entities, belongs to Case, may reference Findings.
6. **Immutable or stateful?** Mutable during open case.

### `Behavior` → **ENTITY ✅**
1. **Business entity?** YES — a labelled, correlated pattern (e.g., "DNS tunnelling").
2. **Identified independently?** YES — `behavior_id`.
3. **Own lifecycle?** YES — derived from Findings and Events.
4. **Independent queries?** YES — "show all exfiltration behaviors across all cases".
5. **Multiple relationships?** YES — linked to Findings, Timeline events, MITRE mappings.
6. **Immutable or stateful?** Mutable during open case.

### `TimelineEvent` → **ENTITY ✅**
1. **Business entity?** YES — a discrete, timestamped investigative fact.
2. **Identified independently?** YES — `timeline_event_id`.
3. **Own lifecycle?** YES — written during investigation, immutable.
4. **Independent queries?** YES — "reconstruct timeline between T1 and T2 for case X".
5. **Multiple relationships?** YES — references Entity, Behavior, Finding, AttackChain.
6. **Immutable or stateful?** Immutable.

### `MITREMapping` → **ENTITY ✅**
1. **Business entity?** YES — maps observed behavior to ATT&CK tactic/technique with justification.
2. **Identified independently?** YES — `mitre_mapping_id`.
3. **Own lifecycle?** YES — versioned (ATT&CK version-aware).
4. **Independent queries?** YES — "show all cases mapped to T1071", "coverage report by tactic".
5. **Multiple relationships?** YES — linked to Behavior, Finding, AttackChain, Case.
6. **Immutable or stateful?** Immutable per version; updates create new records.

### `AttackChain` → **ENTITY ✅**
1. **Business entity?** YES — the ordered sequence of TTPs forming the attack narrative.
2. **Identified independently?** YES — `attack_chain_id`.
3. **Own lifecycle?** YES — assembled during investigation.
4. **Independent queries?** YES — central to report generation.
5. **Multiple relationships?** YES — ordered collection of MITREMappings and TimelineEvents; belongs to Case.
6. **Immutable or stateful?** Mutable during open case; immutable once report is finalised.

---

## M4 — Evidence & Reporting Entities

### `EvidenceItem` → **ENTITY ✅**
1. **Business entity?** YES — a formal evidence entry in the legal custody record.
2. **Identified independently?** YES — `evidence_item_id`.
3. **Own lifecycle?** YES — immutable, permanent legal hold.
4. **Independent queries?** YES — "list all evidence for case X".
5. **Multiple relationships?** YES — belongs to Case; has many ChainOfCustodyEvents.
6. **Immutable or stateful?** Immutable.

### `ChainOfCustodyEvent` → **ENTITY ✅**
1. **Business entity?** YES — a discrete, auditable custody action (ingest, verify, transfer, export).
2. **Identified independently?** YES — `custody_event_id`.
3. **Own lifecycle?** YES — append-only, permanent.
4. **Independent queries?** YES — "show custody log for evidence X".
5. **Multiple relationships?** YES — belongs to EvidenceItem; records custodian identity.
6. **Immutable or stateful?** Immutable (append-only).

### `Report` → **ENTITY ✅**
1. **Business entity?** YES — the final formal deliverable for an investigation.
2. **Identified independently?** YES — `report_id`.
3. **Own lifecycle?** YES — versioned; metadata in PostgreSQL, file in MinIO.
4. **Independent queries?** YES — "list all report versions for case X".
5. **Multiple relationships?** YES — belongs to Case; references MinIO object key, sha256.
6. **Immutable or stateful?** Immutable per version.

### `AuditEvent` → **ENTITY ✅**
1. **Business entity?** YES — a compliance/security log entry.
2. **Identified independently?** YES — `audit_event_id`.
3. **Own lifecycle?** YES — permanent, regulatory retention.
4. **Independent queries?** YES — "who accessed evidence X and when?".
5. **Multiple relationships?** YES — can reference any entity type.
6. **Immutable or stateful?** Immutable (append-only).
