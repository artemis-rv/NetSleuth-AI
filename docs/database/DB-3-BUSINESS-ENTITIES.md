# DB-3: Business Entities

This document defines the durable **domain entities** that NetSleuth-AI manages.
It is grounded in the actual contracts (M1 `NetworkIntelligencePackage`, M3 `InvestigationCase`, M2 `Finding`, M4 `Report`) rather than mirroring Python implementation classes.

The central question for every candidate: **Is this a true business entity with its own identity, lifecycle, and independent query value?**

---

## 1. Business Entity Catalog

| Entity | Owner | Purpose | Canonical ID | Lifecycle | Mutable? | Persistent? |
|:---|:---|:---|:---|:---|:---|:---|
| `Acquisition` | M1 | Record of one ingested PCAP evidence file | `acquisition_id` | Immutable | NO | YES |
| `Evidence` | M1/M4 | Object-storage reference for the PCAP file | `evidence_id` | Immutable | NO | YES |
| `Flow` | M1 | One network connection (Zeek conn.log record) | `flow_id` | Immutable | NO | YES |
| `ProtocolEvent` | M1 | Application-layer event (DNS/HTTP/TLS) on a flow | `event_id` | Immutable | NO | YES |
| `Artifact` | M1 | Observable indicator extracted from an event | `artifact_id` | Immutable | NO | YES |
| `Finding` | M2 | Analytical detection result | `finding_id` | Versioned | NO (append-only) | YES |
| `ModelRun` | M2 | Record of one ML model execution | `run_id` | Immutable | NO | YES |
| `InvestigationCase` | M3 | The root investigation container | `case_id` | Stateful | YES | YES |
| `Entity` | M3 | An investigative actor (host, user, service) | `entity_id` | Stateful | YES | YES |
| `Relationship` | M3 | Directed link between two Entities | `relationship_id` | Derived | YES (during open case) | YES |
| `Behavior` | M3 | Correlated pattern of activity | `behavior_id` | Derived | YES (during open case) | YES |
| `TimelineEvent` | M3 | One timestamped point on the investigation timeline | `timeline_event_id` | Derived | NO | YES |
| `MITREMapping` | M3 | ATT&CK technique assignment to a Behavior/Finding | `mitre_mapping_id` | Derived/Versioned | NO | YES |
| `AttackChain` | M3 | Ordered sequence of correlated TTPs | `attack_chain_id` | Stateful/Derived | YES (during open case) | YES |
| `EvidenceItem` | M4 | Formal evidence entry in the custody record | `evidence_item_id` | Immutable | NO | YES |
| `ChainOfCustodyEvent` | M4 | One action in the evidence custody log | `custody_event_id` | Append-only | NO | YES |
| `Report` | M4 | Finalized report metadata record | `report_id` | Versioned | NO (version new copy) | YES |
| `AuditEvent` | Shared | Security and access audit log entry | `audit_event_id` | Append-only | NO | YES |

---

## 2. Non-Entity Candidates — Explicitly Rejected

These have Python classes but are **not** independent business entities in the database.

| Candidate | Decision | Reason |
|:---|:---|:---|
| `NetworkIntelligencePackage` | ❌ Not an entity | Transient aggregation. Persisted logically through its constituent parts in PostgreSQL. |
| `FindingsPackage` | ❌ Not an entity | Transient aggregation. |
| `RawZeekRecord` | ❌ Not an entity | Intermediate processing state only. Raw files retained in MinIO. |
| `DNSData` | ❌ Not an entity | Protocol payload. Stored as JSONB inside `ProtocolEvent`. Not independently queryable. |
| `HTTPData` | ❌ Not an entity | Protocol payload. Stored as JSONB inside `ProtocolEvent`. |
| `TLSData` | ❌ Not an entity | Protocol payload. Stored as JSONB inside `ProtocolEvent`. |
| `Endpoint` | ❌ Not an entity | Embedded value object on `Flow` (source/destination IP+port). Not independently managed. |
| `FlowProvenance` | ❌ Not an entity | Embedded provenance block on `Flow`. Not independently queried. |
| `EventProvenance` | ❌ Not an entity | Embedded provenance block on `ProtocolEvent`. |
| `ArtifactProvenance` | ❌ Not an entity | Embedded provenance block on `Artifact`. |
| `PacketReference` | ❌ Not an entity | Forensic offset value embedded on `Evidence` or `Flow`. No independent lifecycle. |
| `FeatureVector` (transient) | ❌ Not an entity | Discarded after inference. |
| `FeatureVector` (snapshot) | ⚠️ Stored artifact, not entity | Retained in PostgreSQL as an analytical snapshot tied to a `Finding`. Not independently queried. |

---

## 3. Schema Group Assignment

Entities are grouped into logical PostgreSQL schemas. This is a naming decision only — tables are designed in DB-6.

| Schema | Entities |
|:---|:---|
| `acquisition` | `Acquisition`, `Evidence` |
| `intelligence` | `Flow`, `ProtocolEvent`, `Artifact` |
| `analytics` | `Finding`, `ModelRun` |
| `investigation` | `InvestigationCase`, `Entity`, `Relationship`, `Behavior`, `TimelineEvent`, `MITREMapping`, `AttackChain` |
| `custody` | `EvidenceItem`, `ChainOfCustodyEvent`, `Report` |
| `audit` | `AuditEvent` |
