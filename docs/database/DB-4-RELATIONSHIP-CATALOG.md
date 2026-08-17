# DB-4: Relationship Catalog

This document catalogs every relationship between the 18 confirmed business entities from DB-3. All relationships are grounded in the actual M1/M3/M4 contracts, not assumptions.

---

## 1. `acquisition` Schema Relationships

### Acquisition → Evidence
```
Acquisition ──── 1:N ───► Evidence
```
- One acquisition (one PCAP ingest event) produces exactly one `Evidence` record that points to the MinIO object. The cardinality is modelled as `1:N` to allow future multiple-output formats (e.g., a re-exported subset), but in V1 this will typically be `1:1`.
- `Evidence.acquisition_id` → FK → `Acquisition.acquisition_id`

---

## 2. `intelligence` Schema Relationships

### Acquisition → Flow
```
Acquisition ──── 1:N ───► Flow
```
- One acquisition contains many flows (one per Zeek `conn.log` record / UID).
- `Flow.acquisition_id` → FK → `Acquisition.acquisition_id`

### Flow → ProtocolEvent
```
Flow ──── 1:N ───► ProtocolEvent
```
- One flow (identified by `zeek_uid`) can have many protocol-specific events (one DNS event, one or more HTTP requests, one TLS handshake). Joined via `zeek_uid`.
- `ProtocolEvent.flow_id` → FK → `Flow.flow_id`

### ProtocolEvent → Artifact
```
ProtocolEvent ──── 1:N ───► Artifact
```
- One protocol event can produce many artifacts (e.g., a DNS event produces a DOMAIN artifact and multiple IP artifacts from its answers).
- `Artifact.source_event_id` → FK → `ProtocolEvent.event_id` (nullable)
- `Artifact.flow_id` → FK → `Flow.flow_id` (nullable — Artifact may also be derived directly from a flow)

**Key decision:** Artifact can optionally exist without a `source_event_id` (e.g., an artifact derived purely from a flow). Both FK columns are nullable.

---

## 3. `analytics` Schema Relationships

### Finding → Acquisition (direct reference)
```
Finding ──── N:1 ───► Acquisition
```
- Every finding is scoped to one acquisition.
- `Finding.acquisition_id` → FK → `Acquisition.acquisition_id`

### Finding ↔ Flow (association)
```
Finding ──── N:M ───► Flow
```
- A finding may reference multiple flows as supporting evidence. A flow can appear in multiple findings.
- Implemented as a link table: `finding_flow_links (finding_id, flow_id)`

### Finding ↔ ProtocolEvent (association)
```
Finding ──── N:M ───► ProtocolEvent
```
- A finding may reference multiple protocol events.
- Link table: `finding_event_links (finding_id, event_id)`

### Finding ↔ Artifact (association)
```
Finding ──── N:M ───► Artifact
```
- A finding may reference multiple artifacts (e.g., the suspicious domain, the external IP).
- Link table: `finding_artifact_links (finding_id, artifact_id)`

### Finding → ModelRun
```
Finding ──── N:1 ───► ModelRun
```
- Each finding is produced by exactly one model run. A model run can produce many findings.
- `Finding.run_id` → FK → `ModelRun.run_id`

---

## 4. `investigation` Schema Relationships

### InvestigationCase → Acquisition (N:M — critical decision)
```
InvestigationCase ──── N:M ───► Acquisition
```
- **Decision:** `N:M`. A real investigation may span multiple evidence files (e.g., traffic captured at two different network segments). A single acquisition may also be re-examined across multiple related cases.
- Link table: `case_acquisition_links (case_id, acquisition_id)`

### InvestigationCase → Finding (N:M — with role)
```
InvestigationCase ──── N:M ───► Finding
```
- The `investigation-case-v1.1.json` contract uses `FindingReference` objects with a `role` field (`primary`, `supporting`, `related`). This confirms N:M with a role attribute on the join.
- Link table: `case_finding_links (case_id, finding_id, role)`

### InvestigationCase → Entity (1:N)
```
InvestigationCase ──── 1:N ───► Entity
```
- Entities belong to one case in V1. An entity like "the attacker's IP" is scoped to the investigation that identified it.
- `Entity.case_id` → FK → `InvestigationCase.case_id`

### InvestigationCase → TimelineEvent (1:N)
```
InvestigationCase ──── 1:N ───► TimelineEvent
```
- Timeline events are scoped to one case.
- `TimelineEvent.case_id` → FK → `InvestigationCase.case_id`

### InvestigationCase → AttackChain (1:1)
```
InvestigationCase ──── 1:1 ───► AttackChain
```
- The `investigation-case-v1.1.json` contract has a single `attack_chain` property at the root of a case — one chain per case.
- `AttackChain.case_id` → FK → `InvestigationCase.case_id` (unique)

### InvestigationCase → MITREMapping (1:N)
```
InvestigationCase ──── 1:N ───► MITREMapping
```
- The contract has a `mitre_mappings` array at the case level. Each mapping belongs to one case.
- `MITREMapping.case_id` → FK → `InvestigationCase.case_id`

### Entity ↔ Entity via Relationship (self-referencing N:M)
```
Entity ──── N:M ───► Entity
      (via Relationship)
```
- The `Relationship` entity (approved in DB-3) has `source_entity_id` and `target_entity_id`, both pointing to `Entity`. This is a directed graph edge.
- `Relationship.source_entity_id` → FK → `Entity.entity_id`
- `Relationship.target_entity_id` → FK → `Entity.entity_id`
- `Relationship.case_id` → FK → `InvestigationCase.case_id`

### Relationship → Finding (N:M, via evidence_ids in contract)
```
Relationship ──── N:M ───► Finding
```
- The contract's `Relationship` object carries `evidence_ids[]` which can reference finding IDs. This is a weak cross-schema reference resolved at query time.
- Persisted as: `relationship_finding_links (relationship_id, finding_id)` — optional, only populated when evidence exists.

### Entity → Artifact (N:M — cross-schema pivot)
```
Entity ──── N:M ───► Artifact
```
- An investigative entity (e.g., a domain name) may correspond to one or more M1 Artifacts. This enables pivoting from the investigation graph back to raw observations.
- Link table: `entity_artifact_links (entity_id, artifact_id)`

### Behavior → Finding (N:M)
```
Behavior ──── N:M ───► Finding
```
- A behavior pattern (e.g., "DNS tunnelling") is supported by one or more findings. A finding can be correlated with multiple behaviors.
- Link table: `behavior_finding_links (behavior_id, finding_id)`
- `Behavior.case_id` → FK → `InvestigationCase.case_id`

### MITREMapping ↔ Finding (N:M — confirmed by contract)
```
MITREMapping ──── N:M ───► Finding
```
- The `MitreMapping` contract object has `source_finding_ids[]`. One MITRE technique can be supported by multiple findings; one finding can map to multiple techniques.
- Link table: `mitre_finding_links (mitre_mapping_id, finding_id)`

### AttackChain → TimelineEvent (N:M via stages)
```
AttackChain ──── N:M ───► TimelineEvent
```
- The contract defines `AttackChainStage` objects (with `stage_id`, `event_ids[]`, `finding_ids[]`). A stage references timeline events and findings. The `AttackChainStage` is an embedded concept within `AttackChain` — **not** a separate business entity.
- Persisted as JSONB `stages` column on `AttackChain`, not a separate table. The `event_ids` are soft references to `TimelineEvent.timeline_event_id` resolved at read time.

---

## 5. `custody` Schema Relationships

### InvestigationCase → EvidenceItem (1:N)
```
InvestigationCase ──── 1:N ───► EvidenceItem
```
- Evidence items are registered under a case.
- `EvidenceItem.case_id` → FK → `InvestigationCase.case_id`

### EvidenceItem → ChainOfCustodyEvent (1:N — append-only)
```
EvidenceItem ──── 1:N ───► ChainOfCustodyEvent
```
- Each custody action (ingest, verify, transfer, export) appends a new event.
- `ChainOfCustodyEvent.evidence_item_id` → FK → `EvidenceItem.evidence_item_id`

### InvestigationCase → Report (1:N)
```
InvestigationCase ──── 1:N ───► Report
```
- A case can have multiple report versions.
- `Report.case_id` → FK → `InvestigationCase.case_id`

---

## 6. `audit` Schema Relationships

### AuditEvent → any entity (polymorphic soft reference)
```
AuditEvent ──── N:1 ───► any entity (soft FK)
```
- Audit events reference the entity they pertain to via `target_entity_type` + `target_entity_id` columns (not enforced FKs). This avoids coupling the audit log to every schema.
