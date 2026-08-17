# DB-4: Cardinality Rules

Complete cardinality matrix for all 18 business entities. This is the authoritative reference for DB-5 (ER model) and DB-6 (schema design).

---

## Cardinality Matrix

| # | Source | Relationship | Target | Cardinality | Required? | Implementation |
|:--|:---|:---|:---|:---|:---|:---|
| 1 | `Acquisition` | has evidence | `Evidence` | 1:N (V1: 1:1) | YES | FK on Evidence |
| 2 | `Acquisition` | generates | `Flow` | 1:N | YES | FK on Flow |
| 3 | `Acquisition` | scopes | `Finding` | 1:N | YES | FK on Finding |
| 4 | `Flow` | has events | `ProtocolEvent` | 1:N | NO | FK on ProtocolEvent |
| 5 | `ProtocolEvent` | produces | `Artifact` | 1:N | NO | FK on Artifact (nullable) |
| 6 | `Flow` | produces | `Artifact` | 1:N | NO | FK on Artifact (nullable) |
| 7 | `Finding` | references | `Flow` | N:M | NO | `finding_flow_links` |
| 8 | `Finding` | references | `ProtocolEvent` | N:M | NO | `finding_event_links` |
| 9 | `Finding` | references | `Artifact` | N:M | NO | `finding_artifact_links` |
| 10 | `ModelRun` | produces | `Finding` | 1:N | YES | FK on Finding |
| 11 | `InvestigationCase` | spans | `Acquisition` | N:M | YES | `case_acquisition_links` |
| 12 | `InvestigationCase` | references | `Finding` | N:M (with role) | NO | `case_finding_links` |
| 13 | `InvestigationCase` | contains | `Entity` | 1:N | NO | FK on Entity |
| 14 | `InvestigationCase` | contains | `TimelineEvent` | 1:N | NO | FK on TimelineEvent |
| 15 | `InvestigationCase` | has | `AttackChain` | 1:1 | NO | FK on AttackChain (unique) |
| 16 | `InvestigationCase` | has | `MITREMapping` | 1:N | NO | FK on MITREMapping |
| 17 | `InvestigationCase` | has | `Behavior` | 1:N | NO | FK on Behavior |
| 18 | `Entity` | relates to | `Entity` (via `Relationship`) | N:M (directed, self-ref) | NO | `Relationship` table |
| 19 | `Relationship` | corroborated by | `Finding` | N:M | NO | `relationship_finding_links` |
| 20 | `Entity` | corresponds to | `Artifact` | N:M | NO | `entity_artifact_links` |
| 21 | `Behavior` | supported by | `Finding` | N:M | NO | `behavior_finding_links` |
| 22 | `MITREMapping` | sourced from | `Finding` | N:M | NO | `mitre_finding_links` |
| 23 | `AttackChain` | references | `TimelineEvent` | N:M (via JSONB stages) | NO | JSONB `stages` on AttackChain |
| 24 | `InvestigationCase` | has | `EvidenceItem` | 1:N | NO | FK on EvidenceItem |
| 25 | `EvidenceItem` | has | `ChainOfCustodyEvent` | 1:N | YES | FK on ChainOfCustodyEvent |
| 26 | `InvestigationCase` | produces | `Report` | 1:N | NO | FK on Report |
| 27 | `AuditEvent` | targets | any entity | polymorphic soft ref | NO | type + id columns |

---

## Link Tables Required

These N:M relationships require explicit association tables:

| Link Table | Left FK | Right FK | Additional Columns |
|:---|:---|:---|:---|
| `case_acquisition_links` | `case_id` | `acquisition_id` | `added_at` |
| `case_finding_links` | `case_id` | `finding_id` | `role` (primary/supporting/related) |
| `finding_flow_links` | `finding_id` | `flow_id` | — |
| `finding_event_links` | `finding_id` | `event_id` | — |
| `finding_artifact_links` | `finding_id` | `artifact_id` | — |
| `relationship_finding_links` | `relationship_id` | `finding_id` | — |
| `entity_artifact_links` | `entity_id` | `artifact_id` | — |
| `behavior_finding_links` | `behavior_id` | `finding_id` | — |
| `mitre_finding_links` | `mitre_mapping_id` | `finding_id` | — |

---

## Cardinality Decisions With Rationale

### `InvestigationCase → Acquisition` is N:M (not 1:N)
A real forensic investigation routinely spans multiple captured traffic files (e.g., ingress + egress captures, multiple network segments, over multiple days). Constraining this to 1:N would force investigators to create a separate case per PCAP, which does not match actual forensic workflows.

### `Artifact.source_event_id` is nullable
An artifact can be derived directly from a flow (e.g., source/destination IPs) without belonging to any specific protocol event. Making it required would lose IP-level artifacts on flows with no application-layer events.

### `AttackChainStage` is JSONB, not a table
The contract defines stages as an ordered list inside `AttackChain`, with `stage_id`, `event_ids[]`, and `finding_ids[]`. The stage has no independent identity beyond its parent chain and does not need to be independently queried in V1. Storing it as JSONB on `AttackChain` preserves the ordered structure and avoids an extra table with no query benefit in V1. The soft references to `TimelineEvent` and `Finding` IDs are resolved at read time.

### `MITREMapping → Finding` is N:M
The contract's `MitreMapping` object has `source_finding_ids[]` (an array). One MITRE technique can be corroborated by many findings. One finding can be mapped to multiple techniques (e.g., a DNS tunnelling finding maps to both T1071.004 and T1048).

### `AuditEvent` uses soft (polymorphic) references
Enforcing a hard FK from `AuditEvent` to every table would require either a separate audit table per entity or a complex union constraint. A `target_entity_type` + `target_entity_id` polymorphic pattern decouples the audit log from schema evolution, which is essential for a long-lived compliance record.
