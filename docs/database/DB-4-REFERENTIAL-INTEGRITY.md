# DB-4: Referential Integrity

This document defines how PostgreSQL must enforce the relationships from DB-4-RELATIONSHIP-CATALOG. It distinguishes between hard FK constraints, soft references, and uniqueness rules.

---

## 1. Hard Foreign Key Constraints

These relationships are enforced by PostgreSQL `FOREIGN KEY` constraints. Violations are rejected at the database level.

| Table | Column | References | Nullable? | Note |
|:---|:---|:---|:---|:---|
| `evidence` | `acquisition_id` | `acquisitions.acquisition_id` | NO | Every evidence record has an acquisition. |
| `flows` | `acquisition_id` | `acquisitions.acquisition_id` | NO | Every flow belongs to an acquisition. |
| `flows` | `evidence_id` | `evidence.evidence_id` | YES | Optional link to specific evidence object. |
| `protocol_events` | `flow_id` | `flows.flow_id` | NO | Every event belongs to a flow. |
| `protocol_events` | `acquisition_id` | `acquisitions.acquisition_id` | NO | Denormalised for query performance. |
| `artifacts` | `source_event_id` | `protocol_events.event_id` | YES | Artifact may lack a specific event source. |
| `artifacts` | `flow_id` | `flows.flow_id` | YES | Artifact may be derived from flow only. |
| `artifacts` | `acquisition_id` | `acquisitions.acquisition_id` | NO | All artifacts scoped to an acquisition. |
| `findings` | `acquisition_id` | `acquisitions.acquisition_id` | NO | Every finding scoped to an acquisition. |
| `findings` | `run_id` | `model_runs.run_id` | NO | Every finding produced by a model run. |
| `entities` | `case_id` | `investigation_cases.case_id` | NO | Entities are scoped to a case. |
| `relationships` | `case_id` | `investigation_cases.case_id` | NO | |
| `relationships` | `source_entity_id` | `entities.entity_id` | NO | |
| `relationships` | `target_entity_id` | `entities.entity_id` | NO | |
| `behaviors` | `case_id` | `investigation_cases.case_id` | NO | |
| `timeline_events` | `case_id` | `investigation_cases.case_id` | NO | |
| `mitre_mappings` | `case_id` | `investigation_cases.case_id` | NO | |
| `attack_chains` | `case_id` | `investigation_cases.case_id` | NO | |
| `evidence_items` | `case_id` | `investigation_cases.case_id` | NO | |
| `custody_events` | `evidence_item_id` | `evidence_items.evidence_item_id` | NO | |
| `reports` | `case_id` | `investigation_cases.case_id` | NO | |
| `case_acquisition_links` | `case_id` | `investigation_cases.case_id` | NO | |
| `case_acquisition_links` | `acquisition_id` | `acquisitions.acquisition_id` | NO | |
| `case_finding_links` | `case_id` | `investigation_cases.case_id` | NO | |
| `case_finding_links` | `finding_id` | `findings.finding_id` | NO | |
| `finding_flow_links` | `finding_id` | `findings.finding_id` | NO | |
| `finding_flow_links` | `flow_id` | `flows.flow_id` | NO | |
| `finding_event_links` | `finding_id` | `findings.finding_id` | NO | |
| `finding_event_links` | `event_id` | `protocol_events.event_id` | NO | |
| `finding_artifact_links` | `finding_id` | `findings.finding_id` | NO | |
| `finding_artifact_links` | `artifact_id` | `artifacts.artifact_id` | NO | |
| `relationship_finding_links` | `relationship_id` | `relationships.relationship_id` | NO | |
| `relationship_finding_links` | `finding_id` | `findings.finding_id` | NO | |
| `entity_artifact_links` | `entity_id` | `entities.entity_id` | NO | |
| `entity_artifact_links` | `artifact_id` | `artifacts.artifact_id` | NO | |
| `behavior_finding_links` | `behavior_id` | `behaviors.behavior_id` | NO | |
| `behavior_finding_links` | `finding_id` | `findings.finding_id` | NO | |
| `mitre_finding_links` | `mitre_mapping_id` | `mitre_mappings.mitre_mapping_id` | NO | |
| `mitre_finding_links` | `finding_id` | `findings.finding_id` | NO | |

---

## 2. Soft (Polymorphic) References — No FK Constraint

These references are not enforced by database constraints. They are resolved at the application layer.

| Table | Columns | References | Reason |
|:---|:---|:---|:---|
| `audit_events` | `target_entity_type`, `target_entity_id` | Any entity in any schema | Decouples audit log from schema evolution. Integrity enforced by application layer. |
| `attack_chains` | JSONB `stages[].event_ids[]` | `timeline_events.timeline_event_id` | Ordered stage structure embedded as JSONB; soft references resolved at read time. |
| `attack_chains` | JSONB `stages[].finding_ids[]` | `findings.finding_id` | Same as above. |

---

## 3. Uniqueness Constraints

| Table | Unique Constraint | Purpose |
|:---|:---|:---|
| `acquisitions` | `(acquisition_id)` | PK |
| `acquisitions` | `(sha256)` | Prevent duplicate PCAP ingestion. Same file must not be ingested twice. |
| `evidence` | `(evidence_id)` | PK |
| `attack_chains` | `(case_id)` | Enforces the 1:1 relationship between case and attack chain. |
| `case_acquisition_links` | `(case_id, acquisition_id)` | No duplicate case-acquisition link. |
| `case_finding_links` | `(case_id, finding_id)` | No duplicate case-finding link. |
| `finding_flow_links` | `(finding_id, flow_id)` | No duplicate link. |
| `finding_event_links` | `(finding_id, event_id)` | No duplicate link. |
| `finding_artifact_links` | `(finding_id, artifact_id)` | No duplicate link. |
| `entity_artifact_links` | `(entity_id, artifact_id)` | No duplicate link. |
| `behavior_finding_links` | `(behavior_id, finding_id)` | No duplicate link. |
| `mitre_finding_links` | `(mitre_mapping_id, finding_id)` | No duplicate link. |
| `relationship_finding_links` | `(relationship_id, finding_id)` | No duplicate link. |

---

## 4. Cross-Schema Referencing Policy

PostgreSQL allows cross-schema FK references within the same database. The following cross-schema FKs are intentional:

| From Schema | To Schema | Relationship |
|:---|:---|:---|
| `intelligence` | `acquisition` | `flows.acquisition_id` → `acquisitions.acquisition_id` |
| `analytics` | `acquisition` | `findings.acquisition_id` → `acquisitions.acquisition_id` |
| `analytics` | `analytics` | `findings.run_id` → `model_runs.run_id` |
| `investigation` | `analytics` | `case_finding_links.finding_id` → `findings.finding_id` |
| `investigation` | `acquisition` | `case_acquisition_links.acquisition_id` → `acquisitions.acquisition_id` |
| `investigation` | `intelligence` | `entity_artifact_links.artifact_id` → `artifacts.artifact_id` |
| `investigation` | `analytics` | `behavior_finding_links.finding_id` → `findings.finding_id` |
| `investigation` | `analytics` | `mitre_finding_links.finding_id` → `findings.finding_id` |
| `custody` | `investigation` | `evidence_items.case_id` → `investigation_cases.case_id` |
| `custody` | `investigation` | `reports.case_id` → `investigation_cases.case_id` |
