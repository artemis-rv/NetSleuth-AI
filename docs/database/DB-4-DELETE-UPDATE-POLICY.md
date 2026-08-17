# DB-4: Delete & Update Policy

This document defines the exact behavior when records are deleted or updated in the NetSleuth-AI database. Cascade delete is forbidden for all forensic data.

---

## 1. Core Rule

> **No forensic record may be silently destroyed by a cascading database operation.**

PostgreSQL `ON DELETE CASCADE` is explicitly forbidden for any FK that crosses an evidentiary boundary. The default posture is `ON DELETE RESTRICT`, which forces the application to make an explicit, audited decision.

---

## 2. Delete Behavior by Entity

### `acquisition` Schema

| Table | ON DELETE | ON UPDATE | Notes |
|:---|:---|:---|:---|
| `acquisitions` | RESTRICT (application-only archive) | RESTRICT | Never hard-delete. Archive via `archived_at` timestamp column. |
| `evidence` | RESTRICT | RESTRICT | Immutable. Forbidden to delete. |

### `intelligence` Schema

| Table | ON DELETE parent | ON UPDATE parent | Notes |
|:---|:---|:---|:---|
| `flows` | RESTRICT | CASCADE PK update not applicable | Flows are never deleted individually. Archived with acquisition. |
| `protocol_events` | RESTRICT | N/A | Same as flows. |
| `artifacts` | RESTRICT | N/A | Same as flows. |

### `analytics` Schema

| Table | ON DELETE parent | Notes |
|:---|:---|:---|
| `findings` | RESTRICT | Never deleted. Versioned — a revised finding is a new row. |
| `model_runs` | RESTRICT | Never deleted. Long-term audit record. |

**Link tables in analytics:** If a flow is archived, `finding_flow_links` rows are NOT cascaded. The link remains to preserve the finding's evidentiary chain.

### `investigation` Schema

| Table | ON DELETE parent | Notes |
|:---|:---|:---|
| `investigation_cases` | RESTRICT | Never hard-delete. Soft-close via `status = closed` and `closed_at`. |
| `entities` | RESTRICT on Case | Entities are archived with the case. No cascade. |
| `relationships` | RESTRICT on Entity | If an entity is archived, relationships pointing to it must be explicitly resolved. |
| `behaviors` | RESTRICT on Case | Archived with case. |
| `timeline_events` | RESTRICT on Case | Immutable once written. |
| `mitre_mappings` | RESTRICT on Case | Archived with case. |
| `attack_chains` | RESTRICT on Case | Archived with case. |

**Link tables in investigation:**
- `case_acquisition_links`: RESTRICT on both sides. Removing an acquisition from a case is an explicit audited operation.
- `case_finding_links`: RESTRICT on both sides.
- `relationship_finding_links`: SET NULL on finding side if finding is archived (preserves relationship integrity).
- `entity_artifact_links`: RESTRICT on both sides.
- `behavior_finding_links`: RESTRICT on both sides.
- `mitre_finding_links`: RESTRICT on both sides.

### `custody` Schema

| Table | ON DELETE parent | Notes |
|:---|:---|:---|
| `evidence_items` | RESTRICT | Never deleted. Permanent legal record. |
| `custody_events` | RESTRICT | Append-only. Never deleted. |
| `reports` | RESTRICT | Never deleted. Versioned — new report is a new row. |

### `audit` Schema

| Table | ON DELETE parent | Notes |
|:---|:---|:---|
| `audit_events` | N/A (soft references only) | Never deleted. Regulatory retention. |

---

## 3. Update Behavior

Primary key columns (`acquisition_id`, `flow_id`, `event_id`, etc.) are immutable after creation. There is no `ON UPDATE CASCADE` in this schema. Any attempt to update a PK is a schema design error.

Mutable state columns (e.g., `InvestigationCase.status`, `InvestigationCase.updated_at`) are updated directly with no FK implications.

---

## 4. Archival Pattern

Instead of database-level DELETE, the system uses an **application-level archival pattern**:

```
archived_at  TIMESTAMPTZ  DEFAULT NULL
```

A `NULL` value means the record is active. A non-NULL value means the record has been archived. Application queries filter with `WHERE archived_at IS NULL` for active records.

This pattern applies to:
- `acquisitions`
- `investigation_cases`
- `entities`
- `behaviors`
- `relationships`
- `attack_chains`

It does **not** apply to append-only immutable records (`flows`, `protocol_events`, `artifacts`, `findings`, `timeline_events`, `custody_events`, `audit_events`, `reports`) — these are never modified or archived individually.

---

## 5. Forbidden Operations (to be enforced in repositories)

The application repository layer must explicitly reject the following:

| Operation | Reason |
|:---|:---|
| `DELETE FROM acquisitions` | Evidence immutability |
| `DELETE FROM evidence` | Evidence immutability |
| `DELETE FROM flows` | Forensic chain integrity |
| `DELETE FROM protocol_events` | Forensic chain integrity |
| `DELETE FROM artifacts` | Forensic chain integrity |
| `DELETE FROM findings` | Analytical result immutability |
| `DELETE FROM custody_events` | Legal chain of custody |
| `DELETE FROM audit_events` | Regulatory compliance |
| `UPDATE findings SET ...` (any field) | Use versioning — insert new row |
| `UPDATE acquisitions SET sha256 = ...` | Hash immutability |
