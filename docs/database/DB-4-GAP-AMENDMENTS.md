# DB-4: Gap Amendments (Pre-DB-5 Freeze)

This document resolves the five architectural gaps identified during the DB-4 gap review against the project specification (PS). Each gap is resolved as the **minimum change** required — attributes on existing entities, a new `identity` schema, or a retained column. No new business entities are introduced unless strictly necessary.

After this document is frozen, DB-4 is fully complete and DB-5 (Logical/ER Model) may begin.

---

## Gap 1 — Investigation Trigger and Goals

**Resolution: Attributes on `InvestigationCase`. No new entity.**

The following columns are added to `investigation_cases`:

| Column | Type | Purpose |
|:---|:---|:---|
| `trigger_type` | `TEXT` (enum) | How the investigation was opened: `manual`, `alert`, `complaint`, `scheduled`, `external_referral` |
| `trigger_description` | `TEXT` (nullable) | Free-text description of what prompted the investigation. |
| `external_case_id` | `TEXT` (nullable) | Reference to an external cybercrime case number or system ID. |
| `external_system` | `TEXT` (nullable) | Name of the external system the `external_case_id` belongs to (e.g., "CCTNS", "CMS"). |
| `reported_by` | `TEXT` (nullable) | Identity of the reporting party or source (free text or `user_id` reference). |
| `investigation_goals` | `TEXT[]` (nullable) | Ordered list of stated investigation objectives. |

**Rationale:** These are descriptive metadata on the case itself. They do not require a separate lifecycle, independent queries, or cross-entity relationships. Embedding them on `InvestigationCase` is correct.

**PS Alignment:** Satisfies the PS requirement for linking network evidence with reported cybercrime cases and supporting digital forensic workflows.

---

## Gap 2 — Detection Source and Alert Classification

**Resolution: Attributes on `findings`. No new entity.**

The `findings` table is extended with the following columns:

| Column | Type | Purpose |
|:---|:---|:---|
| `detection_method` | `TEXT` (enum) | Source of the detection: `anomaly`, `supervised_ml`, `signature`, `ioc`, `behavioral`, `rule` |
| `severity` | `TEXT` (enum) | `low`, `medium`, `high`, `critical` |
| `risk_score` | `FLOAT` (nullable) | Normalized 0.0–1.0 risk score from the detection engine. |
| `confidence` | `FLOAT` (nullable) | Normalized 0.0–1.0 confidence from the model/engine. |
| `model_id` | `TEXT` (nullable) | Reference to the specific model ID if ML-produced. May differ from `run_id`. |

**Decision on a separate `Alert` entity:** Rejected. The `Finding` is the shared analytical output for all detection sources. Whether it came from anomaly ML, a signature engine, or an IOC match, the output maps to the same forensic concept: a detected event with severity, confidence, and supporting evidence references. A separate `Alert` entity would create two parallel persistence paths for the same concept with no query benefit.

**Note on Suricata/external signatures:** When Suricata or equivalent is integrated, its alerts are imported as `Finding` records with `detection_method = 'signature'` and a `run_id` pointing to the Suricata engine's `ModelRun` record. No schema change is required.

**PS Alignment:** Satisfies the PS requirement for combining signature, IOC, anomaly, and behavioural detection into a unified severity/risk-scored output.

---

## Gap 3 — Packet-Level Forensic Traceability

**Resolution: Explicit columns on `flows`. The M1 contract already carries this data — the DB must persist it.**

The `network-intelligence-v1.json` contract already defines `packet_references` on the `NetworkIntelligencePackage` with:
- `packet_start` (first frame number)
- `packet_end` (last frame number)
- `byte_offset` (byte offset into the PCAP file)
- `timestamp_start`, `timestamp_end`

DB-3 decided `PacketReference` is an embedded value object, not a business entity. That decision stands. However, the DB must persist these values so the traceability chain is intact.

**Persistence strategy:** The relevant packet reference fields are stored as nullable columns on the `flows` table (since each flow maps to a specific range of packets in the PCAP):

| Column | Type | Purpose |
|:---|:---|:---|
| `pcap_frame_start` | `BIGINT` (nullable) | First frame number in the PCAP for this flow. |
| `pcap_frame_end` | `BIGINT` (nullable) | Last frame number in the PCAP for this flow. |
| `pcap_byte_offset` | `BIGINT` (nullable) | Byte offset into the PCAP where this flow's packets begin. |
| `pcap_timestamp_start` | `TIMESTAMPTZ` (nullable) | First packet timestamp. |
| `pcap_timestamp_end` | `TIMESTAMPTZ` (nullable) | Last packet timestamp. |

**The complete traceability chain is then:**

```
Finding
  ↓ finding_flow_links
Flow  (pcap_frame_start / pcap_byte_offset)
  ↓ acquisition_id → evidence_id
Evidence  (MinIO object_key, sha256)
  ↓
Original PCAP in netsleuth-evidence bucket
```

This satisfies the PS's court-admissibility requirement: any AI finding can be traced back to a specific byte range in the original, SHA-256-verified, immutable PCAP.

**PS Alignment:** Satisfies the PS self-auditing requirement that AI findings link back to supporting packets, sessions, and hashes.

---

## Gap 4 — Acquisition Source and Live Traffic Metadata

**Resolution: Attributes on `acquisitions`. No new entity.**

The PS requires support for both stored PCAP/PCAPNG and live captured traffic. The `acquisitions` table is extended with:

| Column | Type | Purpose |
|:---|:---|:---|
| `source_type` | `TEXT` (enum) | `pcap`, `pcapng`, `live_interface`, `tap`, `span`, `cloud_mirror`, `virtual_interface` |
| `capture_interface` | `TEXT` (nullable) | Network interface name for live captures (e.g., `eth0`, `enp3s0`). |
| `capture_filter` | `TEXT` (nullable) | BPF filter string applied during capture (audit trail). |
| `source_environment` | `TEXT` (nullable) | Free-text description of the capture environment (e.g., "DMZ router", "cloud VPC east-1"). |
| `capture_started_at` | `TIMESTAMPTZ` (nullable) | When the capture session started (relevant for live/tap). |
| `capture_ended_at` | `TIMESTAMPTZ` (nullable) | When the capture session ended (nullable for ongoing live captures). |

**Note:** The current `file_name`, `file_size`, `sha256`, and `format` fields on `Acquisition` remain as-is. For live captures, `sha256` records the hash of the captured file once sealed. `file_name` records the output filename.

**PS Alignment:** Satisfies the PS requirement for both stored PCAP/PCAPNG and live network traffic acquisition.

---

## Gap 5 — Identity, Roles, Case Access, and External Case Reference

**Resolution: New `identity` PostgreSQL schema, separate from all forensic schemas. External case reference resolved under Gap 1.**

**Sub-gap 5a: External case reference** — Resolved in Gap 1 above (`external_case_id`, `external_system` on `InvestigationCase`).

**Sub-gap 5b: Users, roles, and case access** — This belongs to the application/auth domain, completely separate from the forensic core.

A new `identity` schema is introduced with three tables:

### `identity.users`
| Column | Type | Purpose |
|:---|:---|:---|
| `user_id` | `TEXT` PK | Unique user identifier. |
| `username` | `TEXT` UNIQUE | Login name. |
| `full_name` | `TEXT` | Display name. |
| `email` | `TEXT` UNIQUE | Email address. |
| `role` | `TEXT` | `administrator`, `investigator`, `analyst` |
| `is_active` | `BOOLEAN` | Whether the account is active. |
| `created_at` | `TIMESTAMPTZ` | Account creation timestamp. |
| `last_login_at` | `TIMESTAMPTZ` (nullable) | Last successful login. |

### `identity.case_access`
| Column | Type | Purpose |
|:---|:---|:---|
| `case_id` | `TEXT` FK → `investigation.investigation_cases` | Case being accessed. |
| `user_id` | `TEXT` FK → `identity.users` | User being granted access. |
| `access_level` | `TEXT` | `read`, `write`, `admin` |
| `granted_at` | `TIMESTAMPTZ` | When access was granted. |
| `granted_by` | `TEXT` FK → `identity.users` | Who granted the access. |
| `expires_at` | `TIMESTAMPTZ` (nullable) | Optional access expiry. |

**Uniqueness:** `(case_id, user_id)` — a user has one access level per case.

### `audit_events` — actor reference
The existing `audit_events` table in the `audit` schema gains one additional column:

| Column | Type | Purpose |
|:---|:---|:---|
| `actor_id` | `TEXT` (nullable) | `user_id` of the user who triggered the event. Soft reference (no FK) to survive user deactivation. |

**Isolation rule:** The `identity` schema must NOT be imported as a FK dependency into `acquisition`, `intelligence`, `analytics`, `investigation`, or `custody` schemas. The only permitted cross-reference is the soft `actor_id` on `audit_events` and the FK on `case_access`. This preserves the forensic core's independence from the authentication layer.

**PS Alignment:** Satisfies the PS security architecture requirements for Administrator, Investigator, and Analyst roles with authentication, authorization, and audit logging.

---

## Summary of Changes to Existing Entities

| Entity | Change Type | Columns Added |
|:---|:---|:---|
| `Acquisition` | Extended | `source_type`, `capture_interface`, `capture_filter`, `source_environment`, `capture_started_at`, `capture_ended_at` |
| `Flow` | Extended | `pcap_frame_start`, `pcap_frame_end`, `pcap_byte_offset`, `pcap_timestamp_start`, `pcap_timestamp_end` |
| `Finding` | Extended | `detection_method`, `severity`, `risk_score`, `confidence`, `model_id` |
| `InvestigationCase` | Extended | `trigger_type`, `trigger_description`, `external_case_id`, `external_system`, `reported_by`, `investigation_goals` |
| `AuditEvent` | Extended | `actor_id` |

## Summary of New Schemas / Tables

| New Object | Type | Notes |
|:---|:---|:---|
| `identity` | PostgreSQL schema | Application/auth domain. Isolated from forensic schemas. |
| `identity.users` | Table | User accounts and roles. |
| `identity.case_access` | Table | Case-level permission assignments. |

---

## Updated Entity Count

| Previously | Additions | Final |
|:---|:---|:---|
| 18 confirmed business entities | +2 (`identity.users`, `identity.case_access`) | **20 entities** |

`identity.users` and `identity.case_access` are application-domain entities, not forensic entities. They are listed separately from the core 18.

---

## DB-4 Final Status

All five gaps are resolved. No further architectural questions remain before DB-5.

```text
DB-0  Storage Boundary & Ownership     ✅
DB-1  Complete Data Inventory          ✅
DB-2  Lifecycle + Persistence Policy   ✅
DB-3  Business Entities (18 core)      ✅
DB-4  Relationships + Cardinality      ✅
DB-4  Gap Amendments (Pre-DB-5)        ✅
```

**DB-5: Logical / ER Model may now begin.**
