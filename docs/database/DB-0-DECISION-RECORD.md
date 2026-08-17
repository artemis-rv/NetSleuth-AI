# DB-0: Decision Record

This document records the overarching architecture decisions for the NetSleuth-AI persistence layer (DB-0 phase).

## Decision 1: Storage Infrastructure
- **PostgreSQL** is the structured system of record.
- **MinIO** is the object/file store.
- **No additional databases** (MongoDB, Neo4j, OpenSearch, Elasticsearch, Redis, Kafka, Vector DBs) are introduced in V1.

## Decision 2: Relational Integrity over Document Blobs
- The `NetworkIntelligencePackage` (and other large logical entities) are **not** persisted as single giant JSONB blobs.
- They are stored relationally using canonical entities (`Acquisition`, `Flow`, `ProtocolEvent`, etc.) with foreign keys to support complex investigator queries.
- JSONB is used selectively for genuinely variable structures (payloads, probability maps, flexible metadata).

## Decision 3: Pydantic Classes to Tables Mapping
- We do **not** make a table for every Pydantic class automatically.
- Example: `DNSData`, `HTTPData`, and `TLSData` do not automatically become three separate tables.
- Decisions are made during DB-4/DB-8 based on query patterns, cardinality, relationships, immutability, and storage cost.

## Decision 4: Transient vs. Permanent Data
- **RawZeekRecord**: Not stored in Postgres. It's intermediate. Raw logs stay in MinIO.
- **M2 FeatureVectors**: Not all are stored. Only those necessary for finding reproducibility, audits, or experiments.

## Decision 5: Deliverable Scope
- The DB-0 deliverable is strictly limited to documentation architecture artifacts (`DB-0-STORAGE-BOUNDARY.md`, `DB-0-DATA-OWNERSHIP.md`, `DB-0-SOURCE-OF-TRUTH.md`, `DB-0-ID-STRATEGY.md`, and this file).
- No tables, migrations, ORM models, or repositories are created in this phase.
- PostgreSQL schema creation will only happen after completing phases DB-1 through DB-6.
