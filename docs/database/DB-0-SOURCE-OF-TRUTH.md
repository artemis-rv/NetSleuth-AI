# DB-0: Source of Truth

## 1. Immutability Principle
Downstream systems never rewrite upstream observations. The canonical record at each phase is fixed once produced.

## 2. System of Record Mapping
Freeze this exact source of truth mapping:

| Data Type | Source of Truth |
| :--- | :--- |
| **Original evidence bytes** | → MinIO |
| **Acquisition identity/hash** | → M1 + PostgreSQL |
| **Network observations** | → M1 |
| **Analytical finding** | → M2 |
| **Correlation/behavior/investigation** | → M3 |
| **MITRE mapping** | → M3 |
| **Final report/evidence package** | → M4 |

## 3. Transient Processing Records
- **RawZeekRecord**: This is not stored as a normal PostgreSQL entity. It is strictly an intermediate processing representation. The raw Zeek files remain available in MinIO for provenance and reprocessing.
