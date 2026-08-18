# NetSleuth-AI Integration & MITRE ATT&CK Mapping Status

## 1. System Integration Overview

The NetSleuth-AI forensic engine consists of four core modules (M1 through M4) integrated via `ForensicPipelineOrchestrator` (`backend/app/orchestrator/pipeline.py`).

```text
PCAP Input
   │
   ▼
[ M1 Packet Intelligence ]
   │ (Extracts NetworkIntelligencePackage V1)
   ├──► PostgreSQL (acquisitions, flows, protocol_events, artifacts)
   └──► MinIO (netsleuth-evidence, netsleuth-zeek)
   │
   ▼
[ M2 Analysis Engine ]
   │ (Extracts FindingsPackage V1)
   └──► PostgreSQL (findings, evidence_links, anomaly_scores)
   │
   ▼
[ M3 Correlation Engine ]
   │ (Assembles InvestigationCase V1.1)
   └──► PostgreSQL (cases, timeline_events, case_finding_links)
   │
   ▼
[ M4 Reporting Engine ]
   │ (Produces Report V1 & Evidence Packages)
   └──► PostgreSQL + MinIO (reports, evidence_integrity)
```

---

## 2. MITRE ATT&CK Mapping Architecture & Status

### Implemented Components
1. **Knowledge Repository (`backend/app/engines/correlation/mitre/repository.py`)**:
   - Static mapping profile defined in `network-evidence-v1.json`.
   - Caches technique definitions and maps activity classes to MITRE ATT&CK Tactics & Techniques.

2. **Runtime Mapper (`backend/app/engines/correlation/mitre/mapper.py`)**:
   - `MitreMapper` evaluates M2 findings against M3 telemetry capabilities.
   - Assigns mapping status (`SUPPORTED`, `PARTIAL`, `POTENTIAL`) and adjusts confidence scores based on telemetry evidence.

3. **Attack Chain Builder (`backend/app/engines/correlation/investigation/case_builder.py`)**:
   - `_build_attack_chain()` reads `ctx.mitre_mappings`.
   - Sorts stages chronologically, deduplicates them, and generates stage documents inside the `InvestigationCase` payload.

### Current Pipeline Status
- **Domain Logic**: Complete and verified by unit tests.
- **Orchestrator Injection**: Pending direct call inside `pipeline.py`. Currently, `pipeline.py` populates finding references directly into `InvestigationContext` without invoking `MitreMapper.map_finding()`.
- **Next Step**: Wire `MitreMapper` into `ForensicPipelineOrchestrator` to populate `ctx.mitre_mappings` automatically during M3 execution.

---

## 3. End-to-End Test Architecture

NetSleuth-AI uses a two-tier test strategy:

1. **Fast E2E Pipeline Integration Test** (`tests/integration/e2e/test_full_forensic_chain.py`):
   - Primary CI test.
   - Bypasses live Zeek/Docker dependencies by utilizing deterministic mock packages.
   - Validates multi-engine transaction boundaries, SQLAlchemy UOW, dynamic UUID mapping, and PostgreSQL persistence.

2. **Full Forensic Real-PCAP System Test** (`tests/integration/e2e/test_full_forensic_chain_real_pcap.py`):
   - Dedicated integration test for real PCAP parsing (`PCAP -> Zeek -> M1 -> M2 -> M3 -> M4 -> DB`).
   - Guarded by environment flag `RUN_REAL_PCAP_TESTS=1`.
