# Contract Status

| Contract | Producer | Consumer | Status |
|----------|----------|----------|--------|
| NetworkIntelligencePackage | M1 | M2/M3 | V1 |
| Finding | M2 | M3 | V1 |
| InvestigationCase | M3 | M4 | V1.1 |
| EvidenceReference | M3/M4 boundary | M4 | V1 |
| EvidenceIntegrity | M4 | M4 boundary | V1 (FROZEN) |
| Report | M4 Report Engine | Consumers (UI/CLI/Exporter) | V1 (FROZEN) |
| Report | M4 Report Engine | Consumers (UI/CLI/Exporter) | V1.1 (FROZEN) |

## Report Schema Versioning (V1 & V1.1)

- `docs/contracts/report-v1.json`: **STATUS: FROZEN**. Canonical schema contract for V1. Must not be modified.
- `docs/contracts/report-v1.1.json`: **STATUS: FROZEN**. Canonical schema contract for V1.1, introducing MITRE ATT&CK mappings, MITRE provenance, and attack chain fields traceable to InvestigationCase V1.2.

### Compatibility Relationship

- `InvestigationCase V1.1` → `Report V1` (`report-v1.json`)
- `InvestigationCase V1.2` → `Report V1.1` (`report-v1.1.json`)

Note: Report V1.1 is an additive evolution for V1.2 cases and does not replace or invalidate Report V1.

## Investigation Case Schema Versioning (V1.1)

The Investigation Case contract is versioned as `investigation-case-v1.1`.

Canonical schema:

`docs/contracts/investigation-case-v1.1.json`

V1.1 reconciles the M3 → M4 boundary by preserving:

- deterministic correlation relationships
- `protocol_event` entity types
- multiple entity references on timeline events

The V1.1 contract is the authoritative M3 → M4 integration boundary.
