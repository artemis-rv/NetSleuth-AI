# Contract Status

| Contract | Producer | Consumer | Status |
|----------|----------|----------|--------|
| NetworkIntelligencePackage | M1 | M2/M3 | V1 |
| Finding | M2 | M3 | V1 |
| InvestigationCase | M3 | M4 | V1.1 |
| EvidenceReference | M3/M4 boundary | M4 | V1 |

## Investigation Case Schema Versioning (V1.1)

The Investigation Case contract is versioned as `investigation-case-v1.1`.

Canonical schema:

`docs/contracts/investigation-case-v1.1.json`

V1.1 reconciles the M3 → M4 boundary by preserving:

- deterministic correlation relationships
- `protocol_event` entity types
- multiple entity references on timeline events

The V1.1 contract is the authoritative M3 → M4 integration boundary.
