# Contract Status

| Contract | Producer | Consumer | Status |
|----------|----------|----------|--------|
| NetworkIntelligencePackage | M1 | M2/M3 | V1 |
| Finding | M2 | M3 | V1 |
| InvestigationCase | M3 | M4 | V1.1 |
| EvidenceReference | M3/M4 boundary | M4 | V1 |

## Investigation Case Schema Versioning (V1.1)

**Important Note:** The `investigation-case-v1.json` schema explicitly sets its internal `schema_version` to `"investigation-case-v1.1"`.

This filename mismatch is an intentional design decision to preserve backward compatibility. During the M3 → M4 integration phase, critical schema gaps were identified in the original V1 contract that resulted in the loss of deterministic relationship edges and timeline entities. The schema was structurally upgraded to V1.1 to prevent forensic data corruption. 

However, the filename `investigation-case-v1.json` was retained so that existing validation suites, fixture references, and downstream integrations pointing to the original filepath would not immediately break, while still strictly enforcing the upgraded V1.1 internal structure.
