# Runtime Route Proof v1 Private Candidate

## Status

Runtime Route Proof v1 is represented here as a private candidate packet contract and verifier. The platform repo validates the reviewer-safe packet shape only; proof truth remains owned by `hawkinsoperations-proof`.

| Field | Value |
|---|---|
| Marker ID | HO-RUNTIME-V1-20260601T120922Z-BATCH764 |
| Private route | Wazuh -> Cribl -> Splunk |
| Deterministic verifier | PASS_ROUTE_RECEIPTS |
| Manifest verified | true |
| Lifetime Governed Cases | 4 |
| Public-safe count | 0 |
| Public-safe status | NOT_PUBLIC_SAFE |
| Proof ceiling | PRIVATE_RUNTIME_ROUTE_PROOF_V1_CANDIDATE |
| Preservation ceiling | PRIVATE_RUNTIME_ROUTE_PROOF_V1_CANDIDATE_PRESERVED |

## Contract Files

- `contracts/schemas/runtime-route-proof-v1-private-candidate.schema.json`
- `contracts/examples/runtime-route-proof-v1-private-candidate.sample.json`
- `scripts/verify-runtime-route-proof-v1-private-candidate.py`

## Boundary

This platform contract does not run a marker, query runtime systems, mutate Cribl/Wazuh/Splunk, append Lifetime Governed Cases, or promote public-safe status. It verifies that a source-controlled reviewer-safe packet reference remains bounded: Wazuh, Cribl, and Splunk receipts are `PASS`; `manifest_verified=true`; Lifetime Governed Cases remain 4; public-safe count remains 0; AI-decided disposition remains false; and raw private evidence is not included in the repository.

## What This Does Not Prove

- public-safe runtime proof
- production SOC operation
- autonomous SOC operation
- AI-decided disposition
- analyst-approved disposition
- broad ingestion
- broad deployment
- public publication approval

