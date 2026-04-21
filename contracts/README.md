# Platform Contracts

This directory defines cross-repository interface contracts for the HawkinsOperations engineering chain:

- `hawkinsoperations-detections` output artifacts
- `hawkinsoperations-validation` report artifacts
- `hawkinsoperations-proof` proof record artifacts

## Versioning

Current contract version is tracked in:

- `contracts/contract-version.json`

Any schema-breaking change requires:

1. Version increment
2. Migration note
3. Explicit downstream update plan

## Schemas

- `contracts/schemas/detection-artifact.schema.json`
- `contracts/schemas/validation-report.schema.json`
- `contracts/schemas/proof-record.schema.json`

## Contract Intent

These contracts define minimum required fields for reproducible
detection-to-validation-to-proof linkage. They are baseline constraints,
not full maturity coverage.
