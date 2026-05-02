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
- `contracts/schemas/local-llm-runtime-receipt.schema.json`

## Local LLM Runtime Receipt Boundary

The local LLM runtime receipt schema is a schema-level control only. It may
record sanitized model metadata, input hashes, output hashes, runtime status,
operator review state, and explicit AI authority boundaries.

It does not prove:

- runtime-active status
- signal-observed status
- public-safe status
- AI-approved disposition

Minimal examples live in:

- `contracts/examples/local-llm-runtime-receipt.valid.sample.json`

## Contract Intent

These contracts define minimum required fields for reproducible
detection-to-validation-to-proof linkage. They are baseline constraints,
not full maturity coverage.
