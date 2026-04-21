# HawkinsOperations Platform

Platform contracts, integration logic, and operational plumbing for HawkinsOps V2.

## Purpose

This repository defines how detection and validation components are wired, promoted, and operated.

## Scope

- Pipeline contracts and interface definitions
- Deployment orchestration scripts and integration modules
- Environment-agnostic operational controls and runbooks

## Contract Baseline

Initial contract package is now defined under `contracts/`:

- `contracts/contract-version.json`
- `contracts/schemas/detection-artifact.schema.json`
- `contracts/schemas/validation-report.schema.json`
- `contracts/schemas/proof-record.schema.json`

This baseline defines minimum fields required for reproducible
detection-to-validation-to-proof linkage.

## Out of Scope

- Host-specific workstation configuration state
- Public marketing narrative
- Private credentials, tokens, and secret material

## Repository Contract

- Platform behavior must be deterministic and auditable.
- Integration points must be versioned and explicitly documented.
- Operational changes require corresponding proof updates in `hawkinsoperations-proof`.

## Public-Safe Proof

- Architecture/control flow diagrams (sanitized)
- Promotion control descriptions
- Reproducible integration checks

## Related Repositories

- Detections: `hawkinsoperations-detections`
- Validation: `hawkinsoperations-validation`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`
