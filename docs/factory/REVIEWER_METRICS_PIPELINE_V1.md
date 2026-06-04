# Reviewer Metrics Pipeline v1

This contract separates the strict Lifetime Case Ledger count from reviewer-visible activity volume.

## Current Reconciliation Note

The v1 state file is a materialized platform reporting surface, but the `4/4`
Lifetime values below are retained as a Reviewer Metrics Pipeline v1 closeout
snapshot / historical point-in-time value. They are not current governed case
truth.

Current governed case truth is:

- Governed Lifetime Case Ledger cases: `6`
- Lifetime Ledger events: `6`
- Public-safe cases: `0`
- Closed cases: `0`

The current `6/6` count is sourced from the canonical tracked SQLite ledger
`evidence/autosoc-case-ledger-v0.sqlite` and
`contracts/lifetime-case-ledger-v1-state-manifest.json`.

Current activity growth remains separate from governed cases:

- Detection activity count: `49`
- Validation cases: `106`
- Proof records: `8`
- Blocked claims: `31`
- Append-ready runtime candidates: `2`
- Duplicate normalized runtime candidates: `0`
- Append gate: exact human approval required

| Metric | Count | Owner |
| --- | ---: | --- |
| Lifetime Governed Cases v1 closeout snapshot | 4 | `hawkinsoperations-platform` |
| Lifetime Ledger Events v1 closeout snapshot | 4 | `hawkinsoperations-platform` |
| Detection Activity Count | 49 | `hawkinsoperations-validation` |
| Controlled Validation Fire Count | 49 | `hawkinsoperations-validation` |
| Validation Case Count | 106 | `hawkinsoperations-validation` |
| Proof Record Count | 8 | `hawkinsoperations-proof` |
| Blocked Claim Count | 31 | `hawkinsoperations-proof` reviewer map and summary |
| Runtime Public-Safe Count | 0 | Proof/publication boundary |
| Public-Safe Count | 0 | Proof/publication boundary |
| Detection Family Count | 6 | `hawkinsoperations-detections` |

## Boundary

The Lifetime Case Ledger remains strict: it counts governed accepted case records only. Detection activity, validation cases, proof records, and blocked claims are separate reviewer metrics.

This contract does not mutate `evidence/autosoc-case-ledger-v0.sqlite`, does not append a case, does not close a case, does not promote public-safe status, and does not claim runtime or signal truth.

## Update Path

For v1, the state file is a stable JSON contract verified by `scripts/verify-reviewer-metrics-pipeline.py`. A future generator can replace manual refresh by reading:

- `contracts/lifetime-case-ledger-v1-state-manifest.json`
- `../hawkinsoperations-validation/activity/detection-activity-ledger-v1.json`
- `../hawkinsoperations-proof/proof/records/reviewer-metrics-pipeline-v1-summary.json`
- `../hawkinsoperations-detections/detections/DETECTION_PROMOTION_MATRIX.yml`
- `../.github/governance/ISSUE_FACTORY_CONTROL_RECEIPTS.md`
