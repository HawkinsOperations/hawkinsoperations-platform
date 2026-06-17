# Public Status Source Contract v1

`public-status-source-contract-v1.json` is the platform-owned source contract for future website generated public status.

The contract defines where each public status field may come from, which repo owns that field, what the website may render, and which fields must never be sourced from website-only data.

## Source Boundary

The website is a consumer. It is not authority for governed case counts, detection activity, validation volume, proof records, blocked claims, proof ceiling, public-safe state, runtime truth, signal truth, production readiness, customer deployment, SOCaaS deployment, disposition, authorization, or case closure.

Current safe values come only from source-controlled platform state:

| Field group | Source route | Owner |
| --- | --- | --- |
| Governed cases/events, closed cases | `contracts/lifetime-case-ledger-v1-state-manifest.json` | `hawkinsoperations-platform` |
| Runtime candidate count | `contracts/examples/runtime-case-collector-v0-normalizer.sample.json` | `hawkinsoperations-platform` |
| Detection activity and validation counts | `contracts/reviewer-metrics-pipeline-v1-state.json` validation source routes | `hawkinsoperations-validation` |
| Proof records, blocked claims, proof ceiling, public-safe boundary | proof source routes declared by reviewer metrics and lifetime state | `hawkinsoperations-proof` |
| Detection source truth | `../hawkinsoperations-detections/detections/DETECTION_PROMOTION_MATRIX.yml` | `hawkinsoperations-detections` |
| Hoxline product and Gauntlet status | pending direct v1 paths under `../aevumguard/examples/gauntlet/` and `../aevumguard/schemas/` | `hoxline/aevumguard` |
| Hoxline validation bridge | pending PR #67 paths under `../hawkinsoperations-validation/validation/hoxline/` | `hawkinsoperations-validation` |
| Hoxline proof bridge | pending PR #81 paths under `../hawkinsoperations-proof/proof/` | `hawkinsoperations-proof` |

Hoxline PR #15, validation PR #67, and proof PR #81 are represented as pending PR sources when unmerged. Generated public status v1 must preserve `source_pr`, `source_branch`, and pending source status. Pending source routes are not main/default-branch truth.

The preferred Hoxline v1 source manifest remains `UNKNOWN_SOURCE_NOT_CAPTURED` until that manifest exists on a safe source route.

## Freshness

The default freshness window is `14` days. Generated public status v1 should mark stale fields as stale instead of inventing updated values. If a source route is absent, unsafe, or not represented by this contract, the generated output must use `UNKNOWN_SOURCE_NOT_CAPTURED`.

## Proof Boundary

This contract does not create proof authority. Website rendering is not proof. It does not create runtime truth, signal truth, public-safe status, production readiness, customer deployment, SOCaaS deployment, AI-approved disposition, analyst-approved disposition, final authorization, or case closure.

No runtime collector, workflow dispatch, server command, ledger append, private evidence import, or website edit is required to verify this contract.

## Reviewer Verification

Run:

```bash
python -B scripts/verify-public-status-source-contract.py --format json
```

If using the factory wrapper:

```bash
python -B scripts/ho_factory.py public-status-source-contract-verify --format json
```
