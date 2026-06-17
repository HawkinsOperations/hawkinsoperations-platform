# A4 Source Route Closeout

## Public Reviewer Packet: Don't Trust the Page. Check the Route.

Purpose: This packet gives reviewers a public route to check the current HawkinsOperations public status surface without treating the website as proof authority.

Supported claim: Hoxline has a merged v1 source route from product engine to validation bridge, proof bridge, and platform public-status source contract under controlled scope.

Route chain:

```text
Public status JSON
→ Hoxline source route
→ validation bridge
→ proof bridge
→ platform source contract
→ reviewer clone / run path
```

Public state metrics:

* 72 controls fired
* 31 claims blocked
* 106 validation cases
* 8 proof records
* 0 public-safe promotions

The `0 public-safe promotions` value is intentional: the public surface must not promote runtime/public-safe status unless the owning evidence route supports it.

Reviewer links:

* [public status JSON](https://hawkinsoperations.com/data/public-status.json)
* [Hoxline Gauntlet v1 run](https://github.com/HawkinsOperations/hoxline/blob/main/examples/gauntlet/ho-det-001-gauntlet-run-v1.json)
* [Hoxline Claim Authority v1](https://github.com/HawkinsOperations/hoxline/blob/main/docs/claim-authority/CLAIM_AUTHORITY_V1.md)
* [validation bridge](https://github.com/HawkinsOperations/hawkinsoperations-validation/blob/main/validation/hoxline/HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1.md)
* [proof bridge](https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/proof/records/HO-DET-001_HOXLINE_GAUNTLET_BRIDGE_V1.md)
* [platform public-status source contract](https://github.com/HawkinsOperations/hawkinsoperations-platform/blob/main/contracts/PUBLIC_STATUS_SOURCE_CONTRACT_V1.md)

Reviewer commands:

Hoxline:

```bash
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json --schema schemas/gauntlet-run-v1.schema.json
```

Validation:

```bash
python -B scripts/verify_hoxline_gauntlet_validation_bridge.py --format json
```

Proof:

```bash
python -B scripts/verify-hoxline-gauntlet-proof-bridge.py --format json
python -B scripts/verify-proof-pack-001-release.py
```

Platform:

```bash
python -B scripts/verify-public-status-source-contract.py --format json
python -B scripts/ho_factory.py public-status-source-contract-verify --format json
```

Still blocked:

* runtime truth
* signal truth
* public-safe runtime proof
* production readiness
* customer deployment
* SOCaaS deployment
* AI-approved disposition
* analyst-approved disposition
* final authorization
* case closure

Proof ceiling:

Hoxline Gauntlet v1 remains bounded by `CONTROLLED_TEST_VALIDATED`.

Platform public-status source contract remains bounded by `SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY`.

Website boundary:

The website can render status, route reviewers, and expose public reviewer actions. It cannot create proof authority, runtime truth, signal truth, public-safe status, production readiness, customer deployment, approval, authorization, or case closure.

This supports a bounded public reviewer route under controlled scope.

## Purpose

A4 closed the source-route chain for Hoxline Gauntlet v1 under controlled scope.

Supported public-safe wording:

> Hoxline now has a merged v1 source route from product engine to validation bridge, proof bridge, and platform public-status source contract under controlled scope.

## Merge Order

1. Hoxline PR #15: https://github.com/HawkinsOperations/hoxline/pull/15
2. Validation PR #67: https://github.com/HawkinsOperations/hawkinsoperations-validation/pull/67
3. Proof PR #81: https://github.com/HawkinsOperations/hawkinsoperations-proof/pull/81
4. Platform PR #62: https://github.com/HawkinsOperations/hawkinsoperations-platform/pull/62

## Merge Commits

| Repo | PR | Merge commit |
| --- | --- | --- |
| HawkinsOperations/hoxline | #15 | `e2a120579e55686c86afe62402afbef3d4758cfc` |
| HawkinsOperations/hawkinsoperations-validation | #67 | `d64bbdea4cd6129b32b5ce17bc752620844c5c89` |
| HawkinsOperations/hawkinsoperations-proof | #81 | `aa4c52d4d1d9c3fe60db1560bc9d74970d359b65` |
| HawkinsOperations/hawkinsoperations-platform | #62 | `bd9ff0bb0e7c30d4a88c3231010edf339d870898` |

## Source-Route Chain

```text
Hoxline v1 source manifest
  -> Validation bridge
  -> Proof bridge and proof map
  -> Platform public status source contract
```

Primary source anchors:

- `../aevumguard/examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json`
- `../hawkinsoperations-validation/validation/hoxline/ho-det-001-hoxline-gauntlet-validation-bridge-v1.json`
- `../hawkinsoperations-proof/proof/records/ho-det-001-hoxline-gauntlet-bridge-v1.json`
- `contracts/public-status-source-contract-v1.json`

## Supported

- Hoxline Gauntlet v1 source manifest exists on the merged Hoxline main branch.
- Validation bridge references the Hoxline v1 source manifest as primary.
- Proof bridge and proof map reference the Hoxline v1 source manifest and validation bridge.
- Platform public status source contract captures the Hoxline, Validation, and Proof routes as landed source metadata.
- Website remains a consumer/rendering surface only.

## Still Blocked

These claims remain blocked unless separately authorized by an owning source route:

- runtime truth
- signal truth
- public-safe status
- production readiness
- customer deployment
- SOCaaS deployment
- AI-approved disposition
- analyst-approved disposition
- final authorization
- case closure

The intentionally unknown field remains:

- `detection_source_truth`

## Proof Ceiling

A4 closed the source-route chain under controlled scope. Platform public status source contract proof ceiling remains `SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY`. Hoxline Gauntlet v1 remains bounded by `CONTROLLED_TEST_VALIDATED`.

This closeout does not create runtime truth, signal truth, public-safe status, customer deployment, SOCaaS deployment, production readiness, AI-approved disposition, analyst-approved disposition, final authorization, or case closure.

## Verification Commands

Run from each repository root.

Hoxline:

```bash
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json --schema schemas/gauntlet-run-v1.schema.json
```

Validation:

```bash
python -B scripts/verify_hoxline_gauntlet_validation_bridge.py --format json
```

Proof:

```bash
python -B scripts/verify-hoxline-gauntlet-proof-bridge.py --format json
python -B scripts/verify-proof-pack-001-release.py
```

Platform:

```bash
python -B scripts/verify-public-status-source-contract.py --format json
python -B scripts/ho_factory.py public-status-source-contract-verify --format json
```

## Next Recommended Work

The next safe build is a separately scoped detection-owned source truth capture plan for `detection_source_truth`, if approved. That work should remain distinct from runtime collection, website rendering, public-safe promotion, production readiness, customer deployment, SOCaaS deployment, disposition approval, final authorization, or case closure.
