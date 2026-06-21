# Lifetime Case Ledger Recoverability Drill

This platform-owned drill verifies that the tracked Lifetime Case Ledger seed
bridge can be copied and checked without mutating canonical ledger state.

Canonical ledger:

```text
evidence/autosoc-case-ledger-v0.sqlite
```

Current expected seed bridge state:

- 6 events
- 6 cases
- appended detections: `HO-DET-001`, `HO-DET-011`, `HO-DET-012`
- public-safe rows: 0
- closed cases: 0

Boundary:

- platform owns mechanics
- proof owns proof
- website/render surfaces are out of scope
- GitHub Project #1 is operating control only
- tracked platform seed bridge, not runtime truth, not signal truth, not public proof
- public_safe_status=NOT_PUBLIC_SAFE
- proof_ceiling=SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY

## Drill Command

```powershell
python scripts\verify-lifetime-ledger-backup-drill.py
```

The verifier:

- computes canonical SHA256 before the drill
- opens the canonical ledger read-only for metrics
- copies the canonical SQLite file to a temporary test backup path
- computes backup SHA256
- opens the backup read-only for metrics
- computes canonical SHA256 again after the drill
- verifies canonical metrics did not change
- verifies backup metrics match canonical metrics
- deletes the temporary backup when the process exits

The report format includes:

- canonical ledger path
- backup path
- canonical SHA256 before
- canonical SHA256 after
- backup SHA256
- canonical metrics before
- canonical metrics after
- backup metrics
- database_modified=false
- restore_performed=false
- append_performed=false
- public_safe_status=NOT_PUBLIC_SAFE
- proof_ceiling=SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY

## Reviewer Ledger Mechanics Map

```text
candidate event
  -> dry run
  -> approval gate
  -> append
  -> dedupe
  -> correction/superseding model
  -> state manifest
  -> proof handoff
```

Mechanics:

- candidate event: sanitized platform candidate, not raw/private evidence
- dry run: validates candidate and previews metrics without writing a row
- approval gate: requires exact append or correction approval phrase before write-capable paths
- append: inserts a sanitized event only when approved; existing rows are not edited
- dedupe: blocks duplicate event hashes, case IDs, payload hashes, and fingerprints
- correction/superseding model: adds later correction rows instead of updating or deleting prior rows
- state manifest: records current seed bridge counts and repo authority boundaries
- proof handoff: proof records live in `hawkinsoperations-proof`; platform mechanics do not create proof

## Future Append Update Rule

The hard-coded 6 events / 6 cases expectation is an intentional current-state
fail-closed control. Any future approved ledger append must update the expected
metrics in this document, the recoverability contract, and the verifier
constants in the same bounded change. If the canonical seed bridge changes but
those expectations are not updated together, the recoverability drill must fail
closed.

## Failure Conditions

The verifier fails closed if:

- canonical SHA changes during the drill
- canonical count changes
- backup count differs
- `append_performed=true`
- `restore_performed=true`
- `database_modified=true`
- public-safe status is promoted
- proof ceiling is promoted
- runtime, signal, production, SOCaaS, autonomous SOC, AI-approved disposition,
  analyst-approved disposition, or case-closure claims appear

## Project #1 Update Packet

- Item title: Platform Ledger Recoverability Drill / Visual Ledger Map
- Repository: hawkinsoperations-platform
- Lane: Platform / Ledger
- Truth Surface: repo truth / operating control
- Control Level: real control
- Receipt Status: READY_FOR_HUMAN_REVIEW
- Reviewer Facing: yes
- Proof Ceiling: SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY
- Evidence Link: `docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md`; `scripts/verify-lifetime-ledger-backup-drill.py`
- Next Gate: human GitHub review / MERGE_APPROVED
- Demo Value: reviewer can understand ledger mechanics and recoverability without mutating proof or runtime truth
