# Hoxline Controlled Schedule Enable Pilot v0

Hoxline controlled schedule enable pilot v0 proves a bounded private schedule-gate pilot and requires return to disabled schedule state.

## Boundary

- This is a bounded pilot, not permanent schedule enablement.
- No active cron trigger is added.
- `HOXLINE_CONTINUOUS_GATE_ENABLED` may be true only during the approved pilot window and must be false or absent after the pilot.
- The pilot allows at most two cycles.
- Lifetime Ledger append remains blocked.
- Public proof promotion remains blocked.
- Public-safe status remains `NOT_PUBLIC_SAFE`.
- AI output remains support-only.
- Human review remains required for any private candidate.
- Website updates are outside this control plane.

The best pilot verdict is `PILOT_PASS_DISABLED_AFTER`. Idle and suppression-only runs may return `PILOT_PASS_NO_NEW_SIGNAL_DISABLED_AFTER` or `PILOT_PASS_DUPLICATES_SUPPRESSED_DISABLED_AFTER`. All successful verdicts require final disabled state.

## Commands

```powershell
python -B scripts\ho_factory.py hoxline-controlled-schedule-pilot --fixture --cycle-count 2 --format json
python -B scripts\ho_factory.py hoxline-controlled-schedule-pilot --fixture --cycle-count 3 --format json
python -B scripts\ho_factory.py hoxline-schedule-pilot-self-test --repo-root . --format json
```

The three-cycle command must fail closed with `BLOCKED_BACKPRESSURE`; it must not create candidates, append the Lifetime Ledger, publish proof, or leave schedule enabled.

## Start

The GitHub workflow remains `workflow_dispatch` only. The controlled pilot path requires both:

- manual input `enable_continuous_gate=true`
- temporary repo variable `HOXLINE_CONTINUOUS_GATE_ENABLED=true`

If either gate is absent, the workflow exits through the disabled gate. If `HOXLINE_EMERGENCY_DISABLE=true`, emergency disable wins and collection is blocked.

## Stop

After the pilot, restore `HOXLINE_CONTINUOUS_GATE_ENABLED` to false or remove it. Final validation must confirm:

- `schedule_enabled_after=false`
- no active cron trigger
- `HOXLINE_CONTINUOUS_GATE_ENABLED` false or absent
- emergency disable path still present
- no ledger append
- no public proof promotion

## Emergency Disable

Emergency disable is verified by the pilot self-test and by `hoxline-schedule-emergency-disable-drill`. The emergency-disabled path creates no candidate and is not treated as failure spam.

## Cycle Outcomes

Each pilot cycle resolves to one terminal decision:

- `NO_NEW_SIGNAL_NO_CANDIDATE`: success idle state; no candidate.
- `DUPLICATE_SIGNAL_SUPPRESSED`: success suppression state; no candidate.
- `NEW_SIGNAL_CANDIDATE_CREATED`: private candidate state; human review required.
- `DEAD_LETTERED_RETRYABLE`: retryable private failure; no public proof.
- `DEAD_LETTERED_FINAL`: final dead-letter state; no public proof.

No-new-signal and duplicate-suppression are successful controlled outcomes.

## Backpressure

Pilot limits are tighter than readiness limits:

- `max_allowed_cycles`: 2
- `max_candidates_per_run`: 2
- `max_new_signals_per_run`: 2
- retry and dead-letter caps remain enforced

Exceeding the cycle cap returns `BLOCKED_BACKPRESSURE`. Exceeding the dead-letter cap returns `PILOT_FAIL_DISABLED_AFTER`, with final disabled state still required.

## Evidence And Claims

Pilot output links private Evidence Graph, Promotion State, ProofCard draft, and Claim Authority hashes. It does not publish those artifacts as public proof.

Allowed internal claim:

`Hoxline completed a bounded private schedule pilot for HO-DET-001 and returned to disabled schedule state with ledger, public proof, and public-safe counts unchanged.`

Blocked claims include standing `schedule enabled`, production continuous SOC, SOCaaS deployed, customer deployed, public-safe runtime proof, public proof, AI approval, analyst approval, ledger append, and case closure.

## Required Validation

```powershell
python -B -m py_compile scripts\ho_factory.py
python -B scripts\ho_factory.py hoxline-schedule-pilot-self-test --repo-root . --format json
python -B scripts\ho_factory.py hoxline-controlled-schedule-pilot --fixture --cycle-count 2 --format json
python -B scripts\ho_factory.py hoxline-controlled-schedule-pilot --fixture --cycle-count 3 --format json
python -B -m unittest tests\test_hoxline_controlled_schedule_pilot.py
```

## Next Legal Gate

After a successful bounded pilot, the next safe gate is the fixture-based multi-detection runtime expansion runbook in `docs/factory/HOXLINE_MULTI_DETECTION_RUNTIME_EXPANSION_V0.md`, not website work.
