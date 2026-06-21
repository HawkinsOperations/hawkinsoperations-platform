# Hoxline Schedule-Enable Readiness v0

Hoxline schedule-enable readiness v0 proves readiness for a future scheduled runtime collector without enabling schedule.

## Boundary

- Schedule is not enabled.
- No active cron trigger is added.
- `HOXLINE_CONTINUOUS_GATE_ENABLED` is not created or changed.
- Lifetime Ledger append is blocked.
- Public proof promotion is blocked.
- Public-safe status remains `NOT_PUBLIC_SAFE`.
- AI output remains support-only.
- Human review remains required.
- Website updates are outside this control plane.

The only successful readiness verdict is `READY_FOR_SEPARATE_SCHEDULE_APPROVAL`. That verdict does not enable collection. It means the next legal gate is a separate explicit `SCHEDULE_ENABLE_APPROVED` prompt after human review of the readiness truth matrix.

## Commands

```powershell
python -B scripts\ho_factory.py hoxline-schedule-readiness --fixture --format json
python -B scripts\ho_factory.py hoxline-schedule-readiness --execution-id HO-DET-001-20260620T173615Z-6ELQ03 --private-route "<APPROVED_PRIVATE_ROUTE>" --format json
python -B scripts\ho_factory.py hoxline-schedule-emergency-disable-drill --format json
python -B scripts\ho_factory.py hoxline-schedule-recovery-drill --format json
python -B scripts\ho_factory.py hoxline-schedule-readiness-self-test --repo-root . --format json
```

## Readiness Gates

Readiness requires:

- no active cron trigger in workflows
- schedule enabled state remains false
- emergency disable path is present
- continuous gate still requires repo variable plus manual input
- runner health is present
- Wazuh receipt/backend health is present
- private route health is present
- checkpoint hash verifies
- no-new-signal creates no candidate and is a success state
- duplicate signal is suppressed and is a success state
- Evidence Graph, Promotion State, and Claim Authority hashes are present
- Claim Authority blocks schedule-enabled and production/SOCaaS/customer claims

## Backpressure Policy

Default limits:

- `max_candidates_per_run`: 3
- `max_runtime_seconds`: 900
- `max_retries_per_execution_id`: 2
- `max_dead_letters_per_run`: 3
- `max_duplicate_suppressions_per_run`: 10
- `max_new_signals_per_run`: 3

No-new-signal and duplicate-signal outcomes are successful idle/suppression states. Exceeding candidate, retry, dead-letter, duplicate, or new-signal limits blocks readiness.

## Emergency Disable

Emergency disable is modeled by `hoxline-schedule-emergency-disable-drill`. It proves `EMERGENCY_DISABLE_ACTIVE` blocks collection even when the manual input and repo variable would otherwise allow the gate. This is not a failure state. It creates no candidate and mutates no ledger, public proof, schedule, or repo variable.

## Retry And Dead Letter Recovery

`hoxline-schedule-recovery-drill` proves retryable failure state, retry cap enforcement, dead-letter hashing, checkpoint verification, and duplicate suppression after retry. Exhausted retry becomes dead-lettered. The drill does not append the Lifetime Ledger, publish proof, enable schedule, or close a case.

## Claim Authority Integration

Readiness is connected to Evidence Graph, Promotion State, and Claim Authority hashes. The allowed private-runtime claim remains bounded to private controlled runtime operations evidence. Claims such as `schedule enabled`, `production continuous SOC`, `SOCaaS deployed`, customer deployment, AI approval, analyst approval, public-safe proof, public proof, and case closure remain blocked.

## Required Validation

```powershell
python -B -m py_compile scripts\ho_factory.py
python -B scripts\ho_factory.py hoxline-schedule-readiness --fixture --format json
python -B scripts\ho_factory.py hoxline-schedule-emergency-disable-drill --format json
python -B scripts\ho_factory.py hoxline-schedule-recovery-drill --format json
python -B scripts\ho_factory.py hoxline-schedule-readiness-self-test --repo-root . --format json
python -B -m unittest tests\test_hoxline_schedule_readiness.py
```
