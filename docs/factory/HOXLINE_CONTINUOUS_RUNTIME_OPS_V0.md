# Hoxline Continuous Runtime Operations v0

Hoxline continuous runtime operations v0 is a private, controlled runtime operations layer. It adds repeatable CI/CD checks, trusted runtime verification, JSONL-style structured log records, separated metrics, review queue counts, checkpoint/dedupe records, dead-letter records, and disabled-by-default schedule infrastructure.

## Boundary

- Proof ceiling: `PRIVATE_CONTROLLED_RUNTIME_PROOF`.
- Public-safe status: `NOT_PUBLIC_SAFE`.
- Continuous schedule: disabled unless a future enable gate is separately approved.
- Lifetime Ledger append: blocked unless a separate governed append approval is supplied.
- Public proof promotion: blocked.
- Case closure: blocked.
- AI disposition authority: blocked. AI output remains support-only and human review remains required.
- Website update: blocked until Raylee reviews the final truth matrix and approves bounded public wording.

## Commands

- `hoxline-runtime-health`
- `hoxline-runtime-replay`
- `hoxline-runtime-verify`
- `hoxline-runtime-metrics`
- `hoxline-runtime-review-queue`
- `hoxline-runtime-log-verify`
- `hoxline-runtime-checkpoint-verify`
- `hoxline-runtime-dead-letter-self-test`
- `hoxline-runtime-canary`
- `hoxline-runtime-schedule-gate`
- `hoxline-runtime-job-guard`
- `hoxline-workflow-safety-verify`
- `hoxline-runtime-ops-self-test`

The metrics command intentionally separates runtime candidate counts from Lifetime Ledger case/event counts. Review queue counts are runtime queue counters only; they are not public proof and do not imply ledger append readiness.

## Logging And Retention

Runtime log records use schema `hoxline-runtime-log-v0` and include a hash chain with `previous_log_hash` and `log_hash`. Records reject raw alert fields, raw candidate payloads, private route fields, credentials, tokens, passwords, and private keys. Retention is private-route controlled; public artifacts should contain only bounded hashes and counts.

## Future Grafana Ingestion

The JSON metrics are the source of truth for v0. Prometheus text export can be added later as a report-only adapter after the JSON counters are stable and reviewed. Any future dashboard must preserve the same claim boundary and keep public-safe, ledger, schedule, and AI authority counters explicit.
