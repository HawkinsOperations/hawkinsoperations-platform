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
- `hoxline-runtime-canary-from-receipts`
- `hoxline-runtime-schedule-gate`
- `hoxline-runtime-job-guard`
- `hoxline-workflow-safety-verify`
- `hoxline-runtime-ops-self-test`

The next private control-plane layer is documented in `docs/factory/HOXLINE_EVIDENCE_GRAPH_CLAIM_AUTHORITY_V0.md`. It adds hash-only evidence graph, promotion state, Claim Authority, private ProofCard draft, and control-plane self-test commands while preserving the same proof ceiling and public-safe boundary.

Schedule-enable readiness remains disabled-by-default and is documented in `docs/factory/HOXLINE_SCHEDULE_ENABLE_READINESS_V0.md`. It proves future schedule readiness, backpressure, emergency-disable, retry/dead-letter recovery, and claim-boundary checks without adding cron, enabling schedule, mutating repo variables, appending the Lifetime Ledger, or promoting public proof.

The metrics command intentionally separates runtime candidate counts from Lifetime Ledger case/event counts. Review queue counts are runtime queue counters only; they are not public proof and do not imply ledger append readiness.

## Canary Receipts

Live canary artifact processing starts from a private sanitized receipt packet with schema `hoxline-wazuh-signal-receipts-v0`. The packet must contain exactly three unique execution IDs and sanitized Wazuh receipt digests. The command writes only private-route artifacts and verifies replay, metrics, log chain, checkpoint, ledger guards, public-proof guards, and AI authority boundaries. It rejects raw alert fields, raw candidate fields, private route fields, credentials, tokens, passwords, and private keys.

## Logging And Retention

Runtime log records use schema `hoxline-runtime-log-v0` and include a hash chain with `previous_log_hash` and `log_hash`. Records reject raw alert fields, raw candidate payloads, private route fields, credentials, tokens, passwords, and private keys. Retention is private-route controlled; public artifacts should contain only bounded hashes and counts.

## Future Grafana Ingestion

The JSON metrics are the source of truth for v0. Prometheus text export can be added later as a report-only adapter after the JSON counters are stable and reviewed. Any future dashboard must preserve the same claim boundary and keep public-safe, ledger, schedule, and AI authority counters explicit.

## Server-return receipt intake foundation

The receipt-bound collector path is additive to the historical canary examples.
It does not run a backend query, generate telemetry, execute a model, append the
Lifetime Ledger, or establish fresh private runtime proof.

Both Windows and Linux collector hosts consume HO-DET-001 **Windows-origin**
process telemetry from the existing Wazuh rule `100204`. Execution-host OS,
telemetry-source OS, detection, backend, and input provenance remain distinct.
This lane does not establish Linux endpoint detection coverage.

### Prepared sequence

1. Select and deploy the reviewed platform source revision. Keep schedules paused.
   A feature PR or successful hosted test does not deploy the private runner.
2. On the matching host, use Python 3.12 with the explicit PyYAML 6.0.2 dependency.
   Run `python -B scripts/ho_factory.py collector-windows-preflight --help` or
   the equivalent Linux command. A supplied route must already exist, be
   writable, and match the existing approved route; no route is created.
3. Without `--collect`, `collector-<lane>-run-once` is a historical sample
   demonstration with no writes. A supplied output route does not imply consent.
4. Following separate runtime authorization, intake one sanitized receipt using
   `collector-<lane>-run-once --collect --output-route ROUTE --receipt RECEIPT
   --evidence EVIDENCE --execution-id EXECUTION --source-ref EXACT_COMMIT`.
   These uppercase arguments are operator-resolved placeholders, not deployment
   values. Referenced evidence must exist and its actual bytes must match the
   receipt digest. The digest binds content; its origin remains operator-attested.
5. Capture `output_name` and `packet_hash` from that successful invocation.
   Run `collector-<lane>-verify` and `collector-<lane>-dedupe-check` with
   `--candidate` set to that exact output file, plus `--execution-id`,
   `--source-ref`, and `--packet-hash` from the invocation. Verification also
   checks the persisted completion record. No committed sample fallback exists;
   old demonstrations require explicit `--sample`.
6. Replay the same input within its one-hour acceptance window. It must return
   `duplicate_count=1` and preserve the accepted candidate. Different content
   under the same execution identity is blocked. A partial or conflicting output,
   missing completion record, busy transaction, changed source, or failed
   prerequisite must prevent downstream success.
7. Review the stored candidate, actual normalized candidate, checkpoint,
   sanitized `support_input`, and per-stage status. Normalization is
   `REVIEW_REQUIRED`, with no append readiness or closure authority.
8. Optional AI support is a separate explicit operation through
   `scripts/run_local_gpu_triage.py support-run`; see
   [the existing GPU support guide](LOCAL_GPU_TRIAGE_PIPELINE_V0.md).
   Missing AI preserves upstream evidence and reports `AI_UNAVAILABLE`.
   No collector call implicitly invokes inference.

### Receipt contract

The closed `hoxline-collector-receipt-v1` envelope contains exactly
`schema_version`, `receipt`, `input_provenance`, `telemetry_source_os`,
`detection_id`, `window_start_utc`, and `window_end_utc`.

Its `receipt` uses the existing canary fields: `execution_id`,
`receipt_digest`, `observed_at_utc`, `wazuh_rule_id`, `backend_identity`,
`event_class`, and `signal_count`. Detection is HO-DET-001, event class is
`process_behavior`, and telemetry OS is `Windows`. The backend must match the
existing HO-DET-001 canary contract. The evidence JSON contains those same signal
fields except `receipt_digest`, plus `input_provenance`. The digest is SHA-256
of its actual file bytes, not a substituted generated value.

Only `CONTROLLED_TEST` with `--test-only`, or
`OPERATOR_ATTESTED_RECEIPT` without that test flag, is accepted. The execution
timestamp and observation must lie inside a parsed UTC window of at most one
hour. Observations must be no older than one hour and cannot be in the future.
No old observation timestamp is refreshed. A producer's attestation is not
independent origin authentication. Untrusted ChangeWindow fields and raw event
prose are excluded from this input schema and cannot authorize suppression.

### Rehearsal and exclusions

Existing `hoxline-source-checks.yml` exercises clean hosted Windows and Ubuntu
checkouts with explicit dependencies. The collector and adapter tests use
sanitized fixtures, isolated temporary output and injected test transport.
`TEST_DOUBLE` is never reported as actual inference.

Run `python -B -m unittest discover -s tests -p test_runtime_collector_restart.py`
and `python -B -m unittest discover -s tests -p test_local_gpu_triage_adapter.py`.
Run the complete platform suite and canonical seven-source convergence after
source selection stabilizes.

Legacy canary replay embeds historical runner facts and inferred stages; it is
not the fresh restart verifier. The optional 009/010/011/012 sanitized-live
hash projections and scheduled collection remain outside this foundation.
Do not dispatch `hoxline-private-canary.yml`, enable schedules, or use
`collector-normalizer-append-approved` as part of this prepared intake path.
The existing emergency stops remain in place. Later ledger/proof/publication
work requires separate human authority and evidence review.
