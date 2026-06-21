# HOXLINE_SANITIZED_LIVE_RECEIPT_INTAKE_V0

Hoxline sanitized live receipt intake v0 resolves the prior live-canary blocker without changing the safety boundary.

The previous live canary gate stopped because `HO-DET-011` needs service creation telemetry and `HO-DET-012` needs scheduled task creation or update telemetry. Hoxline must not generate those persistence-class behaviors.

This layer accepts only operator-supplied sanitized live receipts from already observed telemetry. It does not create services, create scheduled tasks, run malware, run exploit code, bypass controls, query raw alerts, dump private routes, append the Lifetime Ledger, publish public proof, update the website, or enable schedule.

## Receipt Classes

`OPERATOR_SUPPLIED_SANITIZED_LIVE_RECEIPT` is the only class that can support the bounded operator-supplied receipt claim. It must have:

- `generated_by_hoxline=false`
- `operator_supplied=true`
- `fixture_mode=false`
- `raw_alert_included=false`
- `raw_command_included=false`
- source attestation showing trusted runtime context, non-fixture source, no raw event, and no private evidence in the repo

`FIXTURE_DRY_RUN_RECEIPT` is accepted only as non-live. It can exercise the private runtime pipeline, but it cannot support a live receipt claim.

`UNTRUSTED_RECEIPT` is blocked before candidate creation.

## Commands

```powershell
python -B scripts\ho_factory.py hoxline-sanitized-live-receipt-intake --receipt contracts\examples\hoxline-sanitized-live-receipt-v0.ho-det-011.operator.sample.json --format json
python -B scripts\ho_factory.py hoxline-runtime-from-sanitized-receipt --receipt contracts\examples\hoxline-sanitized-live-receipt-v0.ho-det-012.operator.sample.json --format json
python -B scripts\ho_factory.py hoxline-sanitized-live-receipt-intake-self-test --repo-root . --format json
```

The intake command validates the receipt contract and attestation. The runtime command converts an accepted sanitized receipt into private runtime candidate, normalization, dedupe, enrichment, AI unavailable fallback, human-review packet, replay/no-duplicate, metrics, Evidence Graph, Promotion State, Claim Authority, and private ProofCard draft outputs.

## Claim Authority

Allowed exact claim after an accepted operator-supplied live receipt:

`Hoxline has operator-supplied sanitized live receipt evidence for <DETECTION_ID> with replay/no-duplicate verification and human review required.`

Blocked claims include generated live proof, safe service creation, safe scheduled task creation, production, SOCaaS, customer deployment, fleet-wide coverage, public-safe status, public proof, AI approval, analyst approval, ledger append, schedule enablement, and case closure.

## Boundaries

- Proof ceiling remains `PRIVATE_CONTROLLED_RUNTIME_PROOF`.
- Public-safe status remains `NOT_PUBLIC_SAFE`.
- Human review remains required.
- AI remains support-only.
- Lifetime Ledger append remains blocked.
- Public proof promotion remains blocked.
- Schedule remains disabled.
- Website and Hoxline product repos remain out of scope.

## Next Safe Gate

Operator-supplied sanitized live receipts for `HO-DET-011` and `HO-DET-012` can be generated outside Hoxline and ingested without Hoxline generating persistence behavior. Any later live receipt collection must preserve the same sanitized, operator-supplied, hash-only boundary.
