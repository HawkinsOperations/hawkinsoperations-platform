# HOXLINE_OPERATOR_RECEIPT_COLLECTION_KIT_V0

This layer adds a safe operator-side receipt collection kit for HO-DET-011 and HO-DET-012.

The kit does not generate live signals. It does not create services, create or update scheduled tasks, execute malware, run exploits, attempt bypass or evasion, or perform destructive behavior. It only reads already-observed Wazuh telemetry supplied by an operator and emits sanitized receipt-only packet JSON.

## Boundary

The proof ceiling remains `PRIVATE_CONTROLLED_RUNTIME_PROOF`.

Public-safe remains `NOT_PUBLIC_SAFE`.

Schedule remains disabled.

The Lifetime Ledger is not appended. Public proof is not promoted. Website content is not updated.

## Operator Packet

The packet schema is `hoxline-operator-receipt-packet-v0`.

Each packet contains exactly one `hoxline-sanitized-live-receipt-v0` receipt in v0. The packet also carries an operator attestation with:

- `operator_supplied=true`
- `source_system=Wazuh`
- a bounded UTC source time window
- `collection_method=alerts_json_sanitized_hash_only_scan`
- `raw_payload_omitted=true`
- `persistence_behavior_generated_by_hoxline=false`

The packet must have:

- `raw_alerts_included=false`
- `raw_commands_included=false`
- `generated_by_hoxline=false`
- `fixture_mode=false`

## Collector

Use:

```powershell
python -B scripts/ho_factory.py hoxline-operator-receipt-collect-wazuh `
  --detection-id HO-DET-011 `
  --execution-id HO-DET-011-20260621T084000Z-LR011A `
  --alerts-json <operator-supplied-alerts-json> `
  --time-window-start-utc 2026-06-21T08:40:00Z `
  --time-window-end-utc 2026-06-21T08:45:00Z `
  --operator-attestation <operator-attestation-json> `
  --output <packet-output-json> `
  --format json
```

The collector searches for the supplied execution ID and the detection-specific Wazuh rule. It emits a packet that contains hashes, counts, timestamps, rule refs, backend identity, and attestation only.

It fails closed on no match, conflicting duplicate matches, missing attestation, unsupported detection, wrong rule, raw fields, fixture mode, or Hoxline-generated evidence.

## Packet Verification

Use:

```powershell
python -B scripts/ho_factory.py hoxline-operator-receipt-packet-verify --packet <packet-output-json> --format json
```

Verification recomputes packet, attestation, and receipt hashes. It validates the receipt through the sanitized live receipt intake contract and confirms the packet is not fixture mode, not Hoxline generated, and not raw/private.

## Runtime Flow

Use:

```powershell
python -B scripts/ho_factory.py hoxline-runtime-from-operator-receipt-packet --packet <packet-output-json> --format json
```

The runtime flow validates the packet, validates the embedded receipt, runs `hoxline-runtime-from-sanitized-receipt`, and returns result hashes only. Evidence Graph, Promotion State, Claim Authority, and ProofCard draft remain private and human-review required.

## Claim Authority

The exact bounded claim remains the only allowed receipt claim after validation:

`Hoxline has operator-supplied sanitized live receipt evidence for <DETECTION_ID> with replay/no-duplicate verification and human review required.`

Blocked claims remain blocked:

- Hoxline generated live proof
- Hoxline created a service
- Hoxline created a scheduled task
- production
- SOCaaS
- customer deployment
- public-safe runtime proof
- public proof
- AI approval
- analyst approval
- fleet-wide coverage
- case closure

## Next Safe Gate

Use a real operator-supplied sanitized receipt packet from a controlled environment for HO-DET-011 and HO-DET-012, then ingest it through Hoxline without Hoxline generating persistence behavior.
