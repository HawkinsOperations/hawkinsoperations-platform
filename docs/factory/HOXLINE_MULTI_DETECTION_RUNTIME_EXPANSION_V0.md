# Hoxline Multi-Detection Runtime Expansion v0

Hoxline multi-detection runtime expansion v0 extends private runtime-to-evidence-control-plane support beyond `HO-DET-001` to `HO-DET-011` and `HO-DET-012`.

## Boundary

- This is private operations expansion only.
- `HO-DET-011` and `HO-DET-012` are private controlled runtime candidates only.
- Public-safe status remains `NOT_PUBLIC_SAFE`.
- Proof ceiling remains `PRIVATE_CONTROLLED_RUNTIME_PROOF`.
- Lifetime Ledger append is blocked.
- Public proof promotion is blocked.
- Schedule remains disabled.
- AI remains support-only and has no disposition authority.
- Human review remains required.
- Website updates are outside this control plane.

This runbook does not create production, SOCaaS, customer, autonomous SOC, fleet-wide, analyst-approved, AI-approved, public-safe, or case-closed claims.

## Runtime Contract

The controller defines a structured runtime contract for:

- `HO-DET-001`: PowerShell EncodedCommand, Wazuh rule `100204`, ATT&CK `T1059.001`.
- `HO-DET-011`: Windows service creation, Wazuh source rule `910011`, ATT&CK `T1543.003`.
- `HO-DET-012`: scheduled task creation, Wazuh source rule `910021`, ATT&CK `T1053.005`.

Each contract defines required sanitized signal fields, required candidate fields, normalization key fields, dedupe key fields, private proof ceiling, public-safe status, human-review requirement, and AI disposition boundary.

## Commands

```powershell
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-001 --fixture --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-011 --fixture --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-012 --fixture --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-self-test --repo-root . --format json
```

Fixture mode does not require live runtime firing. It simulates sanitized receipt hashes and private candidate artifacts only.

## Pipeline Shape

For each supported detection, the verifier checks:

- detection-specific contract
- sanitized runtime signal receipt
- private runtime candidate
- normalization
- dedupe
- enrichment
- `AI_TRIAGE_UNAVAILABLE` fallback
- human-review packet
- replay/no-duplicate
- structured log chain
- metrics and count separation
- private review queue
- checkpoint and duplicate/no-new-signal decisions
- Evidence Graph
- Promotion State
- Claim Authority
- private ProofCard draft

## Claim Authority

Allowed scoped private-runtime claim pattern:

`Hoxline has private controlled runtime operations evidence for <detection_id> with replay/no-duplicate verification and human review required.`

Blocked claims include production SOC, SOCaaS deployed, customer deployed, fleet-wide coverage, public-safe runtime proof, public proof, AI approval, analyst approval, ledger append, schedule enablement, and case closure.

## Count Separation

Runtime candidate counts are per-detection runtime queue counters. They are not Lifetime Ledger case/event counts. The self-test requires runtime candidate count to remain separate from the Lifetime Ledger baseline.

## Required Validation

```powershell
python -B -m py_compile scripts\ho_factory.py
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-self-test --repo-root . --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-001 --fixture --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-011 --fixture --format json
python -B scripts\ho_factory.py hoxline-multi-detection-runtime-verify --detection-id HO-DET-012 --fixture --format json
python -B -m unittest tests\test_hoxline_multi_detection_runtime.py
```

Unsupported detection IDs must fail closed.

## Next Legal Gate

After this fixture-based expansion is merged and reviewed, the next safe gate is real controlled live canary for `HO-DET-011` and `HO-DET-012` only. Website work, public proof, ledger append, and schedule enablement remain out of scope.
