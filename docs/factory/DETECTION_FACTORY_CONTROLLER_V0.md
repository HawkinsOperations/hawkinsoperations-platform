# Detection Factory Controller v0

## Purpose

Detection Factory Controller v0 is a platform-owned status and plan entry point
for reading HawkinsOperations detection state across the local organization
mirror.

The v0 controller is intentionally narrow. It produces reviewer packets for
`HO-DET-001` and `HO-DET-011` from existing repo surfaces. It does not promote
proof, publish evidence, update the website, create pull requests, merge
changes, or write generated output files.

## Controller Boundary

The controller is source and contract truth for a read-only platform view.
It is not proof truth, runtime truth, signal truth, evidence truth, or public
approval.

Required boundary statements:

- Website and GitHub rendering are not proof.
- AI output is labor only.
- Evidence and human review authorize claims.
- Public-safe status remains `NOT_PUBLIC_SAFE` unless separately approved.
- Runtime-active, signal-observed, production-ready, fleet-wide, autonomous SOC,
  live Splunk, Cribl-routed, Wazuh-routed, AWS-live, AI-approved, and
  analyst-approved claims remain blocked unless separately proven and promoted.

## Supported Detections

v0 supports:

- `HO-DET-001`
- `HO-DET-011`

Any other detection ID must fail closed as unsupported.

## State Model

Each reviewer packet must include:

- `controller_version`
- `detection_id`
- `current_state`
- `public_proof_ceiling`
- `private_evidence_state`
- `public_safe_status`
- `runtime_active`
- `signal_observed`
- `ai_decided_disposition`
- `human_review_required`
- `gate_summary`
- `decision`
- `truth_boundary`
- `repo_surfaces_found`
- `required_surfaces_missing`
- `validation_state`
- `proof_state`
- `platform_guardrail_status`
- `blocked_claims`
- `supported_claims`
- `next_allowed_move`
- `stop_conditions`
- `state_consistency`
- `does_not_prove`

## State Rules

`HO-DET-001` must remain capped at `CONTROLLED_TEST_VALIDATED` for public proof.
Private/internal runtime context does not create public runtime-active,
signal-observed, or public-safe proof.

`HO-DET-011` must report `PRIVATE_RUNTIME_EVIDENCE_CAPTURED` where supported by
the proof record. Public-safe status remains `NOT_PUBLIC_SAFE`.

The existing platform `HO-DET-011` case-packet guardrail is pinned to an older
6-case sample. Current detection, validation, and proof surfaces record 17
controlled-test fixtures. v0 must not repair that drift. It must report
`STATE_DRIFT_REVIEW_REQUIRED` in `state_consistency`.

## CLI Contract

Entry point:

```powershell
python -B scripts\ho_factory.py status --detection HO-DET-001 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py status --detection HO-DET-011 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py plan --detection all --repo-root "<ORG_REPO_ROOT>" --format json
```

Modes:

- `status` prints the current reviewer packet.
- `plan` prints the same packet with next allowed move and stop conditions.

The CLI writes to stdout only. It must not create generated output files.

## Fail Closed Rules

The controller must fail closed if:

- required repo surfaces are missing
- required validation state is missing
- blocked-claim fields are absent
- the detection ID is unsupported
- cross-repo state conflicts outside documented `STATE_DRIFT_REVIEW_REQUIRED`
  handling are detected
- proof, validation, detection, website, workflow, or GitHub mutation would be
  required

Unsupported detection IDs fail closed with a non-zero CLI exit.

## Reviewer-Grade Fields

`gate_summary` gives the reviewer a closed-loop chain:

- source
- validation
- platform guardrail
- proof record
- blocked claims
- next legal move

Each gate includes the owning repository, the claim it can safely report, and
`promotion_allowed: false`.

`decision` is the controller review disposition. v0 may report
`READY_FOR_REVIEW` or `DRIFT_REVIEW_REQUIRED`, but it must keep
`proof_promotion_allowed: false` and `public_rendering_allowed: false`.

`truth_boundary` separates source truth, validation truth, platform truth, proof
truth, runtime truth, signal truth, and public proof. v0 reports runtime and
signal as not public proven, and public proof as not public-safe.

These fields make the controller easier to review without adding promotion,
publishing, workflow automation, generated output files, or website updates.

## Reviewer Packet Contract

The schema is:

- `contracts/schemas/detection-factory-controller-v0.schema.json`

Sample packets are:

- `contracts/examples/detection-factory-controller-v0.ho-det-001.sample.json`
- `contracts/examples/detection-factory-controller-v0.ho-det-011.sample.json`

These samples are contract examples, not generated run output.
