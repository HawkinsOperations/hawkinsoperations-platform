# Platform Contracts

This directory defines cross-repository interface contracts for the HawkinsOperations engineering chain:

- `hawkinsoperations-detections` output artifacts
- `hawkinsoperations-validation` report artifacts
- `hawkinsoperations-proof` proof record artifacts

## Versioning

Current contract version is tracked in:

- `contracts/contract-version.json`

Any schema-breaking change requires:

1. Version increment
2. Migration note
3. Explicit downstream update plan

## Schemas

- `contracts/schemas/detection-artifact.schema.json`
- `contracts/schemas/validation-report.schema.json`
- `contracts/schemas/proof-record.schema.json`
- `contracts/schemas/local-llm-runtime-receipt.schema.json`
- `contracts/schemas/detection-factory-controller-v0.schema.json`
- `contracts/schemas/local-gpu-triage-support-v0.schema.json`

## Local LLM Runtime Receipt Boundary

The local LLM runtime receipt schema is a schema-level control only. It may
record sanitized model metadata, input hashes, output hashes, runtime status,
operator review state, and explicit AI authority boundaries.

It does not prove:

- runtime-active status
- signal-observed status
- public-safe status
- AI-approved disposition

Minimal examples live in:

- `contracts/examples/local-llm-runtime-receipt.valid.sample.json`
- `contracts/examples/detection-factory-controller-v0.ho-det-001.sample.json`
- `contracts/examples/detection-factory-controller-v0.ho-det-011.sample.json`
- `contracts/examples/local-gpu-triage-support-v0.sample.json`

## Contract Intent

These contracts define minimum required fields for reproducible
detection-to-validation-to-proof linkage. They are baseline constraints,
not full maturity coverage.

## Detection Factory Controller v0

Detection Factory Controller v0 is documented in:

- `docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md`

The controller entry point is:

- `scripts/ho_factory.py`

v0 supports status and plan reviewer packets for `HO-DET-001` and
`HO-DET-011`. It is read-only and stdout-only. It does not create generated
output files, promote proof, publish evidence, update website wording, create
pull requests, merge changes, or claim public-safe/runtime-active/signal-
observed status.

Reviewer packets include `gate_summary`, `decision`, and `truth_boundary`
fields so reviewers can see the source, validation, platform guardrail, proof
record, blocked-claim, and next-legal-move chain without inferring promotion.

`HO-DET-011` currently reports `STATE_DRIFT_REVIEW_REQUIRED` because the
platform case-packet guardrail sample remains pinned to an earlier 6-case shape
while current detection, validation, and proof surfaces record 17 controlled-
test fixtures. v0 reports that drift; it does not repair it.

## Local GPU Triage Pipeline v0

Local GPU Triage Pipeline v0 is documented in:

- `docs/factory/LOCAL_GPU_TRIAGE_PIPELINE_V0.md`

The status entry point is:

- `scripts/run_local_gpu_triage.py`

The deterministic verifier is:

- `scripts/verify_local_gpu_triage.py`

Phase A is contract and verifier only. It reports sanitized private local GPU
support status, preserves `AI_SUPPORT_ONLY`, requires human review, keeps true
GPU CI at `PENDING_RUNNER_CONFIRMATION`, and writes only to stdout. It does not
create generated runtime packets, open SSH, execute model prompts, create
workflows, inspect runner settings, promote proof, or claim public-safe,
runtime-active public proof, signal-observed public proof, production,
autonomous, AI-approved, or analyst-approved status.
