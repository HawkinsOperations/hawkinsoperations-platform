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
- `contracts/schemas/telemetry-coverage-contract-v0.schema.json`

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
- `contracts/examples/telemetry-coverage-contract-v0.sample.json`

## Contract Intent

These contracts define minimum required fields for reproducible
detection-to-validation-to-proof linkage. They are baseline constraints,
not full maturity coverage.

## Detection Factory Controller v0

Detection Factory Controller v0 is documented in:

- `docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md`

The controller entry point is:

- `scripts/ho_factory.py`

v0 supports status and plan reviewer packets for `HO-DET-001`, `HO-DET-011`,
`HO-DET-012`, `ID-DET-001`, `ID-DET-002`, `ID-DET-003`, and `ID-DET-004`.
It is read-only and stdout-only. It does not create generated output files,
promote proof, publish evidence, update website wording, create pull requests,
merge changes, or claim public-safe/runtime-active/signal-observed status.

Reviewer packets include `gate_summary`, `decision`, and `truth_boundary`
fields so reviewers can see the source, validation, platform guardrail, proof
record, blocked-claim, and next-legal-move chain without inferring promotion.

`HO-DET-011` now aligns the platform case-packet guardrail sample, schema,
verifier, and factory status with the current 17 controlled-test fixture
validation shape. The update is non-promotional: proof ceiling remains
`CONTROLLED_TEST_VALIDATED`, public-safe status remains `NOT_PUBLIC_SAFE`, and
runtime-active, signal-observed, public-safe runtime, production, and AI
authority claims remain blocked.

`ID-DET-002`, `ID-DET-003`, and `ID-DET-004` are validation-backed platform
visibility packets after `hawkinsoperations-validation` PR #46. They report
controlled-test validation visibility only and keep proof, runtime, signal,
public-safe, production identity coverage, and live IdP/SIEM/NDR claims blocked.

## Local GPU Triage Pipeline v0

Local GPU Triage Pipeline v0 is documented in:

- `docs/factory/LOCAL_GPU_TRIAGE_PIPELINE_V0.md`

The status entry point is:

- `scripts/run_local_gpu_triage.py`

The deterministic verifier is:

- `scripts/verify_local_gpu_triage.py`

The current bounded status packet reports sanitized private local GPU support
status, preserves `AI_SUPPORT_ONLY`, requires human review, and records the
approved reclassified Local GPU Triage Gate run `26006504673` as
`LOCAL_GPU_TRIAGE_GATE_GITHUB_ACTIONS_RUN_PASSED_WITH_PRIVATE_OPERATIONAL_METADATA`.
The manual GitHub Actions gate executed on the configured self-hosted GPU runner
label route and passed deterministic contract/status/verifier checks. It does
not create generated runtime packets, open SSH, execute model prompts in CI,
run Ollama prompts in CI, inspect runner settings, promote proof, or claim
public-safe, runtime-active public proof, signal-observed public proof,
production, autonomous, AI-approved, or analyst-approved status.

## Telemetry Coverage Contract v0

Telemetry Coverage Contract v0 is documented in:

- `docs/factory/TELEMETRY_COVERAGE_CONTRACT_V0.md`

The deterministic verifier is:

- `scripts/verify-telemetry-coverage-contract.py`

The contract aligns `HO-NDR-001` and `HO-PIPE-001` as Command & Control support
lane contract truth only. It preserves `VALIDATION_CONTRACT_ENFORCED`,
`NOT_PUBLIC_SAFE`, `runtime_active=false`, `signal_observed=false`, and human
review requirements while blocking runtime-active, signal-observed, live Splunk,
Cribl-routed proof, Wazuh-routed proof, Security Onion observed proof,
production-ready, public-safe runtime, autonomous SOC, AI-approved, and
analyst-approved claims.
