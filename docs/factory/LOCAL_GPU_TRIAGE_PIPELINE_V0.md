# Local GPU Triage Pipeline v0

## Purpose

Local GPU Triage Pipeline v0 is a platform-side contract and verifier lane for
bounded local model support in the HawkinsOperations detection factory.

Phase A is intentionally limited to contract, sample, status, and deterministic
verification. It does not create a GitHub Actions GPU workflow, execute a model,
open an SSH connection, generate runtime packets, promote proof, or publish
evidence.

## Phase A Boundary

Phase A records private runtime/support truth as a bounded status packet:

- `ai_support_mode: AI_SUPPORT_ONLY`
- `local_gpu_runtime_status: PRIVATE_RUNTIME_SUPPORT_CONFIRMED`
- `local_gpu_runtime_label: LOCAL_GPU_SUPPORT_NODE`
- `true_gpu_ci_status: PENDING_RUNNER_CONFIRMATION`
- `human_review_required: true`
- `ai_decided_disposition: false`
- `recommended_disposition: null`
- `public_safe_status: NOT_PUBLIC_SAFE`
- `public_proof_ceiling: CONTROLLED_TEST_VALIDATED`
- `runtime_active_public_proof: false`
- `signal_observed_public_proof: false`
- `production_ready: false`

The packet may report that a private local GPU support node and local model
support are available for governed triage support. It must not expose real host
identifiers, local paths, internal network details, raw model output, private
evidence filenames, secrets, or public-proof claims.

## Truth Classes

Artifact truth:

- Existing private Work artifacts may support the internal statement that local
  GPU-backed support-only triage has been observed under guardrails.
- Those artifacts remain private and are not copied into this repo.

Runtime truth:

- Runtime refresh results are private runtime/support truth.
- Runtime truth does not become public proof by being represented in a schema or
  sample.

Platform contract truth:

- This contract defines required packet fields and verifier behavior.
- The verifier enforces claim and privacy boundaries over sanitized packets.

GitHub CI truth:

- True GPU CI remains `PENDING_RUNNER_CONFIRMATION` until self-hosted runner
  labels and repository access are separately proven.
- Phase A does not add a workflow and does not claim GPU CI is implemented.

## CLI Contract

Entry point:

```powershell
python -B scripts\run_local_gpu_triage.py status --format json
```

The CLI prints one sanitized status packet to stdout. It does not write files,
connect over SSH, run local model prompts, pull models, install packages, restart
services, or inspect GitHub runner settings.

## Verifier Contract

Entry point:

```powershell
python -B scripts\verify_local_gpu_triage.py contracts\examples\local-gpu-triage-support-v0.sample.json
```

The verifier fails closed if the packet:

- omits required truth fields
- uses a real host identifier instead of a sanitized label
- includes local paths or internal IP addresses
- includes secrets, tokens, API keys, or passwords
- includes raw model output or private evidence filenames
- promotes public-safe status
- claims runtime-active public proof
- claims signal-observed public proof
- claims production, fleet, or autonomous operation
- gives AI or analyst disposition authority
- decides final disposition
- claims true GPU CI before runner confirmation

## Reviewer Packet Contract

Schema:

- `contracts/schemas/local-gpu-triage-support-v0.schema.json`

Sample:

- `contracts/examples/local-gpu-triage-support-v0.sample.json`

The sample is a contract example only. It is not generated runtime evidence and
does not promote private runtime support to public proof.

## Stop Conditions

Stop before extending Phase A if the next action would require:

- workflow creation or workflow edits
- GitHub runner settings or secret access
- SSH, model execution, or runtime mutation
- generated runtime packet files
- proof, website, validation, detections, or organization metadata edits
- public-safe, runtime-active public proof, signal-observed public proof,
  production, fleet, autonomous, AI-approved, or analyst-approved claims
