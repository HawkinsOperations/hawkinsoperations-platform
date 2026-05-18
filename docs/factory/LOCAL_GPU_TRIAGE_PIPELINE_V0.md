# Local GPU Triage Pipeline v0

## Purpose

Local GPU Triage Pipeline v0 is a platform-side contract and verifier lane for
bounded local model support in the HawkinsOperations detection factory.

Phase A is intentionally limited to contract, sample, status, and deterministic
verification. Phase B adds a manual GitHub Actions gate that schedules onto the
strictly labeled local GPU runner and runs deterministic contract/status checks.
Neither phase executes a model, opens SSH, generates runtime packets, promotes
proof, or publishes evidence.

## Phase A Boundary

The current bounded status packet records private runtime/support truth and the
approved reclassified Phase B GitHub Actions gate receipt:

- `ai_support_mode: AI_SUPPORT_ONLY`
- `local_gpu_runtime_status: PRIVATE_RUNTIME_SUPPORT_CONFIRMED`
- `local_gpu_runtime_label: LOCAL_GPU_SUPPORT_NODE`
- `true_gpu_ci_status: LOCAL_GPU_TRIAGE_GATE_GITHUB_ACTIONS_RUN_PASSED_WITH_PRIVATE_OPERATIONAL_METADATA`
- `github_ci_truth.workflow_run_id: 26006504673`
- `github_ci_truth.model_execution_in_ci: false`
- `github_ci_truth.ollama_prompt_execution_in_ci: false`
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

GitHub Actions gate truth:

- Local GPU Triage Gate run `26006504673` is the current bounded receipt.
- The run is logged as
  `LOCAL_GPU_TRIAGE_GATE_GITHUB_ACTIONS_RUN_PASSED_WITH_PRIVATE_OPERATIONAL_METADATA`.
- The manual GitHub Actions gate executed on the configured self-hosted GPU
  runner label route and passed deterministic contract/status/verifier checks.
- The gate receipt does not claim model execution in CI, Ollama prompt
  execution in CI, public-safe runtime proof, runtime-active public proof, or
  signal-observed public proof.

## CLI Contract

Entry point:

```powershell
python -B scripts\run_local_gpu_triage.py status --format json
```

The CLI prints one sanitized status packet to stdout. It does not write files,
connect over SSH, run local model prompts, pull models, install packages, restart
services, or inspect GitHub runner settings.

## Phase B Workflow Gate

Workflow:

- `.github/workflows/local-gpu-triage-gate.yml`

Trigger:

- `workflow_dispatch` only

Runner labels:

- `self-hosted`
- `ho-gpu-01`
- `gpu`
- `v100`

The workflow confirms the runner context, validates Local GPU Triage Pipeline v0
JSON syntax, runs the deterministic verifier with negative self-tests, prints the
sanitized status packet, and runs existing platform verifier gates.

The factory controller plan is conditional because a normal Actions checkout
contains only this repository, while `ho_factory.py` expects a local organization
mirror with sibling repos. If the sibling repos are absent, the workflow prints an
explicit skip reason and keeps the Phase B proof limited to the local GPU triage
contract/status lane.

Phase B does not run an Ollama prompt, execute model inference, upload
artifacts, print secrets, use Docker, mutate runner configuration, or claim
public-safe, runtime-active public proof, signal-observed public proof,
production, autonomous, AI-approved, or analyst-approved status.

## Measurable Upgrade From Legacy Script Loop

| Control | Legacy 35-script/manual loop | Phase B gate |
| --- | --- | --- |
| Entry point | Many local scripts and manual sequencing | One manual `workflow_dispatch` workflow |
| Runner routing | Operator memory and local shell state | Strict labels: `self-hosted`, `ho-gpu-01`, `gpu`, `v100` |
| Overlap control | Manual discipline | GitHub concurrency group `local-gpu-triage-gate` |
| Time bound | Manual timeout discipline | 10 minute job timeout |
| Verifier coverage | Local command history | CI-visible verifier plus negative self-tests |
| CI receipt | Local transcript or operator notes | GitHub check result after run |
| Model boundary | Manual prompt discipline | No model prompt commands in the workflow |

## Phase B Success Criteria

Phase B is successful only after the manual workflow run completes on the
strictly labeled runner and the GitHub check shows:

- one workflow entry point
- strict GPU runner labels
- deterministic verifier self-tests pass
- status packet prints from `run_local_gpu_triage.py`
- no model prompt execution
- no artifact upload
- no public proof promotion
- no production or autonomous claim
- manual dispatch only
- bounded timeout
- concurrency gate
- GitHub check result acts as the CI receipt

## Current Gate Receipt

Manual `workflow_dispatch` run `26006504673` is the current bounded Phase B
receipt after approved metadata reclassification. The passed bounded markers are:

- `GPU_CAPABILITY_CHECK=pass`
- `LOCAL_GPU_TRIAGE_JSON_VALIDATION=pass`
- `LOCAL_GPU_TRIAGE_VERIFIER=pass`
- `STATUS_PACKET_RECEIPT=pass`
- `PLATFORM_VERIFIERS=pass`

The next gate before any model prompt execution remains a separate approval.
Private/local Ollama support is tracked as private Work artifact truth and is
not CI model execution.

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
- claims model execution in CI or Ollama prompt execution in CI

## Reviewer Packet Contract

Schema:

- `contracts/schemas/local-gpu-triage-support-v0.schema.json`

Sample:

- `contracts/examples/local-gpu-triage-support-v0.sample.json`

The sample is a contract example only. It is not generated runtime evidence and
does not promote private runtime support to public proof.

## Stop Conditions

Stop before extending this pipeline if the next action would require:

- workflow triggers beyond manual `workflow_dispatch`
- GitHub runner settings or secret access
- SSH, model execution, or runtime mutation
- generated runtime packet files
- proof, website, validation, detections, or organization metadata edits
- public-safe, runtime-active public proof, signal-observed public proof,
  production, fleet, autonomous, AI-approved, or analyst-approved claims
