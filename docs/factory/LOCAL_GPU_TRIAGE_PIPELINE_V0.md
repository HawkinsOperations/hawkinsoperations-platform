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
- Phase B may move GitHub CI truth to scheduled validation only after the
  manual workflow runs successfully on the labeled runner.

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

## Not Yet Proven Until Workflow Dispatch Passes

Until a manual `workflow_dispatch` run succeeds, Phase B is implemented but not
validated as GPU CI. `true_gpu_ci_status` remains
`PENDING_RUNNER_CONFIRMATION`. The next gate before model prompt execution is a
separate approval after the Phase B check run is reviewed.

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

Stop before extending this pipeline if the next action would require:

- workflow triggers beyond manual `workflow_dispatch`
- GitHub runner settings or secret access
- SSH, model execution, or runtime mutation
- generated runtime packet files
- proof, website, validation, detections, or organization metadata edits
- public-safe, runtime-active public proof, signal-observed public proof,
  production, fleet, autonomous, AI-approved, or analyst-approved claims
