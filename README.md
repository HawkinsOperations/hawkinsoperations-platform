# HawkinsOperations Platform

HawkinsOperations Platform is the contract, verifier, ledger, and automation guardrail layer for HawkinsOperations.

It shows how AI-assisted SOC and detection work can be controlled before it becomes security truth: detections move through schemas, deterministic verifiers, case-packet rules, runtime-receipt shapes, ledger mechanics, reviewer metrics, and proof handoff boundaries instead of relying on generated output or presentation alone.

## 10-Second Platform Signal

Open this repo when you want to see the control layer between AI-assisted security labor and validated security claims.

| Platform receipt | What to inspect | Why it matters |
| --- | --- | --- |
| Detection Factory Controller v0 | `scripts/ho_factory.py`, `docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md` | Produces read-only reviewer packets with gate summaries, decisions, truth boundaries, blocked claims, and next legal moves for `HO-DET-*` and `ID-DET-*` lanes. |
| Lifetime Case Ledger spine | `contracts/lifetime-case-ledger-v1-state-manifest.json`, `docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md`, `scripts/verify-lifetime-ledger-backup-drill.py` | Models governed case state, recoverability, append gates, correction gates, dedupe, and proof handoff support without mutating canonical ledger state. |
| Runtime and case-packet guardrails | `contracts/schemas/ho-det-001-runtime-contract.schema.json`, `contracts/schemas/ho-det-011-case-packet.schema.json`, `scripts/verify-ho-det-011-case-packet.py`, `scripts/verify-soar-case-packet-v0.py` | Defines the fields a runtime receipt or case packet must carry before it can support review. The guardrail is the receipt shape, not a runtime claim. |
| Reviewer metrics pipeline | `contracts/reviewer-metrics-pipeline-v1-state.json`, `docs/factory/REVIEWER_METRICS_PIPELINE_V1.md`, `scripts/verify-reviewer-metrics-pipeline.py` | Separates strict governed case counts from reviewer-visible validation, proof, blocked-claim, and detection-family metrics. |
| AI support and telemetry boundary lanes | `docs/factory/LOCAL_GPU_TRIAGE_PIPELINE_V0.md`, `docs/factory/TELEMETRY_COVERAGE_CONTRACT_V0.md`, `scripts/verify_local_gpu_triage.py`, `scripts/verify-telemetry-coverage-contract.py` | Shows support-only AI/GPU triage and telemetry coverage contracts with deterministic checks and explicit human-review gates. |

## What This Repo Owns

Platform owns enforceable interface mechanics for HawkinsOperations:

- **Contracts and schemas** for detection artifacts, validation reports, proof records, runtime receipts, case packets, SOAR packets, collector eligibility, telemetry coverage, and reviewer metrics.
- **Deterministic verifiers** that fail closed when required fields, boundaries, or fixture shapes drift.
- **Ledger mechanics** for governed case state, recoverability drills, append gates, correction gates, manual-fire modeling, and state manifests.
- **Runtime-receipt and case-packet guardrails** that describe what a safe packet must include before a runtime, signal, or proof claim can even be reviewed.
- **Reviewer metrics state** that makes activity volume visible without inflating proof, runtime, or public-safe status.
- **Automation checks** that run platform contract and guardrail verification in GitHub workflows where configured.

The hiring signal is platform engineering discipline: Raylee can design the control layer between AI-assisted SOC work and security truth.

## Strongest Platform Receipts

| Receipt | Route | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Detection Factory Controller v0 | `scripts/ho_factory.py` and `docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md` | A source-controlled, read-only platform controller can emit bounded reviewer packets for supported detection IDs with explicit state, gate, boundary, and next-action fields. | It does not promote proof, publish evidence, update websites, create PRs, merge changes, or claim runtime-active, signal-observed, production, public-safe, AI-approved, or analyst-approved status. |
| Lifetime Case Ledger v1 mechanics | `contracts/lifetime-case-ledger-v1-state-manifest.json`, `contracts/lifetime-case-ledger-v1-recoverability-drill.json`, `scripts/verify-lifetime-ledger-backup-drill.py` | The repo contains verifier-backed ledger state and recoverability mechanics for governed case handling, including backup comparison and no-mutation drill behavior. | It does not append a real case, restore production state, prove runtime truth, close a case, or create public proof. |
| HO-DET-011 case-packet guardrail | `contracts/schemas/ho-det-011-case-packet.schema.json`, `contracts/examples/ho-det-011-case-packet.sample.json`, `scripts/verify-ho-det-011-case-packet.py` | The platform can enforce controlled case-packet shape and boundary fields for a current detection workflow. | It does not prove live runtime execution, live signal observation, public-safe runtime proof, production deployment, or disposition approval. |
| Runtime Route Proof v1 private candidate shape | `docs/factory/RUNTIME_ROUTE_PROOF_V1_PRIVATE_CANDIDATE.md`, `contracts/schemas/runtime-route-proof-v1-private-candidate.schema.json`, `scripts/verify-runtime-route-proof-v1-private-candidate.py` | The platform can validate a reviewer-safe private route-proof packet reference while preserving manifest, receipt, and public-safe-count boundaries. | It does not run markers, query Wazuh/Cribl/Splunk, mutate runtime systems, include raw private evidence, or approve public publication. |
| Local GPU Triage Pipeline v0 | `docs/factory/LOCAL_GPU_TRIAGE_PIPELINE_V0.md`, `contracts/schemas/local-gpu-triage-support-v0.schema.json`, `.github/workflows/local-gpu-triage-gate.yml` | The repo defines a support-only AI/GPU triage contract and manual workflow gate with deterministic verifier checks and human review required. | It does not run model prompts in CI, decide disposition, approve analyst action, publish private output, or prove public-safe/runtime-active/signal-observed status. |
| Reviewer Metrics Pipeline v1 | `contracts/reviewer-metrics-pipeline-v1-state.json`, `docs/factory/REVIEWER_METRICS_PIPELINE_V1.md` | Reviewer-facing activity metrics are separated from strict Lifetime Case Ledger counts and proof/public-safe status. | Metrics volume does not prove runtime execution, signal observation, public-safe proof, production coverage, or deployment maturity. |
| Telemetry Coverage Contract v0 | `docs/factory/TELEMETRY_COVERAGE_CONTRACT_V0.md`, `contracts/examples/telemetry-coverage-contract-v0.sample.json`, `scripts/verify-telemetry-coverage-contract.py` | `HO-NDR-001` and `HO-PIPE-001` have bounded contract truth for NDR visibility and pipeline route integrity concepts. | It does not prove packet capture, observed Security Onion telemetry, live Splunk results, Cribl-routed proof, Wazuh-routed proof, or production NDR coverage. |

## How Platform Fits HawkinsOperations

HawkinsOperations separates work into truth surfaces:

```text
Detection source
  -> controlled validation
  -> platform contracts and verifiers
  -> case packet / runtime receipt guardrails
  -> proof records and reviewer metrics
  -> public routing only after approval
```

Platform is the enforceable interface layer in that chain. It does not replace detections, validation, proof, or human governance. It makes the handoff between them auditable.

## Reviewer Path

Start here:

1. Read `contracts/README.md` for the contract inventory and current platform lanes.
2. Inspect `scripts/ho_factory.py` and `docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md` for the reviewer-packet controller.
3. Inspect `docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md` and `contracts/lifetime-case-ledger-v1-state-manifest.json` for ledger mechanics.
4. Inspect `docs/factory/REVIEWER_METRICS_PIPELINE_V1.md` and `contracts/reviewer-metrics-pipeline-v1-state.json` for reviewer metrics boundaries.
5. Inspect `.github/workflows/governance-gate.yml` for platform verifier automation.

Useful local checks:

```powershell
python -B scripts/ho_factory.py --help
python -B scripts/verify-lifetime-ledger-backup-drill.py --format json
python -B scripts/verify-ho-det-011-case-packet.py
python -B scripts/verify-reviewer-metrics-pipeline.py
python -B scripts/verify-runtime-route-proof-v1-private-candidate.py
python -B scripts/verify-runtime-collector-eligibility-v0.py --registry contracts/examples/runtime-collector-eligibility-v0.sample.json --schema contracts/schemas/runtime-collector-eligibility-v0.schema.json
python -B scripts/verify-soar-case-packet-v0.py
python -B scripts/verify-telemetry-coverage-contract.py
python -B scripts/verify_local_gpu_triage.py contracts/examples/local-gpu-triage-support-v0.sample.json --self-test
```

Some controller commands expect a local HawkinsOperations organization mirror with sibling repositories. If those siblings are absent, treat the result as a local-environment limitation, not as proof failure or proof promotion.

## Automation And Guardrails

The governance workflow currently wires multiple platform checks, including required-file presence, ledger recoverability context, HO-DET-011 case-packet validation, Runtime Route Proof v1 private candidate shape, runtime collector eligibility, and Lifetime Case Ledger v1 gate checks.

Automation in this repo supports source and validation truth. It is not merge authority, publication authority, runtime authority, or proof authority.

## Current Claim Boundary

This repo can claim source-controlled contracts, schemas, examples, verifier scripts, workflow wiring, and bounded documentation exist.

It can claim a deterministic verifier passed only within that verifier's stated source-controlled scope.

It does not claim:

- live runtime execution
- live signal observation
- public-safe runtime proof
- production SOCaaS
- customer deployment
- autonomous SOC
- AI-decided disposition
- AI-approved disposition
- analyst-approved disposition
- live Splunk, Wazuh, Cribl, Security Onion, AWS, or FortiSIEM proof
- fleet-wide deployment
- production-ready platform status

Private runtime, signal, evidence, or support context stays private unless it is separately reviewed, bounded, redacted, and approved for a public or reviewer surface.

## Repository Contract

- Platform behavior must be deterministic and auditable.
- Integration points must be versioned and explicitly documented.
- Runtime, signal, evidence, proof, and public-safe claims must stay in their proven trust classes.
- Operational proof wording belongs in `hawkinsoperations-proof`, not in platform by implication.
- Website or reviewer navigation may point to proof records, but presentation does not replace proof.

## Scope

In scope:

- Platform contracts and schema definitions
- Ledger recoverability and state-mechanics checks
- Case-packet, SOAR-packet, runtime-receipt, and collector guardrails
- Deterministic verifier scripts
- Environment-agnostic automation mechanics
- Reviewer navigation for platform contracts and metrics

Out of scope:

- Host-specific workstation configuration state
- Private credentials, tokens, secrets, or raw evidence
- Runtime execution claims
- Live telemetry or signal claims
- SOCaaS availability claims
- Production-ready platform claims
- Public-safe promotion
- Disposition approval authority

## Related HawkinsOperations Repositories

- Organization profile and reviewer start: [HawkinsOperations/.github](https://github.com/HawkinsOperations/.github)
- Detections: `hawkinsoperations-detections`
- Validation: `hawkinsoperations-validation`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`

HawkinsOperations is the governed successor system. HawkinsOps and older surfaces are legacy/reference unless revalidated.

AI is labor. Governance is authority.
