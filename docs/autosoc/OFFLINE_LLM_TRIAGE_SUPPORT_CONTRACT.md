# Offline LLM Triage Support Contract

## Purpose

This contract defines how HawkinsOperations may use an offline or local model as triage-support labor without granting it authority.

The contract is sanitized for repo review by design. It does not include raw prompts, raw model output, local paths, host labels, device identifiers, private evidence filenames, or runtime configuration details.

## Current Scope

- Contract status: `SOURCE_EXISTS`
- Supported workflow: support-only triage over a sanitized case packet
- Public proof ceiling: `CONTROLLED_TEST_VALIDATED`
- Private evidence classification: `PRIVATE_RUNTIME_EVIDENCE` or `PRIVATE_SUPPORTING_EVIDENCE`
- Public-safe status: `NOT_PUBLIC_SAFE`

Private model-support and GPU-activity observations remain private evidence. They do not promote public runtime, signal, production, or public-safe proof.

## Input Case Packet Requirements

The input case packet must be sanitized before model use.

Required fields:

- `case_id`
- `detection_id`
- `proof_ceiling`
- `public_safe_status`
- `validation_summary`
- `allowed_ai_actions`
- `blocked_ai_actions`
- `human_review_required`

Blocked input content:

- raw private evidence
- local filesystem paths
- hostnames
- LAN IPs
- usernames
- VM IDs
- MAC addresses
- command-line dumps from private runtime evidence
- raw model prompts from private runs
- private evidence filenames
- internal service names
- device paths
- SSH or infrastructure details

## Allowed Model Output Fields

The model may produce support-only fields:

- `summary`
- `triage_notes`
- `questions_for_human_review`
- `hypotheses`
- `recommended_next_checks`
- `confidence_notes`

Every output is advisory. AI output is not authority.

## AutoSOC Case Factory v0 Issue Boundary

AutoSOC Case Factory v0 may attach model-support context only to sanitized case
packets. The case factory may prepare a dry-run GitHub Issue label/comment plan,
but it must not mutate GitHub Issues, close cases, approve cases, promote proof,
or mark anything public-safe.

Required v0 issue-boundary values:

```text
GITHUB_ISSUE_PLAN_MODE=dry_run_only
GITHUB_ISSUE_MUTATION_ALLOWED=false
GITHUB_ISSUE_CLOSE_ALLOWED=false
DETERMINISTIC_CLOSE_ELIGIBLE=false
CASE_FACTORY_RESULT=BLOCKED_HUMAN_REVIEW_REQUIRED
AI_SUPPORT_MODE=AI_SUPPORT_ONLY
```

The deterministic verifier may evaluate whether a case packet is complete enough
to prepare a dry-run status update. That evaluation is not closure authority.
Human review remains required.

## Blocked Model Output Fields And Actions

The model must not set or imply:

- `approved=true`
- `closed=true`
- `promoted=true`
- `public_safe=true`
- `ai_decided_disposition=true`
- `analyst_approved_disposition=true`
- production status
- runtime-active public proof
- signal-observed public proof
- public-safe runtime proof

Blocked actions:

- approve
- promote
- close
- decide disposition
- mark public-safe
- claim production
- claim autonomous SOC

## Verifier Failure Conditions

The deterministic verifier must fail if:

- AI decides disposition.
- AI may approve, promote, close, or mark public-safe.
- Human review is not required.
- Recommended disposition is non-null.
- GitHub Issue mutation or closure is allowed in a v0 packet.
- Public-safe status is anything other than `NOT_PUBLIC_SAFE`.
- Proof ceiling is stronger than the current allowed ceiling.
- Output contains private paths, hostnames, LAN IPs, usernames, VM IDs, MAC addresses, raw model output, private evidence filenames, internal service names, device paths, SSH details, infrastructure details, or GPU host labels.

## Proof Ceiling Handling

For HO-DET-001, public proof remains:

```text
PROOF_CEILING=CONTROLLED_TEST_VALIDATED
```

Private model support and private GPU activity do not change the public proof ceiling.

## Required Boundary Values

```text
AI_DECIDED_DISPOSITION=false
HUMAN_REVIEW_REQUIRED=true
RECOMMENDED_DISPOSITION=null
AI_MAY_APPROVE=false
AI_MAY_PROMOTE=false
AI_MAY_CLOSE=false
PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE
PROOF_CEILING=CONTROLLED_TEST_VALIDATED
```

## Allowed Internal Classification Wording

These phrases are allowed only as bounded internal classification or reviewed contract language. They are not public proof claims and do not make private runtime evidence public-safe.

- `private lab model support completed`
- `private GPU activity observed during bounded model call`
- `AI remained support-only`
- `deterministic verifier preserved boundary`
- `public proof ceiling remains CONTROLLED_TEST_VALIDATED`

## Blocked Public Wording

- `GPU triage public proof`
- `runtime-active public proof`
- `production AutoSOC`
- `autonomous SOC`
- `AI disposition approved`
- `analyst-approved disposition`
