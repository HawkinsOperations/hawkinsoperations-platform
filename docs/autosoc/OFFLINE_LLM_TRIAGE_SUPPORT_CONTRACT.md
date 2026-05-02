# Offline LLM Triage Support Contract

## Purpose

This contract defines how HawkinsOperations may use an offline or local model as triage-support labor without granting it authority.

The contract is public-safe by design. It does not include raw prompts, raw model output, local paths, host labels, device identifiers, private evidence filenames, or runtime configuration details.

## Current Scope

- Contract status: `SOURCE_EXISTS`
- Supported workflow: support-only triage over a sanitized case packet
- Public proof ceiling: `TEST_VALIDATED_SYNTHETIC_SCOPE`
- Private evidence classification: `PRIVATE_RUNTIME_EVIDENCE` or `PRIVATE_SUPPORTING_EVIDENCE`
- Public-safe status: `NOT_PUBLIC_SAFE`

Private lab model support completed and private GPU activity was observed during a bounded model call. Those observations remain private evidence and do not promote public runtime, signal, production, or public-safe proof.

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
- Public-safe status is anything other than `NOT_PUBLIC_SAFE`.
- Proof ceiling is stronger than the current allowed ceiling.
- Output contains private paths, hostnames, LAN IPs, usernames, VM IDs, MAC addresses, raw model output, private evidence filenames, internal service names, device paths, SSH details, infrastructure details, or GPU host labels.

## Proof Ceiling Handling

For HO-DET-001, public proof remains:

```text
PROOF_CEILING=TEST_VALIDATED_SYNTHETIC_SCOPE
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
PROOF_CEILING=TEST_VALIDATED_SYNTHETIC_SCOPE
```

## Allowed Public Wording

- `private lab model support completed`
- `private GPU activity observed during bounded model call`
- `AI remained support-only`
- `deterministic verifier preserved boundary`
- `public proof ceiling remains TEST_VALIDATED_SYNTHETIC_SCOPE`

## Blocked Public Wording

- `GPU triage public proof`
- `runtime-active public proof`
- `production AutoSOC`
- `autonomous SOC`
- `AI disposition approved`
- `analyst-approved disposition`
