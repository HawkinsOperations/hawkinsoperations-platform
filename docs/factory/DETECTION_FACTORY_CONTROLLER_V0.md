# Detection Factory Controller v0

## Purpose

Detection Factory Controller v0 is a platform-owned status and plan entry point
for reading HawkinsOperations detection state across the local organization
mirror.

The v0 controller is intentionally narrow. It produces reviewer packets for
`HO-DET-001`, `HO-DET-011`, and `HO-DET-012` from existing repo surfaces. It does not promote
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
- `HO-DET-012`

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

`HO-DET-012` must report `CONTROLLED_TEST_VALIDATED` for controlled scheduled
task creation and update fixtures only. It has no proof record in v0, no
platform sample guardrail in v0, and no runtime-active, signal-observed,
public-safe, or scheduled-task coverage completeness claim. The platform entry
is status visibility only.

## CLI Contract

Entry point:

```powershell
python -B scripts\ho_factory.py status --detection HO-DET-001 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py status --detection HO-DET-011 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py status --detection HO-DET-012 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py plan --detection HO-DET-012 --repo-root "<ORG_REPO_ROOT>" --format json
python -B scripts\ho_factory.py plan --detection all --repo-root "<ORG_REPO_ROOT>" --format json
```

Modes:

- `status` prints the current reviewer packet.
- `plan` prints the same packet with next allowed move and stop conditions.

The CLI writes to stdout only. It must not create generated output files.

## AutoSOC Case Ledger v0

AutoSOC Case Ledger v0 is a platform-owned SQLite seed ledger for durable
schema, insert, verifier, and metrics validation. SQLite is used for v0 because
the standard library can enforce `CHECK` constraints, append-only triggers,
unique event hashes, and metrics queries without adding a service or dependency.

The approved seed path is:

```text
evidence/autosoc-case-ledger-v0.sqlite
```

This repository SQLite file is a v0 seed/sample artifact only. It is not the
long-term live accumulating production or runtime ledger. A live runtime ledger
requires separate non-source-controlled route approval.

### Ledger Schema

`ledger_metadata`:

- `key TEXT PRIMARY KEY`
- `value TEXT NOT NULL`

`case_events`:

- `event_id INTEGER PRIMARY KEY AUTOINCREMENT`
- `event_hash TEXT NOT NULL UNIQUE`
- `parent_event_hash TEXT`
- `inserted_at TEXT NOT NULL`
- `ledger_version TEXT NOT NULL`
- `case_id TEXT NOT NULL`
- `detection_id TEXT NOT NULL`
- `truth_class TEXT NOT NULL`
- `case_status TEXT NOT NULL`
- `proof_ceiling TEXT NOT NULL`
- `public_safe_status TEXT NOT NULL`
- `ai_support_mode TEXT NOT NULL`
- `ai_decided_disposition INTEGER NOT NULL`
- `recommended_disposition TEXT`
- `deterministic_close_eligible INTEGER NOT NULL`
- `deterministic_close_blocked INTEGER NOT NULL`
- `human_review_required INTEGER NOT NULL`
- `gpu_supported INTEGER NOT NULL`
- `public_safe INTEGER NOT NULL`
- `proof_blocked INTEGER NOT NULL`
- `github_issue_mutation_allowed INTEGER NOT NULL`
- `case_closed INTEGER NOT NULL`
- `legacy_import_count INTEGER NOT NULL`
- `payload_json TEXT NOT NULL`
- `source_packet_ref TEXT NOT NULL`

Allowed `truth_class` values:

- `FORWARD_GOVERNED_CASE`
- `SYNTHETIC_TEST_CASE`
- `RECOVERED_HISTORICAL_IMPORT`
- `PRIVATE_RUNTIME_EVIDENCE`
- `PUBLIC_PROOF_CANDIDATE`
- `PUBLIC_BLOCKED`

Required v0 constraints:

- `ai_support_mode = AI_SUPPORT_ONLY`
- `ai_decided_disposition = 0`
- `recommended_disposition IS NULL`
- `deterministic_close_eligible = 0`
- `deterministic_close_blocked = 1`
- `human_review_required = 1`
- `public_safe = 0`
- `proof_blocked = 1`
- `github_issue_mutation_allowed = 0`
- `case_closed = 0`
- `legacy_import_count = 0`

The ledger installs SQLite triggers that abort `UPDATE` and `DELETE` against
`case_events`, preserving append-only behavior. `ledger-verify` confirms those
append-only guards by inspecting the trigger definitions in `sqlite_master`;
it does not run `UPDATE` or `DELETE` negative tests against the seed ledger.

### Ledger CLI

```powershell
python -B scripts\ho_factory.py ledger-init-sample --repo-root "<ORG_REPO_ROOT>" --ledger evidence\autosoc-case-ledger-v0.sqlite
python -B scripts\ho_factory.py ledger-verify --repo-root "<ORG_REPO_ROOT>" --ledger evidence\autosoc-case-ledger-v0.sqlite
python -B scripts\ho_factory.py ledger-metrics --repo-root "<ORG_REPO_ROOT>" --ledger evidence\autosoc-case-ledger-v0.sqlite
```

Only `ledger-init-sample` may create the approved ledger parent directory.
`ledger-verify` and `ledger-metrics` require the seed ledger file to exist and
fail closed if it is missing.

`ledger-verify` and `ledger-metrics` may also inspect an approved external
runtime ledger path outside this repository. In that mode the controller opens
SQLite with `mode=ro`, reports `ledger_scope: external_runtime_ledger`, and
keeps the truth boundary at private runtime review only. `ledger-init-sample`
remains limited to the repository seed ledger and must not initialize or append
to the runtime ledger.

The sample insert path reads the sanitized HO-DET-001 case-factory packet from
the validation repo and inserts one `SYNTHETIC_TEST_CASE` seed event. It does not
copy raw event fields, private paths, hostnames, LAN IPs, usernames, VM IDs, MAC
addresses, raw model output, secrets, private evidence filenames, or internal
service details.

The metrics output includes:

- `total_cases`
- `cases_by_detection`
- `cases_by_truth_class`
- `cases_by_status`
- `gpu_supported_count`
- `deterministic_close_eligible_count`
- `deterministic_close_blocked_count`
- `human_review_required_count`
- `public_safe_count`
- `proof_blocked_count`

Ledger metrics count ledger rows only. They do not import or claim legacy/V1
historical counts as current governed proof.

### Splunk HO-DET-001 Runtime Ingest Dry Run

The controller includes a bounded dry-run adapter for sanitized Splunk
`HO-DET-001` runtime candidates:

```powershell
python -B scripts\ho_factory.py runtime-ledger-ingest-splunk-ho-det-001 --mode dry-run --ledger "<APPROVED_RUNTIME_LEDGER>" --sanitized-input - --format json
```

The adapter does not connect to Splunk, run Splunk searches, mutate GitHub
Issues, append ledger rows, close cases, promote proof, or promote public-safe
status. It opens the runtime ledger read-only, parses sanitized JSON from stdin
or an existing approved input path, builds one candidate case packet in memory,
computes the deterministic `event_hash`, checks duplicate `event_hash` and
`case_id`, and prints before/expected-after metrics.

Allowed sanitized input fields:

- `case_id`
- `detection_id`
- `source_system`
- `observed_time_utc`
- `splunk_result_ref`
- `sanitized_event_fingerprint`
- `rule_match_name`
- `rule_match_version`

Blocked input fields include raw Splunk `_raw`, raw event payloads, raw command
lines, hostnames, usernames, LAN IPs, MAC addresses, VM IDs, private paths,
private evidence filenames, secrets, tokens, credentials, and internal service
details. The dry-run candidate preserves `AI_SUPPORT_ONLY`,
`human_review_required=true`, `deterministic_close_eligible=false`,
`deterministic_close_blocked=true`, `github_issue_mutation_allowed=false`,
`public_safe=false`, `proof_blocked=true`, and `case_closed=false`.

The exact approval phrase required before any later append is:

```text
APPEND_ONE_SANITIZED_SPLUNK_HO_DET_001_RUNTIME_CASE_APPROVED
```

### Runtime Case Review

The controller includes a repeatable read-only review command for a single
runtime ledger case:

```powershell
python -B scripts\ho_factory.py runtime-ledger-review-case --self-test --format json
python -B scripts\ho_factory.py runtime-ledger-review-case --ledger "<APPROVED_RUNTIME_LEDGER>" --case-id "<CASE_ID>" --format json
python -B scripts\ho_factory.py runtime-ledger-review-case --ledger "<APPROVED_RUNTIME_LEDGER>" --case-id "<CASE_ID>" --self-test --format json
```

The standalone `--self-test` command runs in-memory negative checks only and
does not open an external runtime ledger or require a target case. The review
command opens the approved runtime ledger read-only, verifies the target case
exists, runs the ledger verifier, inspects append-only trigger definitions,
scans the stored case text fields for private markers, prints a metrics
snapshot, and returns the blocked claims, supported internal claim, and next
allowed move. The combined form runs the same runtime ledger review and attaches
the in-memory self-test result. Self-tests create no files, append no ledger
rows, and perform no runtime or GitHub mutation.

The command must fail closed if the target case is missing, if append-only
triggers are missing or non-aborting, if a private marker appears in stored
case text fields, or if any reviewed boundary field is promoted. The reviewed
case must preserve `github_issue_mutation_allowed=false`, `case_closed=false`,
`ai_decided_disposition=false`, `deterministic_close_eligible=false`,
`human_review_required=true`, `public_safe=false`, `proof_blocked=true`,
`proof_promotion_allowed=false`, and `public_safe_promotion_allowed=false`.

The runtime review self-tests must fail closed for missing case IDs, private
markers in reviewed case text, raw Splunk `_raw`, host fields, username fields,
LAN IPs, local paths, token or secret markers, public-safe promotion, proof
promotion, case closure authority, and AI disposition authority.

The review command does not append ledger rows, connect to Splunk, run Splunk
searches, mutate GitHub Issues, close cases, promote proof, promote public-safe
status, or grant AI close, approval, or disposition authority.

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
- the ledger would promote proof, public-safe status, AI disposition authority,
  GitHub Issue mutation, or case closure
- the ledger would import legacy/V1 historical counts as governed proof
- the ledger would expose private paths, hostnames, LAN IPs, usernames, VM IDs,
  MAC addresses, raw model output, secrets, private evidence filenames, or
  internal service details

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
