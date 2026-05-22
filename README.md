# HawkinsOperations Platform

Platform contracts, integration logic, and operational plumbing for HawkinsOperations.

Owner identity: Raylee Hawkins, Detection Engineer | SOC Automation | Detection-as-Code | Security Automation.

Official links: [Raylee Hawkins on LinkedIn](https://www.linkedin.com/in/raylee-hawkins) | [Raylee Hawkins on GitHub](https://github.com/raylee-hawkins) | [HawkinsOps legacy/reference portfolio](https://hawkinsops.com) | [HawkinsOperations GitHub organization](https://github.com/HawkinsOperations) | [RayleeOps public operating journal](https://rayleeops.com)

## Purpose

This repository defines how detection and validation components are wired, promoted, and operated.

## HawkinsOperations Closed SOC Loop 001

- GitHub Project: pending ProjectV2 access / attachment. Current org project route: https://github.com/orgs/HawkinsOperations/projects
- Reviewer entry point: https://github.com/HawkinsOperations/.github/blob/main/profile/START_HERE.md
- Closed SOC Loop 001 route: https://github.com/HawkinsOperations/hawkinsoperations-validation/blob/main/docs/HO-DET-001_CLOSED_LOOP.md
- Current HO-DET-001 ceiling: CONTROLLED_TEST_VALIDATED
- HawkinsOperations is the governed successor system; HawkinsOps and older surfaces are legacy/reference unless revalidated.
- Truth surface: platform contract and architecture truth. This repository defines integration contracts, promotion plumbing, and environment-agnostic operational controls.
- Sprint thesis: speed with enforcement through deterministic validation, required checks where configured, evidence records, proof contracts, and bounded public claims.
- AI is labor. Governance is authority.
- Build loud. Verify hard. Claim tight. Ship receipts.
- Website/public pages route to proof records; they do not replace proof.
- Validation PR #18 clone-runnable proof pack: merged into `hawkinsoperations-validation`.
- Platform runtime contract enforcement: merged through `HawkinsOperations/hawkinsoperations-platform#5`.
- Platform verifier status: `PLATFORM_RUNTIME_CONTRACT=pass`; this is schema and verifier guardrail only.
- HO-DET-011 case-packet guardrail: `scripts/verify-ho-det-011-case-packet.py` runs in the governance gate workflow; this is claim-boundary CI only.
- Platform contract status: non-promotional guardrail; it does not prove live runtime, public-safe signal, public-safe runtime evidence, live Splunk fired, Splunk-proven Runtime Signal 001, Cribl-routed status, Wazuh-routed public proof, AWS-live status, production-ready status, fleet-wide coverage, autonomous SOC operation, AI-approved disposition, or analyst-approved disposition.
- Next gate: evidence-backed runtime or signal promotion only after separate proof review, privacy review, stale review, wording review, and Raylee approval.
- Runtime-active and signal-observed claims remain blocked.
- Cyber Kill Chain coverage: this repo contributes workflow, case-packet, automation, and AI-support boundary truth to the canonical [Cyber Kill Chain coverage map](https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/docs/mappings/CYBER_KILL_CHAIN_COVERAGE.md) in `hawkinsoperations-proof`. The map is reviewer navigation, not runtime, signal, production, or public-safe proof authority.

## Blocked Claims

This repository does not claim: runtime-active, signal-observed, evidence-linked public proof, public-safe, live Splunk firing, production triage, analyst-approved disposition, LOCAL_GPU_SUPPORT_NODE runtime-active, Cribl-routed, Wazuh-routed, AWS-live, autonomous SOC, production-ready SOC, fleet-wide deployment, or AI-approved disposition.

## Scope

- Pipeline contracts and interface definitions
- Deployment orchestration scripts and integration modules
- Environment-agnostic operational controls and runbooks

## Contract Baseline

Initial contract package is now defined under `contracts/`:

- `contracts/contract-version.json`
- `contracts/schemas/detection-artifact.schema.json`
- `contracts/schemas/validation-report.schema.json`
- `contracts/schemas/proof-record.schema.json`
- `contracts/schemas/local-llm-runtime-receipt.schema.json`
- `contracts/schemas/ho-det-001-runtime-contract.schema.json`
- `contracts/schemas/ho-det-011-case-packet.schema.json`

This baseline defines minimum fields required for reproducible
detection-to-validation-to-proof linkage.

## Out of Scope

- Host-specific workstation configuration state
- Public marketing narrative
- Private credentials, tokens, and secret material

## Repository Contract

- Platform behavior must be deterministic and auditable.
- Integration points must be versioned and explicitly documented.
- Operational changes require corresponding proof updates in `hawkinsoperations-proof`.

## Reviewed External Proof Candidates

- Architecture/control flow diagrams (sanitized)
- Promotion control descriptions
- Reproducible integration checks

## Related Repositories

- Detections: `hawkinsoperations-detections`
- Validation: `hawkinsoperations-validation`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`
