# HawkinsOperations Platform

HawkinsOperations Platform is the contract and automation layer for the HawkinsOperations security-engineering system.

It shows how platform mechanics keep detection, validation, ledger, and proof work bounded: schemas define allowed shapes, verifiers enforce guardrails, ledgers preserve controlled state, and automation checks whether the contract still holds.

This repository does not prove live runtime execution, live signal observation, SOCaaS availability, production readiness, public-safe evidence, or analyst-approved disposition.

## 10-Second Reviewer Path

If you have limited time, inspect these first:

1. `contracts/` - versioned schemas and contract files.
2. `scripts/` - deterministic verifier and ledger-mechanics checks.
3. `.github/workflows/` - automation hooks that run contract and guardrail checks where configured.
4. `docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md` - how the lifetime ledger mechanics are modeled.
5. `contracts/lifetime-case-ledger-v1-recoverability-drill.json` - tracked seed contract for ledger recoverability validation.

## What Security Leaders Should Inspect

- Whether contracts separate source, validation, proof, runtime, and public-safe claims.
- Whether automation fails closed when required fields, ledgers, or claim boundaries drift.
- Whether the runtime contract is treated as a schema/verifier guardrail instead of runtime proof.
- Whether ledger checks preserve recoverability, dedupe, correction, and approval-gate mechanics.
- Whether README wording, docs, and verifier outputs avoid overclaiming production, signal, public-safe, or SOCaaS status.

## Platform Value

This repo translates HawkinsOperations from "security content exists" into "security work has enforceable interfaces."

- **Contracts:** define the fields and boundaries needed for detection, validation, proof, runtime receipt, and case-packet handoffs.
- **Ledgers:** model controlled state, recoverability, dedupe, correction, and approval-gated append mechanics.
- **Automation mechanics:** run deterministic checks so reviewer-facing claims are backed by source-controlled guardrails.
- **Guardrails:** keep platform claims inside the current proof ceiling and block runtime, signal, production, public-safe, or autonomous-SOC language unless separately promoted.

The hiring signal is platform engineering discipline: translating detection and SOC automation work into auditable contracts, bounded claims, and repeatable reviewer paths.

## Current Proof Boundary

Current platform ceiling: source-controlled contracts, schemas, verifier logic, ledger mechanics, and automation guardrails exist in this repository.

The platform can support controlled validation language when a verifier passes within its stated scope.

The platform cannot claim:

- live runtime execution
- live signal observation
- public-safe evidence
- SOCaaS availability
- production-ready platform status
- fleet-wide deployment
- autonomous SOC operation
- AI-approved disposition
- analyst-approved disposition
- live Splunk, Cribl, Wazuh, or AWS status
- public-proof promotion

Public-safe or runtime-active claims require separate proof review, privacy review, stale review, wording review, and Raylee approval.

## Runtime Contract Guardrail

The HO-DET-001 runtime contract in this repo is a schema and verifier guardrail only.

`PLATFORM_RUNTIME_CONTRACT=pass` means the controlled contract verifier passed for the tracked source inputs in scope. It does not mean a runtime system fired, a live signal was observed, a production SOC path is available, or public-safe proof exists.

Use the runtime contract to inspect whether a runtime receipt would have the required bounded fields before any runtime claim is considered.

## Contract Baseline

The current contract package is defined under `contracts/`:

- `contracts/contract-version.json`
- `contracts/schemas/detection-artifact.schema.json`
- `contracts/schemas/validation-report.schema.json`
- `contracts/schemas/proof-record.schema.json`
- `contracts/schemas/local-llm-runtime-receipt.schema.json`
- `contracts/schemas/ho-det-001-runtime-contract.schema.json`
- `contracts/schemas/ho-det-011-case-packet.schema.json`
- `contracts/lifetime-case-ledger-v1-recoverability-drill.json`

These files define minimum source-controlled fields for reproducible detection-to-validation-to-proof linkage and case-packet boundary checks.

## Ledger Mechanics

The lifetime case ledger work in this repo is contract and mechanics truth.

- `scripts/verify-lifetime-ledger-backup-drill.py` checks a tracked SQLite seed bridge by copying it to a temporary backup, comparing SHA256 and ledger metrics, and verifying no restore or append action occurred.
- `docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md` maps candidate event, dry run, approval gate, append, dedupe, correction, superseding, state manifest, and proof handoff mechanics.
- Current tracked seed boundary remains source-controlled platform seed only.

Known ledger proof ceiling: `SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY`.

Known public-safe status: `NOT_PUBLIC_SAFE`.

## Automation And Guardrails

Platform automation is intended to make unsafe claim expansion visible before it reaches reviewer or public surfaces.

- Contract schemas define expected fields.
- Verifier scripts check source-controlled fixtures and ledgers.
- Governance gate workflow wiring can run claim-boundary checks where configured.
- Case-packet validation checks whether required boundaries are represented.
- Guardrail language blocks runtime, signal, production, public-safe, and autonomous-SOC claims unless separately approved.

Automation in this repo is source/validation support. It is not merge authority, publication authority, runtime authority, or public-proof authority.

## Repository Contract

- Platform behavior must be deterministic and auditable.
- Integration points must be versioned and explicitly documented.
- Runtime, signal, and public-proof claims must stay outside this repo unless separately proven and approved.
- Operational changes that affect proof wording or claim ceilings require corresponding proof updates in `hawkinsoperations-proof`.
- Website or reviewer navigation may point to proof records, but presentation does not replace proof.

## Scope

In scope:

- Platform contracts and schema definitions
- Ledger recoverability and state-mechanics checks
- Case-packet and runtime-receipt guardrails
- Deterministic verifier scripts
- Environment-agnostic automation mechanics
- Reviewer navigation for platform contracts

Out of scope:

- Host-specific workstation configuration state
- Private credentials, tokens, secrets, or raw evidence
- Public marketing narrative
- Runtime execution claims
- Live telemetry or signal claims
- SOCaaS availability claims
- Production-ready platform claims
- Public-safe promotion

## Related HawkinsOperations Repositories

- Organization profile and reviewer start: [HawkinsOperations/.github](https://github.com/HawkinsOperations/.github)
- Detections: `hawkinsoperations-detections`
- Validation: `hawkinsoperations-validation`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`

HawkinsOperations is the governed successor system. HawkinsOps and older surfaces are legacy/reference unless revalidated.

AI is labor. Governance is authority.
