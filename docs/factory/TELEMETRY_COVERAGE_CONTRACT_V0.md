# Telemetry Coverage Contract v0

## Purpose

Telemetry Coverage Contract v0 aligns the `HO-NDR-001` and `HO-PIPE-001`
Command & Control support lane as platform contract truth.

The contract exists so reviewers can see that the NDR visibility boundary and
pipeline route integrity contract are deterministic, bounded, and validated for
shape without inferring runtime proof.

## Contract Surfaces

- Schema: `contracts/schemas/telemetry-coverage-contract-v0.schema.json`
- Sample: `contracts/examples/telemetry-coverage-contract-v0.sample.json`
- Verifier: `scripts/verify-telemetry-coverage-contract.py`

## Lane Boundaries

`HO-NDR-001` remains an NDR visibility and cross-source corroboration boundary
contract. It does not claim packet capture, observed Security Onion telemetry,
Splunk correlation, Wazuh routing, Cribl routing, production NDR, or public-safe
runtime status.

`HO-PIPE-001` remains a pipeline route integrity and field-preservation contract.
It does not claim delivered traffic, live Splunk results, Cribl-routed proof,
Wazuh-routed proof, Security Onion observed proof, production readiness, or
public-safe runtime status.

## Claim Boundary

The contract does not prove runtime-active status, signal-observed status, live
Splunk, Cribl-routed proof, Wazuh-routed proof, Security Onion observed proof,
production-ready status, public-safe runtime status, autonomous SOC behavior,
AI-approved status, or analyst-approved status.

Proof repository updates, workflow coverage, runtime evidence capture, evidence
linkage, stale review, wording review, public-safe review, and human review are
separate scopes.
