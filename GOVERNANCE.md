# Governance

Repository: `hawkinsoperations-platform`

## Rules

1. Integration contracts must be explicit and versioned.
2. Claims and operational assertions must map to evidence entries.
3. No host-local paths, credentials, or secret material in tracked files.
4. Contract-breaking changes require clear migration notes.

## Evidence Contract

- Evidence ledger files:
  - `evidence/EVIDENCE_LEDGER_SCHEMA.json`
  - `evidence/evidence-ledger.json`
- Entries track contract revisions and artifact checksums.

## Promotion Gate

- Required governance files must exist.
- CI gate must pass before merge.
- Public-safe output only; internal control-plane data stays out.

