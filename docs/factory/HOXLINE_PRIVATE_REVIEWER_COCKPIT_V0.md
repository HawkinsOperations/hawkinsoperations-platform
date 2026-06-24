# Hoxline Private Reviewer Cockpit v0

The Hoxline private reviewer cockpit is a private operator view of the current
Hoxline proof state. It aggregates governed hashes, counts, packet digests, and
bounded status fields so Raylee can inspect the current truth state in one
command.

This cockpit is not public proof, not a Lifetime Ledger append, not analyst approval, and not AI disposition authority. It does not generate telemetry, create services, create scheduled tasks, generate persistence-class behavior, enable or disable schedules, or close cases. It may report the current standing private collector scope as private reviewer state only.

## Command

Run from the platform repo:

```powershell
python -B scripts\ho_factory.py hoxline-private-reviewer-cockpit --repo-root . --format json
```

Self-test:

```powershell
python -B scripts\ho_factory.py hoxline-private-reviewer-cockpit-self-test --repo-root . --format json
```

The command writes the private local report to:

```text
C:\Raylee\Data\Hoxline\private-reviewer-cockpit-20260621.json
```

The report is private-only and omits private payloads.

## HO-DET-001

HO-DET-001 is displayed as canonical private runtime proof only:

- execution ID: `HO-DET-001-20260620T173615Z-6ELQ03`
- GitHub run: `27878994407`
- runner: `HO-GPU-01`
- Wazuh receipt digest:
  `9b44ac77420ec3f87d30c228bdb246875e2d7a263dad083cd3c7acab9e4d88b4`
- candidate hash:
  `bf0ef4fc62e11d612b08083d0326eeb3ae65ae996fbc34422ba3edefcd89dd30`
- normalized hash:
  `3e6062119a1f90d70e1753f9ba21e9c38837fb5d06c559c8c34e84459c945ec2`
- AI status: `AI_TRIAGE_RECOVERED_AND_CANONICAL`
- canonical human-review packet digest:
  `589e4220b73cc26115629281f29fe34c17950e539454881734802392729ec2f9`
- historical noncanonical packet digest:
  `78100a2e72b5ca5f1866f4bfba48d3b48dc0512eef8620d0eed1fe3c854cc891`

The cockpit keeps `human_review_required=true`, `public_safe=false`, and
`proof_ceiling=PRIVATE_CONTROLLED_RUNTIME_PROOF`.

## Standing Private Collector Scope

The cockpit now displays the current private scheduled collector scope:

- `HO-DET-009`
- `HO-DET-010`
- `HO-DET-011`
- `HO-DET-012`

These rows are represented as private runtime candidate / private packet review state. They are not public-safe proof and do not authorize a Lifetime Ledger append, website proof promotion, production wording, SOCaaS wording, customer wording, AI disposition, analyst disposition, final authorization, or case closure.

HO-DET-010 is represented only with bounded metadata: source package present, controlled validation present, Windows Security EventChannel telemetry contract, private VM108-scoped signal observed, verified private packet, and standing private collector inclusion. Raw Wazuh alerts, endpoint logs, execution IDs, generated credentials, command lines, private payloads, and packet contents are outside this doc and outside the public repo.

The next safe action for each private runtime candidate is private human review packet evaluation only.

## Claim Boundaries

Allowed claim class:

- `PRIVATE_CONTROLLED_RUNTIME_PROOF_ONLY`

Blocked claim classes:

- `PUBLIC_SAFE`
- `PRODUCTION`
- `SOCAAS`
- `CUSTOMER_DEPLOYED`
- `AI_APPROVED`
- `ANALYST_APPROVED`
- `CASE_CLOSED`
- `FLEET_WIDE`

## Remote Lab Authority

The cockpit verifies that Codex local AGENTS rules include the remote lab / SSH
evidence surface authority. That rule allows Raylee-owned lab servers and VMs
to be used for evidence collection and verification when a task requires it.

Default remote mode is read-only. Remote writes require explicit current-task
authorization. Remote evidence collection does not authorize public proof,
Lifetime Ledger append, schedule enablement, website update, case closure,
analyst approval simulation, or AI disposition authority.
