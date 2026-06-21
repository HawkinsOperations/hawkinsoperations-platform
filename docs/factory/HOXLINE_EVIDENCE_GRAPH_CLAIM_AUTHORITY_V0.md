# Hoxline Evidence Graph And Claim Authority v0

Hoxline evidence graph and claim authority v0 turns private runtime operations evidence into private product-control-plane state. It is bounded to hash and reference handling only.

## Boundary

- Proof ceiling: `PRIVATE_CONTROLLED_RUNTIME_PROOF`.
- Public-safe status: `NOT_PUBLIC_SAFE`.
- Lifetime Ledger append: blocked.
- Public proof promotion: blocked.
- Schedule enablement: blocked.
- Case closure: blocked.
- AI disposition authority: blocked. AI output remains support-only.
- Human review remains required.
- Website updates are outside this control plane.

## Pipeline

Runtime artifact -> Evidence Graph -> Promotion State -> Claim Authority -> ProofCard Draft -> Allowed Claim / Constrained Claim / Blocked Claim -> Next Legal Action.

The evidence graph includes only hashes, references, status values, and counts. It rejects raw alert fields, raw candidate fields, private route fields, credentials, tokens, passwords, private keys, and any key prefixed with `raw_`.

## Commands

```powershell
python -B scripts\ho_factory.py hoxline-evidence-graph --execution-id HO-DET-001-20260620T173615Z-6ELQ03 --private-route "<APPROVED_PRIVATE_ROUTE>" --format json
python -B scripts\ho_factory.py hoxline-promotion-state --evidence-graph "<GRAPH_JSON>" --format json
python -B scripts\ho_factory.py hoxline-claim-authority-check --evidence-graph "<GRAPH_JSON>" --proposed-claim "Hoxline has private controlled runtime operations evidence for HO-DET-001 with replay/no-duplicate verification and human review required." --format json
python -B scripts\ho_factory.py hoxline-proofcard-draft --evidence-graph "<GRAPH_JSON>" --format json
python -B scripts\ho_factory.py hoxline-control-plane-self-test --repo-root . --format json
```

Fixture mode exists for deterministic source and CI validation:

```powershell
python -B scripts\ho_factory.py hoxline-evidence-graph --fixture --format json
python -B scripts\ho_factory.py hoxline-claim-authority-check --fixture --proposed-claim "Hoxline is production SOC" --format json
```

## Exact Allowed Claim

Only this scoped claim is allowed without rewrite:

`Hoxline has private controlled runtime operations evidence for HO-DET-001 with replay/no-duplicate verification and human review required.`

Other non-blocked wording receives `CONSTRAINED_REWRITE_REQUIRED`.

## Blocked Claim Classes

Claim Authority blocks production, SOCaaS, customer deployment, autonomous SOC, public-safe runtime proof, public proof approval, analyst approval without evidence, AI approval, AI-decided disposition, case closure, fleet-wide coverage, schedule enablement, and ledger append without exact ledger evidence.

## ProofCard Draft

The ProofCard draft is private draft state only. It includes evidence graph and promotion hashes, allowed and blocked claim lists, missing evidence, and reviewer next actions. It does not mark public-safe, publish public proof, append the Lifetime Ledger, enable schedule, or close a case.

## Required Validation

```powershell
python -B -m py_compile scripts\ho_factory.py
python -B scripts\ho_factory.py hoxline-control-plane-self-test --repo-root . --format json
python -B -m unittest tests\test_hoxline_control_plane.py
```
