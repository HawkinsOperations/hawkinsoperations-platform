# Status

## Current Milestone

Governance baseline initialized and initial contract package defined.

## Next Gate

Promote platform contract checks from repository-local verifier scripts into required CI where branch protection or rulesets can block bad output.

## Blocking Risks

- Org-level PR, deletion, and non-fast-forward protections exist, but this repository currently has no required status checks recorded.
- Platform runtime contract verification is not a required status check here.
- Contract files are documentation/verifier inputs until CI and branch protection or rulesets require the check.
