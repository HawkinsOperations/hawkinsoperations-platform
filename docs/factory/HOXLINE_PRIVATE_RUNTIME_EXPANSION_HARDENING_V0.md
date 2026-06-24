# Hoxline Private Runtime Expansion Hardening v0

This note documents private-runtime expansion mechanics that are safe to commit. It intentionally excludes private evidence, endpoint logs, secrets, keys, raw alerts, raw command lines, and private payloads.

## Operator Wazuh Receipt Intake

The operator Wazuh receipt collector accepts bounded sanitized records only. Valid inputs are:

- a single sanitized receipt object,
- a JSON array of sanitized receipt objects, or
- a sanitizer summary object with the bounded keys `host_searched`, `sources_searched`, `search_time_utc`, `match_count`, `unique_execution_id_count`, `rule_ids_observed`, `event_ids_observed`, `earliest_timestamp`, `latest_timestamp`, `sanitizer_version`, and `matches`.

A sanitizer summary must have `matches` as a list of objects, `match_count` equal to the number of matches when present, and a non-empty `sanitizer_version`. Unknown wrapper fields fail closed. Receipt records still pass through the private-field scanner.

## Attestation Wording

Operator attestation notes are scanned with the same private-marker policy as receipt inputs. Authors should use bounded phrasing such as `sensitive source fields omitted` rather than marker terms that resemble unbounded evidence. This preserves the fail-closed behavior without weakening the scanner.

## Runtime-From-Packet Wrappers

Private wrapper scripts must not emit a bare optional route flag. For `hoxline-runtime-from-operator-receipt-packet`, either omit route options entirely or pass an explicit value to `--private-route` or `--fixture-private-route`. Bare optional flags are invalid and should be covered by wrapper tests or review.

## Bounded Wazuh Enrollment Window

For private Raylee-owned lab endpoints, a temporary Wazuh authd enrollment window may be used only when password/key transfer would expose a secret and the run is explicitly authorized. The bounded pattern is:

1. Back up `ossec.conf` and relevant authd password config.
2. Record pre-change hashes and agent-list hash/count.
3. Verify the manager is reachable only through Raylee-owned lab/private surfaces.
4. Temporarily disable the authd password requirement for the shortest enrollment window.
5. Restart/reload only the Wazuh component needed for enrollment.
6. Enroll exactly the intended endpoint.
7. Restore the original authd config immediately and verify post-restore hashes match the backups.
8. Verify exactly one expected agent was added and no unexpected agents appeared.
9. Verify the agent is active before any controlled event.

This method must not store enrollment secrets, print keys, or broaden runtime claims. It remains private runtime infrastructure, not public proof.
