#!/usr/bin/env python3
"""Verify the HO-DET-011 platform case packet stays claim-bounded."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = ROOT / "contracts" / "examples" / "ho-det-011-case-packet.sample.json"
SCHEMA_PATH = ROOT / "contracts" / "schemas" / "ho-det-011-case-packet.schema.json"

EXPECTED = {
    "detection_id": "HO-DET-011",
    "proof_ceiling": "TEST_VALIDATED_SYNTHETIC_SCOPE",
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "promotion_status": "BLOCKED",
    "validation_result_ref": "hawkinsoperations-validation/reports/ho-det-011/validation-result.json",
    "validation_cases_ref": "hawkinsoperations-validation/validation/successor/ho-det-011/validation-cases.json",
    "validation_pr": "HawkinsOperations/hawkinsoperations-validation#25",
    "validation_merge_commit": "4c4bf5a",
    "validation_status": "pass",
    "synthetic_validation": True,
    "runtime_active": False,
    "signal_observed": False,
    "evidence_linked_public_proof": False,
    "public_safe_runtime_proof": False,
    "production_ready": False,
    "fleet_wide": False,
    "live_splunk_fired": False,
    "wazuh_routed": False,
    "cribl_routed": False,
    "aws_live": False,
    "service_creation_coverage_complete": False,
    "ai_decided_disposition": False,
    "ai_may_approve": False,
    "ai_may_promote": False,
    "ai_may_close": False,
    "human_review_required": True,
}

EXPECTED_COUNTS = {
    "total_cases": 6,
    "positive_cases": 3,
    "negative_cases": 3,
    "pass": 6,
    "fail": 0,
    "matched_positive_count": 3,
}

REQUIRED_BLOCKED_CLAIMS = {
    "runtime-active",
    "signal-observed",
    "public-safe",
    "evidence-linked public proof",
    "live Splunk fired",
    "Wazuh-routed",
    "Cribl-routed",
    "AWS-live",
    "production-ready",
    "fleet-wide",
    "service-creation coverage completeness",
    "AI-decided disposition",
    "AI-approved disposition",
    "AI-closed disposition",
}

BLOCKED_ALLOWED_CLAIM_PATTERNS = [
    r"runtime[-\s]+active",
    r"signal[-\s]+observed",
    r"public[-\s]+safe",
    r"evidence[-\s]+linked\s+public\s+proof",
    r"live\s+splunk\s+fired",
    r"wazuh[-\s]+routed",
    r"cribl[-\s]+routed",
    r"aws[-\s]+live",
    r"production[-\s]+ready",
    r"fleet[-\s]+wide",
    r"service[-\s]+creation\s+coverage\s+complet",
    r"ai[-\s]+decided",
    r"ai[-\s]+approved",
    r"ai[-\s]+closed",
]

PRIVATE_LEAK_PATTERNS = [
    "C:" + re.escape("\\"),
    r"\b[A-Z]:\\",
    r"192\.168\.",
    r"172\.16\.",
    r"\btoken\b",
    r"\bsecret\b",
    r"\bscreenshot\b",
    r"raw\s+runtime\s+evidence",
]


def fail(message: str) -> None:
    print(f"HO_DET_011_CASE_PACKET=fail: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def validate_schema_if_possible(sample: dict, schema: dict) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception as exc:
        fail(f"jsonschema dependency is required for schema validation: {exc}")

    try:
        jsonschema.Draft202012Validator(schema).validate(sample)
    except Exception as exc:
        fail(f"schema validation failed: {exc}")


def require_expected_values(sample: dict) -> None:
    for key, expected in EXPECTED.items():
        actual = sample.get(key)
        if actual != expected:
            fail(f"{key} expected {expected!r}, got {actual!r}")


def require_validation_counts(sample: dict) -> None:
    counts = sample.get("validation_counts")
    if not isinstance(counts, dict):
        fail("validation_counts must be an object")

    for key, expected in EXPECTED_COUNTS.items():
        actual = counts.get(key)
        if actual != expected:
            fail(f"validation_counts.{key} expected {expected!r}, got {actual!r}")


def require_privacy_boundary(sample: dict) -> None:
    boundary = sample.get("privacy_boundary")
    if not isinstance(boundary, dict):
        fail("privacy_boundary must be an object")

    if boundary.get("synthetic_fixtures_only") is not True:
        fail("privacy_boundary.synthetic_fixtures_only must be true")

    for key, actual in boundary.items():
        if key == "synthetic_fixtures_only":
            continue
        if actual is not False:
            fail(f"privacy_boundary.{key} must be false")


def require_blocked_claim_inventory(sample: dict) -> None:
    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list):
        fail("blocked_claims must be a list")

    missing = sorted(REQUIRED_BLOCKED_CLAIMS - set(blocked))
    if missing:
        fail(f"missing blocked_claims entries: {', '.join(missing)}")


def reject_promoted_allowed_claims(sample: dict) -> None:
    allowed = sample.get("allowed_claims")
    if not isinstance(allowed, list) or not allowed:
        fail("allowed_claims must be a non-empty list")

    for claim in allowed:
        normalized = str(claim).lower()
        for pattern in BLOCKED_ALLOWED_CLAIM_PATTERNS:
            if re.search(pattern, normalized):
                if "not_public_safe" in normalized or "capped at" in normalized:
                    continue
                fail(f"allowed_claims promotes blocked wording: {claim!r}")


def reject_private_leakage(sample: dict) -> None:
    sample_text = json.dumps(sample, sort_keys=True)
    allowed_field_terms = {
        "secret_material_included",
        "screenshots_included",
        "raw_runtime_evidence_included",
    }
    scan_text = sample_text
    for term in allowed_field_terms:
        scan_text = scan_text.replace(term, "")

    for pattern in PRIVATE_LEAK_PATTERNS:
        if re.search(pattern, scan_text, flags=re.IGNORECASE):
            fail(f"private/local leakage pattern found: {pattern}")


def main() -> int:
    sample = load_json(SAMPLE_PATH)
    schema = load_json(SCHEMA_PATH)

    validate_schema_if_possible(sample, schema)
    require_expected_values(sample)
    require_validation_counts(sample)
    require_privacy_boundary(sample)
    require_blocked_claim_inventory(sample)
    reject_promoted_allowed_claims(sample)
    reject_private_leakage(sample)

    print("HO_DET_011_CASE_PACKET=pass")
    print("DETECTION_ID=HO-DET-011")
    print("PROOF_CEILING=TEST_VALIDATED_SYNTHETIC_SCOPE")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("PROMOTION_STATUS=BLOCKED")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print("AI_MAY_APPROVE=false")
    print("AI_MAY_PROMOTE=false")
    print("AI_MAY_CLOSE=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
