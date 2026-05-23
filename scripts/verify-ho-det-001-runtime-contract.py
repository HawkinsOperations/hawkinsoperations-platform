#!/usr/bin/env python3
"""Verify the HO-DET-001 platform runtime contract stays claim-bounded."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = ROOT / "contracts" / "examples" / "ho-det-001-runtime-contract.sample.json"
SCHEMA_PATH = ROOT / "contracts" / "schemas" / "ho-det-001-runtime-contract.schema.json"

EXPECTED = {
    "detection_id": "HO-DET-001",
    "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "promotion_status": "BLOCKED",
    "validation_pr": "HawkinsOperations/hawkinsoperations-validation#18",
    "validation_merge_commit": "ce6a2501b27ff0301529aa604f1d39e5d6d6d185",
    "runtime_active": False,
    "signal_observed": False,
    "public_safe_runtime_proof": False,
    "ai_decided_disposition": False,
    "ai_may_approve": False,
    "ai_may_promote": False,
    "ai_may_close": False,
    "human_review_required": True,
}

REQUIRED_TRUTH_PLANES = {
    "source_truth",
    "validation_truth",
    "runtime_truth",
    "signal_truth",
    "evidence_truth",
    "ai_triage_truth",
    "public_proof_truth",
    "human_review_truth",
}

TRUTH_PLANE_INVARIANTS = {
    "source_truth": {
        "state": "SOURCE_EXISTS",
        "owner": "hawkinsoperations-detections",
    },
    "validation_truth": {
        "state": "CONTROLLED_TEST_VALIDATED",
        "owner": "hawkinsoperations-validation",
    },
    "runtime_truth": {
        "state": "RUNTIME_EVIDENCE_VERIFIED_PRIVATE",
        "public_runtime_claim_status": "PUBLIC_RUNTIME_BLOCKED",
    },
    "signal_truth": {
        "state": "SIGNAL_OBSERVED_PRIVATE",
        "public_signal_claim_status": "PUBLIC_RUNTIME_BLOCKED",
    },
    "evidence_truth": {
        "state": "RUNTIME_EVIDENCE_VERIFIED_PRIVATE",
        "raw_private_evidence_public_safe": False,
        "repo_contains_raw_private_evidence": False,
        "hash_only_private_refs": True,
    },
    "ai_triage_truth": {
        "support_state": "AI_SUPPORT_ONLY",
        "triage_output_state": "AI_TRIAGE_OUTPUT_PRIVATE",
        "authority_state": "AI_NOT_AUTHORITY",
        "ai_decided_disposition": False,
        "human_review_required": True,
    },
    "public_proof_truth": {
        "state": "PUBLIC_RUNTIME_BLOCKED",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    "human_review_truth": {
        "state": "HUMAN_REVIEW_REQUIRED",
        "public_runtime_summary_state": "PUBLIC_RUNTIME_BLOCKED",
        "approval_required_for_public_summary": True,
    },
}

BLOCKED_ALLOWED_CLAIM_PATTERNS = [
    r"runtime-active",
    r"signal-observed",
    r"public-safe",
    r"production-ready",
    r"production\s+deployment",
    r"fleet-wide",
    r"splunk-proven\s+runtime\s+signal\s+001",
    r"cribl-routed",
    r"wazuh-routed",
    r"aws-live",
    r"autonomous\s+soc",
    r"ai-approved\s+disposition",
    r"analyst-approved\s+disposition",
]

PRIVATE_LEAK_PATTERNS = [
    r"C:\\",
    r"\b[A-Z]:\\",
    r"192\.168\.",
    r"172\.16\.",
    r"\btoken\b",
    r"\bsecret\b",
    r"\bscreenshot\b",
    r"raw\s+command",
    r"raw\s+runtime\s+evidence",
    r"private\s+evidence\s+filename",
]


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def fail(message: str) -> None:
    print(f"PLATFORM_RUNTIME_CONTRACT=fail: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_schema_if_possible(sample: dict, schema: dict) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return

    try:
        jsonschema.Draft202012Validator(schema).validate(sample)
    except Exception as exc:
        fail(f"schema validation failed: {exc}")


def require_expected_values(sample: dict) -> None:
    for key, expected in EXPECTED.items():
        actual = sample.get(key)
        if actual != expected:
            fail(f"{key} expected {expected!r}, got {actual!r}")


def require_privacy_boundary(sample: dict) -> None:
    boundary = sample.get("privacy_boundary")
    if not isinstance(boundary, dict):
        fail("privacy_boundary must be an object")

    for key, actual in boundary.items():
        if actual is not False:
            fail(f"privacy_boundary.{key} must be false")


def reject_promoted_allowed_claims(sample: dict) -> None:
    allowed = sample.get("allowed_claims")
    if not isinstance(allowed, list) or not allowed:
        fail("allowed_claims must be a non-empty list")

    for claim in allowed:
        normalized = str(claim).lower()
        for pattern in BLOCKED_ALLOWED_CLAIM_PATTERNS:
            if re.search(pattern, normalized):
                if "remain blocked" in normalized:
                    continue
                fail(f"allowed_claims promotes blocked wording: {claim!r}")


def reject_private_leakage(sample: dict) -> None:
    sample_text = json.dumps(sample, sort_keys=True)
    allowed_field_terms = {
        "secret_material_included",
        "screenshots_included",
        "raw_command_lines_included",
        "raw_runtime_evidence_included",
        "private_evidence_filenames_included",
    }
    scan_text = sample_text
    for term in allowed_field_terms:
        scan_text = scan_text.replace(term, "")

    for pattern in PRIVATE_LEAK_PATTERNS:
        if re.search(pattern, scan_text, flags=re.IGNORECASE):
            fail(f"private/local leakage pattern found: {pattern}")


def require_blocked_claim_inventory(sample: dict) -> None:
    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list):
        fail("blocked_claims must be a list")

    required = {
        "runtime-active",
        "signal-observed",
        "public-safe runtime proof",
        "production-ready",
        "fleet-wide",
        "Splunk-proven Runtime Signal 001",
        "Cribl-routed",
        "Wazuh-routed public proof",
        "AWS-live",
        "autonomous SOC",
        "AI-approved disposition",
        "analyst-approved disposition",
    }
    missing = sorted(required - set(blocked))
    if missing:
        fail(f"missing blocked_claims entries: {', '.join(missing)}")


def require_object(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_expected_field(container: dict, plane_name: str, field_name: str, expected: object) -> None:
    actual = container.get(field_name)
    if actual != expected:
        fail(f"{plane_name}.{field_name} must remain {expected!r}, got {actual!r}")


def require_minimum_refs(container: dict, plane_name: str, field_name: str) -> None:
    refs = container.get(field_name)
    if not isinstance(refs, list) or len(refs) < 2:
        fail(f"{plane_name}.{field_name} requires at least two refs")


def require_truth_spine(sample: dict) -> None:
    spine = require_object(sample.get("runtime_truth_spine"), "runtime_truth_spine")
    missing = sorted(REQUIRED_TRUTH_PLANES - set(spine))
    if missing:
        fail(f"runtime_truth_spine missing truth planes: {', '.join(missing)}")

    planes = {
        plane_name: require_object(spine.get(plane_name), f"runtime_truth_spine.{plane_name}")
        for plane_name in sorted(REQUIRED_TRUTH_PLANES)
    }

    for plane_name, invariants in TRUTH_PLANE_INVARIANTS.items():
        for field_name, expected in invariants.items():
            require_expected_field(planes[plane_name], plane_name, field_name, expected)

    require_minimum_refs(planes["source_truth"], "source_truth", "refs")
    require_minimum_refs(planes["validation_truth"], "validation_truth", "refs")
    require_minimum_refs(
        planes["runtime_truth"],
        "runtime_truth",
        "verified_runtime_evidence_refs",
    )
    require_minimum_refs(
        planes["signal_truth"],
        "signal_truth",
        "verified_signal_record_refs",
    )


def main() -> int:
    sample = load_json(SAMPLE_PATH)
    schema = load_json(SCHEMA_PATH)

    validate_schema_if_possible(sample, schema)
    require_expected_values(sample)
    require_truth_spine(sample)
    require_privacy_boundary(sample)
    require_blocked_claim_inventory(sample)
    reject_promoted_allowed_claims(sample)
    reject_private_leakage(sample)

    print("PLATFORM_RUNTIME_CONTRACT=pass")
    print("DETECTION_ID=HO-DET-001")
    print("PROOF_CEILING=CONTROLLED_TEST_VALIDATED")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("PROMOTION_STATUS=BLOCKED")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print("PUBLIC_RUNTIME_CLAIM_STATUS=PUBLIC_RUNTIME_BLOCKED")
    print("AI_TRIAGE_TRUTH=AI_SUPPORT_ONLY/AI_TRIAGE_OUTPUT_PRIVATE/AI_NOT_AUTHORITY")
    print("AI_DECIDED_DISPOSITION=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
