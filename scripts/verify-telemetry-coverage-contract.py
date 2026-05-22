#!/usr/bin/env python3
"""Verify Telemetry Coverage Contract v0 stays claim-bounded."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = ROOT / "contracts" / "examples" / "telemetry-coverage-contract-v0.sample.json"
SCHEMA_PATH = ROOT / "contracts" / "schemas" / "telemetry-coverage-contract-v0.schema.json"

EXPECTED_LANES = {
    "HO-NDR-001": {
        "coverage_family": "ndr_visibility_boundary",
        "source_truth": "BOUNDARY_CONTRACT_ONLY",
        "validation_state": "VALIDATION_CONTRACT_ENFORCED",
        "proof_ceiling": "BOUNDARY_CONTRACT_ONLY",
    },
    "HO-PIPE-001": {
        "coverage_family": "pipeline_route_integrity",
        "source_truth": "SOURCE_EXISTS",
        "validation_state": "VALIDATION_CONTRACT_ENFORCED",
        "proof_ceiling": "SOURCE_EXISTS",
    },
}
BLOCKED_CLAIMS = {
    "runtime-active",
    "signal-observed",
    "live Splunk",
    "Cribl-routed proof",
    "Wazuh-routed proof",
    "Security Onion observed proof",
    "production-ready",
    "public-safe runtime",
    "autonomous SOC",
    "AI-approved",
    "analyst-approved",
}
PRIVATE_LEAK_PATTERNS = (
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"),
    re.compile(r"(?i)\b(secret|password|token|api[_-]?key|credential)\b"),
    re.compile(r"(?i)\b(raw event|raw payload|private evidence filename|internal service)\b"),
)


def fail(message: str) -> None:
    print(f"TELEMETRY_COVERAGE_CONTRACT=fail: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT).as_posix()}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT).as_posix()}: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT).as_posix()} must be a JSON object")
    return data


def validate_schema_if_possible(sample: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return

    try:
        jsonschema.Draft202012Validator(schema).validate(sample)
    except Exception as exc:
        fail(f"schema validation failed: {exc}")


def require_false(sample: dict[str, Any], key: str) -> None:
    if sample.get(key) is not False:
        fail(f"{key} must remain false")


def require_blocked_claims(label: str, claims: Any) -> None:
    if not isinstance(claims, list):
        fail(f"{label} blocked_claims must be a list")
    missing = sorted(BLOCKED_CLAIMS - set(claims))
    if missing:
        fail(f"{label} missing blocked claims: {', '.join(missing)}")


def reject_private_leakage(sample: dict[str, Any]) -> None:
    text = json.dumps(sample, sort_keys=True)
    for pattern in PRIVATE_LEAK_PATTERNS:
        if pattern.search(text):
            fail(f"private/local leakage pattern found: {pattern.pattern}")


def validate_sample(sample: dict[str, Any]) -> None:
    if sample.get("schema_version") != "TELEMETRY_COVERAGE_CONTRACT_V0":
        fail("schema_version mismatch")
    if sample.get("contract_status") != "VALIDATION_CONTRACT_ENFORCED":
        fail("contract_status mismatch")
    if sample.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("public_safe_status must remain NOT_PUBLIC_SAFE")
    require_false(sample, "runtime_active")
    require_false(sample, "signal_observed")
    if sample.get("human_review_required") is not True:
        fail("human_review_required must remain true")
    require_blocked_claims("sample", sample.get("blocked_claims"))

    lanes = sample.get("lanes")
    if not isinstance(lanes, list) or len(lanes) != len(EXPECTED_LANES):
        fail("lanes must contain exactly HO-NDR-001 and HO-PIPE-001")
    seen = set()
    for lane in lanes:
        if not isinstance(lane, dict):
            fail("lane entries must be objects")
        detection_id = lane.get("detection_id")
        if detection_id not in EXPECTED_LANES:
            fail(f"unexpected lane detection_id: {detection_id}")
        seen.add(detection_id)
        expected = EXPECTED_LANES[str(detection_id)]
        for key, expected_value in expected.items():
            if lane.get(key) != expected_value:
                fail(f"{detection_id} {key} expected {expected_value!r}, got {lane.get(key)!r}")
        if lane.get("public_safe_status") != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} public_safe_status must remain NOT_PUBLIC_SAFE")
        require_false(lane, "runtime_active")
        require_false(lane, "signal_observed")
        require_blocked_claims(str(detection_id), lane.get("blocked_claims"))
    if seen != set(EXPECTED_LANES):
        fail("lane set mismatch")


def main() -> int:
    sample = load_json(SAMPLE_PATH)
    schema = load_json(SCHEMA_PATH)
    validate_schema_if_possible(sample, schema)
    validate_sample(sample)
    reject_private_leakage(sample)
    print("TELEMETRY_COVERAGE_CONTRACT=pass")
    print("LANES=HO-NDR-001,HO-PIPE-001")
    print("CONTRACT_STATUS=VALIDATION_CONTRACT_ENFORCED")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
