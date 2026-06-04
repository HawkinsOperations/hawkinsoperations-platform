#!/usr/bin/env python3
"""Fail-closed verifier for Runtime Collector Eligibility Registry v0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ALLOWED_ELIGIBILITY_STATES = {
    "ELIGIBLE_CURRENT_TARGET",
    "ELIGIBLE_PENDING_REGISTRY",
    "NEEDS_SOURCE",
    "NEEDS_VALIDATION",
    "NEEDS_TELEMETRY_CONTRACT",
    "NEEDS_COLLECTOR_DESIGN",
    "BLOCKED_PUBLIC_CLAIM",
    "NOT_COLLECTOR_ELIGIBLE_YET",
    "UNKNOWN",
}

ALLOWED_PROOF_CEILINGS = {
    "PRIVATE_RUNTIME_CANDIDATE_ONLY",
    "CONTROLLED_TEST_VALIDATED",
}

REQUIRED_DETECTIONS = {
    "HO-DET-001",
    "HO-DET-011",
    "HO-DET-012",
    "HO-DET-013",
    "ID-DET-001",
    "ID-DET-002",
    "ID-DET-003",
    "ID-DET-004",
    "AWS-DET-001",
    "HO-PIPE-001",
    "HO-NDR-002",
}


def fail(message: str) -> None:
    print(f"runtime collector eligibility verifier failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        fail(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid json in {path}: {exc}")


def maybe_validate_schema(registry: Any, schema: Any) -> bool:
    try:
        import jsonschema  # type: ignore
    except ModuleNotFoundError:
        return False

    try:
        jsonschema.Draft202012Validator(schema).validate(registry)
    except jsonschema.ValidationError as exc:
        fail(f"schema validation failed: {exc.message}")
    return True


def require_bool(value: Any, expected: bool, field: str) -> None:
    if value is not expected:
        fail(f"{field} must be {str(expected).lower()}")


def verify_registry(registry: dict[str, Any]) -> dict[str, Any]:
    if registry.get("registry_name") != "Runtime Collector Eligibility Registry v0":
        fail("registry_name must be Runtime Collector Eligibility Registry v0")
    if registry.get("registry_version") != "runtime-collector-eligibility-v0":
        fail("registry_version must be runtime-collector-eligibility-v0")
    if registry.get("proof_ceiling") not in ALLOWED_PROOF_CEILINGS:
        fail("proof_ceiling exceeds allowed private/control ceiling")
    if registry.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("public_safe_status must be NOT_PUBLIC_SAFE")
    require_bool(registry.get("org_wide_auto_collection"), False, "org_wide_auto_collection")
    if registry.get("current_collector_scope") != "HO-DET-001_ONLY":
        fail("current_collector_scope must be HO-DET-001_ONLY")
    require_bool(
        registry.get("append_requires_human_approval"),
        True,
        "append_requires_human_approval",
    )
    require_bool(
        registry.get("collector_behavior_changed_by_this_registry"),
        False,
        "collector_behavior_changed_by_this_registry",
    )

    detections = registry.get("detections")
    if not isinstance(detections, list) or not detections:
        fail("detections must be a non-empty array")

    by_detection: dict[str, dict[str, Any]] = {}
    for entry in detections:
        if not isinstance(entry, dict):
            fail("each detection entry must be an object")
        detection_id = entry.get("detection_id")
        if not isinstance(detection_id, str) or not detection_id:
            fail("each detection entry must include detection_id")
        if detection_id in by_detection:
            fail(f"duplicate detection_id: {detection_id}")
        by_detection[detection_id] = entry

        eligibility = entry.get("collector_eligibility")
        if eligibility not in ALLOWED_ELIGIBILITY_STATES:
            fail(f"{detection_id} has unknown collector_eligibility: {eligibility}")

        for field in (
            "public_claim_allowed",
            "runtime_claim_allowed",
            "case_closure_allowed",
            "disposition_allowed",
        ):
            require_bool(entry.get(field), False, f"{detection_id}.{field}")

        for field in ("source_status", "validation_status", "proof_status", "current_safe_status", "next_gate", "notes"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                fail(f"{detection_id}.{field} must be a non-empty string")

        row_count = entry.get("collector_row_count")
        if not isinstance(row_count, int) or row_count < 0:
            fail(f"{detection_id}.collector_row_count must be a non-negative integer")

    missing = sorted(REQUIRED_DETECTIONS.difference(by_detection))
    if missing:
        fail(f"required detections missing: {', '.join(missing)}")

    ho_det_001 = by_detection["HO-DET-001"]
    if ho_det_001.get("collector_eligibility") != "ELIGIBLE_CURRENT_TARGET":
        fail("HO-DET-001 must be ELIGIBLE_CURRENT_TARGET")
    require_bool(ho_det_001.get("collector_target_proven"), True, "HO-DET-001.collector_target_proven")
    require_bool(ho_det_001.get("collector_row_observed"), True, "HO-DET-001.collector_row_observed")
    if ho_det_001.get("collector_row_count") != 2:
        fail("HO-DET-001 collector_row_count must be 2")

    for detection_id, entry in by_detection.items():
        if detection_id == "HO-DET-001":
            continue
        require_bool(entry.get("collector_target_proven"), False, f"{detection_id}.collector_target_proven")
        require_bool(entry.get("collector_row_observed"), False, f"{detection_id}.collector_row_observed")
        if entry.get("collector_row_count") > 0:
            fail(f"{detection_id} collector_row_count must be 0")

    return {
        "status": "PASS",
        "registry_version": registry["registry_version"],
        "detection_count": len(detections),
        "current_collector_scope": registry["current_collector_scope"],
        "org_wide_auto_collection": registry["org_wide_auto_collection"],
        "collector_behavior_changed_by_this_registry": registry[
            "collector_behavior_changed_by_this_registry"
        ],
        "required_detections_verified": sorted(REQUIRED_DETECTIONS),
        "ho_det_001_collector_row_count": ho_det_001["collector_row_count"],
        "public_claim_allowed": False,
        "runtime_claim_allowed": False,
        "case_closure_allowed": False,
        "disposition_allowed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify Runtime Collector Eligibility Registry v0 invariants."
    )
    parser.add_argument(
        "--registry",
        default="contracts/examples/runtime-collector-eligibility-v0.sample.json",
        help="Registry JSON path relative to repo root or absolute path.",
    )
    parser.add_argument(
        "--schema",
        default="contracts/schemas/runtime-collector-eligibility-v0.schema.json",
        help="Schema JSON path relative to repo root or absolute path.",
    )
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def main() -> int:
    args = parse_args()
    registry_path = resolve_path(args.registry)
    schema_path = resolve_path(args.schema)

    registry = load_json(registry_path)
    schema = load_json(schema_path)
    schema_validated = maybe_validate_schema(registry, schema)

    if not isinstance(registry, dict):
        fail("registry root must be an object")

    result = verify_registry(registry)
    result["registry"] = str(registry_path)
    result["schema"] = str(schema_path)
    result["schema_validated"] = schema_validated
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
