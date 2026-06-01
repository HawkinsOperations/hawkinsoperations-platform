#!/usr/bin/env python3
"""Verify the platform-owned reviewer metrics pipeline state."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "contracts" / "reviewer-metrics-pipeline-v1-state.json"

REQUIRED_METRICS = {
    "lifetime_governed_cases",
    "lifetime_ledger_events",
    "detection_activity_count",
    "controlled_validation_fire_count",
    "validation_case_count",
    "proof_record_count",
    "blocked_claim_count",
    "runtime_public_safe_count",
    "public_safe_count",
    "detection_family_count",
}
DENIED_TEXT = [
    ("C:\\Raylee\\Work", re.compile(r"C:\\Raylee\\Work", re.IGNORECASE)),
    ("private IPv4 address", re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}\b")),
    ("secret marker", re.compile(r"\b(secret|password|credential|api[_-]?key|token)\b", re.IGNORECASE)),
]


class VerificationError(Exception):
    """Raised when reviewer metrics state violates the contract."""


def fail(message: str) -> None:
    raise VerificationError(message)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing reviewer metrics state: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"malformed reviewer metrics state: {exc}")
    if not isinstance(data, dict):
        fail("reviewer metrics state root must be an object")
    return data


def scan_value(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            scan_value(key, label)
            scan_value(nested, label)
    elif isinstance(value, list):
        for nested in value:
            scan_value(nested, label)
    elif isinstance(value, str):
        for name, pattern in DENIED_TEXT:
            if pattern.search(value):
                fail(f"{label} contains blocked text: {name}")


def _require_repo_relative_source_artifacts(state: dict[str, Any]) -> None:
    source_artifacts = state.get("source_artifacts")
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        fail("source_artifacts must be a non-empty object")
    for key, value in source_artifacts.items():
        if not isinstance(value, str) or not value:
            fail(f"source artifact {key} must be a string")
        path = Path(value)
        if path.is_absolute():
            fail(f"source artifact {key} must be repo-relative or sibling-relative")


def verify_state(state_path: Path = STATE_PATH, repo_root: Path = ROOT) -> dict[str, Any]:
    state = load_json(state_path)
    scan_value(state, "reviewer metrics state")

    if state.get("owner_repo") != "hawkinsoperations-platform":
        fail("owner_repo must be hawkinsoperations-platform")
    if state.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("public_safe_status must be NOT_PUBLIC_SAFE")
    if state.get("proof_ceiling") != "SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY":
        fail("proof_ceiling must remain SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY")
    _require_repo_relative_source_artifacts(state)

    metrics = state.get("metrics")
    if not isinstance(metrics, dict):
        fail("metrics must be present")
    missing = REQUIRED_METRICS - set(metrics)
    if missing:
        fail(f"metrics missing fields: {sorted(missing)}")
    for key in REQUIRED_METRICS:
        if not isinstance(metrics[key], int) or metrics[key] < 0:
            fail(f"{key} must be a non-negative integer")

    assertions = state.get("assertions")
    if not isinstance(assertions, dict):
        fail("assertions must be present")
    if assertions.get("lifetime_governed_cases_separate_from_detection_activity") is not True:
        fail("lifetime governed cases separation assertion must be true")
    if assertions.get("detection_activity_is_governed_case_count") is not False:
        fail("detection activity must remain separate from governed case count")
    for key in (
        "sqlite_mutation_performed",
        "case_append_performed",
        "public_safe_promotion_performed",
        "runtime_promotion_performed",
        "signal_promotion_performed",
        "website_is_proof_authority",
        "github_project_metadata_is_proof_authority",
    ):
        if assertions.get(key) is not False:
            fail(f"{key} must be false")

    if metrics["detection_activity_count"] != metrics["controlled_validation_fire_count"]:
        fail("v1 detection activity count must equal controlled validation fire count")
    if metrics["detection_activity_count"] <= metrics["lifetime_governed_cases"]:
        fail("detection activity count must expose broader activity than strict governed cases")
    if metrics["public_safe_count"] != 0 or metrics["runtime_public_safe_count"] != 0:
        fail("v1 must not claim public-safe or runtime-public-safe counts")
    if not state.get("blocked_claims"):
        fail("blocked_claims must not be empty")

    return {
        "status": "pass",
        "state_path": str(state_path.relative_to(repo_root)) if state_path.is_relative_to(repo_root) else str(state_path),
        "metrics": metrics,
        "proof_ceiling": state["proof_ceiling"],
        "public_safe_status": state["public_safe_status"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=STATE_PATH)
    parser.add_argument("--format", choices={"text", "json"}, default="text")
    args = parser.parse_args(argv)
    try:
        result = verify_state(args.state, ROOT)
    except VerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS: reviewer metrics pipeline state is proof-bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
