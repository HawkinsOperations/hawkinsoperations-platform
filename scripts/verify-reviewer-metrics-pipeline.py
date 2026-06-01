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
METRIC_SOURCE_ARTIFACT_KEYS = {
    "lifetime_governed_cases": "proof_lifetime_summary",
    "lifetime_ledger_events": "proof_lifetime_summary",
    "detection_activity_count": "validation_activity_ledger",
    "controlled_validation_fire_count": "validation_activity_ledger",
    "controlled_negative_test_count": "validation_activity_ledger",
    "validation_case_count": "validation_activity_ledger",
    "detection_activity_entry_count": "validation_activity_ledger",
    "runtime_public_safe_count": "validation_activity_ledger",
    "public_safe_count": "validation_activity_ledger",
    "proof_record_count": "proof_reviewer_map",
    "blocked_claim_count": "proof_reviewer_map",
    "detection_family_count": "detections_promotion_matrix",
}
REQUIRED_SOURCE_ARTIFACT_KEYS = set(METRIC_SOURCE_ARTIFACT_KEYS.values()) | {
    "lifetime_case_ledger_manifest",
    "github_project_reconciliation_source",
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


def load_json(path: Path, label: str = "reviewer metrics state") -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"malformed {label}: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} root must be an object")
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
    missing = REQUIRED_SOURCE_ARTIFACT_KEYS - set(source_artifacts)
    if missing:
        fail(f"source_artifacts missing fields: {sorted(missing)}")
    for key, value in source_artifacts.items():
        if not isinstance(value, str) or not value:
            fail(f"source artifact {key} must be a string")
        path = Path(value)
        if path.is_absolute():
            fail(f"source artifact {key} must be repo-relative or sibling-relative")


def _load_detection_promotion_matrix(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependency is available in CI.
        fail(f"PyYAML is required to verify detection promotion matrix: {exc}")
    if not path.exists():
        fail(f"missing detection promotion matrix: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(f"malformed detection promotion matrix: {exc}")
    if not isinstance(data, dict):
        fail("detection promotion matrix root must be an object")
    return data


def _source_artifact_path(state: dict[str, Any], key: str, repo_root: Path) -> Path:
    source_artifacts = state.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        fail("source_artifacts must be a non-empty object")
    value = source_artifacts.get(key)
    if not isinstance(value, str) or not value:
        fail(f"source artifact {key} must be a string")
    path = Path(value)
    if path.is_absolute():
        fail(f"source artifact {key} must be repo-relative or sibling-relative")
    return (repo_root / path).resolve()


def source_metrics_from_state(state_path: Path = STATE_PATH, repo_root: Path = ROOT) -> dict[str, int]:
    state = load_json(state_path)
    _require_repo_relative_source_artifacts(state)

    lifetime_summary_path = _source_artifact_path(state, "proof_lifetime_summary", repo_root)
    validation_ledger_path = _source_artifact_path(state, "validation_activity_ledger", repo_root)
    proof_reviewer_map_path = _source_artifact_path(state, "proof_reviewer_map", repo_root)
    detections_promotion_matrix_path = _source_artifact_path(state, "detections_promotion_matrix", repo_root)
    lifetime_summary = load_json(lifetime_summary_path, "lifetime case ledger summary")
    validation_ledger = load_json(validation_ledger_path, "detection activity ledger")
    proof_reviewer_map = load_json(proof_reviewer_map_path, "reviewer proof map")
    detections_promotion_matrix = _load_detection_promotion_matrix(detections_promotion_matrix_path)

    ledger_counts = lifetime_summary.get("ledger_counts")
    if not isinstance(ledger_counts, dict):
        fail("lifetime case ledger summary ledger_counts must be present")
    activity_metrics = validation_ledger.get("aggregate_metrics")
    if not isinstance(activity_metrics, dict):
        fail("detection activity ledger aggregate_metrics must be present")
    trust_backup_checklist = proof_reviewer_map.get("trust_backup_checklist")
    proof_blocked_claims = proof_reviewer_map.get("blocked_claims")
    if not isinstance(trust_backup_checklist, list):
        fail("reviewer proof map trust_backup_checklist must be present")
    if not isinstance(proof_blocked_claims, list):
        fail("reviewer proof map blocked_claims must be present")
    detection_entries = detections_promotion_matrix.get("entries")
    if not isinstance(detection_entries, list):
        fail("detection promotion matrix entries must be present")
    detection_families: set[str] = set()
    detection_blocked_claims: set[str] = set()
    for entry in detection_entries:
        if not isinstance(entry, dict):
            fail("detection promotion matrix entry must be an object")
        family = entry.get("detection_family")
        if not isinstance(family, str) or not family:
            fail("detection promotion matrix entry missing detection_family")
        detection_families.add(family)
        blocked_claims = entry.get("blocked_claims")
        if isinstance(blocked_claims, list):
            detection_blocked_claims.update(str(claim) for claim in blocked_claims)

    required = {
        "lifetime_governed_cases": ledger_counts.get("total_cases"),
        "lifetime_ledger_events": ledger_counts.get("total_ledger_events"),
        "detection_activity_count": activity_metrics.get("detection_activity_count"),
        "controlled_validation_fire_count": activity_metrics.get("controlled_validation_fire_count"),
        "controlled_negative_test_count": activity_metrics.get("controlled_negative_test_count"),
        "validation_case_count": activity_metrics.get("validation_case_count"),
        "detection_activity_entry_count": activity_metrics.get("activity_entry_count"),
        "runtime_public_safe_count": activity_metrics.get("runtime_public_safe_count"),
        "public_safe_count": activity_metrics.get("public_safe_count"),
        "proof_record_count": len(trust_backup_checklist),
        "blocked_claim_count": len(proof_blocked_claims) + len(detection_blocked_claims),
        "detection_family_count": len(detection_families),
    }
    for key, value in required.items():
        if not isinstance(value, int) or value < 0:
            fail(f"source metric {key} must be a non-negative integer")
    return required


def project_reconciliation_from_state(state_path: Path = STATE_PATH, repo_root: Path = ROOT) -> dict[str, bool]:
    state = load_json(state_path)
    receipt_path = _source_artifact_path(state, "github_project_reconciliation_source", repo_root)
    text = receipt_path.read_text(encoding="utf-8")
    lowered = text.lower()
    reconciliation = state.get("project_board_reconciliation_status")
    if not isinstance(reconciliation, dict):
        fail("project_board_reconciliation_status must be present")

    return {
        "standing_issue_8_present": "#8" in text and "standing control" in lowered,
        "standing_issue_10_present": "#10" in text and "blocked claims" in lowered,
        "project_2_route_present": "project #2" in lowered,
        "report_only_boundary_present": "report_only" in lowered or "not proof" in lowered,
        "project_metadata_is_proof_authority": reconciliation.get("github_project_metadata_is_proof_authority") is True,
        "github_project_mutation_performed": reconciliation.get("github_project_mutation_performed") is True,
    }


def verify_state(state_path: Path = STATE_PATH, repo_root: Path = ROOT, require_source_artifacts: bool = False) -> dict[str, Any]:
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
    if require_source_artifacts:
        for key, expected in source_metrics_from_state(state_path, repo_root).items():
            if metrics.get(key) != expected:
                fail(f"{key} source metric mismatch: expected {expected}, found {metrics.get(key)}")
    reconciliation = state.get("project_board_reconciliation_status")
    if not isinstance(reconciliation, dict):
        fail("project_board_reconciliation_status must be present")
    if reconciliation.get("status") != "REPO_BACKED_RECONCILIATION_PLAN_NO_PROJECT_MUTATION":
        fail("project_board_reconciliation_status must remain repo-backed and non-mutating")
    if reconciliation.get("standing_issue_8_status") != "KEEP_OPEN_STANDING_CONTROL":
        fail("standing issue #8 must remain an open standing control")
    if reconciliation.get("standing_issue_10_status") != "KEEP_OPEN_STANDING_CONTROL":
        fail("standing issue #10 must remain an open standing control")
    if require_source_artifacts:
        project_reconciliation = project_reconciliation_from_state(state_path, repo_root)
        for key in ("standing_issue_8_present", "standing_issue_10_present", "project_2_route_present", "report_only_boundary_present"):
            if project_reconciliation[key] is not True:
                fail(f"project reconciliation source missing boundary: {key}")
        if project_reconciliation["project_metadata_is_proof_authority"] is not False:
            fail("GitHub Project metadata must remain non-authoritative")
        if project_reconciliation["github_project_mutation_performed"] is not False:
            fail("reviewer metrics pipeline must not mutate GitHub Projects")

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
    parser.add_argument(
        "--require-source-artifacts",
        action="store_true",
        help="Require sibling/source artifact files and compare source-backed metrics.",
    )
    parser.add_argument("--format", choices={"text", "json"}, default="text")
    args = parser.parse_args(argv)
    try:
        result = verify_state(args.state, ROOT, require_source_artifacts=args.require_source_artifacts)
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
