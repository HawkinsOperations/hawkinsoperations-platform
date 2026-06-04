#!/usr/bin/env python3
"""Non-mutating Lifetime Case Ledger recoverability drill verifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any


EXPECTED_PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
EXPECTED_PROOF_CEILING = "SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY"
EXPECTED_LEDGER_BOUNDARY = "tracked platform seed bridge, not runtime truth, not signal truth, not public proof"
EXPECTED_LEDGER_PATH = Path("evidence/autosoc-case-ledger-v0.sqlite")
EXPECTED_CONTRACT_PATH = Path("contracts/lifetime-case-ledger-v1-recoverability-drill.json")
EXPECTED_EVENT_COUNT = 6
EXPECTED_CASE_COUNT = 6
EXPECTED_DETECTION_COUNTS = {
    "HO-DET-001": 4,
    "HO-DET-011": 1,
    "HO-DET-012": 1,
}
EXPECTED_APPEND_ONLY_TRIGGERS = ["case_events_no_delete", "case_events_no_update"]


class DrillError(Exception):
    """Recoverability drill failure."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def grouped(conn: sqlite3.Connection, column: str) -> dict[str, int]:
    rows = conn.execute(f"SELECT {column}, COUNT(*) FROM case_events GROUP BY {column} ORDER BY {column}").fetchall()
    return {str(key): int(count) for key, count in rows}


def ledger_metrics(path: Path) -> dict[str, Any]:
    conn = connect_read_only(path)
    try:
        counts = conn.execute(
            """
            SELECT
              COUNT(*),
              COUNT(DISTINCT case_id),
              COALESCE(SUM(public_safe), 0),
              COALESCE(SUM(case_closed), 0),
              COALESCE(SUM(proof_blocked), 0),
              COALESCE(SUM(human_review_required), 0),
              COALESCE(SUM(github_issue_mutation_allowed), 0)
            FROM case_events
            """
        ).fetchone()
        triggers = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
            ).fetchall()
        ]
        metadata = {
            str(key): str(value)
            for key, value in conn.execute("SELECT key, value FROM ledger_metadata ORDER BY key").fetchall()
        }
        return {
            "total_ledger_events": int(counts[0]),
            "total_cases": int(counts[1]),
            "public_safe_count": int(counts[2]),
            "closed_case_count": int(counts[3]),
            "proof_blocked_count": int(counts[4]),
            "human_review_required_count": int(counts[5]),
            "github_issue_mutation_count": int(counts[6]),
            "cases_by_detection": grouped(conn, "detection_id"),
            "cases_by_status": grouped(conn, "case_status"),
            "cases_by_truth_class": grouped(conn, "truth_class"),
            "cases_by_public_safe_status": grouped(conn, "public_safe_status"),
            "append_only_trigger_names": triggers,
            "metadata": metadata,
        }
    finally:
        conn.close()


def load_contract(repo_root: Path) -> dict[str, Any]:
    contract_path = repo_root / EXPECTED_CONTRACT_PATH
    if not contract_path.is_file():
        raise DrillError(f"recoverability drill contract is missing: {contract_path}")
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DrillError(f"recoverability drill contract JSON is invalid: {exc}") from exc
    if not isinstance(contract, dict):
        raise DrillError("recoverability drill contract root must be a JSON object")
    return contract


def compare_metrics(left: dict[str, Any], right: dict[str, Any]) -> bool:
    ignored = {"metadata", "append_only_trigger_names"}
    left_view = {key: value for key, value in left.items() if key not in ignored}
    right_view = {key: value for key, value in right.items() if key not in ignored}
    return left_view == right_view


def validate_metrics(metrics: dict[str, Any], label: str) -> None:
    if metrics.get("total_ledger_events") != EXPECTED_EVENT_COUNT:
        raise DrillError(
            f"{label} expected {EXPECTED_EVENT_COUNT} ledger events, got {metrics.get('total_ledger_events')}"
        )
    if metrics.get("total_cases") != EXPECTED_CASE_COUNT:
        raise DrillError(f"{label} expected {EXPECTED_CASE_COUNT} cases, got {metrics.get('total_cases')}")
    if metrics.get("cases_by_detection") != EXPECTED_DETECTION_COUNTS:
        raise DrillError(f"{label} detection counts mismatch: {metrics.get('cases_by_detection')}")
    if metrics.get("public_safe_count") != 0:
        raise DrillError(f"{label} public_safe_count must remain 0")
    if metrics.get("closed_case_count") != 0:
        raise DrillError(f"{label} closed_case_count must remain 0")
    if metrics.get("github_issue_mutation_count") != 0:
        raise DrillError(f"{label} GitHub issue mutation count must remain 0")
    if metrics.get("append_only_trigger_names") != EXPECTED_APPEND_ONLY_TRIGGERS:
        raise DrillError(f"{label} append-only triggers mismatch: {metrics.get('append_only_trigger_names')}")
    metadata = metrics.get("metadata") or {}
    required_metadata = {
        "ledger_kind": "seed_sample_only",
        "long_term_runtime_ledger": "false",
        "proof_promotion_allowed": "false",
        "public_safe_promotion_allowed": "false",
        "github_issue_mutation_allowed": "false",
        "case_closure_allowed": "false",
        "ai_support_mode": "AI_SUPPORT_ONLY",
    }
    for key, expected in required_metadata.items():
        if metadata.get(key) != expected:
            raise DrillError(f"{label} metadata {key} expected {expected!r}, got {metadata.get(key)!r}")


def validate_contract(contract: dict[str, Any]) -> None:
    expected = {
        "contract_id": "LIFETIME_CASE_LEDGER_V1_RECOVERABILITY_DRILL",
        "ledger_path": str(EXPECTED_LEDGER_PATH).replace("\\", "/"),
        "ledger_boundary": EXPECTED_LEDGER_BOUNDARY,
        "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
        "proof_ceiling": EXPECTED_PROOF_CEILING,
        "restore_performed": False,
        "append_performed": False,
        "database_modified": False,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise DrillError(f"contract {key} expected {value!r}, got {contract.get(key)!r}")
    required_report_fields = {
        "canonical_ledger_path",
        "backup_path",
        "canonical_sha256_before",
        "canonical_sha256_after",
        "backup_sha256",
        "canonical_metrics_before",
        "canonical_metrics_after",
        "backup_metrics",
        "database_modified",
        "restore_performed",
        "append_performed",
        "public_safe_status",
        "proof_ceiling",
    }
    actual_fields = set(contract.get("required_report_fields") or [])
    missing = sorted(required_report_fields - actual_fields)
    if missing:
        raise DrillError(f"contract required_report_fields missing: {missing}")


def validate_report(report: dict[str, Any]) -> None:
    required_false_flags = ("database_modified", "restore_performed", "append_performed")
    for flag in required_false_flags:
        if report.get(flag) is not False:
            raise DrillError(f"{flag} must be false")
    if report.get("public_safe_status") != EXPECTED_PUBLIC_SAFE_STATUS:
        raise DrillError("public_safe_status must remain NOT_PUBLIC_SAFE")
    if report.get("proof_ceiling") != EXPECTED_PROOF_CEILING:
        raise DrillError("proof_ceiling must remain SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY")
    if report.get("ledger_boundary") != EXPECTED_LEDGER_BOUNDARY:
        raise DrillError("ledger boundary was changed or promoted")
    if report.get("claimed_runtime_status") != "NOT_CLAIMED":
        raise DrillError("runtime or production claim appeared")
    if report.get("claimed_signal_status") != "NOT_CLAIMED":
        raise DrillError("signal claim appeared")
    if report.get("claimed_deployment_status") != "NO_PRODUCTION_DEPLOYMENT_CLAIM":
        raise DrillError("production deployment claim appeared")
    if report.get("disposition_authority") != "NO_AI_OR_ANALYST_DISPOSITION_AUTHORITY":
        raise DrillError("AI or analyst disposition authority claim appeared")
    if report.get("canonical_sha256_before") != report.get("canonical_sha256_after"):
        raise DrillError("canonical ledger SHA changed during drill")
    if report.get("canonical_sha256_before") != report.get("backup_sha256"):
        raise DrillError("backup SHA differs from canonical source SHA")
    before_metrics = report.get("canonical_metrics_before")
    after_metrics = report.get("canonical_metrics_after")
    backup_metrics = report.get("backup_metrics")
    if before_metrics != after_metrics:
        raise DrillError("canonical metrics changed during drill")
    if not compare_metrics(before_metrics, backup_metrics):
        raise DrillError("backup metrics differ from canonical metrics")
    validate_metrics(before_metrics, "canonical before")
    validate_metrics(after_metrics, "canonical after")
    validate_metrics(backup_metrics, "backup")


def expect_negative_failure(name: str, report: dict[str, Any], mutation: dict[str, Any], expected_text: str) -> dict[str, Any]:
    candidate = copy.deepcopy(report)
    candidate.update(mutation)
    try:
        validate_report(candidate)
    except DrillError as exc:
        actual = str(exc)
        if expected_text not in actual:
            raise DrillError(f"negative test {name} failed for wrong reason: {actual}") from exc
        return {"name": name, "passed": True, "expected_failure": expected_text, "actual_failure": actual}
    raise DrillError(f"negative test {name} unexpectedly passed")


def run_negative_tests(report: dict[str, Any]) -> list[dict[str, Any]]:
    changed_metrics = copy.deepcopy(report["canonical_metrics_before"])
    changed_metrics["total_ledger_events"] += 1
    changed_backup_metrics = copy.deepcopy(report["backup_metrics"])
    changed_backup_metrics["total_cases"] += 1
    tests = [
        expect_negative_failure(
            "canonical_sha_changed",
            report,
            {"canonical_sha256_after": "0" * 64},
            "canonical ledger SHA changed",
        ),
        expect_negative_failure(
            "canonical_count_changed",
            report,
            {"canonical_metrics_after": changed_metrics},
            "canonical metrics changed",
        ),
        expect_negative_failure(
            "backup_count_differs",
            report,
            {"backup_metrics": changed_backup_metrics},
            "backup metrics differ",
        ),
        expect_negative_failure("append_performed_true", report, {"append_performed": True}, "append_performed must be false"),
        expect_negative_failure("restore_performed_true", report, {"restore_performed": True}, "restore_performed must be false"),
        expect_negative_failure("database_modified_true", report, {"database_modified": True}, "database_modified must be false"),
        expect_negative_failure(
            "public_safe_status_promoted",
            report,
            {"public_safe_status": "PUBLIC_SAFE"},
            "public_safe_status must remain",
        ),
        expect_negative_failure(
            "proof_ceiling_promoted",
            report,
            {"proof_ceiling": "PUBLIC_PROOF"},
            "proof_ceiling must remain",
        ),
        expect_negative_failure(
            "runtime_signal_production_claim",
            report,
            {
                "claimed_runtime_status": "runtime-active",
                "claimed_signal_status": "signal-observed",
                "claimed_deployment_status": "production deployment",
            },
            "runtime or production claim appeared",
        ),
    ]
    return tests


def build_report(repo_root: Path) -> dict[str, Any]:
    ledger_path = repo_root / EXPECTED_LEDGER_PATH
    if not ledger_path.is_file():
        raise DrillError(f"canonical ledger is missing: {ledger_path}")

    contract = load_contract(repo_root)
    validate_contract(contract)

    canonical_sha_before = sha256_file(ledger_path)
    canonical_metrics_before = ledger_metrics(ledger_path)
    validate_metrics(canonical_metrics_before, "canonical before")

    with tempfile.TemporaryDirectory(prefix="ho-lifetime-ledger-drill-") as temp_dir:
        backup_path = Path(temp_dir) / "autosoc-case-ledger-v0.backup.sqlite"
        shutil.copy2(ledger_path, backup_path)
        backup_sha = sha256_file(backup_path)
        backup_metrics = ledger_metrics(backup_path)

        canonical_sha_after = sha256_file(ledger_path)
        canonical_metrics_after = ledger_metrics(ledger_path)

        report = {
            "mode": "lifetime-case-ledger-recoverability-drill",
            "status": "pass",
            "canonical_ledger_path": str(EXPECTED_LEDGER_PATH).replace("\\", "/"),
            "backup_path": "temporary_test_copy_deleted_after_process_exit",
            "backup_retained": False,
            "backup_storage_class": "temporary_test_copy_deleted_after_process_exit",
            "canonical_sha256_before": canonical_sha_before,
            "canonical_sha256_after": canonical_sha_after,
            "backup_sha256": backup_sha,
            "canonical_metrics_before": canonical_metrics_before,
            "canonical_metrics_after": canonical_metrics_after,
            "backup_metrics": backup_metrics,
            "database_modified": False,
            "restore_performed": False,
            "append_performed": False,
            "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
            "proof_ceiling": EXPECTED_PROOF_CEILING,
            "ledger_boundary": EXPECTED_LEDGER_BOUNDARY,
            "claimed_runtime_status": "NOT_CLAIMED",
            "claimed_signal_status": "NOT_CLAIMED",
            "claimed_deployment_status": "NO_PRODUCTION_DEPLOYMENT_CLAIM",
            "disposition_authority": "NO_AI_OR_ANALYST_DISPOSITION_AUTHORITY",
            "project_1_packet": {
                "item_title": "Platform Ledger Recoverability Drill / Visual Ledger Map",
                "repository": "hawkinsoperations-platform",
                "lane": "Platform / Ledger",
                "truth_surface": "repo truth / operating control",
                "control_level": "real control",
                "receipt_status": "READY_FOR_HUMAN_REVIEW",
                "reviewer_facing": True,
                "proof_ceiling": EXPECTED_PROOF_CEILING,
                "evidence_link": (
                    "docs/factory/LIFETIME_CASE_LEDGER_RECOVERABILITY_DRILL.md; "
                    "scripts/verify-lifetime-ledger-backup-drill.py"
                ),
                "next_gate": "human GitHub review / MERGE_APPROVED",
                "demo_value": (
                    "reviewer can understand ledger mechanics and recoverability without mutating proof or runtime truth"
                ),
            },
            "does_not_prove": [
                "runtime truth",
                "signal truth",
                "public proof",
                "public-safe status",
                "production deployment",
                "SOCaaS deployment",
                "autonomous SOC",
                "AI-approved disposition",
                "analyst-approved disposition",
                "case closure",
            ],
        }
        validate_report(report)
        report["negative_tests"] = run_negative_tests(report)
        report["negative_test_summary"] = {
            "passed": len(report["negative_tests"]),
            "failed": 0,
            "covered": [
                "canonical SHA changes",
                "canonical count changes",
                "backup count differs",
                "append_performed=true",
                "restore_performed=true",
                "database_modified=true",
                "public-safe status promotion",
                "proof ceiling promotion",
                "runtime/signal/production claim appearance",
            ],
        }
        return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify Lifetime Case Ledger non-mutating backup drill")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path to hawkinsoperations-platform repository root",
    )
    parser.add_argument("--format", choices=("json", "text"), default="json")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    try:
        report = build_report(repo_root)
    except DrillError as exc:
        print(f"BLOCKED: LIFETIME_LEDGER_RECOVERABILITY_DRILL_FAILED: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("LIFETIME_LEDGER_RECOVERABILITY_DRILL=pass")
        print(f"canonical_ledger_path={report['canonical_ledger_path']}")
        print(f"canonical_sha256_before={report['canonical_sha256_before']}")
        print(f"canonical_sha256_after={report['canonical_sha256_after']}")
        print(f"backup_sha256={report['backup_sha256']}")
        print("database_modified=false")
        print("restore_performed=false")
        print("append_performed=false")
        print(f"public_safe_status={report['public_safe_status']}")
        print(f"proof_ceiling={report['proof_ceiling']}")
        print(f"negative_tests_passed={report['negative_test_summary']['passed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
