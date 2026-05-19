#!/usr/bin/env python3
"""Detection Factory Controller v0.

Read-only status and plan packets for selected HawkinsOperations detections.
The controller prints to stdout only and does not create generated output files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONTROLLER_VERSION = "0.1.0"
CASE_LEDGER_VERSION = "AUTOSOC_CASE_LEDGER_V0"
PLATFORM_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO_ROOT = PLATFORM_ROOT.parent
DEFAULT_CASE_LEDGER = PLATFORM_ROOT / "evidence" / "autosoc-case-ledger-v0.sqlite"
SPLUNK_HO_DET_001_APPEND_APPROVAL = "APPEND_ONE_SANITIZED_SPLUNK_HO_DET_001_RUNTIME_CASE_APPROVED"
RUNTIME_LEDGER_TRUTH_BOUNDARY = "private_runtime_review_only_not_public_proof_not_public_safe"
RUNTIME_REVIEW_NEXT_ALLOWED_MOVE = (
    "Review the sanitized runtime case packet and metrics snapshot. Any append remains blocked unless "
    f"{SPLUNK_HO_DET_001_APPEND_APPROVAL} is explicitly provided."
)

CASE_LEDGER_TRUTH_CLASSES = (
    "FORWARD_GOVERNED_CASE",
    "SYNTHETIC_TEST_CASE",
    "RECOVERED_HISTORICAL_IMPORT",
    "PRIVATE_RUNTIME_EVIDENCE",
    "PUBLIC_PROOF_CANDIDATE",
    "PUBLIC_BLOCKED",
)

CASE_LEDGER_TEXT_SCAN_FIELDS = (
    "case_id",
    "detection_id",
    "truth_class",
    "case_status",
    "source_packet_ref",
    "proof_ceiling",
    "public_safe_status",
    "ai_support_mode",
    "closure_reason",
    "created_at",
    "inserted_at",
    "event_hash",
    "parent_event_hash",
    "ledger_version",
    "recommended_disposition",
    "payload_json",
)

CASE_LEDGER_APPEND_ONLY_TRIGGERS = {
    "case_events_no_update": "BEFORE UPDATE",
    "case_events_no_delete": "BEFORE DELETE",
}

PRIVATE_MARKER_PATTERNS = (
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"),
    re.compile(r"(?i)\b(secret|password|token|api[_-]?key|credential)\b"),
    re.compile(r"(?i)\b(raw model output|private evidence filename|internal service)\b"),
)

SPLUNK_SANITIZED_INPUT_ALLOWED_KEYS = {
    "case_id",
    "detection_id",
    "source_system",
    "observed_time_utc",
    "splunk_result_ref",
    "sanitized_event_fingerprint",
    "rule_match_name",
    "rule_match_version",
}

SPLUNK_SANITIZED_INPUT_BLOCKED_KEYS = {
    "_raw",
    "raw",
    "raw_event",
    "raw_event_payload",
    "raw_payload",
    "event_payload",
    "payload",
    "command_line",
    "process_command_line",
    "cmdline",
    "host",
    "hostname",
    "user",
    "username",
    "src_ip",
    "dest_ip",
    "ip",
    "mac",
    "mac_address",
    "vm_id",
    "private_path",
    "private_evidence_filename",
    "secret",
    "token",
    "credential",
    "password",
    "internal_service",
    "internal_service_detail",
}

SPLUNK_SANITIZED_VALUE_PATTERNS = (
    re.compile(r"(?i)\b_raw\b"),
    re.compile(r"(?i)\braw\s+(event|payload|command)\b"),
    re.compile(r"(?i)\bcommand\s+line\b"),
    re.compile(r"(?i)\b(hostname|host\s+name|username|user\s+name|vm\s*id)\b"),
    re.compile(r"(?i)\bprivate\s+(path|evidence|filename)\b"),
    re.compile(r"(?i)\binternal\s+service\b"),
)

RUNTIME_CASE_REVIEW_BLOCKED_CLAIMS = (
    "Splunk connection proof",
    "live Splunk query proof",
    "raw event proof",
    "public proof",
    "public-safe",
    "proof promotion",
    "GitHub Issue mutation",
    "case closure",
    "AI-approved disposition",
    "analyst-approved disposition",
    "production SOC",
    "autonomous SOC",
)


class FactoryError(RuntimeError):
    """Fail-closed controller error."""


@dataclass(frozen=True)
class Surface:
    repo: str
    path: str
    required: bool = True


@dataclass(frozen=True)
class DetectionSpec:
    detection_id: str
    current_state: str
    public_proof_ceiling: str
    private_evidence_state: str
    public_safe_status: str
    platform_guardrail_status: str
    validation_result: str
    validation_expected: dict[str, int]
    validation_claim: str
    proof_record: str
    proof_card: str | None
    proof_state: str
    platform_sample: str
    platform_sample_expected_total: int
    required_blocked_claims: tuple[str, ...]
    supported_claims: tuple[str, ...]
    next_allowed_move: str
    decision_status: str
    decision_reason: str
    truth_boundary: dict[str, str]
    stop_conditions: tuple[str, ...]
    state_consistency: tuple[str, ...]
    does_not_prove: tuple[str, ...]
    surfaces: tuple[Surface, ...]


COMMON_BLOCKED = (
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production-ready",
    "fleet-wide",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
)

PLATFORM_SAMPLE_BLOCKED = (
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production-ready",
    "fleet-wide",
    "AI-approved disposition",
)


def case_factory_issue_plan(spec: DetectionSpec) -> dict[str, Any]:
    labels = [
        "autosoc:case",
        "autosoc:sanitized",
        "autosoc:validated",
        "autosoc:needs-human-review",
        "autosoc:blocked-close",
        "publication:not-approved",
        "ai:support-only",
        f"det:{spec.detection_id.lower()}",
    ]
    result = "BLOCKED_HUMAN_REVIEW_REQUIRED"
    blockers = [
        "human_review_required=true",
        "github_issue_mutation_allowed=false",
        "close_action_allowed=false",
        "ai_support_is_labor_not_authority",
    ]
    if spec.detection_id == "HO-DET-011" and spec.platform_guardrail_status == "STATE_DRIFT_REVIEW_REQUIRED":
        result = "BLOCKED_PLATFORM_GUARDRAIL_DRIFT"
        blockers.append("ho_det_011_platform_guardrail_drift_review_required")

    return {
        "factory_version": "AUTOSOC_CASE_FACTORY_V0",
        "case_state": "DETERMINISTIC_RULE_EVALUATED",
        "github_issue_plan": {
            "mode": "dry_run_only",
            "mutation_allowed": False,
            "issue_ref": None,
            "labels_to_add": labels,
            "labels_to_remove": [],
            "comment_intent": "Prepare sanitized deterministic status only; do not mutate GitHub Issues.",
            "close_action_allowed": False,
        },
        "deterministic_close_rule": {
            "evaluated": True,
            "close_eligible": False,
            "result": result,
            "blockers": blockers,
            "ai_authority_granted": False,
            "proof_promotion_allowed": False,
            "public_safe_promotion_allowed": False,
        },
        "ai_support_boundary": {
            "allowed_role": "AI_SUPPORT_ONLY",
            "ai_decided_disposition": False,
            "recommended_disposition": None,
            "may_approve": False,
            "may_promote": False,
            "may_close": False,
        },
    }


def bool_int(value: bool) -> int:
    return 1 if value else 0


def stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def case_ledger_schema_sql() -> str:
    truth_values = ", ".join(f"'{item}'" for item in CASE_LEDGER_TRUTH_CLASSES)
    return f"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS ledger_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_hash TEXT NOT NULL UNIQUE,
  parent_event_hash TEXT,
  inserted_at TEXT NOT NULL,
  ledger_version TEXT NOT NULL CHECK (ledger_version = '{CASE_LEDGER_VERSION}'),
  case_id TEXT NOT NULL,
  detection_id TEXT NOT NULL,
  truth_class TEXT NOT NULL CHECK (truth_class IN ({truth_values})),
  case_status TEXT NOT NULL,
  proof_ceiling TEXT NOT NULL,
  public_safe_status TEXT NOT NULL CHECK (public_safe_status IN ('NO', 'BLOCKED', 'NOT_PUBLIC_SAFE')),
  ai_support_mode TEXT NOT NULL CHECK (ai_support_mode = 'AI_SUPPORT_ONLY'),
  ai_decided_disposition INTEGER NOT NULL CHECK (ai_decided_disposition = 0),
  recommended_disposition TEXT CHECK (recommended_disposition IS NULL),
  deterministic_close_eligible INTEGER NOT NULL CHECK (deterministic_close_eligible = 0),
  deterministic_close_blocked INTEGER NOT NULL CHECK (deterministic_close_blocked = 1),
  human_review_required INTEGER NOT NULL CHECK (human_review_required = 1),
  gpu_supported INTEGER NOT NULL CHECK (gpu_supported IN (0, 1)),
  public_safe INTEGER NOT NULL CHECK (public_safe = 0),
  proof_blocked INTEGER NOT NULL CHECK (proof_blocked = 1),
  github_issue_mutation_allowed INTEGER NOT NULL CHECK (github_issue_mutation_allowed = 0),
  case_closed INTEGER NOT NULL CHECK (case_closed = 0),
  legacy_import_count INTEGER NOT NULL DEFAULT 0 CHECK (legacy_import_count = 0),
  payload_json TEXT NOT NULL,
  source_packet_ref TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS case_events_no_update
BEFORE UPDATE ON case_events
BEGIN
  SELECT RAISE(ABORT, 'case ledger is append-only: update blocked');
END;

CREATE TRIGGER IF NOT EXISTS case_events_no_delete
BEFORE DELETE ON case_events
BEGIN
  SELECT RAISE(ABORT, 'case ledger is append-only: delete blocked');
END;
"""


def connect_ledger(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def initialize_ledger_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(case_ledger_schema_sql())
    metadata = {
        "ledger_version": CASE_LEDGER_VERSION,
        "ledger_kind": "seed_sample_only",
        "long_term_runtime_ledger": "false",
        "proof_promotion_allowed": "false",
        "public_safe_promotion_allowed": "false",
        "github_issue_mutation_allowed": "false",
        "case_closure_allowed": "false",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "human_review_required": "true",
    }
    conn.executemany(
        "INSERT OR IGNORE INTO ledger_metadata(key, value) VALUES (?, ?)",
        sorted(metadata.items()),
    )


def scan_private_markers(label: str, value: Any) -> None:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    for pattern in PRIVATE_MARKER_PATTERNS:
        if pattern.search(text):
            raise FactoryError(f"{label} contains blocked private marker: {pattern.pattern}")


def scan_ledger_event_text_fields(event: dict[str, Any]) -> dict[str, Any]:
    scanned_fields: dict[str, Any] = {}
    for field in CASE_LEDGER_TEXT_SCAN_FIELDS:
        if field in event and event[field] is not None:
            scanned_fields[field] = event[field]
    payload = json.loads(str(event["payload_json"]))
    scanned_fields["payload_json_parsed"] = payload
    scan_private_markers("case ledger stored event text fields", scanned_fields)
    return payload


def load_sanitized_input(path_or_stdin: str) -> dict[str, Any]:
    if path_or_stdin == "-":
        raw_text = sys.stdin.read()
        source = "stdin"
    else:
        path = Path(path_or_stdin)
        if not path.is_file():
            raise FactoryError(f"sanitized input file is missing: {path}")
        raw_text = path.read_text(encoding="utf-8")
        source = str(path)
    try:
        value = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise FactoryError(f"invalid sanitized input JSON from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise FactoryError("sanitized input root must be a JSON object")
    return value


def validate_splunk_sanitized_input(candidate: dict[str, Any]) -> None:
    blocked = sorted(set(candidate) & SPLUNK_SANITIZED_INPUT_BLOCKED_KEYS)
    if blocked:
        raise FactoryError(f"sanitized Splunk input contains blocked raw/private fields: {', '.join(blocked)}")
    unknown = sorted(set(candidate) - SPLUNK_SANITIZED_INPUT_ALLOWED_KEYS)
    if unknown:
        raise FactoryError(f"sanitized Splunk input contains unsupported fields: {', '.join(unknown)}")
    if candidate.get("detection_id") != "HO-DET-001":
        raise FactoryError("sanitized Splunk input detection_id must be HO-DET-001")
    if candidate.get("source_system") != "Splunk":
        raise FactoryError("sanitized Splunk input source_system must be Splunk")
    for key, value in candidate.items():
        if value is not None and not isinstance(value, str):
            raise FactoryError(f"sanitized Splunk input {key} must be a string or null")
    fingerprint = candidate.get("sanitized_event_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise FactoryError("sanitized Splunk input requires sanitized_event_fingerprint")
    case_id = candidate.get("case_id")
    if case_id is not None and (not isinstance(case_id, str) or not case_id.startswith("AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-")):
        raise FactoryError("sanitized Splunk input case_id must start with AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-")
    scan_private_markers("sanitized Splunk input", candidate)
    scan_text = json.dumps(candidate, sort_keys=True)
    for pattern in SPLUNK_SANITIZED_VALUE_PATTERNS:
        if pattern.search(scan_text):
            raise FactoryError(f"sanitized Splunk input contains blocked raw/private value: {pattern.pattern}")


def validate_runtime_ledger_path(ledger_path: Path) -> None:
    resolved = ledger_path.resolve()
    platform_root = PLATFORM_ROOT.resolve()
    try:
        resolved.relative_to(platform_root)
    except ValueError:
        pass
    else:
        raise FactoryError(f"runtime ledger path must be outside platform repo: {resolved}")
    if not resolved.is_file():
        raise FactoryError(f"runtime ledger file is missing: {resolved}")


def connect_read_only_ledger(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def build_splunk_ho_det_001_runtime_candidate(sanitized_input: dict[str, Any]) -> dict[str, Any]:
    validate_splunk_sanitized_input(sanitized_input)
    observed_time = str(sanitized_input.get("observed_time_utc") or "not_provided")
    case_id = str(
        sanitized_input.get("case_id")
        or f"AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-{hashlib.sha256(stable_json(sanitized_input).encode('utf-8')).hexdigest()[:12].upper()}"
    )
    payload = {
        "case_factory_version": "AUTOSOC_CASE_FACTORY_V0",
        "case_state": "SPLUNK_LIVE_INGESTION_DRY_RUN_ONLY",
        "case_source": "splunk_sanitized_result_candidate",
        "source_system": "Splunk",
        "observed_time_utc": observed_time,
        "splunk_result_ref": sanitized_input.get("splunk_result_ref"),
        "sanitized_event_fingerprint": sanitized_input["sanitized_event_fingerprint"],
        "rule_match_name": sanitized_input.get("rule_match_name"),
        "rule_match_version": sanitized_input.get("rule_match_version"),
        "supported_claim": "A sanitized Splunk HO-DET-001 candidate was prepared for human review.",
        "issue_plan_mode": "dry_run_only",
        "close_rule_result": "BLOCKED_HUMAN_REVIEW_REQUIRED",
        "truth_boundary": (
            "Dry-run candidate only. Not appended, not proof promotion, not public-safe approval, "
            "not GitHub Issue mutation, not case closure, and not public runtime proof."
        ),
    }
    event = {
        "inserted_at": observed_time,
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": case_id,
        "detection_id": "HO-DET-001",
        "truth_class": "FORWARD_GOVERNED_CASE",
        "case_status": "HUMAN_REVIEW_REQUIRED",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "recommended_disposition": None,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "human_review_required": True,
        "gpu_supported": False,
        "public_safe": False,
        "proof_blocked": True,
        "github_issue_mutation_allowed": False,
        "case_closed": False,
        "legacy_import_count": 0,
        "payload_json": payload,
        "source_packet_ref": "splunk-ho-det-001-sanitized-dry-run/no-raw-export",
    }
    event_hash_input = dict(event)
    event_hash_input["payload_json"] = payload
    event["event_hash"] = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    scan_private_markers("sanitized Splunk runtime candidate", event)
    return event


def metrics_after_candidate(before: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    after = json.loads(json.dumps(before))
    after["total_cases"] = int(after["total_cases"]) + 1
    for key, event_field in (
        ("cases_by_detection", "detection_id"),
        ("cases_by_truth_class", "truth_class"),
        ("cases_by_status", "case_status"),
    ):
        group = dict(after[key])
        value = str(event[event_field])
        group[value] = int(group.get(value, 0)) + 1
        after[key] = group
    after["deterministic_close_blocked_count"] = int(after["deterministic_close_blocked_count"]) + 1
    after["human_review_required_count"] = int(after["human_review_required_count"]) + 1
    after["proof_blocked_count"] = int(after["proof_blocked_count"]) + 1
    return after


def runtime_splunk_ho_det_001_dry_run(ledger_path: Path, sanitized_input: dict[str, Any]) -> dict[str, Any]:
    validate_runtime_ledger_path(ledger_path)
    candidate = build_splunk_ho_det_001_runtime_candidate(sanitized_input)
    with connect_read_only_ledger(ledger_path) as conn:
        verification = verify_ledger(conn, RUNTIME_LEDGER_TRUTH_BOUNDARY)
        metadata = dict(conn.execute("SELECT key, value FROM ledger_metadata ORDER BY key").fetchall())
        for key in (
            "live_ingestion_allowed",
            "splunk_ingestion_allowed",
            "github_issue_mutation_allowed",
            "proof_promotion_allowed",
            "public_safe_promotion_allowed",
        ):
            if metadata.get(key) != "false":
                raise FactoryError(f"runtime ledger metadata {key} must remain false for dry-run")
        before_metrics = ledger_metrics(conn, RUNTIME_LEDGER_TRUTH_BOUNDARY)
        duplicate_event_hash_count = int(
            conn.execute("SELECT COUNT(*) FROM case_events WHERE event_hash = ?", (candidate["event_hash"],)).fetchone()[0]
        )
        duplicate_case_id_count = int(
            conn.execute("SELECT COUNT(*) FROM case_events WHERE case_id = ?", (candidate["case_id"],)).fetchone()[0]
        )
    return {
        "mode": "runtime-ledger-ingest-splunk-ho-det-001",
        "dry_run": True,
        "ledger_path": str(ledger_path.resolve()),
        "runtime_ledger_open_mode": "read_only",
        "source_system": "Splunk",
        "detection_id": "HO-DET-001",
        "candidate_event": candidate,
        "dedupe": {
            "duplicate_event_hash_count": duplicate_event_hash_count,
            "duplicate_case_id_count": duplicate_case_id_count,
            "append_would_be_blocked": duplicate_event_hash_count != 0 or duplicate_case_id_count != 0,
        },
        "before_metrics": before_metrics,
        "expected_after_metrics": metrics_after_candidate(before_metrics, candidate),
        "verification": verification,
        "approval_required_before_append": SPLUNK_HO_DET_001_APPEND_APPROVAL,
        "boundaries": {
            "database_modified": False,
            "splunk_connected": False,
            "github_issue_mutation_allowed": False,
            "proof_promotion_allowed": False,
            "public_safe_promotion_allowed": False,
            "ai_disposition_authority": False,
            "case_closure_allowed": False,
        },
    }


def row_to_event(conn: sqlite3.Connection, row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    columns = [item[1] for item in conn.execute("PRAGMA table_info(case_events)").fetchall()]
    if isinstance(row, sqlite3.Row):
        return {column: row[column] for column in columns}
    return dict(zip(columns, row))


def bool_from_int_field(event: dict[str, Any], field: str) -> bool:
    return bool(int(event[field]))


def runtime_ledger_review_case_from_conn(conn: sqlite3.Connection, ledger_label: str, case_id: str) -> dict[str, Any]:
    verification = verify_ledger(conn, RUNTIME_LEDGER_TRUTH_BOUNDARY)
    metadata = dict(conn.execute("SELECT key, value FROM ledger_metadata ORDER BY key").fetchall())
    rows = conn.execute("SELECT * FROM case_events WHERE case_id = ? ORDER BY event_id", (case_id,)).fetchall()
    if not rows:
        raise FactoryError(f"runtime ledger case not found: {case_id}")
    if len(rows) > 1:
        raise FactoryError(f"runtime ledger case_id is not unique: {case_id} matched {len(rows)} rows")
    row = rows[0]
    event = row_to_event(conn, row)
    payload = scan_ledger_event_text_fields(event)

    required_false_fields = (
        "github_issue_mutation_allowed",
        "case_closed",
        "ai_decided_disposition",
        "deterministic_close_eligible",
        "public_safe",
    )
    for field in required_false_fields:
        if bool_from_int_field(event, field):
            raise FactoryError(f"runtime case review field must remain false: {field}")
    if not bool_from_int_field(event, "human_review_required"):
        raise FactoryError("runtime case review human_review_required must remain true")
    if not bool_from_int_field(event, "deterministic_close_blocked"):
        raise FactoryError("runtime case review deterministic_close_blocked must remain true")
    if not bool_from_int_field(event, "proof_blocked"):
        raise FactoryError("runtime case review proof_blocked must remain true")
    if event.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        raise FactoryError("runtime case review public_safe_status must remain NOT_PUBLIC_SAFE")
    if event.get("ai_support_mode") != "AI_SUPPORT_ONLY":
        raise FactoryError("runtime case review ai_support_mode must be AI_SUPPORT_ONLY")
    for key in (
        "proof_promotion_allowed",
        "public_safe_promotion_allowed",
        "github_issue_mutation_allowed",
        "case_closure_allowed",
    ):
        if metadata.get(key) != "false":
            raise FactoryError(f"runtime ledger metadata {key} must remain false")
    if metadata.get("ai_support_mode") != "AI_SUPPORT_ONLY":
        raise FactoryError("runtime ledger metadata ai_support_mode must remain AI_SUPPORT_ONLY")

    case_summary = {
        "case_id": event["case_id"],
        "detection_id": event["detection_id"],
        "truth_class": event["truth_class"],
        "case_status": event["case_status"],
        "event_hash": event["event_hash"],
        "proof_ceiling": event["proof_ceiling"],
        "public_safe_status": event["public_safe_status"],
        "ai_support_mode": event["ai_support_mode"],
        "human_review_required": bool_from_int_field(event, "human_review_required"),
        "deterministic_close_eligible": bool_from_int_field(event, "deterministic_close_eligible"),
        "deterministic_close_blocked": bool_from_int_field(event, "deterministic_close_blocked"),
        "github_issue_mutation_allowed": bool_from_int_field(event, "github_issue_mutation_allowed"),
        "case_closed": bool_from_int_field(event, "case_closed"),
        "ai_decided_disposition": bool_from_int_field(event, "ai_decided_disposition"),
        "public_safe": bool_from_int_field(event, "public_safe"),
        "proof_blocked": bool_from_int_field(event, "proof_blocked"),
        "source_packet_ref": event["source_packet_ref"],
        "payload_json": payload,
    }
    return {
        "mode": "runtime-ledger-review-case",
        "ledger_path": ledger_label,
        "runtime_ledger_open_mode": "read_only",
        "case": case_summary,
        "metrics_snapshot": verification["metrics"],
        "append_only_trigger_inspection": {
            "status": "pass",
            "mode": verification["append_only_triggers"],
            "trigger_names": verification["append_only_trigger_names"],
        },
        "private_marker_scan": {
            "status": "pass",
            "scanned_fields": list(CASE_LEDGER_TEXT_SCAN_FIELDS),
        },
        "verification": verification,
        "supported_internal_claim": (
            f"Sanitized runtime ledger case {event['case_id']} exists for human review under "
            f"{event['truth_class']} with {event['case_status']} status."
        ),
        "blocked_claims": list(RUNTIME_CASE_REVIEW_BLOCKED_CLAIMS),
        "boundary_confirmations": {
            "github_issue_mutation_allowed": False,
            "case_closed": False,
            "ai_decided_disposition": False,
            "deterministic_close_eligible": False,
            "human_review_required": True,
            "proof_promotion_allowed": False,
            "public_safe_promotion_allowed": False,
            "ai_disposition_authority": False,
            "public_safe": False,
            "proof_blocked": True,
        },
        "next_allowed_move": RUNTIME_REVIEW_NEXT_ALLOWED_MOVE,
        "append_required_before_next_case": SPLUNK_HO_DET_001_APPEND_APPROVAL,
        "proof_boundary": (
            "Local runtime ledger review only. Not proof promotion, not public-safe approval, "
            "not GitHub Issue mutation, not case closure, and not AI disposition authority."
        ),
    }


def runtime_ledger_review_case(ledger_path: Path, case_id: str) -> dict[str, Any]:
    validate_runtime_ledger_path(ledger_path)
    with connect_read_only_ledger(ledger_path) as conn:
        return runtime_ledger_review_case_from_conn(conn, str(ledger_path.resolve()), case_id)


def build_sample_case_event(repo_root: Path) -> dict[str, Any]:
    packet_ref = "hawkinsoperations-validation/validation/successor/ho-det-001/case-packet.json"
    packet = load_json(repo_root / packet_ref)
    if packet.get("detection_id") != "HO-DET-001":
        raise FactoryError("sample case packet detection_id must be HO-DET-001")
    if packet.get("proof_level") != "CONTROLLED_TEST_VALIDATED":
        raise FactoryError("sample case packet proof_level must be CONTROLLED_TEST_VALIDATED")
    if packet.get("public_safe_status") not in {"NO", "BLOCKED", "NOT_PUBLIC_SAFE"}:
        raise FactoryError("sample case packet public_safe_status must remain blocked")
    case_factory = packet.get("case_factory")
    if not isinstance(case_factory, dict):
        raise FactoryError("sample case packet missing case_factory object")
    close_rule = case_factory.get("deterministic_close_rule")
    if not isinstance(close_rule, dict):
        raise FactoryError("sample case packet missing deterministic close rule")
    if close_rule.get("close_eligible") is not False:
        raise FactoryError("sample case packet close eligibility must remain false")
    if close_rule.get("ai_authority_granted") is not False:
        raise FactoryError("sample case packet must not grant AI authority")

    payload = {
        "packet_ref": packet_ref,
        "case_factory_version": case_factory.get("factory_version"),
        "case_state": case_factory.get("case_state"),
        "supported_claim": packet.get("public_claim_boundary", {}).get("supported_claim"),
        "issue_plan_mode": case_factory.get("github_issue_plan", {}).get("mode"),
        "close_rule_result": close_rule.get("result"),
        "truth_boundary": (
            "SQLite seed records one sanitized controlled-test case-factory packet only. "
            "It is not a live runtime ledger, proof promotion, public-safe approval, or case closure."
        ),
    }
    scan_private_markers("case ledger sample payload", payload)

    event = {
        "inserted_at": "2026-05-18T18:10:00Z",
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": packet["case_id"],
        "detection_id": packet["detection_id"],
        "truth_class": "SYNTHETIC_TEST_CASE",
        "case_status": "HUMAN_REVIEW_REQUIRED",
        "proof_ceiling": packet["proof_level"],
        "public_safe_status": packet["public_safe_status"],
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "recommended_disposition": None,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "human_review_required": True,
        "gpu_supported": False,
        "public_safe": False,
        "proof_blocked": True,
        "github_issue_mutation_allowed": False,
        "case_closed": False,
        "legacy_import_count": 0,
        "payload_json": payload,
        "source_packet_ref": packet_ref,
    }
    event_hash_input = dict(event)
    event_hash_input["payload_json"] = payload
    event["event_hash"] = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    return event


def insert_case_event(conn: sqlite3.Connection, event: dict[str, Any]) -> str:
    scan_private_markers("case ledger event", event)
    existing = conn.execute(
        "SELECT event_hash FROM case_events WHERE event_hash = ?",
        (event["event_hash"],),
    ).fetchone()
    if existing:
        return "already_present"
    conn.execute(
        """
        INSERT INTO case_events (
          event_hash, parent_event_hash, inserted_at, ledger_version, case_id,
          detection_id, truth_class, case_status, proof_ceiling, public_safe_status,
          ai_support_mode, ai_decided_disposition, recommended_disposition,
          deterministic_close_eligible, deterministic_close_blocked,
          human_review_required, gpu_supported, public_safe, proof_blocked,
          github_issue_mutation_allowed, case_closed, legacy_import_count,
          payload_json, source_packet_ref
        ) VALUES (
          :event_hash, NULL, :inserted_at, :ledger_version, :case_id,
          :detection_id, :truth_class, :case_status, :proof_ceiling, :public_safe_status,
          :ai_support_mode, :ai_decided_disposition, :recommended_disposition,
          :deterministic_close_eligible, :deterministic_close_blocked,
          :human_review_required, :gpu_supported, :public_safe, :proof_blocked,
          :github_issue_mutation_allowed, :case_closed, :legacy_import_count,
          :payload_json, :source_packet_ref
        )
        """,
        {
            **event,
            "payload_json": stable_json(event["payload_json"]),
            "ai_decided_disposition": bool_int(event["ai_decided_disposition"]),
            "deterministic_close_eligible": bool_int(event["deterministic_close_eligible"]),
            "deterministic_close_blocked": bool_int(event["deterministic_close_blocked"]),
            "human_review_required": bool_int(event["human_review_required"]),
            "gpu_supported": bool_int(event["gpu_supported"]),
            "public_safe": bool_int(event["public_safe"]),
            "proof_blocked": bool_int(event["proof_blocked"]),
            "github_issue_mutation_allowed": bool_int(event["github_issue_mutation_allowed"]),
            "case_closed": bool_int(event["case_closed"]),
        },
    )
    return "inserted"


def ledger_metrics(
    conn: sqlite3.Connection,
    truth_boundary: str = "seed_sample_only_not_live_runtime_ledger_not_proof",
) -> dict[str, Any]:
    def grouped(column: str) -> dict[str, int]:
        rows = conn.execute(f"SELECT {column}, COUNT(*) FROM case_events GROUP BY {column} ORDER BY {column}").fetchall()
        return {str(key): int(count) for key, count in rows}

    counts = conn.execute(
        """
        SELECT
          COUNT(*),
          COALESCE(SUM(gpu_supported), 0),
          COALESCE(SUM(deterministic_close_eligible), 0),
          COALESCE(SUM(deterministic_close_blocked), 0),
          COALESCE(SUM(human_review_required), 0),
          COALESCE(SUM(public_safe), 0),
          COALESCE(SUM(proof_blocked), 0)
        FROM case_events
        """
    ).fetchone()
    return {
        "ledger_version": CASE_LEDGER_VERSION,
        "total_cases": int(counts[0]),
        "cases_by_detection": grouped("detection_id"),
        "cases_by_truth_class": grouped("truth_class"),
        "cases_by_status": grouped("case_status"),
        "gpu_supported_count": int(counts[1]),
        "deterministic_close_eligible_count": int(counts[2]),
        "deterministic_close_blocked_count": int(counts[3]),
        "human_review_required_count": int(counts[4]),
        "public_safe_count": int(counts[5]),
        "proof_blocked_count": int(counts[6]),
        "truth_boundary": truth_boundary,
    }


def verify_append_only_triggers(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'case_events'"
    ).fetchall()
    triggers = {str(name): str(sql or "") for name, sql in rows}
    for name, required_clause in CASE_LEDGER_APPEND_ONLY_TRIGGERS.items():
        sql = triggers.get(name)
        if not sql:
            raise FactoryError(f"append-only trigger missing: {name}")
        normalized_sql = " ".join(sql.upper().split())
        if required_clause not in normalized_sql:
            raise FactoryError(f"append-only trigger {name} missing {required_clause}")
        if "RAISE" not in normalized_sql or "ABORT" not in normalized_sql:
            raise FactoryError(f"append-only trigger {name} must abort mutation")
    return sorted(CASE_LEDGER_APPEND_ONLY_TRIGGERS)


def verify_ledger(
    conn: sqlite3.Connection,
    metrics_truth_boundary: str = "seed_sample_only_not_live_runtime_ledger_not_proof",
) -> dict[str, Any]:
    metadata = dict(conn.execute("SELECT key, value FROM ledger_metadata").fetchall())
    required_metadata = {
        "ledger_version": CASE_LEDGER_VERSION,
        "long_term_runtime_ledger": "false",
        "proof_promotion_allowed": "false",
        "public_safe_promotion_allowed": "false",
        "github_issue_mutation_allowed": "false",
        "case_closure_allowed": "false",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "human_review_required": "true",
    }
    for key, expected in required_metadata.items():
        if metadata.get(key) != expected:
            raise FactoryError(f"ledger metadata {key} expected {expected!r}, got {metadata.get(key)!r}")

    rows = conn.execute("SELECT * FROM case_events ORDER BY event_id").fetchall()
    columns = [item[1] for item in conn.execute("PRAGMA table_info(case_events)").fetchall()]
    if not rows:
        raise FactoryError("case ledger must contain at least one sanitized seed event")
    for row in rows:
        event = dict(zip(columns, row))
        if not event.get("proof_ceiling"):
            raise FactoryError("ledger event missing proof_ceiling")
        if event.get("public_safe_status") not in {"NO", "BLOCKED", "NOT_PUBLIC_SAFE"}:
            raise FactoryError("ledger event public_safe_status is promoted or missing")
        false_fields = (
            "ai_decided_disposition",
            "deterministic_close_eligible",
            "public_safe",
            "github_issue_mutation_allowed",
            "case_closed",
            "legacy_import_count",
        )
        for field in false_fields:
            if int(event[field]) != 0:
                raise FactoryError(f"ledger event {field} must remain 0")
        true_fields = ("deterministic_close_blocked", "human_review_required", "proof_blocked")
        for field in true_fields:
            if int(event[field]) != 1:
                raise FactoryError(f"ledger event {field} must remain 1")
        if event.get("ai_support_mode") != "AI_SUPPORT_ONLY":
            raise FactoryError("ledger event ai_support_mode must be AI_SUPPORT_ONLY")
        if event.get("recommended_disposition") is not None:
            raise FactoryError("ledger event recommended_disposition must be null")
        payload = scan_ledger_event_text_fields(event)
        if "proof" in str(payload.get("truth_boundary", "")).lower() and "not" not in str(payload.get("truth_boundary", "")).lower():
            raise FactoryError("ledger payload implies proof promotion")

    trigger_names = verify_append_only_triggers(conn)

    return {
        "ledger_verifier": "pass",
        "append_only_triggers": "sqlite_master_trigger_inspection_no_dml",
        "append_only_trigger_names": trigger_names,
        "event_count": len(rows),
        "metrics": ledger_metrics(conn, metrics_truth_boundary),
    }


def sql_bool(value: Any) -> int:
    if isinstance(value, bool):
        return bool_int(value)
    return int(value)


def insert_case_event_unchecked(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
    payload = event["payload_json"]
    payload_json = stable_json(payload) if isinstance(payload, dict) else str(payload)
    conn.execute(
        """
        INSERT INTO case_events (
          event_hash, parent_event_hash, inserted_at, ledger_version, case_id,
          detection_id, truth_class, case_status, proof_ceiling, public_safe_status,
          ai_support_mode, ai_decided_disposition, recommended_disposition,
          deterministic_close_eligible, deterministic_close_blocked,
          human_review_required, gpu_supported, public_safe, proof_blocked,
          github_issue_mutation_allowed, case_closed, legacy_import_count,
          payload_json, source_packet_ref
        ) VALUES (
          :event_hash, NULL, :inserted_at, :ledger_version, :case_id,
          :detection_id, :truth_class, :case_status, :proof_ceiling, :public_safe_status,
          :ai_support_mode, :ai_decided_disposition, :recommended_disposition,
          :deterministic_close_eligible, :deterministic_close_blocked,
          :human_review_required, :gpu_supported, :public_safe, :proof_blocked,
          :github_issue_mutation_allowed, :case_closed, :legacy_import_count,
          :payload_json, :source_packet_ref
        )
        """,
        {
            **event,
            "payload_json": payload_json,
            "ai_decided_disposition": sql_bool(event["ai_decided_disposition"]),
            "deterministic_close_eligible": sql_bool(event["deterministic_close_eligible"]),
            "deterministic_close_blocked": sql_bool(event["deterministic_close_blocked"]),
            "human_review_required": sql_bool(event["human_review_required"]),
            "gpu_supported": sql_bool(event["gpu_supported"]),
            "public_safe": sql_bool(event["public_safe"]),
            "proof_blocked": sql_bool(event["proof_blocked"]),
            "github_issue_mutation_allowed": sql_bool(event["github_issue_mutation_allowed"]),
            "case_closed": sql_bool(event["case_closed"]),
        },
    )


def self_test_runtime_event(
    *,
    event_updates: dict[str, Any] | None = None,
    payload_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = build_splunk_ho_det_001_runtime_candidate(
        {
            "case_id": "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            "detection_id": "HO-DET-001",
            "source_system": "Splunk",
            "observed_time_utc": "2026-05-19T00:00:00Z",
            "splunk_result_ref": "sanitized-self-test-ref",
            "sanitized_event_fingerprint": "sanitized-self-test-fingerprint",
            "rule_match_name": "HO-DET-001 self-test",
            "rule_match_version": "v0",
        }
    )
    if payload_updates:
        event["payload_json"] = {**event["payload_json"], **payload_updates}
    if event_updates:
        event.update(event_updates)
    event_hash_input = dict(event)
    event_hash_input["payload_json"] = event["payload_json"]
    event["event_hash"] = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    return event


def self_test_runtime_conn(
    *,
    event_updates: dict[str, Any] | None = None,
    payload_updates: dict[str, Any] | None = None,
    metadata_updates: dict[str, str] | None = None,
) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    initialize_ledger_schema(conn)
    if metadata_updates:
        conn.executemany(
            "INSERT OR REPLACE INTO ledger_metadata(key, value) VALUES (?, ?)",
            sorted(metadata_updates.items()),
        )
    event = self_test_runtime_event(event_updates=event_updates, payload_updates=payload_updates)
    conn.execute("PRAGMA ignore_check_constraints = ON")
    insert_case_event_unchecked(conn, event)
    conn.execute("PRAGMA ignore_check_constraints = OFF")
    conn.commit()
    return conn


def expect_factory_error(name: str, callback: Any) -> str:
    try:
        callback()
    except FactoryError:
        return name
    raise FactoryError(f"runtime review negative self-test did not fail closed: {name}")


def runtime_review_self_tests() -> dict[str, Any]:
    valid_input = {
        "detection_id": "HO-DET-001",
        "source_system": "Splunk",
        "sanitized_event_fingerprint": "sanitized-self-test-fingerprint",
    }
    passed = [
        expect_factory_error(
            "missing case ID fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(), "memory:self-test", "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-MISSING"
            ),
        ),
        expect_factory_error(
            "private marker in reviewed case fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(payload_updates={"private_marker": "C:\\private\\case.txt"}),
                "memory:self-test",
                "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            ),
        ),
        expect_factory_error("raw Splunk _raw field fails closed", lambda: validate_splunk_sanitized_input({**valid_input, "_raw": "blocked"})),
        expect_factory_error("host field fails closed", lambda: validate_splunk_sanitized_input({**valid_input, "host": "blocked-host"})),
        expect_factory_error("username field fails closed", lambda: validate_splunk_sanitized_input({**valid_input, "username": "blocked-user"})),
        expect_factory_error(
            "LAN IP fails closed",
            lambda: validate_splunk_sanitized_input({**valid_input, "sanitized_event_fingerprint": "192.168.1.10"}),
        ),
        expect_factory_error(
            "local path fails closed",
            lambda: validate_splunk_sanitized_input({**valid_input, "sanitized_event_fingerprint": "C:\\private\\case.txt"}),
        ),
        expect_factory_error(
            "token or secret marker fails closed",
            lambda: validate_splunk_sanitized_input({**valid_input, "sanitized_event_fingerprint": "token marker"}),
        ),
        expect_factory_error(
            "public-safe promotion fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(event_updates={"public_safe": True}),
                "memory:self-test",
                "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            ),
        ),
        expect_factory_error(
            "proof promotion fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(event_updates={"proof_blocked": False}),
                "memory:self-test",
                "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            ),
        ),
        expect_factory_error(
            "case closure authority fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(event_updates={"case_closed": True}),
                "memory:self-test",
                "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            ),
        ),
        expect_factory_error(
            "AI disposition authority fails closed",
            lambda: runtime_ledger_review_case_from_conn(
                self_test_runtime_conn(event_updates={"ai_decided_disposition": True}),
                "memory:self-test",
                "AUTOSOC-RUNTIME-SPLUNK-HO-DET-001-SELFTEST",
            ),
        ),
    ]
    return {
        "status": "pass",
        "mode": "in_memory_no_files_no_runtime_mutation",
        "negative_checks": passed,
    }


SPECS: dict[str, DetectionSpec] = {
    "HO-DET-001": DetectionSpec(
        detection_id="HO-DET-001",
        current_state="CONTROLLED_TEST_VALIDATED",
        public_proof_ceiling="CONTROLLED_TEST_VALIDATED",
        private_evidence_state="PRIVATE_INTERNAL_BOUNDARY_CONTEXT",
        public_safe_status="NOT_PUBLIC_SAFE",
        platform_guardrail_status="SATISFIED_NON_PROMOTIONAL_BOUNDARY",
        validation_result="hawkinsoperations-validation/reports/ho-det-001/validation-result.json",
        validation_expected={
            "total_cases": 14,
            "positive_cases": 7,
            "negative_cases": 7,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
        },
        validation_claim="HO-DET-001 passed controlled-test validation against controlled positive and negative process-creation fixtures.",
        proof_record="hawkinsoperations-proof/proof/records/HO-DET-001.md",
        proof_card="hawkinsoperations-proof/proof/cards/HO-DET-001.md",
        proof_state="CONTROLLED_TEST_VALIDATED_WITH_PRIVATE_INTERNAL_BOUNDARY_CONTEXT",
        platform_sample="hawkinsoperations-platform/contracts/examples/ho-det-001-runtime-contract.sample.json",
        platform_sample_expected_total=0,
        required_blocked_claims=(
            *COMMON_BLOCKED,
            "evidence-linked public proof",
            "live Splunk fired",
            "Cribl-routed",
            "Wazuh-routed",
            "AWS-live",
        ),
        supported_claims=(
            "HO-DET-001 source exists.",
            "HO-DET-001 Splunk source exists.",
            "HO-DET-001 passed controlled-test validation against controlled positive and negative process-creation fixtures.",
            "HO-DET-001 platform runtime contract enforcement exists as a non-promotional guardrail.",
        ),
        next_allowed_move="Review packet only; stronger claims require separate evidence linkage, privacy review, stale review, wording review, and Raylee approval.",
        decision_status="READY_FOR_REVIEW",
        decision_reason="Controller v0 reports HO-DET-001 state only and preserves proof boundaries.",
        truth_boundary={
            "source_truth": "reported",
            "validation_truth": "controlled-test validated",
            "platform_truth": "controller and runtime-contract guardrail reported",
            "proof_truth": "proof record reported",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not promote proof.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not create generated output files.",
        ),
        state_consistency=("STATE_CONSISTENT_WITH_V0_BOUNDARY",),
        does_not_prove=(
            "runtime activity",
            "signal observation",
            "public-safe status",
            "production deployment",
            "fleet-wide coverage",
            "live Splunk firing",
            "Cribl routing",
            "Wazuh routing",
            "AWS-live coverage",
            "AI-approved disposition",
            "analyst-approved disposition",
        ),
        surfaces=(
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-001/status.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-001/rule.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-001/splunk.spl"),
            Surface("hawkinsoperations-detections", "detections/DETECTION_FACTORY_INDEX.md"),
            Surface("hawkinsoperations-validation", "reports/ho-det-001/validation-result.json"),
            Surface("hawkinsoperations-validation", "validation/successor/ho-det-001/case-packet.json"),
            Surface("hawkinsoperations-validation", "validation/successor/ho-det-001/autosoc-triage-packet.json"),
            Surface("hawkinsoperations-validation", "validation/successor/ho-det-001/llm-summary.json"),
            Surface("hawkinsoperations-proof", "proof/records/HO-DET-001.md"),
            Surface("hawkinsoperations-proof", "proof/cards/HO-DET-001.md"),
            Surface("hawkinsoperations-platform", "contracts/examples/ho-det-001-runtime-contract.sample.json"),
            Surface("hawkinsoperations-platform", "contracts/schemas/ho-det-001-runtime-contract.schema.json"),
            Surface("hawkinsoperations-platform", "scripts/verify-ho-det-001-runtime-contract.py"),
        ),
    ),
    "HO-DET-011": DetectionSpec(
        detection_id="HO-DET-011",
        current_state="PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        public_proof_ceiling="CONTROLLED_TEST_VALIDATED",
        private_evidence_state="PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        public_safe_status="NOT_PUBLIC_SAFE",
        platform_guardrail_status="STATE_DRIFT_REVIEW_REQUIRED",
        validation_result="hawkinsoperations-validation/reports/ho-det-011/validation-result.json",
        validation_expected={
            "total_cases": 17,
            "positive_cases": 7,
            "negative_cases": 10,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
        },
        validation_claim="HO-DET-011 passed controlled-test validation against controlled Windows service creation fixtures.",
        proof_record="hawkinsoperations-proof/proof/records/HO-DET-011.md",
        proof_card=None,
        proof_state="PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        platform_sample="hawkinsoperations-platform/contracts/examples/ho-det-011-case-packet.sample.json",
        platform_sample_expected_total=6,
        required_blocked_claims=(
            *COMMON_BLOCKED,
            "evidence-linked public proof",
            "live Splunk fired",
            "Splunk observed",
            "Wazuh observed",
            "Wazuh-routed",
            "Cribl-routed",
            "Security Onion observed",
            "service-creation coverage completeness",
        ),
        supported_claims=(
            "HO-DET-011 source artifacts exist.",
            "HO-DET-011 passed controlled-test validation against 17 controlled Windows service creation fixtures.",
            "HO-DET-011 has a platform case-packet guardrail that preserves controlled-test-scope claim boundaries.",
            "HO-DET-011 has sanitized private local Windows runtime evidence captured for one controlled service-creation test.",
            "HO-DET-011 is capped at PRIVATE_RUNTIME_EVIDENCE_CAPTURED for private evidence and NOT_PUBLIC_SAFE for public use.",
        ),
        next_allowed_move="Review platform drift before any guardrail update; routed telemetry or public-safe wording remains blocked until separate evidence linkage, redaction review, stale review, wording review, and Raylee approval.",
        decision_status="DRIFT_REVIEW_REQUIRED",
        decision_reason="Platform guardrail remains pinned to an earlier 6-case shape while current validation, proof, and detection surfaces record 17 controlled-test fixtures.",
        truth_boundary={
            "source_truth": "reported",
            "validation_truth": "controlled-test validated",
            "platform_truth": "controller reported drift review required",
            "proof_truth": "private runtime evidence state reported",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not repair the 6-case platform guardrail in v0.",
            "Do not promote proof.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not create generated output files.",
        ),
        state_consistency=(
            "STATE_DRIFT_REVIEW_REQUIRED",
            "Platform sample and verifier remain pinned to an earlier 6-case guardrail while current validation, proof, and detection facts record 17 controlled-test fixtures.",
        ),
        does_not_prove=(
            "runtime activity",
            "public or routed signal observation",
            "public-safe proof",
            "live Splunk firing",
            "Wazuh observation",
            "Cribl routing",
            "Security Onion observation",
            "production deployment",
            "fleet-wide coverage",
            "service-creation coverage completeness",
            "AI-approved disposition",
            "analyst-approved disposition",
        ),
        surfaces=(
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-011/status.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-011/rule.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-011/splunk.spl"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-011/wazuh.xml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-011/event-mapping.yml"),
            Surface("hawkinsoperations-detections", "detections/DETECTION_FACTORY_INDEX.md"),
            Surface("hawkinsoperations-validation", "reports/ho-det-011/validation-result.json"),
            Surface("hawkinsoperations-validation", "validation/successor/ho-det-011/validation-cases.json"),
            Surface("hawkinsoperations-proof", "proof/records/HO-DET-011.md"),
            Surface("hawkinsoperations-platform", "contracts/examples/ho-det-011-case-packet.sample.json"),
            Surface("hawkinsoperations-platform", "contracts/schemas/ho-det-011-case-packet.schema.json"),
            Surface("hawkinsoperations-platform", "scripts/verify-ho-det-011-case-packet.py"),
        ),
    ),
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FactoryError(f"missing required JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FactoryError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FactoryError(f"JSON root must be object: {path}")
    return value


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FactoryError(f"missing required text surface: {path}") from exc


def repo_path(repo_root: Path, repo: str, relpath: str) -> Path:
    return repo_root / repo / relpath


def require_detection_id(value: dict[str, Any], expected: str, source: str) -> None:
    actual = value.get("detection_id")
    if actual != expected:
        raise FactoryError(f"{source} detection_id expected {expected}, got {actual!r}")


def require_blocked_claims(claims: Any, required: tuple[str, ...], source: str) -> list[str]:
    if not isinstance(claims, list) or not claims:
        raise FactoryError(f"{source} blocked_claims must be a non-empty list")
    claim_strings = [str(item) for item in claims]

    def normalize(value: str) -> str:
        return " ".join(value.lower().replace("-", " ").split())

    normalized = [normalize(claim) for claim in claim_strings]

    def is_present(required_claim: str) -> bool:
        required_normalized = normalize(required_claim)
        variants = {
            "live splunk fired": ("live splunk fired", "live splunk firing", "splunk fired"),
            "splunk observed": ("splunk observed", "splunk fired", "live splunk fired", "live splunk firing"),
        }.get(required_normalized, (required_normalized,))

        for variant in variants:
            for claim in normalized:
                if variant in claim or claim in variant:
                    return True
        return False

    missing = [claim for claim in required if not is_present(claim)]
    if missing:
        raise FactoryError(f"{source} blocked_claims missing: {', '.join(missing)}")
    return claim_strings


def validation_summary(spec: DetectionSpec, validation: dict[str, Any]) -> dict[str, Any]:
    require_detection_id(validation, spec.detection_id, spec.validation_result)
    if validation.get("status") != "pass":
        raise FactoryError(f"{spec.validation_result} status must be pass")

    totals = validation.get("totals") if isinstance(validation.get("totals"), dict) else validation
    observed = {
        "total_cases": int(totals.get("total_cases", validation.get("total_cases", -1))),
        "positive_cases": int(totals.get("positive_cases", validation.get("positive_cases", -1))),
        "negative_cases": int(totals.get("negative_cases", validation.get("negative_cases", -1))),
        "missed_positive_count": len(validation.get("missed_positive_cases", [])),
        "false_positive_negative_count": len(validation.get("false_positive_negative_cases", [])),
    }

    for key, expected in spec.validation_expected.items():
        actual = observed.get(key)
        if actual != expected:
            raise FactoryError(f"{spec.detection_id} {key} expected {expected}, got {actual}")

    if validation.get("exact_claim_supported") != spec.validation_claim:
        raise FactoryError(f"{spec.detection_id} exact_claim_supported does not match v0 contract")

    return {
        "status": "pass",
        **observed,
        "exact_claim_supported": spec.validation_claim,
    }


def platform_sample_claims(spec: DetectionSpec, sample: dict[str, Any]) -> list[str]:
    require_detection_id(sample, spec.detection_id, spec.platform_sample)
    if sample.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        raise FactoryError(f"{spec.platform_sample} public_safe_status must be NOT_PUBLIC_SAFE")
    for key in ("runtime_active", "signal_observed", "ai_decided_disposition", "human_review_required"):
        expected = True if key == "human_review_required" else False
        if sample.get(key) is not expected:
            raise FactoryError(f"{spec.platform_sample} {key} expected {expected!r}")

    counts = sample.get("validation_counts")
    if spec.platform_sample_expected_total:
        if not isinstance(counts, dict):
            raise FactoryError(f"{spec.platform_sample} validation_counts must be present")
        total = counts.get("total_cases")
        if total != spec.platform_sample_expected_total:
            raise FactoryError(
                f"{spec.platform_sample} expected historical total_cases {spec.platform_sample_expected_total}, got {total}"
            )

    require_blocked_claims(sample.get("blocked_claims"), PLATFORM_SAMPLE_BLOCKED, spec.platform_sample)
    return list(spec.required_blocked_claims)


def group_found_surfaces(repo_root: Path, spec: DetectionSpec) -> tuple[list[dict[str, Any]], list[str]]:
    grouped: dict[str, list[str]] = {}
    missing: list[str] = []
    for surface in spec.surfaces:
        candidate = repo_path(repo_root, surface.repo, surface.path)
        if candidate.exists():
            grouped.setdefault(surface.repo, []).append(surface.path)
        elif surface.required:
            missing.append(f"{surface.repo}/{surface.path}")
    found = [{"repo": repo, "paths": paths} for repo, paths in grouped.items()]
    return found, missing


def assert_proof_record(repo_root: Path, spec: DetectionSpec) -> tuple[bool, bool]:
    record_path = repo_root / spec.proof_record
    record_text = load_text(record_path)
    for required_text in (spec.detection_id, "NOT_PUBLIC_SAFE", "Blocked Claims"):
        if required_text not in record_text:
            raise FactoryError(f"{spec.proof_record} missing required proof text: {required_text}")
    if spec.private_evidence_state not in record_text and spec.current_state not in record_text:
        raise FactoryError(f"{spec.proof_record} missing expected state text")

    card_exists = False
    if spec.proof_card is not None:
        card_path = repo_root / spec.proof_card
        load_text(card_path)
        card_exists = True
    return True, card_exists


def gate_summary(spec: DetectionSpec) -> list[dict[str, Any]]:
    return [
        {
            "gate": "source",
            "status": "FOUND",
            "owner_repo": "hawkinsoperations-detections",
            "claim": "source exists",
            "promotion_allowed": False,
        },
        {
            "gate": "validation",
            "status": "CONTROLLED_TEST_VALIDATED",
            "owner_repo": "hawkinsoperations-validation",
            "claim": "controlled-test validation passed",
            "promotion_allowed": False,
        },
        {
            "gate": "platform_guardrail",
            "status": spec.platform_guardrail_status,
            "owner_repo": "hawkinsoperations-platform",
            "claim": "platform guardrail reported",
            "promotion_allowed": False,
        },
        {
            "gate": "proof_record",
            "status": "FOUND",
            "owner_repo": "hawkinsoperations-proof",
            "claim": "proof state reported, not promoted",
            "promotion_allowed": False,
        },
        {
            "gate": "blocked_claims",
            "status": "PRESENT",
            "owner_repo": "hawkinsoperations-platform",
            "claim": "blocked claims inventory present",
            "promotion_allowed": False,
        },
        {
            "gate": "next_legal_move",
            "status": "REVIEW_REQUIRED",
            "owner_repo": "hawkinsoperations-platform",
            "claim": spec.next_allowed_move,
            "promotion_allowed": False,
        },
    ]


def build_packet(repo_root: Path, spec: DetectionSpec) -> dict[str, Any]:
    found, missing = group_found_surfaces(repo_root, spec)
    if missing:
        raise FactoryError(f"{spec.detection_id} required surfaces missing: {', '.join(missing)}")

    validation = load_json(repo_root / spec.validation_result)
    summary = validation_summary(spec, validation)
    validation_blocked = validation.get("blocked_claims") or validation.get("claims_not_supported")
    if spec.detection_id == "HO-DET-001":
        case_packet = load_json(repo_root / "hawkinsoperations-validation/validation/successor/ho-det-001/case-packet.json")
        public_boundary = case_packet.get("public_claim_boundary", {})
        if not isinstance(public_boundary, dict):
            raise FactoryError("HO-DET-001 case packet public_claim_boundary must be object")
        validation_blocked = public_boundary.get("blocked_claims")
    validation_required = tuple(
        claim for claim in spec.required_blocked_claims if claim not in {"Splunk observed", "Wazuh observed"}
    )
    require_blocked_claims(validation_blocked, validation_required, spec.validation_result)

    platform_claims = platform_sample_claims(spec, load_json(repo_root / spec.platform_sample))
    record_exists, card_exists = assert_proof_record(repo_root, spec)

    return {
        "controller_version": CONTROLLER_VERSION,
        "detection_id": spec.detection_id,
        "current_state": spec.current_state,
        "public_proof_ceiling": spec.public_proof_ceiling,
        "private_evidence_state": spec.private_evidence_state,
        "public_safe_status": spec.public_safe_status,
        "runtime_active": False,
        "signal_observed": False,
        "ai_decided_disposition": False,
        "human_review_required": True,
        "gate_summary": gate_summary(spec),
        "decision": {
            "status": spec.decision_status,
            "merge_recommendation": "REVIEW_REQUIRED",
            "proof_promotion_allowed": False,
            "public_rendering_allowed": False,
            "reason": spec.decision_reason,
        },
        "truth_boundary": spec.truth_boundary,
        "repo_surfaces_found": found,
        "required_surfaces_missing": [],
        "validation_state": summary,
        "proof_state": {
            "record_path": spec.proof_record,
            "card_path": spec.proof_card,
            "record_exists": record_exists,
            "card_exists": card_exists,
            "state": spec.proof_state,
        },
        "platform_guardrail_status": spec.platform_guardrail_status,
        "blocked_claims": sorted(set(platform_claims)),
        "supported_claims": list(spec.supported_claims),
        "case_factory": case_factory_issue_plan(spec),
        "next_allowed_move": spec.next_allowed_move,
        "stop_conditions": list(spec.stop_conditions),
        "state_consistency": list(spec.state_consistency),
        "does_not_prove": list(spec.does_not_prove),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detection Factory Controller v0")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("status", "plan"):
        sub = subparsers.add_parser(mode)
        sub.add_argument("--detection", required=True, choices=("HO-DET-001", "HO-DET-011", "all"))
        sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
        sub.add_argument("--format", default="json", choices=("json",))
    for mode in ("ledger-init-sample", "ledger-verify", "ledger-metrics"):
        sub = subparsers.add_parser(mode)
        sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
        sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
        sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("runtime-ledger-ingest-splunk-ho-det-001")
    sub.add_argument("--mode", dest="ingest_mode", required=True, choices=("dry-run",))
    sub.add_argument("--ledger", required=True)
    sub.add_argument("--sanitized-input", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("runtime-ledger-review-case")
    sub.add_argument("--ledger", required=True)
    sub.add_argument("--case-id", required=True)
    sub.add_argument("--self-test", action="store_true")
    sub.add_argument("--format", default="json", choices=("json",))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    if args.mode in {"ledger-init-sample", "ledger-verify", "ledger-metrics"}:
        repo_root = Path(args.repo_root).resolve()
        ledger_path = Path(args.ledger_path).resolve()
        seed_ledger = ledger_path == DEFAULT_CASE_LEDGER.resolve()
        if args.mode == "ledger-init-sample":
            if not seed_ledger:
                raise FactoryError(f"Case Ledger v0 seed init path is not approved for this scope: {ledger_path}")
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
        elif not ledger_path.is_file():
            raise FactoryError(f"Case Ledger v0 seed file is missing: {ledger_path}")
        if not seed_ledger:
            validate_runtime_ledger_path(ledger_path)
        ledger_scope = "repo_seed_ledger" if seed_ledger else "external_runtime_ledger"
        open_mode = "read_write_seed_scope" if args.mode == "ledger-init-sample" else ("read_only" if not seed_ledger else "read_write_seed_scope")
        metrics_truth_boundary = (
            "seed_sample_only_not_live_runtime_ledger_not_proof" if seed_ledger else RUNTIME_LEDGER_TRUTH_BOUNDARY
        )
        connector = connect_ledger if seed_ledger else connect_read_only_ledger
        with connector(ledger_path) as conn:
            if args.mode == "ledger-init-sample":
                initialize_ledger_schema(conn)
                insert_status = insert_case_event(conn, build_sample_case_event(repo_root))
                verification = verify_ledger(conn, metrics_truth_boundary)
                output = {
                    "ledger_version": CASE_LEDGER_VERSION,
                    "mode": args.mode,
                    "ledger_path": str(ledger_path),
                    "ledger_scope": ledger_scope,
                    "open_mode": open_mode,
                    "sqlite_choice": "SQLite is used for v0 because CHECK constraints, append-only triggers, unique event hashes, and metrics queries can be verified deterministically without a new dependency.",
                    "sample_insert_status": insert_status,
                    "verification": verification,
                }
            elif args.mode == "ledger-verify":
                output = {
                    "ledger_version": CASE_LEDGER_VERSION,
                    "mode": args.mode,
                    "ledger_path": str(ledger_path),
                    "ledger_scope": ledger_scope,
                    "open_mode": open_mode,
                    "verification": verify_ledger(conn, metrics_truth_boundary),
                }
            else:
                output = {
                    "ledger_version": CASE_LEDGER_VERSION,
                    "mode": args.mode,
                    "ledger_path": str(ledger_path),
                    "ledger_scope": ledger_scope,
                    "open_mode": open_mode,
                    "metrics": ledger_metrics(conn, metrics_truth_boundary),
                }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "runtime-ledger-ingest-splunk-ho-det-001":
        sanitized_input = load_sanitized_input(args.sanitized_input)
        output = runtime_splunk_ho_det_001_dry_run(Path(args.ledger).resolve(), sanitized_input)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "runtime-ledger-review-case":
        output = runtime_ledger_review_case(Path(args.ledger).resolve(), args.case_id)
        if args.self_test:
            output["self_tests"] = runtime_review_self_tests()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    repo_root = Path(args.repo_root).resolve()
    detection_ids = sorted(SPECS) if args.detection == "all" else [args.detection]

    packets = [build_packet(repo_root, SPECS[detection_id]) for detection_id in detection_ids]
    output = {
        "controller_version": CONTROLLER_VERSION,
        "mode": args.mode,
        "generated_output_files": False,
        "packets": packets,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FactoryError as exc:
        print(f"DETECTION_FACTORY_CONTROLLER=fail: {exc}", file=sys.stderr)
        raise SystemExit(1)
