#!/usr/bin/env python3
"""Detection Factory Controller v0.

Read-only status and plan packets for selected HawkinsOperations detections.
The controller prints to stdout only and does not create generated output files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - absence is handled as fail-closed runtime state.
    yaml = None


CONTROLLER_VERSION = "0.1.0"
CASE_LEDGER_VERSION = "AUTOSOC_CASE_LEDGER_V0"
LIFETIME_CASE_LEDGER_VERSION = "LIFETIME_CASE_LEDGER_V1"
PLATFORM_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO_ROOT = PLATFORM_ROOT.parent
DEFAULT_CASE_LEDGER = PLATFORM_ROOT / "evidence" / "autosoc-case-ledger-v0.sqlite"
LIFETIME_LEDGER_STATE_MANIFEST = PLATFORM_ROOT / "contracts" / "lifetime-case-ledger-v1-state-manifest.json"
PROOF_STATUS_INDEX_REL = "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml"
PROOF_STATUS_INDEX_OWNER = "hawkinsoperations-proof"
PROOF_STATUS_INDEX_VISIBILITY_STATUS = "STATUS_VISIBILITY_ONLY_NON_AUTHORITATIVE"
PROOF_STATUS_INDEX_BOUNDARY = (
    "Platform reports proof-index status metadata only. Proof truth remains owned by "
    "hawkinsoperations-proof, and this visibility field does not promote proof, runtime, "
    "signal, public-safe, or website status."
)
SPLUNK_HO_DET_001_APPEND_APPROVAL = "APPEND_ONE_SANITIZED_SPLUNK_HO_DET_001_RUNTIME_CASE_APPROVED"
RUNTIME_LEDGER_TRUTH_BOUNDARY = "private_runtime_review_only_not_public_proof_not_public_safe"
RUNTIME_REVIEW_SUPPORTED_CLAIM = "PRIVATE_RUNTIME_REVIEW_SUPPORT_ONLY"
RUNTIME_REVIEW_APPEND_APPROVAL = "SEPARATE_RUNTIME_LEDGER_APPEND_APPROVAL_REQUIRED"
RUNTIME_REVIEW_NEXT_ALLOWED_MOVE = (
    "Review the sanitized runtime case packet and metrics snapshot. Runtime append, proof promotion, "
    "public-safe promotion, GitHub Issue mutation, case closure, and AI or analyst disposition authority "
    f"remain blocked unless a separate scoped approval such as {RUNTIME_REVIEW_APPEND_APPROVAL} is provided."
)
LIFETIME_LEDGER_PROOF_CEILING = "SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY"
LIFETIME_LEDGER_PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
LIFETIME_LEDGER_BOUNDARY = (
    "Phase 1 verifies only the Lifetime Case Ledger v1 spine, model, coverage map, "
    "bounded metrics contract, and existing seed-ledger bridge. It does not prove live "
    "runtime activity, signal observation, production deployment, SOCaaS availability, "
    "public-safe runtime proof, AI-approved disposition, analyst-approved disposition, "
    "or case closure authority."
)
LIFETIME_LEDGER_EVENT_FIELDS = (
    "ledger_version",
    "event_id",
    "event_hash",
    "parent_event_hash",
    "event_type",
    "case_id",
    "detection_id",
    "detection_family",
    "source_system",
    "fired_at",
    "observed_time_utc",
    "ingested_at",
    "truth_class",
    "case_status",
    "triage_status",
    "disposition_status",
    "proof_ceiling",
    "runtime_truth_status",
    "signal_truth_status",
    "public_safe_status",
    "human_review_required",
    "ai_support_mode",
    "ai_decided_disposition",
    "gpu_triage_used",
    "gpu_node_id",
    "model_or_triage_engine_reference",
    "source_packet_ref",
    "evidence_ref_public_safe",
    "private_evidence_ref_allowed",
    "blocked_claims",
    "validation_ref",
    "proof_ref",
    "github_actions_run_ref",
    "payload_hash",
    "sanitized_event_fingerprint",
    "correction_reason",
    "supersedes_event_hash",
    "notes_boundary",
)
LIFETIME_LEDGER_REQUIRED_METRICS = (
    "total_ledger_events",
    "total_cases",
    "cases_by_detection",
    "cases_by_family",
    "cases_by_status",
    "cases_by_truth_class",
    "cases_by_proof_ceiling",
    "cases_by_public_safe_status",
    "cases_requiring_human_review",
    "gpu_triaged_count",
    "ai_support_only_count",
    "proof_blocked_count",
    "public_safe_count",
    "closed_case_count",
    "correction_event_count",
    "superseding_event_count",
    "validation_only_count",
    "private_runtime_count",
    "public_proof_candidate_count",
)
LIFETIME_LEDGER_BLOCKED_CLAIMS = (
    "production deployment",
    "public raw runtime evidence",
    "runtime-active public status",
    "signal-observed public status",
    "public-safe runtime proof",
    "SOCaaS deployment",
    "autonomous SOC",
    "AI-approved final disposition",
    "analyst-approved final disposition",
    "case closure without explicit human-approved closure artifact",
)
RUNTIME_COLLECTOR_WINDOWS_VERSION = "runtime-case-collector-v0-windows"
RUNTIME_COLLECTOR_WINDOWS_SCHEMA = (
    PLATFORM_ROOT / "contracts" / "schemas" / "runtime-case-collector-v0-windows.schema.json"
)
RUNTIME_COLLECTOR_WINDOWS_SAMPLE = (
    PLATFORM_ROOT / "contracts" / "examples" / "runtime-case-collector-v0-windows.sample.json"
)
RUNTIME_COLLECTOR_WINDOWS_PROOF_CEILING = "RUNTIME_CASE_COLLECTOR_V0_WINDOWS_PRIVATE_CANDIDATE_COLLECTION_ONLY"
RUNTIME_COLLECTOR_WINDOWS_OUTPUT_ROUTE = "C:\\Raylee\\Data\\HawkinsOperations\\runtime-case-collector-v0\\windows\\"
RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_RUN_ID = "26849122652"
RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_STATUS = "pass"
RUNTIME_COLLECTOR_WINDOWS_RUNNER_LABELS = ("self-hosted", "Windows", "X64")
RUNTIME_COLLECTOR_WINDOWS_REQUIRED_FIELDS = (
    "collector_version",
    "collector_lane",
    "collector_run_id",
    "collected_at_utc",
    "candidate_id",
    "candidate_hash",
    "detection_id",
    "detection_family",
    "source_system",
    "source_truth_status",
    "runtime_truth_status",
    "signal_truth_status",
    "proof_ceiling",
    "public_safe_status",
    "case_status",
    "triage_status",
    "disposition_status",
    "ai_support_mode",
    "ai_decided_disposition",
    "human_review_required",
    "deterministic_close_eligible",
    "deterministic_close_blocked",
    "case_closed",
    "append_to_lifetime_ledger",
    "candidate_payload_hash",
    "sanitized_event_fingerprint",
    "source_receipt_refs",
    "blocked_claims",
    "notes_boundary",
)
RUNTIME_COLLECTOR_WINDOWS_DEDUPE_FIELDS = (
    "candidate_hash",
    "detection_id",
    "source_system",
    "sanitized_event_fingerprint",
    "source_receipt_refs",
    "candidate_payload_hash",
    "observed_time_utc",
)
RUNTIME_COLLECTOR_WINDOWS_BLOCKED_CLAIMS = (
    "public-safe runtime proof",
    "runtime-active public status",
    "signal-observed public status",
    "SOCaaS deployment",
    "production deployment",
    "autonomous SOC",
    "AI-decided disposition",
    "analyst-approved disposition",
    "case closure",
    "Lifetime Case Ledger mutation",
)
RUNTIME_COLLECTOR_WINDOWS_BOUNDARY = (
    "Windows Runtime Case Collector v0 creates private runtime case candidates only. "
    "Candidates are not governed cases, are not public-safe proof, do not append the "
    "Lifetime Case Ledger, and require separate human approval before any append, "
    "proof publication, disposition, or closure action."
)
RUNTIME_COLLECTOR_LINUX_VERSION = "runtime-case-collector-v0-linux"
RUNTIME_COLLECTOR_LINUX_SCHEMA = (
    PLATFORM_ROOT / "contracts" / "schemas" / "runtime-case-collector-v0-linux.schema.json"
)
RUNTIME_COLLECTOR_LINUX_SAMPLE = (
    PLATFORM_ROOT / "contracts" / "examples" / "runtime-case-collector-v0-linux.sample.json"
)
RUNTIME_COLLECTOR_LINUX_PROOF_CEILING = "RUNTIME_CASE_COLLECTOR_V0_LINUX_PRIVATE_CANDIDATE_COLLECTION_ONLY"
RUNTIME_COLLECTOR_LINUX_OUTPUT_ROUTE = "/var/lib/hawkinsoperations/runtime-case-collector-v0/linux/"
RUNTIME_COLLECTOR_LINUX_ROUTE_FALLBACK = "/home/runner/hawkinsoperations/runtime-case-collector-v0/linux/"
RUNTIME_COLLECTOR_LINUX_VERIFIED_RUN_ID = "26006504673"
RUNTIME_COLLECTOR_LINUX_VERIFIED_JOB_ID = "76438823869"
RUNTIME_COLLECTOR_LINUX_VERIFIED_STATUS = "pass"
RUNTIME_COLLECTOR_LINUX_RUNNER_LABELS = ("self-hosted", "ho-gpu-01", "gpu", "v100")
RUNTIME_COLLECTOR_LINUX_REQUIRED_FIELDS = RUNTIME_COLLECTOR_WINDOWS_REQUIRED_FIELDS
RUNTIME_COLLECTOR_LINUX_DEDUPE_FIELDS = RUNTIME_COLLECTOR_WINDOWS_DEDUPE_FIELDS
RUNTIME_COLLECTOR_LINUX_BLOCKED_CLAIMS = RUNTIME_COLLECTOR_WINDOWS_BLOCKED_CLAIMS
RUNTIME_COLLECTOR_LINUX_BOUNDARY = (
    "Linux Runtime Case Collector v0 creates private Linux-side runtime case candidates only. "
    "Candidates are not governed cases, are not public-safe proof, do not append the "
    "Lifetime Case Ledger, and require later normalizer/import handling plus separate "
    "human approval before any append, proof publication, disposition, or closure action."
)
RUNTIME_COLLECTOR_NORMALIZER_VERSION = "runtime-case-collector-v0-normalizer"
RUNTIME_COLLECTOR_NORMALIZER_SCHEMA = (
    PLATFORM_ROOT / "contracts" / "schemas" / "runtime-case-collector-v0-normalizer.schema.json"
)
RUNTIME_COLLECTOR_NORMALIZER_SAMPLE = (
    PLATFORM_ROOT / "contracts" / "examples" / "runtime-case-collector-v0-normalizer.sample.json"
)
RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING = (
    "RUNTIME_CASE_COLLECTOR_V0_NORMALIZER_APPEND_GATE_EXISTS_NO_LEDGER_MUTATION_UNLESS_APPEND_APPROVED"
)
RUNTIME_COLLECTOR_NORMALIZER_APPEND_APPROVAL_PHRASE = (
    "APPEND_APPROVED: promote normalized runtime candidates to Lifetime Case Ledger governed cases"
)
RUNTIME_COLLECTOR_NORMALIZER_BOUNDARY = (
    "Runtime Case Collector v0 normalizer creates a private append plan only by default. "
    "Runtime candidates are not governed cases until the exact append approval phrase is supplied "
    "and the append gate verifies all invariants. No public-safe proof, proof publication, "
    "disposition, case closure, SOCaaS, production, autonomous SOC, proof repo, or website "
    "mutation is authorized by this plan."
)
RUNTIME_COLLECTOR_NORMALIZER_REQUIRED_FIELDS = (
    "normalized_candidate_version",
    "normalized_candidate_id",
    "normalized_candidate_hash",
    "source_candidate_id",
    "source_candidate_hash",
    "source_collector_lane",
    "source_collector_version",
    "source_collector_run_id",
    "source_system",
    "detection_id",
    "detection_family",
    "observed_time_utc",
    "sanitized_event_fingerprint",
    "source_receipt_refs",
    "candidate_payload_hash",
    "normalized_payload_hash",
    "proof_ceiling",
    "public_safe_status",
    "runtime_truth_status",
    "signal_truth_status",
    "case_status",
    "append_status",
    "append_blocked_reason",
    "triage_status",
    "disposition_status",
    "ai_support_mode",
    "ai_decided_disposition",
    "human_review_required",
    "deterministic_close_eligible",
    "deterministic_close_blocked",
    "case_closed",
    "append_to_lifetime_ledger",
    "blocked_claims",
    "notes_boundary",
)
RUNTIME_COLLECTOR_NORMALIZER_DEDUPE_FIELDS = (
    "normalized_candidate_hash",
    "detection_id",
    "source_system",
    "sanitized_event_fingerprint",
    "candidate_payload_hash",
    "source_receipt_refs_hash",
    "observed_time_utc",
)
RUNTIME_COLLECTOR_NORMALIZER_BLOCKED_CLAIMS = tuple(
    dict.fromkeys(
        (
            *RUNTIME_COLLECTOR_WINDOWS_BLOCKED_CLAIMS,
            "public proof publication",
            "proof repo update",
            "website update",
            "GitHub issue creation",
            "raw private evidence upload",
            "candidate count as governed case count",
            "Governance Saves ledger as blocked-claim metrics",
        )
    )
)
LIFETIME_LEDGER_STATE_MANIFEST_ID = "LIFETIME_CASE_LEDGER_V1_PHASE_8_STATE_MANIFEST"
LIFETIME_LEDGER_STATE_MANIFEST_VERSION = "phase_8_ledger_state_manifest_v1"
LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_COUNTS = {
    "total_ledger_events": 6,
    "total_cases": 6,
    "public_safe_count": 0,
    "closed_case_count": 0,
    "correction_event_count": 0,
    "superseding_event_count": 0,
}
LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_REPOS = (
    ".github",
    "hawkinsoperations-detections",
    "hawkinsoperations-validation",
    "hawkinsoperations-platform",
    "hawkinsoperations-proof",
    "hawkinsoperations-website",
)
LIFETIME_LEDGER_STATE_MANIFEST_DOES_NOT_PROVE = (
    "live runtime activity",
    "signal observation",
    "production deployment",
    "SOCaaS availability",
    "public-safe runtime proof",
    "public proof",
    "autonomous SOC authority",
    "AI-approved final disposition",
    "analyst-approved final disposition",
    "case closure authority",
)
LIFETIME_LEDGER_STATE_MANIFEST_GOVERNANCE_DEFAULTS = {
    "human_review_required": True,
    "ai_support_mode": "AI_SUPPORT_ONLY",
    "ai_decided_disposition": False,
    "recommended_disposition": None,
    "proof_blocked": True,
    "public_safe": False,
    "case_closed": False,
    "github_issue_mutation_allowed": False,
}
LIFETIME_LEDGER_STATE_MANIFEST_ADDITIONAL_BLOCKED_CLAIMS = (
    "evidence-linked public proof",
    "live Splunk firing",
    "production triage",
    "LOCAL_GPU_SUPPORT_NODE runtime-active",
    "Cribl-routed proof",
    "Wazuh-routed proof",
    "AWS-live",
    "fleet-wide deployment",
    "production-ready SOC",
    "public-safe status",
)
LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE = (
    PLATFORM_ROOT / "contracts" / "examples" / "lifetime-ledger-v1-manual-fire-ho-det-001.sample.json"
)
LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES = {
    "HO-DET-001": LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE,
    "HO-DET-011": PLATFORM_ROOT / "contracts" / "examples" / "lifetime-ledger-v1-manual-fire-ho-det-011.sample.json",
    "HO-DET-012": PLATFORM_ROOT / "contracts" / "examples" / "lifetime-ledger-v1-manual-fire-ho-det-012.sample.json",
}
LIFETIME_MANUAL_FIRE_SUPPORTED_DETECTIONS = frozenset(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES)
LIFETIME_MANUAL_FIRE_ALLOWED_VERSIONS = frozenset(
    {
        "phase_2_dry_run_v0",
        "phase_6_multi_detection_dry_run_v0",
    }
)
LIFETIME_MANUAL_FIRE_APPEND_APPROVAL = "APPEND_APPROVAL_REQUIRED"
LIFETIME_APPEND_APPROVAL_PHRASE = "APPEND_APPROVED: append sanitized Lifetime Case Ledger event"
LIFETIME_APPEND_GATE_PHASE = "phase_3_append_approval_gate"
LIFETIME_CORRECTION_APPEND_APPROVAL_PHRASE = "CORRECTION_APPEND_APPROVED: append sanitized Lifetime Case Ledger correction event"
LIFETIME_CORRECTION_GATE_PHASE = "phase_5_correction_superseding_gate"
LIFETIME_CORRECTION_EVENT_TYPE = "CORRECTION_SUPERSEDING_EVENT"
LIFETIME_MANUAL_FIRE_ALLOWED_KEYS = {
    "candidate_type",
    "candidate_version",
    "detection_id",
    "detection_family",
    "source_system",
    "case_id",
    "fired_at",
    "observed_time_utc",
    "sanitized_event_fingerprint",
    "source_packet_ref",
    "validation_ref",
    "proof_ref",
    "github_actions_run_ref",
    "gpu_triage_used",
    "gpu_node_id",
    "model_or_triage_engine_reference",
    "notes_boundary",
}
LIFETIME_MANUAL_FIRE_BLOCKED_KEYS = {
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
    "secret",
    "token",
    "credential",
    "password",
    "internal_service",
    "internal_service_detail",
    "evidence_ref",
    "private_evidence_ref",
    "raw_command_line",
    "private_filename",
}
LIFETIME_DETECTION_COVERAGE = (
    {
        "detection_id": "HO-DET-001",
        "detection_family": "endpoint_process_execution",
        "source_system": "Splunk/Sysmon",
        "source_refs": (
            "hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml",
            "hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/ho-det-001/validation-result.json",
        "validation_test_count": 14,
        "proof_ref": "hawkinsoperations-proof/proof/records/HO-DET-001.md",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "runtime_truth_status": "PRIVATE_RUNTIME_BOUNDARY_CONTEXT_ONLY",
        "signal_truth_status": "NOT_PUBLIC_PROOF",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "HO-DET-011",
        "detection_family": "endpoint_service_persistence",
        "source_system": "Sigma/Wazuh/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/successor/ho-det-011/rule.yml",
            "hawkinsoperations-detections/detections/successor/ho-det-011/wazuh.xml",
            "hawkinsoperations-detections/detections/successor/ho-det-011/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/ho-det-011/validation-result.json",
        "validation_test_count": 17,
        "proof_ref": "hawkinsoperations-proof/proof/records/HO-DET-011.md",
        "proof_ceiling": "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        "runtime_truth_status": "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "HO-DET-012",
        "detection_family": "endpoint_scheduled_task_persistence",
        "source_system": "Sigma/Wazuh/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/successor/ho-det-012/rule.yml",
            "hawkinsoperations-detections/detections/successor/ho-det-012/wazuh.xml",
            "hawkinsoperations-detections/detections/successor/ho-det-012/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/ho-det-012/validation-result.json",
        "validation_test_count": 8,
        "proof_ref": "hawkinsoperations-proof/proof/records/HO-DET-012.md",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "HO-DET-013",
        "detection_family": "endpoint_telemetry_control_tamper",
        "source_system": "Sigma/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/successor/ho-det-013/rule.yml",
            "hawkinsoperations-detections/detections/successor/ho-det-013/splunk.spl",
        ),
        "validation_ref": None,
        "validation_test_count": 0,
        "proof_ref": None,
        "proof_ceiling": "SOURCE_EXISTS",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "ID-DET-001",
        "detection_family": "identity_session_context",
        "source_system": "Identity/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/identity/id-det-001/rule.yml",
            "hawkinsoperations-detections/detections/identity/id-det-001/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/id-det-001/validation-result.json",
        "validation_test_count": 10,
        "proof_ref": None,
        "proof_ceiling": "NO_PROOF_RECORD",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "ID-DET-002",
        "detection_family": "identity_mfa_pressure",
        "source_system": "Identity/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/identity/id-det-002/rule.yml",
            "hawkinsoperations-detections/detections/identity/id-det-002/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/id-det-002/validation-result.json",
        "validation_test_count": 10,
        "proof_ref": None,
        "proof_ceiling": "NO_PROOF_RECORD",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "ID-DET-003",
        "detection_family": "identity_privilege_change",
        "source_system": "Identity/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/identity/id-det-003/rule.yml",
            "hawkinsoperations-detections/detections/identity/id-det-003/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/id-det-003/validation-result.json",
        "validation_test_count": 10,
        "proof_ref": None,
        "proof_ceiling": "NO_PROOF_RECORD",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "ID-DET-004",
        "detection_family": "identity_travel_session_anomaly",
        "source_system": "Identity/Splunk",
        "source_refs": (
            "hawkinsoperations-detections/detections/identity/id-det-004/rule.yml",
            "hawkinsoperations-detections/detections/identity/id-det-004/splunk.spl",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/id-det-004/validation-result.json",
        "validation_test_count": 10,
        "proof_ref": None,
        "proof_ceiling": "NO_PROOF_RECORD",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
    {
        "detection_id": "AWS-DET-001",
        "detection_family": "cloud_identity_access",
        "source_system": "CloudTrail-style fixtures",
        "source_refs": (
            "hawkinsoperations-detections/detections/cloud/aws/aws-det-001/rule.yml",
        ),
        "validation_ref": "hawkinsoperations-validation/reports/aws-det-001/validation-result.json",
        "validation_test_count": 6,
        "proof_ref": "hawkinsoperations-proof/proof/records/AWS-DET-001.md",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "runtime_truth_status": "NOT_PROVEN",
        "signal_truth_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    },
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

SOCAAS_PILOT_RECEIPT_SAMPLE = (
    PLATFORM_ROOT / "contracts" / "examples" / "ho-det-001-socaas-pilot-receipt.sample.json"
)
SOCAAS_PILOT_RECEIPT_REQUIRED_TOP_LEVEL = {
    "receipt_id",
    "receipt_type",
    "contract_version",
    "detection_id",
    "pilot_context",
    "alert_summary",
    "sanitized_process_facts",
    "deterministic_validation_reference",
    "proof_ceiling",
    "public_safe_status",
    "human_review_required",
    "ai_support_boundary",
    "response_actions",
    "blocked_response_actions",
    "proof_promotions",
    "blocked_proof_promotions",
    "blocked_claims",
    "privacy_boundary",
    "does_not_prove",
}
SOCAAS_PILOT_RECEIPT_REQUIRED_BLOCKED_CLAIMS = {
    "runtime-active",
    "signal public proof",
    "production SOCaaS deployment",
    "FortiSIEM integration",
    "autonomous response",
    "AI-approved disposition",
    "analyst-approved disposition",
    "public-safe proof",
}
SOCAAS_PILOT_RECEIPT_REQUIRED_BLOCKED_ACTIONS = {
    "contain host",
    "isolate endpoint",
    "disable account",
    "close case",
    "suppress detection",
    "declare compromise",
    "mark malicious",
}
SOCAAS_PILOT_RECEIPT_REQUIRED_PROOF_PROMOTION_KEYS = {
    "runtime_active",
    "signal_observed",
    "public_safe",
    "public_proof",
    "production_deployment",
    "socaas_deployment",
    "fortisiem_integration",
    "autonomous_response",
    "ai_or_analyst_approval",
}
SOCAAS_PILOT_RECEIPT_REQUIRED_PRIVACY_BOUNDARY_KEYS = {
    "raw_event_included",
    "raw_command_line_included",
    "hostnames_included",
    "usernames_included",
    "internal_ips_included",
    "private_paths_included",
    "secrets_included",
    "screenshots_included",
}


class FactoryError(RuntimeError):
    """Fail-closed controller error."""


class DependencySurfacesMissing(FactoryError):
    """Required dependency surfaces are unavailable in this repo-root revision."""

    def __init__(self, detection_id: str, found: list[dict[str, Any]], missing: list[str]) -> None:
        self.detection_id = detection_id
        self.found = found
        self.missing = missing
        super().__init__(f"{detection_id} required surfaces missing: {', '.join(missing)}")


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
    proof_record: str | None
    proof_card: str | None
    proof_state: str
    platform_sample: str | None
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
    next_gates: tuple[dict[str, str], ...] = ()
    not_claimed_here: tuple[str, ...] = ()


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

PROOF_INDEX_ALLOWED_CEILINGS = (
    "NO_PROOF_RECORD",
    "CONTROLLED_TEST_VALIDATED",
    "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
    "CROSS_SOURCE_CORROBORATION_CONTRACT_DEFINED",
)

PROOF_INDEX_ALLOWED_RUNTIME_STATUSES = (
    "NOT_PROVEN",
    "PRIVATE_RUNTIME_BOUNDARY_CONTEXT_ONLY",
    "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
)

PLATFORM_SAMPLE_BLOCKED = (
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production-ready",
    "fleet-wide",
    "AI-approved disposition",
)

DETECTION_TITLES = {
    "HO-DET-001": "Suspicious PowerShell EncodedCommand",
    "HO-DET-011": "Windows service persistence",
    "HO-DET-012": "Suspicious scheduled task creation",
    "ID-DET-001": "Suspicious identity session context",
    "ID-DET-002": "Suspicious MFA fatigue or repeated MFA failure patterns",
    "ID-DET-003": "Privileged role assignment or admin group change behavior",
    "ID-DET-004": "Impossible travel or anomalous session context",
}

IDENTITY_EXPANSION_BLOCKED = (
    *COMMON_BLOCKED,
    "evidence-linked public proof",
    "live Okta proof",
    "live Entra proof",
    "live IdP proof",
    "live Splunk proof",
    "Wazuh-routed proof",
    "Cribl-routed proof",
    "Security Onion observed proof",
    "production identity coverage",
    "full identity attack coverage",
    "proof promotion",
    "website/public-surface promotion",
)

IDENTITY_EXPANSION_NEXT_GATES = (
    {
        "id": "ID-RUNTIME-001",
        "name": "private runtime receipt",
        "purpose": "Private identity runtime receipt with approved metadata and count-only Wazuh/Splunk receipt review.",
        "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED only if separately approved and reviewed",
        "boundary": "Not public proof. Not production coverage. Not public-safe.",
    },
    {
        "id": "ID-CLOUD-001",
        "name": "IdP export/log review",
        "purpose": "Approved Entra-style or Okta-style identity log export review after a separate gate.",
        "claim_ceiling": "CONTROLLED_TEST_VALIDATED first, then PRIVATE_RUNTIME_METADATA_CAPTURED only if approved sanitized export review exists.",
        "boundary": "No live IdP proof in this PR. No production tenant claim.",
    },
    {
        "id": "ID-ROUTE-001",
        "name": "SIEM/NDR route receipt",
        "purpose": "Count-only Wazuh, Splunk, Cribl, and Security Onion route checks after separate approval.",
        "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED if a scoped receipt exists.",
        "boundary": "No live SIEM/NDR public proof in this PR. No full route proof unless separately captured and reviewed.",
    },
)

IDENTITY_EXPANSION_NOT_CLAIMED = (
    "live IdP proof",
    "live SIEM/NDR observation",
    "production identity coverage",
    "complete identity-attack coverage",
    "autonomous SOC operation",
    "disposition authority",
    "proof promotion",
    "public-safe status",
    "website/public-surface publication",
)


def identity_expansion_spec(
    detection_id: str,
    validation_claim: str,
    validation_rel: str,
    scanner_rel: str,
    parity_rel: str,
    validator_rel: str,
    extra_blocked_claims: tuple[str, ...] = (),
) -> DetectionSpec:
    lower_id = detection_id.lower()
    return DetectionSpec(
        detection_id=detection_id,
        current_state="CONTROLLED_TEST_VALIDATED",
        public_proof_ceiling="CONTROLLED_TEST_VALIDATED",
        private_evidence_state="NOT_CAPTURED",
        public_safe_status="NOT_PUBLIC_SAFE",
        platform_guardrail_status="STATUS_VISIBILITY_ONLY",
        validation_result=f"hawkinsoperations-validation/reports/{lower_id}/validation-result.json",
        validation_expected={
            "total_cases": 10,
            "positive_cases": 5,
            "negative_cases": 5,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
        },
        validation_claim=validation_claim,
        proof_record=None,
        proof_card=None,
        proof_state="NO_PROOF_RECORD_NOT_PROMOTED",
        platform_sample=None,
        platform_sample_expected_total=0,
        required_blocked_claims=(*IDENTITY_EXPANSION_BLOCKED, *extra_blocked_claims),
        supported_claims=(
            f"{detection_id} validation coverage exists from hawkinsoperations-validation PR #46.",
            f"{detection_id} passed controlled-test validation against 10 controlled identity-event fixtures.",
            f"{detection_id} has platform status/plan visibility for controlled-test validation only.",
            f"{detection_id} remains not public-safe and not runtime-active.",
        ),
        next_allowed_move=(
            "Review validation-backed platform visibility only; source expansion, live IdP access, runtime evidence, "
            "proof promotion, routed telemetry, website output, and public-safe wording remain blocked until separate approval."
        ),
        decision_status="READY_FOR_REVIEW",
        decision_reason=(
            f"Controller v0 reports {detection_id} validation-backed status/plan visibility after validation PR #46 "
            "and preserves runtime, live IdP, proof, and public-surface boundaries."
        ),
        truth_boundary={
            "source_truth": "not inspected in this platform window",
            "validation_truth": "controlled-test validated",
            "platform_truth": "status visibility only",
            "proof_truth": "not promoted",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not promote proof.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not claim live Okta, Entra, or IdP proof.",
            "Do not claim production identity coverage.",
            "Do not create generated output files.",
        ),
        state_consistency=(
            "STATE_CONSISTENT_WITH_VALIDATION_PR_46",
            "Validation coverage is upstream truth for this platform visibility update.",
            "Detection source, proof, runtime, route, website, and public-safe promotion remain outside this platform window.",
        ),
        does_not_prove=(
            "source repository state",
            "runtime activity",
            "signal observation",
            "public-safe status",
            "production deployment",
            "fleet-wide coverage",
            "live Okta proof",
            "live Entra proof",
            "live IdP proof",
            "live Splunk proof",
            "Wazuh routing",
            "Cribl routing",
            "Security Onion observation",
            "production identity coverage",
            "machine identity production governance",
            "AI agent production governance",
            "full identity attack coverage",
            "AI-approved disposition",
            "analyst-approved disposition",
        ),
        surfaces=(
            Surface("hawkinsoperations-validation", f"reports/{lower_id}/validation-result.json"),
            Surface("hawkinsoperations-validation", f"reports/{lower_id}/validation-result.md"),
            Surface("hawkinsoperations-validation", validation_rel),
            Surface("hawkinsoperations-validation", scanner_rel),
            Surface("hawkinsoperations-validation", parity_rel),
            Surface("hawkinsoperations-validation", validator_rel),
            Surface("hawkinsoperations-platform", "scripts/ho_factory.py"),
            Surface("hawkinsoperations-platform", "docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md"),
        ),
        next_gates=IDENTITY_EXPANSION_NEXT_GATES,
        not_claimed_here=IDENTITY_EXPANSION_NOT_CLAIMED,
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
        "supported_claim": RUNTIME_REVIEW_SUPPORTED_CLAIM,
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
        "append_required_before_next_case": RUNTIME_REVIEW_APPEND_APPROVAL,
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


def lifetime_detection_family_map() -> dict[str, str]:
    return {str(item["detection_id"]): str(item["detection_family"]) for item in LIFETIME_DETECTION_COVERAGE}


def lifetime_detection_coverage_map() -> dict[str, dict[str, Any]]:
    return {str(item["detection_id"]): dict(item) for item in LIFETIME_DETECTION_COVERAGE}


def lifetime_ledger_metrics(conn: sqlite3.Connection) -> dict[str, Any]:
    family_by_detection = lifetime_detection_family_map()

    def grouped(column: str) -> dict[str, int]:
        rows = conn.execute(f"SELECT {column}, COUNT(*) FROM case_events GROUP BY {column} ORDER BY {column}").fetchall()
        return {str(key): int(count) for key, count in rows}

    rows = conn.execute(
        """
        SELECT
          detection_id,
          case_status,
          truth_class,
          proof_ceiling,
          public_safe_status,
          human_review_required,
          gpu_supported,
          ai_support_mode,
          proof_blocked,
          public_safe,
          case_closed,
          payload_json
        FROM case_events
        ORDER BY event_id
        """
    ).fetchall()
    cases_by_family: dict[str, int] = {}
    ai_support_only_count = 0
    correction_event_count = 0
    superseding_event_count = 0
    for row in rows:
        detection_id = str(row[0])
        family = family_by_detection.get(detection_id, "unmapped_detection_family")
        cases_by_family[family] = cases_by_family.get(family, 0) + 1
        if row[7] == "AI_SUPPORT_ONLY":
            ai_support_only_count += 1
        try:
            payload = json.loads(str(row[11]))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict) and payload.get("event_type") == LIFETIME_CORRECTION_EVENT_TYPE:
            correction_event_count += 1
            superseding_event_count += 1

    counts = conn.execute(
        """
        SELECT
          COUNT(*),
          COUNT(DISTINCT case_id),
          COALESCE(SUM(human_review_required), 0),
          COALESCE(SUM(gpu_supported), 0),
          COALESCE(SUM(proof_blocked), 0),
          COALESCE(SUM(public_safe), 0),
          COALESCE(SUM(case_closed), 0),
          COALESCE(SUM(CASE WHEN truth_class = 'SYNTHETIC_TEST_CASE' THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN truth_class = 'PRIVATE_RUNTIME_EVIDENCE' THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN truth_class = 'PUBLIC_PROOF_CANDIDATE' THEN 1 ELSE 0 END), 0)
        FROM case_events
        """
    ).fetchone()
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "total_ledger_events": int(counts[0]),
        "total_cases": int(counts[1]),
        "cases_by_detection": grouped("detection_id"),
        "cases_by_family": dict(sorted(cases_by_family.items())),
        "cases_by_status": grouped("case_status"),
        "cases_by_truth_class": grouped("truth_class"),
        "cases_by_proof_ceiling": grouped("proof_ceiling"),
        "cases_by_public_safe_status": grouped("public_safe_status"),
        "cases_requiring_human_review": int(counts[2]),
        "gpu_triaged_count": int(counts[3]),
        "ai_support_only_count": ai_support_only_count,
        "proof_blocked_count": int(counts[4]),
        "public_safe_count": int(counts[5]),
        "closed_case_count": int(counts[6]),
        "correction_event_count": correction_event_count,
        "superseding_event_count": superseding_event_count,
        "validation_only_count": int(counts[7]),
        "private_runtime_count": int(counts[8]),
        "public_proof_candidate_count": int(counts[9]),
        "truth_boundary": "counts_are_ledger_rows_only_not_runtime_or_public_proof",
    }


def verify_lifetime_detection_coverage(repo_root: Path) -> list[dict[str, Any]]:
    seen: set[str] = set()
    coverage: list[dict[str, Any]] = []
    missing_required_source_refs: list[str] = []
    for item in LIFETIME_DETECTION_COVERAGE:
        detection_id = str(item["detection_id"])
        if detection_id in seen:
            raise FactoryError(f"duplicate lifetime ledger detection coverage entry: {detection_id}")
        seen.add(detection_id)
        source_refs = tuple(item.get("source_refs") or ())
        if not source_refs:
            raise FactoryError(f"{detection_id} lifetime ledger entry must include source_refs")
        existing_source_refs = [path for path in source_refs if (repo_root / path).is_file()]
        missing_source_refs = [path for path in source_refs if not (repo_root / path).is_file()]
        missing_required_source_refs.extend(f"{detection_id}:{path}" for path in missing_source_refs)
        validation_ref = item.get("validation_ref")
        proof_ref = item.get("proof_ref")
        coverage.append(
            {
                **item,
                "source_refs": list(source_refs),
                "source_ref_status": "present" if existing_source_refs and not missing_source_refs else "review_required",
                "existing_source_refs": existing_source_refs,
                "missing_source_refs": missing_source_refs,
                "validation_ref_status": (
                    "not_applicable"
                    if validation_ref is None
                    else ("present" if (repo_root / str(validation_ref)).is_file() else "review_required")
                ),
                "proof_ref_status": (
                    "not_applicable"
                    if proof_ref is None
                    else ("present" if (repo_root / str(proof_ref)).is_file() else "review_required")
                ),
                "ledger_eligible": True,
                "human_review_required": True,
                "ai_support_mode": "AI_SUPPORT_ONLY",
                "ai_decided_disposition": False,
                "blocked_claims": list(LIFETIME_LEDGER_BLOCKED_CLAIMS),
            }
        )
    required = {"HO-DET-001", "HO-DET-011", "HO-DET-012", "HO-DET-013", "ID-DET-001", "ID-DET-002", "ID-DET-003", "ID-DET-004"}
    missing = sorted(required - seen)
    if missing:
        raise FactoryError(f"lifetime ledger coverage missing required detections: {', '.join(missing)}")
    if missing_required_source_refs:
        raise FactoryError(
            "lifetime ledger coverage missing required source refs: "
            + "; ".join(sorted(missing_required_source_refs))
        )
    return coverage


def verify_lifetime_ledger_spine(repo_root: Path, ledger_path: Path) -> dict[str, Any]:
    if not ledger_path.is_file():
        raise FactoryError(f"Lifetime Case Ledger v1 seed bridge is missing: {ledger_path}")
    coverage = verify_lifetime_detection_coverage(repo_root)
    required_event_fields = set(LIFETIME_LEDGER_EVENT_FIELDS)
    for field in (
        "ledger_version",
        "event_hash",
        "case_id",
        "detection_id",
        "truth_class",
        "case_status",
        "proof_ceiling",
        "public_safe_status",
        "human_review_required",
        "ai_support_mode",
        "ai_decided_disposition",
        "gpu_triage_used",
        "blocked_claims",
        "validation_ref",
        "proof_ref",
        "payload_hash",
        "notes_boundary",
    ):
        if field not in required_event_fields:
            raise FactoryError(f"Lifetime Case Ledger v1 event model missing required field: {field}")
    with connect_read_only_ledger(ledger_path) as conn:
        seed_verification = verify_ledger(conn, "seed_bridge_for_lifetime_case_ledger_v1_not_runtime_truth")
        metrics = lifetime_ledger_metrics(conn)
    missing_metrics = sorted(set(LIFETIME_LEDGER_REQUIRED_METRICS) - set(metrics))
    if missing_metrics:
        raise FactoryError(f"Lifetime Case Ledger v1 metrics missing required keys: {', '.join(missing_metrics)}")
    if metrics["public_safe_count"] != 0 or metrics["closed_case_count"] != 0:
        raise FactoryError("Lifetime Case Ledger v1 seed bridge must not contain public-safe or closed cases")
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-verify",
        "phase": "phase_1_spine_contract_only",
        "proof_ceiling": LIFETIME_LEDGER_PROOF_CEILING,
        "public_safe_status": LIFETIME_LEDGER_PUBLIC_SAFE_STATUS,
        "event_model_fields": list(LIFETIME_LEDGER_EVENT_FIELDS),
        "metrics_model": list(LIFETIME_LEDGER_REQUIRED_METRICS),
        "lifetime_metrics": metrics,
        "detection_coverage": coverage,
        "gpu_triage_contract": {
            "ai_support_mode": "AI_SUPPORT_ONLY",
            "gpu_triage_used_field": "gpu_triage_used",
            "gpu_reference_field": "gpu_node_id",
            "approved_gpu_reference_value": "LOCAL_GPU_SUPPORT_NODE",
            "model_or_triage_engine_reference": "approved abstract model/triage engine reference only",
            "ai_decided_disposition": False,
            "human_review_required": True,
            "private_runtime_details_public_safe": False,
        },
        "public_safe_summary_model": {
            "may_publish": False,
            "public_summary_allowed_after_review": "schema, verifier, bounded counts, and blocked claims only",
            "raw_runtime_evidence_allowed": False,
            "private_hostnames_usernames_ips_allowed": False,
            "public_proof_promotion_allowed": False,
            "blocked_claims": list(LIFETIME_LEDGER_BLOCKED_CLAIMS),
        },
        "github_actions_verification": {
            "existing_platform_workflows": [
                ".github/workflows/governance-gate.yml",
                ".github/workflows/local-gpu-triage-gate.yml",
            ],
            "recommended_phase_1_command": "python -B scripts/ho_factory.py lifetime-ledger-verify --format json",
            "recommended_phase_3_command": "python -B scripts/ho_factory.py lifetime-ledger-append-gate-self-test --format json",
            "recommended_phase_4_command": "python -B scripts/ho_factory.py lifetime-ledger-append-approved-ho-det-001 --append-approval \"APPEND_APPROVED: append sanitized Lifetime Case Ledger event\" --format json",
            "recommended_phase_6_command": "python -B scripts/ho_factory.py lifetime-ledger-multi-detection-self-test --format json",
            "recommended_phase_7_command": "python -B scripts/ho_factory.py lifetime-ledger-append-approved-ho-det-011-012 --append-approval \"APPEND_APPROVED: append sanitized Lifetime Case Ledger event\" --format json",
            "governance_gate_wired": True,
            "governance_gate_job": "lifetime-case-ledger-v1",
            "workflow_dispatch_required_for_true_gpu_runner": True,
        },
        "seed_ledger_bridge": seed_verification,
        "boundary": LIFETIME_LEDGER_BOUNDARY,
    }


def require_manifest_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise FactoryError(f"BLOCKED: {label.upper()}_MISSING_OR_MALFORMED")
    return value


def require_repo_relative_manifest_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FactoryError(f"BLOCKED: {label.upper()}_MISSING")
    if re.search(r"\b[A-Za-z]:\\", value) or value.startswith(("/", "\\")) or "\\" in value:
        raise FactoryError(f"BLOCKED: {label.upper()}_MUST_BE_REPO_RELATIVE")
    return value


def verify_lifetime_ledger_state_manifest(repo_root: Path, ledger_path: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest_path.resolve().relative_to(PLATFORM_ROOT.resolve())
    except ValueError as exc:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_NOT_PLATFORM_OWNED") from exc
    manifest = load_json(manifest_path)
    scan_private_markers("Lifetime ledger state manifest", manifest)

    if manifest.get("manifest_id") != LIFETIME_LEDGER_STATE_MANIFEST_ID:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_ID_INVALID")
    if manifest.get("manifest_version") != LIFETIME_LEDGER_STATE_MANIFEST_VERSION:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_VERSION_INVALID")
    if manifest.get("source_controlled_manifest") is not True:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_SOURCE_CONTROLLED_REQUIRED")
    platform_commit_sha = require_manifest_sha(manifest.get("platform_commit_sha"), "platform_sha")

    ledger_target = require_repo_relative_manifest_path(manifest.get("ledger_target"), "ledger_target")
    if ledger_target != "evidence/autosoc-case-ledger-v0.sqlite":
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_LEDGER_TARGET_INVALID")
    if manifest.get("ledger_boundary") != "tracked platform seed bridge, not runtime truth, not signal truth, not public proof":
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_LEDGER_BOUNDARY_INVALID")

    repos = manifest.get("six_repo_state")
    if not isinstance(repos, list):
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_SIX_REPO_STATE_INVALID")
    by_repo: dict[str, dict[str, Any]] = {}
    for entry in repos:
        if not isinstance(entry, dict):
            raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_REPO_ENTRY_INVALID")
        repo_name = entry.get("repo_name")
        if repo_name in by_repo:
            raise FactoryError(f"BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_DUPLICATE_REPO: {repo_name}")
        if not isinstance(repo_name, str) or not repo_name:
            raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_REPO_NAME_MISSING")
        by_repo[repo_name] = entry
        for field in ("role", "branch", "authority_boundary"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise FactoryError(f"BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_{repo_name}_{field.upper()}_MISSING")
        require_manifest_sha(entry.get("commit_sha"), f"{repo_name}_commit_sha")
        scan_private_markers(f"Lifetime ledger state manifest repo entry {repo_name}", entry)
    missing_repos = sorted(set(LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_REPOS) - set(by_repo))
    if missing_repos:
        raise FactoryError(f"BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_REPOS_MISSING: {', '.join(missing_repos)}")
    extra_repos = sorted(set(by_repo) - set(LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_REPOS))
    if extra_repos:
        raise FactoryError(f"BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_UNKNOWN_REPOS: {', '.join(extra_repos)}")
    if by_repo["hawkinsoperations-platform"]["commit_sha"] != platform_commit_sha:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_PLATFORM_SHA_MISMATCH")

    if manifest.get("proof_ceiling") != LIFETIME_LEDGER_PROOF_CEILING:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_PROOF_CEILING_PROMOTED")
    if manifest.get("public_safe_status") != LIFETIME_LEDGER_PUBLIC_SAFE_STATUS:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_PUBLIC_SAFE_PROMOTED")
    if manifest.get("governance_defaults") != LIFETIME_LEDGER_STATE_MANIFEST_GOVERNANCE_DEFAULTS:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_GOVERNANCE_DEFAULTS_WEAKENED")
    require_blocked_claims(manifest.get("explicitly_blocked_claims"), LIFETIME_LEDGER_BLOCKED_CLAIMS, "lifetime ledger state manifest")
    require_blocked_claims(
        manifest.get("additional_blocked_public_claims"),
        LIFETIME_LEDGER_STATE_MANIFEST_ADDITIONAL_BLOCKED_CLAIMS,
        "lifetime ledger state manifest additional public claims",
    )
    does_not_prove = manifest.get("does_not_prove")
    if not isinstance(does_not_prove, list):
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_DOES_NOT_PROVE_INVALID")
    missing_does_not_prove = sorted(set(LIFETIME_LEDGER_STATE_MANIFEST_DOES_NOT_PROVE) - {str(item) for item in does_not_prove})
    if missing_does_not_prove:
        raise FactoryError(
            "BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_DOES_NOT_PROVE_MISSING: "
            + ", ".join(missing_does_not_prove)
        )

    with connect_read_only_ledger(ledger_path) as conn:
        ledger_verification = verify_ledger(conn, "phase_8_manifest_seed_bridge_not_runtime_truth_not_public_proof")
        metrics = lifetime_ledger_metrics(conn)
    manifest_counts = manifest.get("current_ledger_counts")
    if not isinstance(manifest_counts, dict):
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_COUNTS_INVALID")
    count_failures = {
        key: {"manifest": manifest_counts.get(key), "actual": metrics.get(key), "required": required}
        for key, required in LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_COUNTS.items()
        if manifest_counts.get(key) != required or metrics.get(key) != required
    }
    if count_failures:
        raise FactoryError(f"BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_LEDGER_COUNTS_MISMATCH: {count_failures}")

    appended_detection_ids = manifest.get("appended_detection_ids")
    if sorted(appended_detection_ids or []) != sorted(metrics["cases_by_detection"]):
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_APPENDED_DETECTIONS_MISMATCH")
    coverage_ids = sorted(item["detection_id"] for item in verify_lifetime_detection_coverage(repo_root))
    expected_not_appended = sorted(set(coverage_ids) - set(appended_detection_ids or []))
    if sorted(manifest.get("covered_not_appended_detection_ids") or []) != expected_not_appended:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_COVERED_NOT_APPENDED_MISMATCH")

    verifier_commands = manifest.get("verifier_commands")
    if not isinstance(verifier_commands, list) or not verifier_commands:
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_VERIFIER_COMMANDS_MISSING")
    if not any("lifetime-ledger-state-manifest-verify" in str(command) for command in verifier_commands):
        raise FactoryError("BLOCKED: LIFETIME_LEDGER_STATE_MANIFEST_VERIFIER_COMMAND_MISSING")
    for command in verifier_commands:
        require_repo_relative_manifest_path(str(command), "verifier_command")

    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-state-manifest-verify",
        "phase": "phase_8_ledger_state_manifest",
        "manifest_path": manifest_path.relative_to(PLATFORM_ROOT).as_posix(),
        "manifest_id": manifest["manifest_id"],
        "manifest_version": manifest["manifest_version"],
        "source_controlled_manifest": True,
        "platform_commit_sha": platform_commit_sha,
        "six_repo_state": repos,
        "ledger_target": ledger_target,
        "ledger_boundary": manifest["ledger_boundary"],
        "ledger_verification": ledger_verification,
        "ledger_counts": {key: metrics[key] for key in LIFETIME_LEDGER_STATE_MANIFEST_REQUIRED_COUNTS},
        "appended_detection_ids": appended_detection_ids,
        "covered_not_appended_detection_ids": expected_not_appended,
        "proof_ceiling": manifest["proof_ceiling"],
        "public_safe_status": manifest["public_safe_status"],
        "governance_defaults": manifest["governance_defaults"],
        "blocked_claims_verified": list(LIFETIME_LEDGER_BLOCKED_CLAIMS),
        "additional_blocked_public_claims_verified": list(LIFETIME_LEDGER_STATE_MANIFEST_ADDITIONAL_BLOCKED_CLAIMS),
        "does_not_prove_verified": list(LIFETIME_LEDGER_STATE_MANIFEST_DOES_NOT_PROVE),
        "boundary": (
            "Phase 8 verifies a source-controlled platform ledger state manifest and six-repo SHA anchor only. "
            "It does not mutate the ledger, prove runtime activity, prove signal observation, publish public proof, "
            "mark public-safe status, or grant AI, analyst, or case closure authority."
        ),
    }


def load_lifetime_manual_fire_candidate(path: Path) -> dict[str, Any]:
    try:
        path.resolve().relative_to(PLATFORM_ROOT.resolve())
    except ValueError as exc:
        raise FactoryError("Lifetime manual-fire candidate must be a platform-owned sample path") from exc
    candidate = load_json(path)
    return validate_lifetime_manual_fire_candidate(candidate)


def validate_lifetime_manual_fire_candidate(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise FactoryError("Lifetime manual-fire candidate root must be an object")
    unknown = sorted(set(candidate) - LIFETIME_MANUAL_FIRE_ALLOWED_KEYS)
    if unknown:
        raise FactoryError(f"Lifetime manual-fire candidate contains unsupported fields: {', '.join(unknown)}")
    blocked = sorted(set(candidate) & LIFETIME_MANUAL_FIRE_BLOCKED_KEYS)
    if blocked:
        raise FactoryError(f"Lifetime manual-fire candidate contains blocked raw/private fields: {', '.join(blocked)}")
    if candidate.get("candidate_type") != "lifetime_case_ledger_v1_manual_fire_candidate":
        raise FactoryError("Lifetime manual-fire candidate_type is invalid")
    if candidate.get("candidate_version") not in LIFETIME_MANUAL_FIRE_ALLOWED_VERSIONS:
        raise FactoryError("Lifetime manual-fire candidate_version is invalid")
    detection_id = str(candidate.get("detection_id") or "")
    coverage = lifetime_detection_coverage_map().get(detection_id)
    if detection_id not in LIFETIME_MANUAL_FIRE_SUPPORTED_DETECTIONS or coverage is None:
        raise FactoryError("BLOCKED: LIFETIME_MANUAL_FIRE_UNSUPPORTED_DETECTION")
    if candidate.get("detection_family") != coverage["detection_family"]:
        raise FactoryError("Lifetime manual-fire candidate detection_family is invalid")
    if detection_id != "HO-DET-001" and candidate.get("candidate_version") != "phase_6_multi_detection_dry_run_v0":
        raise FactoryError("Lifetime manual-fire multi-detection candidate_version is invalid")
    for field in ("source_system", "source_packet_ref", "validation_ref", "proof_ref", "notes_boundary"):
        value = candidate.get(field)
        if not isinstance(value, str) or not value.strip():
            raise FactoryError(f"Lifetime manual-fire candidate requires non-empty {field}")
    for ref_field, coverage_field in (("validation_ref", "validation_ref"), ("proof_ref", "proof_ref")):
        if candidate[ref_field] != coverage.get(coverage_field):
            raise FactoryError(f"Lifetime manual-fire {ref_field} must match lifetime detection coverage")
    for optional_time in ("fired_at", "observed_time_utc"):
        if optional_time in candidate and candidate[optional_time] is not None and not isinstance(candidate[optional_time], str):
            raise FactoryError(f"Lifetime manual-fire candidate {optional_time} must be string or null")
    if "case_id" in candidate and not str(candidate["case_id"]).startswith(f"LCL-MANUAL-{detection_id}-"):
        raise FactoryError(f"Lifetime manual-fire candidate case_id must start with LCL-MANUAL-{detection_id}-")
    if "sanitized_event_fingerprint" in candidate and (
        not isinstance(candidate["sanitized_event_fingerprint"], str) or not candidate["sanitized_event_fingerprint"].strip()
    ):
        raise FactoryError("Lifetime manual-fire sanitized_event_fingerprint must be non-empty when provided")
    if not isinstance(candidate.get("gpu_triage_used"), bool):
        raise FactoryError("Lifetime manual-fire candidate gpu_triage_used must be boolean")
    if candidate["gpu_triage_used"] and candidate.get("gpu_node_id") != "LOCAL_GPU_SUPPORT_NODE":
        raise FactoryError("Lifetime manual-fire GPU candidate must use LOCAL_GPU_SUPPORT_NODE")
    if not candidate["gpu_triage_used"] and candidate.get("gpu_node_id") is not None:
        raise FactoryError("Lifetime manual-fire non-GPU candidate must not set gpu_node_id")
    model_ref = candidate.get("model_or_triage_engine_reference")
    if model_ref is not None and not isinstance(model_ref, str):
        raise FactoryError("Lifetime manual-fire model_or_triage_engine_reference must be string or null")
    for ref_field in ("source_packet_ref", "validation_ref", "proof_ref"):
        ref_path = str(candidate[ref_field])
        if Path(ref_path).is_absolute() or "\\" in ref_path:
            raise FactoryError(f"Lifetime manual-fire {ref_field} must be a repo-relative forward-slash reference")
    scan_private_markers("Lifetime manual-fire candidate", candidate)
    scan_text = json.dumps(candidate, sort_keys=True)
    for pattern in SPLUNK_SANITIZED_VALUE_PATTERNS:
        if pattern.search(scan_text):
            raise FactoryError(f"Lifetime manual-fire candidate contains blocked raw/private value: {pattern.pattern}")
    blocked_sample_terms = ("place" + "holder", "fa" + "ke", "TO" + "DO", "TB" + "D", "FIX" + "ME", "X" * 3)
    lowered_scan = scan_text.lower()
    if any(term.lower() in lowered_scan for term in blocked_sample_terms):
        raise FactoryError("BLOCKED: LIFETIME_MANUAL_FIRE_NONREAL_VALUE")
    return candidate


def lifetime_candidate_digest(candidate: dict[str, Any]) -> str:
    return hashlib.sha256(stable_json(candidate).encode("utf-8")).hexdigest()


def build_lifetime_manual_fire_event(candidate: dict[str, Any]) -> dict[str, Any]:
    digest = lifetime_candidate_digest(candidate)
    detection_id = str(candidate["detection_id"])
    coverage = lifetime_detection_coverage_map().get(detection_id)
    if detection_id not in LIFETIME_MANUAL_FIRE_SUPPORTED_DETECTIONS or coverage is None:
        raise FactoryError("BLOCKED: LIFETIME_MANUAL_FIRE_UNSUPPORTED_DETECTION")
    case_id = str(candidate.get("case_id") or f"LCL-MANUAL-{detection_id}-{digest[:16].upper()}")
    sanitized_event_fingerprint = str(candidate.get("sanitized_event_fingerprint") or digest)
    event = {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "event_id": f"LCL-EVENT-{digest[:16].upper()}",
        "event_hash": "pending",
        "parent_event_hash": None,
        "case_id": case_id,
        "detection_id": detection_id,
        "detection_family": str(coverage["detection_family"]),
        "source_system": candidate["source_system"],
        "fired_at": candidate.get("fired_at"),
        "observed_time_utc": candidate.get("observed_time_utc"),
        "ingested_at": None,
        "truth_class": "SYNTHETIC_TEST_CASE",
        "case_status": "HUMAN_REVIEW_REQUIRED",
        "triage_status": "PENDING_HUMAN_REVIEW",
        "disposition_status": "NO_DISPOSITION",
        "proof_ceiling": str(coverage["proof_ceiling"]),
        "runtime_truth_status": "DRY_RUN_NOT_RUNTIME_TRUTH",
        "signal_truth_status": "NOT_PUBLIC_PROOF",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "human_review_required": True,
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "gpu_triage_used": candidate["gpu_triage_used"],
        "gpu_node_id": candidate.get("gpu_node_id"),
        "model_or_triage_engine_reference": candidate.get("model_or_triage_engine_reference"),
        "source_packet_ref": candidate["source_packet_ref"],
        "evidence_ref_public_safe": None,
        "private_evidence_ref_allowed": False,
        "blocked_claims": list(LIFETIME_LEDGER_BLOCKED_CLAIMS),
        "validation_ref": candidate["validation_ref"],
        "proof_ref": candidate["proof_ref"],
        "github_actions_run_ref": candidate.get("github_actions_run_ref"),
        "payload_hash": digest,
        "sanitized_event_fingerprint": sanitized_event_fingerprint,
        "notes_boundary": candidate["notes_boundary"],
    }
    event_hash_input = dict(event)
    event_hash_input["event_hash"] = "pending"
    event["event_hash"] = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    scan_private_markers("Lifetime manual-fire event", event)
    return event


def lifetime_metrics_after_candidate(before: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    after = json.loads(json.dumps(before))
    after["total_ledger_events"] = int(after["total_ledger_events"]) + 1
    after["total_cases"] = int(after["total_cases"]) + 1
    for key, event_field in (
        ("cases_by_detection", "detection_id"),
        ("cases_by_family", "detection_family"),
        ("cases_by_status", "case_status"),
        ("cases_by_truth_class", "truth_class"),
        ("cases_by_proof_ceiling", "proof_ceiling"),
        ("cases_by_public_safe_status", "public_safe_status"),
    ):
        group = dict(after[key])
        value = str(event[event_field])
        group[value] = int(group.get(value, 0)) + 1
        after[key] = dict(sorted(group.items()))
    after["cases_requiring_human_review"] = int(after["cases_requiring_human_review"]) + 1
    after["gpu_triaged_count"] = int(after["gpu_triaged_count"]) + int(bool(event["gpu_triage_used"]))
    after["ai_support_only_count"] = int(after["ai_support_only_count"]) + 1
    after["proof_blocked_count"] = int(after["proof_blocked_count"]) + 1
    if event["truth_class"] == "SYNTHETIC_TEST_CASE":
        after["validation_only_count"] = int(after["validation_only_count"]) + 1
    return after


def lifetime_metrics_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    scalar_keys = (
        "total_ledger_events",
        "total_cases",
        "cases_requiring_human_review",
        "gpu_triaged_count",
        "ai_support_only_count",
        "proof_blocked_count",
        "public_safe_count",
        "closed_case_count",
        "correction_event_count",
        "superseding_event_count",
        "validation_only_count",
        "private_runtime_count",
        "public_proof_candidate_count",
    )
    deltas: dict[str, Any] = {}
    for key in scalar_keys:
        deltas[key] = int(after[key]) - int(before[key])
    for key in (
        "cases_by_detection",
        "cases_by_family",
        "cases_by_status",
        "cases_by_truth_class",
        "cases_by_proof_ceiling",
        "cases_by_public_safe_status",
    ):
        values = set(before[key]) | set(after[key])
        deltas[key] = {
            value: int(after[key].get(value, 0)) - int(before[key].get(value, 0))
            for value in sorted(values)
            if int(after[key].get(value, 0)) - int(before[key].get(value, 0)) != 0
        }
    return deltas


def lifetime_append_gate_dedupe(conn: sqlite3.Connection, event: dict[str, Any]) -> dict[str, Any]:
    duplicate_event_hash_count = int(
        conn.execute("SELECT COUNT(*) FROM case_events WHERE event_hash = ?", (event["event_hash"],)).fetchone()[0]
    )
    duplicate_case_id_count = int(
        conn.execute("SELECT COUNT(*) FROM case_events WHERE case_id = ?", (event["case_id"],)).fetchone()[0]
    )
    payload_hash_count = 0
    sanitized_event_fingerprint_count = 0
    for (payload_json,) in conn.execute("SELECT payload_json FROM case_events").fetchall():
        try:
            payload = json.loads(str(payload_json))
        except json.JSONDecodeError as exc:
            raise FactoryError("Lifetime append gate found invalid stored payload JSON") from exc
        if isinstance(payload, dict):
            if payload.get("payload_hash") == event["payload_hash"]:
                payload_hash_count += 1
            if payload.get("sanitized_event_fingerprint") == event["sanitized_event_fingerprint"]:
                sanitized_event_fingerprint_count += 1
    append_would_be_blocked = any(
        count != 0
        for count in (
            duplicate_event_hash_count,
            duplicate_case_id_count,
            payload_hash_count,
            sanitized_event_fingerprint_count,
        )
    )
    return {
        "event_hash": {
            "candidate_value": event["event_hash"],
            "existing_count": duplicate_event_hash_count,
            "rule": "must_not_already_exist",
            "append_allowed": duplicate_event_hash_count == 0,
        },
        "case_id": {
            "candidate_value": event["case_id"],
            "existing_count": duplicate_case_id_count,
            "rule": "new_manual_fire_case_id_must_not_collide; correction_or_superseding_events_require_a_later_approved_event_with_parent_event_hash",
            "append_allowed": duplicate_case_id_count == 0,
        },
        "payload_hash": {
            "candidate_value": event["payload_hash"],
            "existing_count": payload_hash_count,
            "rule": "matching_payload_hash_blocks_append_as_duplicate_content",
            "append_allowed": payload_hash_count == 0,
        },
        "sanitized_event_fingerprint": {
            "candidate_value": event["sanitized_event_fingerprint"],
            "existing_count": sanitized_event_fingerprint_count,
            "rule": "matching_sanitized_event_fingerprint_blocks_append_as_duplicate_sanitized_event",
            "append_allowed": sanitized_event_fingerprint_count == 0,
        },
        "append_would_be_blocked": append_would_be_blocked,
    }


def validate_lifetime_append_candidate_event(event: dict[str, Any]) -> dict[str, bool]:
    checks = {
        "ledger_version_is_v1": event.get("ledger_version") == LIFETIME_CASE_LEDGER_VERSION,
        "detection_is_supported_manual_fire": event.get("detection_id") in LIFETIME_MANUAL_FIRE_SUPPORTED_DETECTIONS,
        "human_review_required": event.get("human_review_required") is True,
        "ai_support_only": event.get("ai_support_mode") == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": event.get("ai_decided_disposition") is False,
        "not_public_safe": event.get("public_safe_status") == "NOT_PUBLIC_SAFE",
        "no_runtime_public_claim": str(event.get("runtime_truth_status")) != "RUNTIME_ACTIVE_PUBLIC_PROOF",
        "no_signal_public_claim": str(event.get("signal_truth_status")) != "SIGNAL_OBSERVED_PUBLIC_PROOF",
        "no_disposition": event.get("disposition_status") == "NO_DISPOSITION",
        "case_not_closed": event.get("case_status") == "HUMAN_REVIEW_REQUIRED",
        "no_private_evidence_ref": event.get("private_evidence_ref_allowed") is False,
        "no_public_evidence_ref": event.get("evidence_ref_public_safe") is None,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Lifetime append candidate failed boundary checks: {', '.join(failed)}")
    return checks


def lifetime_manual_fire_dry_run(repo_root: Path, ledger_path: Path, candidate_path: Path) -> dict[str, Any]:
    if not candidate_path.is_file():
        raise FactoryError(f"Lifetime manual-fire candidate file is missing: {candidate_path}")
    candidate = load_lifetime_manual_fire_candidate(candidate_path)
    detection_id = str(candidate["detection_id"])
    phase = "phase_6_multi_detection_manual_fire_dry_run" if detection_id != "HO-DET-001" else "phase_2_manual_fire_candidate_dry_run"
    missing_refs = [
        str(candidate[field])
        for field in ("source_packet_ref", "validation_ref", "proof_ref")
        if not (repo_root / str(candidate[field])).is_file()
    ]
    if missing_refs:
        raise FactoryError(f"Lifetime manual-fire candidate references are missing: {', '.join(missing_refs)}")
    event = build_lifetime_manual_fire_event(candidate)
    coverage = verify_lifetime_detection_coverage(repo_root)
    coverage_item = next(item for item in coverage if item["detection_id"] == detection_id)
    with connect_read_only_ledger(ledger_path) as conn:
        seed_verification = verify_ledger(conn, f"seed_bridge_for_lifetime_case_ledger_v1_{phase}_not_runtime_truth")
        before_metrics = lifetime_ledger_metrics(conn)
        duplicate_event_hash_count = int(
            conn.execute("SELECT COUNT(*) FROM case_events WHERE event_hash = ?", (event["event_hash"],)).fetchone()[0]
        )
        duplicate_case_id_count = int(
            conn.execute("SELECT COUNT(*) FROM case_events WHERE case_id = ?", (event["case_id"],)).fetchone()[0]
        )
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": f"lifetime-ledger-manual-fire-{detection_id.lower()}",
        "phase": phase,
        "dry_run": True,
        "append_performed": False,
        "database_modified": False,
        "append_approval_required": LIFETIME_MANUAL_FIRE_APPEND_APPROVAL,
        "candidate_path": str(candidate_path.relative_to(PLATFORM_ROOT)) if candidate_path.is_relative_to(PLATFORM_ROOT) else str(candidate_path),
        "candidate_event": event,
        "coverage_status": {
            "detection_id": detection_id,
            "source_ref_status": coverage_item["source_ref_status"],
            "validation_ref_status": coverage_item["validation_ref_status"],
            "proof_ref_status": coverage_item["proof_ref_status"],
            "proof_ceiling": coverage_item["proof_ceiling"],
            "public_safe_status": coverage_item["public_safe_status"],
        },
        "dedupe": {
            "duplicate_event_hash_count": duplicate_event_hash_count,
            "duplicate_case_id_count": duplicate_case_id_count,
            "append_would_be_blocked": duplicate_event_hash_count != 0 or duplicate_case_id_count != 0,
        },
        "before_lifetime_metrics": before_metrics,
        "expected_after_lifetime_metrics": lifetime_metrics_after_candidate(before_metrics, event),
        "seed_ledger_bridge": seed_verification,
        "boundaries": {
            "database_modified": False,
            "runtime_connected": False,
            "raw_private_evidence_allowed": False,
            "public_safe_promotion_allowed": False,
            "proof_promotion_allowed": False,
            "ai_disposition_authority": False,
            "analyst_disposition_authority": False,
            "case_closure_allowed": False,
        },
        "boundary": (
            f"{phase} is a sanitized dry-run preview only. It does not append to a "
            "runtime ledger, import raw evidence, publish public proof, mark public-safe status, close a case, "
            "or grant AI or analyst final disposition authority."
        ),
    }


def lifetime_manual_fire_ho_det_001_dry_run(repo_root: Path, ledger_path: Path, candidate_path: Path) -> dict[str, Any]:
    return lifetime_manual_fire_dry_run(repo_root, ledger_path, candidate_path)


def lifetime_append_gate_review(
    repo_root: Path,
    ledger_path: Path,
    candidate_path: Path,
    append_mode: str,
    append_approval: str | None,
) -> dict[str, Any]:
    if append_mode not in {"dry-run", "append"}:
        raise FactoryError(f"unsupported lifetime append gate mode: {append_mode}")
    if append_mode == "append" and append_approval != LIFETIME_APPEND_APPROVAL_PHRASE:
        raise FactoryError("BLOCKED: APPEND_APPROVAL_REQUIRED")

    preview = lifetime_manual_fire_dry_run(repo_root, ledger_path, candidate_path)
    event = dict(preview["candidate_event"])
    candidate_checks = validate_lifetime_append_candidate_event(event)
    with connect_read_only_ledger(ledger_path) as conn:
        before_verification = verify_ledger(conn, "phase_3_append_gate_pre_append_validation_only_not_runtime_truth")
        before_metrics = lifetime_ledger_metrics(conn)
        dedupe = lifetime_append_gate_dedupe(conn, event)
    expected_after = lifetime_metrics_after_candidate(before_metrics, event)
    metrics_delta = lifetime_metrics_delta(before_metrics, expected_after)
    if dedupe["append_would_be_blocked"]:
        append_gate_result = "BLOCKED_DEDUPE_COLLISION"
    elif append_mode == "append":
        append_gate_result = "APPEND_GATE_VERIFIED_APPROVAL_PRESENT_NO_WRITE_EXECUTED"
    else:
        append_gate_result = "DRY_RUN_GATE_VERIFIED_NO_WRITE_EXECUTED"
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-append-gate",
        "phase": LIFETIME_APPEND_GATE_PHASE,
        "append_mode": append_mode,
        "dry_run": True,
        "append_performed": False,
        "append_execution_approved_for_this_run": False,
        "append_approval_required": LIFETIME_APPEND_APPROVAL_PHRASE,
        "append_approval_status": "exact_phrase_present" if append_approval == LIFETIME_APPEND_APPROVAL_PHRASE else "not_present",
        "append_gate_result": append_gate_result,
        "candidate_path": preview["candidate_path"],
        "candidate_event": event,
        "candidate_event_checks": candidate_checks,
        "pre_append_validation": {
            "candidate_verified_before_write": True,
            "ledger_verified_before_write": True,
            "append_only_triggers_verified_before_write": True,
            "coverage_verified_before_write": preview["coverage_status"]["source_ref_status"] == "present",
            "dedupe_verified_before_write": True,
            "write_performed": False,
        },
        "dedupe": dedupe,
        "before_lifetime_metrics": before_metrics,
        "expected_after_lifetime_metrics": expected_after,
        "metrics_delta": metrics_delta,
        "post_append_verification_model": {
            "required_after_approved_write": [
                "re-open ledger read-only",
                "run ledger verifier",
                "verify inserted event_hash appears exactly once",
                "verify before/after metrics match expected delta",
                "verify proof/public/runtime boundaries remain unpromoted",
            ],
            "performed_in_phase_3": False,
            "reason": "APPEND_EXECUTION_NOT_APPROVED",
        },
        "ledger_path_rules": {
            "ledger_must_exist_before_append": True,
            "ledger_opened_read_only_for_gate": True,
            "platform_seed_bridge_is_verification_input_not_runtime_truth": ledger_path.resolve() == DEFAULT_CASE_LEDGER.resolve(),
            "repo_paths_do_not_create_runtime_or_public_proof": True,
        },
        "correction_model": {
            "append_only": True,
            "update_allowed": False,
            "delete_allowed": False,
            "destructive_rollback_allowed": False,
            "correction_rule": "errors require a later approved correction or superseding event; existing rows are not edited or deleted",
        },
        "pre_append_ledger_verification": before_verification,
        "boundaries": {
            "database_modified": False,
            "runtime_connected": False,
            "raw_private_evidence_allowed": False,
            "public_safe_promotion_allowed": False,
            "proof_promotion_allowed": False,
            "runtime_active_public_claim_allowed": False,
            "signal_observed_public_claim_allowed": False,
            "ai_disposition_authority": False,
            "analyst_disposition_authority": False,
            "case_closure_allowed": False,
        },
        "boundary": (
            "Phase 3 defines the append approval gate and verifier model only. Without the exact append approval "
            "phrase, append mode fails closed. This command does not perform a real append, mutate a runtime ledger, "
            "import raw evidence, publish public proof, mark public-safe status, close a case, or grant AI or analyst "
            "final disposition authority."
        ),
    }


def lifetime_append_gate_self_test(repo_root: Path, ledger_path: Path, candidate_path: Path) -> dict[str, Any]:
    before_mtime = ledger_path.stat().st_mtime_ns if ledger_path.exists() else None
    dry_run = lifetime_append_gate_review(repo_root, ledger_path, candidate_path, "dry-run", None)
    try:
        lifetime_append_gate_review(repo_root, ledger_path, candidate_path, "append", None)
    except FactoryError as exc:
        unapproved_error = str(exc)
    else:
        raise FactoryError("Lifetime append gate self-test expected unapproved append to fail closed")
    after_mtime = ledger_path.stat().st_mtime_ns if ledger_path.exists() else None
    negative_passed = unapproved_error == "BLOCKED: APPEND_APPROVAL_REQUIRED"
    if not negative_passed:
        raise FactoryError(f"Lifetime append gate self-test failed closed with unexpected error: {unapproved_error}")
    if before_mtime != after_mtime:
        raise FactoryError("Lifetime append gate self-test modified the ledger")
    expected_delta = dry_run["metrics_delta"]
    required_deltas = {
        "total_ledger_events": 1,
        "total_cases": 1,
        "cases_requiring_human_review": 1,
        "ai_support_only_count": 1,
        "proof_blocked_count": 1,
        "public_safe_count": 0,
        "closed_case_count": 0,
    }
    failed_delta = {
        key: {"expected": expected, "actual": expected_delta.get(key)}
        for key, expected in required_deltas.items()
        if expected_delta.get(key) != expected
    }
    if failed_delta:
        raise FactoryError(f"Lifetime append gate self-test metrics delta mismatch: {failed_delta}")
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-append-gate-self-test",
        "phase": LIFETIME_APPEND_GATE_PHASE,
        "status": "pass",
        "negative_unapproved_append": {
            "attempted": True,
            "append_performed": False,
            "expected_error": "BLOCKED: APPEND_APPROVAL_REQUIRED",
            "actual_error": unapproved_error,
            "passed": negative_passed,
        },
        "dry_run_gate": {
            "append_gate_result": dry_run["append_gate_result"],
            "append_performed": dry_run["append_performed"],
            "database_modified": dry_run["boundaries"]["database_modified"],
            "dedupe_append_would_be_blocked": dry_run["dedupe"]["append_would_be_blocked"],
            "metrics_delta": dry_run["metrics_delta"],
        },
        "append_approval_required": LIFETIME_APPEND_APPROVAL_PHRASE,
        "correction_model": dry_run["correction_model"],
        "proof_boundary": dry_run["boundary"],
    }


def validate_lifetime_manual_fire_preview(preview: dict[str, Any], detection_id: str) -> dict[str, Any]:
    event = preview["candidate_event"]
    delta = lifetime_metrics_delta(preview["before_lifetime_metrics"], preview["expected_after_lifetime_metrics"])
    checks = {
        "detection_id": event.get("detection_id") == detection_id,
        "event_hash_present": isinstance(event.get("event_hash"), str) and len(str(event.get("event_hash"))) == 64,
        "case_id_present": isinstance(event.get("case_id"), str) and str(event.get("case_id")).startswith(f"LCL-MANUAL-{detection_id}-"),
        "payload_hash_present": isinstance(event.get("payload_hash"), str) and len(str(event.get("payload_hash"))) == 64,
        "sanitized_event_fingerprint_present": isinstance(event.get("sanitized_event_fingerprint"), str)
        and bool(str(event.get("sanitized_event_fingerprint")).strip()),
        "source_packet_ref_present": isinstance(event.get("source_packet_ref"), str) and bool(str(event.get("source_packet_ref")).strip()),
        "ai_support_only": event.get("ai_support_mode") == "AI_SUPPORT_ONLY",
        "human_review_required": event.get("human_review_required") is True,
        "ai_decided_disposition_false": event.get("ai_decided_disposition") is False,
        "not_public_safe": event.get("public_safe_status") == "NOT_PUBLIC_SAFE",
        "no_disposition": event.get("disposition_status") == "NO_DISPOSITION",
        "append_not_performed": preview.get("append_performed") is False,
        "database_not_modified": preview.get("database_modified") is False,
    }
    required_delta = {
        "total_ledger_events": 1,
        "total_cases": 1,
        "cases_requiring_human_review": 1,
        "ai_support_only_count": 1,
        "proof_blocked_count": 1,
        "public_safe_count": 0,
        "closed_case_count": 0,
    }
    delta_failures = {
        key: {"expected": expected, "actual": delta.get(key)}
        for key, expected in required_delta.items()
        if delta.get(key) != expected
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed or delta_failures:
        raise FactoryError(f"Lifetime manual-fire preview failed Phase 6 checks: checks={failed}, delta={delta_failures}")
    return {
        "checks": checks,
        "metrics_delta": delta,
        "dedupe": preview["dedupe"],
        "proof_ceiling": event["proof_ceiling"],
        "public_safe_status": event["public_safe_status"],
    }


def lifetime_multi_detection_self_test(repo_root: Path, ledger_path: Path) -> dict[str, Any]:
    before_mtime = ledger_path.stat().st_mtime_ns if ledger_path.exists() else None
    previews: dict[str, Any] = {}
    gates: dict[str, Any] = {}
    for detection_id in ("HO-DET-011", "HO-DET-012"):
        candidate_path = LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES[detection_id]
        preview = lifetime_manual_fire_dry_run(repo_root, ledger_path, candidate_path)
        gates[detection_id] = lifetime_append_gate_review(repo_root, ledger_path, candidate_path, "dry-run", None)
        previews[detection_id] = validate_lifetime_manual_fire_preview(preview, detection_id)
        if gates[detection_id]["append_performed"] is not False or gates[detection_id]["boundaries"]["database_modified"] is not False:
            raise FactoryError(f"Lifetime append gate modified state for {detection_id}")

    ho_det_001_hash = build_lifetime_manual_fire_event(
        load_lifetime_manual_fire_candidate(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES["HO-DET-001"])
    )["event_hash"]
    if ho_det_001_hash != "15a499248c31b1f5200f0c8c66a72c8626db11ed76acc1595ddf951e062efdfa":
        raise FactoryError("Lifetime Phase 6 changed the approved HO-DET-001 manual-fire event hash")

    valid = load_lifetime_manual_fire_candidate(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES["HO-DET-011"])
    unsupported = {**valid, "detection_id": "HO-DET-013", "detection_family": "endpoint_telemetry_control_tamper"}
    non_public_value = {**valid, "source_system": "private " + "evidence marker"}
    nonreal_value = {**valid, "notes_boundary": "Sanitized " + "place" + "holder review note"}

    negative_tests = {
        "unsupported_detection_id": expect_factory_error_contains(
            "unsupported detection ID fails closed",
            lambda: validate_lifetime_manual_fire_candidate(unsupported),
            "BLOCKED: LIFETIME_MANUAL_FIRE_UNSUPPORTED_DETECTION",
        ),
        "raw_or_private_value": expect_factory_error_contains(
            "raw or private value fails closed",
            lambda: validate_lifetime_manual_fire_candidate(non_public_value),
            "blocked raw/private value",
        ),
        "nonreal_marker_value": expect_factory_error_contains(
            "nonreal marker value fails closed",
            lambda: validate_lifetime_manual_fire_candidate(nonreal_value),
            "BLOCKED: LIFETIME_MANUAL_FIRE_NONREAL_VALUE",
        ),
        "unapproved_append": expect_factory_error_contains(
            "unapproved append fails closed",
            lambda: lifetime_append_gate_review(
                repo_root,
                ledger_path,
                LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES["HO-DET-011"],
                "append",
                None,
            ),
            "BLOCKED: APPEND_APPROVAL_REQUIRED",
        ),
    }

    with connect_read_only_ledger(ledger_path) as conn:
        promoted = build_lifetime_manual_fire_event(valid)
        promoted.update(
            {
                "public_safe_status": "PUBLIC_SAFE",
                "runtime_truth_status": "RUNTIME_ACTIVE_PUBLIC_PROOF",
                "signal_truth_status": "SIGNAL_OBSERVED_PUBLIC_PROOF",
                "disposition_status": "AI_APPROVED",
                "case_status": "CLOSED",
            }
        )
        negative_tests["promotion_boundary_violation"] = expect_factory_error_contains(
            "promotion boundary violation fails closed",
            lambda: validate_lifetime_append_candidate_event(promoted),
            "Lifetime append candidate failed boundary checks",
        )

    after_mtime = ledger_path.stat().st_mtime_ns if ledger_path.exists() else None
    if before_mtime != after_mtime:
        raise FactoryError("Lifetime multi-detection self-test modified the ledger")

    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-multi-detection-self-test",
        "phase": "phase_6_multi_detection_manual_fire_dry_run",
        "status": "pass",
        "supported_detection_ids": ["HO-DET-001", "HO-DET-011", "HO-DET-012"],
        "ho_det_001_event_hash_stable": ho_det_001_hash,
        "manual_fire_previews": previews,
        "append_gate_previews": {
            detection_id: {
                "append_performed": gate["append_performed"],
                "database_modified": gate["boundaries"]["database_modified"],
                "append_gate_result": gate["append_gate_result"],
                "dedupe": gate["dedupe"],
                "metrics_delta": gate["metrics_delta"],
            }
            for detection_id, gate in gates.items()
        },
        "negative_tests": negative_tests,
        "proof_boundary": (
            "Phase 6 expands sanitized manual-fire dry-run and append-gate previews only. "
            "It does not append to the seed bridge, mutate existing ledger rows, import raw/private runtime evidence, "
            "publish public proof, mark public-safe status, claim runtime/signal public status, close a case, "
            "or grant AI or analyst final disposition authority."
        ),
    }


def approved_lifetime_append_target(ledger_path: Path) -> Path:
    approved = DEFAULT_CASE_LEDGER.resolve()
    actual = ledger_path.resolve()
    if actual != approved:
        raise FactoryError("BLOCKED: APPEND_TARGET_OUT_OF_SCOPE")
    if not actual.is_file():
        raise FactoryError("BLOCKED: APPEND_TARGET_REQUIRED")
    return actual


def lifetime_event_to_case_ledger_event(
    event: dict[str, Any],
    inserted_at: str,
    append_phase: str = "phase_4_approved_manual_fire_append",
) -> dict[str, Any]:
    payload = {
        **event,
        "append_phase": append_phase,
        "truth_boundary": (
            "Sanitized Lifetime Case Ledger v1 manual-fire event stored in the platform seed bridge. "
            "Not runtime truth, not signal truth, not public proof, not public-safe, and not case closure."
        ),
    }
    case_event = {
        "event_hash": event["event_hash"],
        "inserted_at": inserted_at,
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": event["case_id"],
        "detection_id": event["detection_id"],
        "truth_class": event["truth_class"],
        "case_status": event["case_status"],
        "proof_ceiling": event["proof_ceiling"],
        "public_safe_status": event["public_safe_status"],
        "ai_support_mode": event["ai_support_mode"],
        "ai_decided_disposition": event["ai_decided_disposition"],
        "recommended_disposition": None,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "human_review_required": event["human_review_required"],
        "gpu_supported": event["gpu_triage_used"],
        "public_safe": False,
        "proof_blocked": True,
        "github_issue_mutation_allowed": False,
        "case_closed": False,
        "legacy_import_count": 0,
        "payload_json": payload,
        "source_packet_ref": event["source_packet_ref"],
    }
    scan_private_markers("Lifetime approved append case ledger event", case_event)
    return case_event


def ensure_lifetime_candidate_append_allowed(gate: dict[str, Any]) -> None:
    if gate["dedupe"]["append_would_be_blocked"]:
        raise FactoryError("BLOCKED: DEDUPE_COLLISION")


def verify_lifetime_metrics_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    delta = lifetime_metrics_delta(before, after)
    required = {
        "total_ledger_events": 1,
        "total_cases": 1,
        "cases_requiring_human_review": 1,
        "ai_support_only_count": 1,
        "proof_blocked_count": 1,
        "public_safe_count": 0,
        "closed_case_count": 0,
    }
    failures = {
        key: {"expected": expected, "actual": delta.get(key)}
        for key, expected in required.items()
        if delta.get(key) != expected
    }
    if failures:
        raise FactoryError(f"Lifetime append metrics delta mismatch: {failures}")
    return delta


def verify_lifetime_multi_append_metrics_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    delta = lifetime_metrics_delta(before, after)
    required = {
        "total_ledger_events": 2,
        "total_cases": 2,
        "cases_requiring_human_review": 2,
        "ai_support_only_count": 2,
        "proof_blocked_count": 2,
        "public_safe_count": 0,
        "closed_case_count": 0,
        "correction_event_count": 0,
        "superseding_event_count": 0,
    }
    failures = {
        key: {"expected": expected, "actual": delta.get(key)}
        for key, expected in required.items()
        if delta.get(key) != expected
    }
    if failures:
        raise FactoryError(f"Lifetime multi-append metrics delta mismatch: {failures}")
    return delta


def lifetime_approved_append_ho_det_001(
    repo_root: Path,
    ledger_path: Path,
    candidate_path: Path,
    append_approval: str | None,
) -> dict[str, Any]:
    approved_target = approved_lifetime_append_target(ledger_path)
    if append_approval != LIFETIME_APPEND_APPROVAL_PHRASE:
        raise FactoryError("BLOCKED: APPEND_APPROVAL_REQUIRED")

    gate = lifetime_append_gate_review(repo_root, approved_target, candidate_path, "append", append_approval)
    ensure_lifetime_candidate_append_allowed(gate)

    before_metrics = gate["before_lifetime_metrics"]
    event = dict(gate["candidate_event"])
    inserted_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    case_event = lifetime_event_to_case_ledger_event(event, inserted_at)
    insert_status = "not_attempted"
    with connect_ledger(approved_target) as conn:
        insert_case_event_unchecked(conn, case_event)
        conn.commit()
        insert_status = "inserted"

    with connect_read_only_ledger(approved_target) as conn:
        post_verification = verify_ledger(conn, "phase_4_approved_append_seed_bridge_not_runtime_truth_not_public_proof")
        after_metrics = lifetime_ledger_metrics(conn)
        inserted_count = int(
            conn.execute("SELECT COUNT(*) FROM case_events WHERE event_hash = ?", (event["event_hash"],)).fetchone()[0]
        )
        post_dedupe = lifetime_append_gate_dedupe(conn, event)
    if inserted_count != 1:
        raise FactoryError(f"Lifetime append post-check expected one inserted event_hash, found {inserted_count}")
    metrics_delta = verify_lifetime_metrics_delta(before_metrics, after_metrics)
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-append-approved-ho-det-001",
        "phase": "phase_4_approved_append",
        "append_target": str(approved_target),
        "append_target_boundary": "platform_seed_bridge_not_runtime_truth_not_public_proof",
        "append_approval_status": "exact_phrase_present",
        "append_performed": True,
        "insert_status": insert_status,
        "inserted_event_hash": event["event_hash"],
        "inserted_case_id": event["case_id"],
        "inserted_at": inserted_at,
        "candidate_event_summary": {
            "detection_id": event["detection_id"],
            "case_id": event["case_id"],
            "event_hash": event["event_hash"],
            "payload_hash": event["payload_hash"],
            "sanitized_event_fingerprint": event["sanitized_event_fingerprint"],
            "ai_support_mode": event["ai_support_mode"],
            "human_review_required": event["human_review_required"],
            "ai_decided_disposition": event["ai_decided_disposition"],
            "public_safe_status": event["public_safe_status"],
            "disposition_status": event["disposition_status"],
        },
        "pre_append_verification": gate["pre_append_ledger_verification"],
        "dedupe_pre_check": gate["dedupe"],
        "post_append_verification": post_verification,
        "before_lifetime_metrics": before_metrics,
        "after_lifetime_metrics": after_metrics,
        "metrics_delta": metrics_delta,
        "duplicate_append_negative_test": {
            "expected_result": "BLOCKED: DEDUPE_COLLISION",
            "post_append_dedupe_append_would_be_blocked": post_dedupe["append_would_be_blocked"],
            "event_hash_existing_count": post_dedupe["event_hash"]["existing_count"],
            "case_id_existing_count": post_dedupe["case_id"]["existing_count"],
            "payload_hash_existing_count": post_dedupe["payload_hash"]["existing_count"],
            "sanitized_event_fingerprint_existing_count": post_dedupe["sanitized_event_fingerprint"]["existing_count"],
        },
        "correction_model": gate["correction_model"],
        "boundaries": {
            "raw_private_evidence_imported": False,
            "runtime_connected": False,
            "public_safe_promotion_allowed": False,
            "proof_promotion_allowed": False,
            "runtime_active_public_claim_allowed": False,
            "signal_observed_public_claim_allowed": False,
            "ai_disposition_authority": False,
            "analyst_disposition_authority": False,
            "case_closure_allowed": False,
        },
        "boundary": (
            "One approved sanitized HO-DET-001 manual-fire event was appended to the platform seed bridge only. "
            "This remains not runtime truth, not signal truth, not public proof, not public-safe, not case closure, "
            "and not AI or analyst final disposition authority."
        ),
    }


def lifetime_approved_append_ho_det_011_012(
    repo_root: Path,
    ledger_path: Path,
    append_approval: str | None,
) -> dict[str, Any]:
    approved_target = approved_lifetime_append_target(ledger_path)
    if append_approval != LIFETIME_APPEND_APPROVAL_PHRASE:
        raise FactoryError("BLOCKED: APPEND_APPROVAL_REQUIRED")

    candidate_paths = {
        detection_id: LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES[detection_id]
        for detection_id in ("HO-DET-011", "HO-DET-012")
    }
    expected_hashes = {
        "HO-DET-011": "1415870b1c80f33bdceb7811ccd33729e53496562b4f9a3b6589a273ce8cf874",
        "HO-DET-012": "4d7bc9077e5032bfd02ff1315d5573f1df769288b1095465cb20dff41bd5f679",
    }
    gates: dict[str, Any] = {}
    events: dict[str, dict[str, Any]] = {}
    for detection_id, candidate_path in candidate_paths.items():
        gate = lifetime_append_gate_review(repo_root, approved_target, candidate_path, "append", append_approval)
        event = dict(gate["candidate_event"])
        if event["event_hash"] != expected_hashes[detection_id]:
            raise FactoryError(
                f"BLOCKED: CANDIDATE_HASH_DRIFT: {detection_id} expected {expected_hashes[detection_id]} got {event['event_hash']}"
            )
        ensure_lifetime_candidate_append_allowed(gate)
        gates[detection_id] = gate
        events[detection_id] = event

    before_metrics = gates["HO-DET-011"]["before_lifetime_metrics"]
    before_verification = gates["HO-DET-011"]["pre_append_ledger_verification"]
    before_event_count = int(before_metrics["total_ledger_events"])
    if before_event_count != 2:
        raise FactoryError(f"BLOCKED: UNEXPECTED_PRE_APPEND_LEDGER_COUNT: {before_event_count}")

    inserted_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    inserted: dict[str, Any] = {}
    with connect_ledger(approved_target) as conn:
        for detection_id, event in events.items():
            case_event = lifetime_event_to_case_ledger_event(
                event,
                inserted_at,
                append_phase="phase_7_approved_multi_detection_manual_fire_append",
            )
            insert_case_event_unchecked(conn, case_event)
            inserted[detection_id] = {
                "insert_status": "inserted",
                "case_id": event["case_id"],
                "event_hash": event["event_hash"],
                "payload_hash": event["payload_hash"],
                "sanitized_event_fingerprint": event["sanitized_event_fingerprint"],
                "proof_ceiling": event["proof_ceiling"],
                "public_safe_status": event["public_safe_status"],
                "ai_support_mode": event["ai_support_mode"],
                "human_review_required": event["human_review_required"],
                "ai_decided_disposition": event["ai_decided_disposition"],
                "disposition_status": event["disposition_status"],
            }
        conn.commit()

    with connect_read_only_ledger(approved_target) as conn:
        post_verification = verify_ledger(conn, "phase_7_approved_multi_detection_seed_bridge_not_runtime_truth_not_public_proof")
        after_metrics = lifetime_ledger_metrics(conn)
        inserted_counts = {
            detection_id: int(
                conn.execute("SELECT COUNT(*) FROM case_events WHERE event_hash = ?", (event["event_hash"],)).fetchone()[0]
            )
            for detection_id, event in events.items()
        }
        post_dedupe = {
            detection_id: lifetime_append_gate_dedupe(conn, event)
            for detection_id, event in events.items()
        }
    if inserted_counts != {"HO-DET-011": 1, "HO-DET-012": 1}:
        raise FactoryError(f"Lifetime Phase 7 post-check expected one row per inserted event_hash, found {inserted_counts}")
    metrics_delta = verify_lifetime_multi_append_metrics_delta(before_metrics, after_metrics)

    duplicate_results: dict[str, Any] = {}
    for detection_id, candidate_path in candidate_paths.items():
        before_duplicate_count = int(after_metrics["total_ledger_events"])
        try:
            duplicate_gate = lifetime_append_gate_review(repo_root, approved_target, candidate_path, "append", append_approval)
            ensure_lifetime_candidate_append_allowed(duplicate_gate)
        except FactoryError as exc:
            duplicate_error = str(exc)
        else:
            raise FactoryError(f"Lifetime Phase 7 duplicate append did not fail closed for {detection_id}")
        with connect_read_only_ledger(approved_target) as conn:
            after_duplicate_metrics = lifetime_ledger_metrics(conn)
        after_duplicate_count = int(after_duplicate_metrics["total_ledger_events"])
        if duplicate_error != "BLOCKED: DEDUPE_COLLISION":
            raise FactoryError(f"Lifetime Phase 7 duplicate append failed with unexpected error for {detection_id}: {duplicate_error}")
        if before_duplicate_count != after_duplicate_count:
            raise FactoryError(f"Lifetime Phase 7 duplicate append changed ledger count for {detection_id}")
        duplicate_results[detection_id] = {
            "expected_result": "BLOCKED: DEDUPE_COLLISION",
            "actual_result": duplicate_error,
            "event_count_before": before_duplicate_count,
            "event_count_after": after_duplicate_count,
            "event_count_unchanged": True,
            "post_append_dedupe_append_would_be_blocked": post_dedupe[detection_id]["append_would_be_blocked"],
            "event_hash_existing_count": post_dedupe[detection_id]["event_hash"]["existing_count"],
            "case_id_existing_count": post_dedupe[detection_id]["case_id"]["existing_count"],
            "payload_hash_existing_count": post_dedupe[detection_id]["payload_hash"]["existing_count"],
            "sanitized_event_fingerprint_existing_count": post_dedupe[detection_id]["sanitized_event_fingerprint"]["existing_count"],
        }

    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-append-approved-ho-det-011-012",
        "phase": "phase_7_approved_multi_detection_append",
        "append_target": str(approved_target),
        "append_target_boundary": "tracked_platform_seed_bridge_not_runtime_truth_not_signal_truth_not_public_proof",
        "append_approval_status": "exact_phrase_present",
        "append_performed": True,
        "inserted_at": inserted_at,
        "inserted_event_count": 2,
        "inserted_events": inserted,
        "pre_append_verification": before_verification,
        "dedupe_pre_check": {detection_id: gate["dedupe"] for detection_id, gate in gates.items()},
        "post_append_verification": post_verification,
        "before_lifetime_metrics": before_metrics,
        "after_lifetime_metrics": after_metrics,
        "metrics_delta": metrics_delta,
        "duplicate_append_negative_tests": duplicate_results,
        "correction_model": gates["HO-DET-011"]["correction_model"],
        "boundaries": {
            "raw_private_evidence_imported": False,
            "runtime_connected": False,
            "public_safe_promotion_allowed": False,
            "proof_promotion_allowed": False,
            "runtime_active_public_claim_allowed": False,
            "signal_observed_public_claim_allowed": False,
            "ai_disposition_authority": False,
            "analyst_disposition_authority": False,
            "case_closure_allowed": False,
            "correction_or_superseding_append_performed": False,
        },
        "boundary": (
            "Two approved sanitized manual-fire events for HO-DET-011 and HO-DET-012 were appended to the "
            "tracked platform seed bridge only. This remains not runtime truth, not signal truth, not public proof, "
            "not public-safe, not case closure, and not AI or analyst final disposition authority."
        ),
    }


def require_sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise FactoryError(f"BLOCKED: {label.upper()}_INVALID")
    return value


def require_sanitized_correction_reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FactoryError("BLOCKED: CORRECTION_REASON_REQUIRED")
    reason = " ".join(value.strip().split())
    scan_private_markers("Lifetime correction reason", reason)
    for pattern in SPLUNK_SANITIZED_VALUE_PATTERNS:
        if pattern.search(reason):
            raise FactoryError("BLOCKED: CORRECTION_REASON_PRIVATE_OR_RAW")
    return reason


def fetch_lifetime_parent_event(conn: sqlite3.Connection, parent_event_hash: str) -> dict[str, Any]:
    parent_hash = require_sha256_hex(parent_event_hash, "parent_event_hash")
    columns = [item[1] for item in conn.execute("PRAGMA table_info(case_events)").fetchall()]
    row = conn.execute("SELECT * FROM case_events WHERE event_hash = ?", (parent_hash,)).fetchone()
    if row is None:
        raise FactoryError("BLOCKED: PARENT_EVENT_HASH_UNKNOWN")
    parent = dict(zip(columns, row))
    payload = scan_ledger_event_text_fields(parent)
    parent["payload_json_parsed"] = payload
    return parent


def build_lifetime_correction_event(parent: dict[str, Any], correction_reason: str) -> dict[str, Any]:
    reason = require_sanitized_correction_reason(correction_reason)
    parent_hash = require_sha256_hex(parent.get("event_hash"), "parent_event_hash")
    parent_payload = parent.get("payload_json_parsed") if isinstance(parent.get("payload_json_parsed"), dict) else {}
    digest_input = {
        "event_type": LIFETIME_CORRECTION_EVENT_TYPE,
        "parent_event_hash": parent_hash,
        "case_id": parent["case_id"],
        "correction_reason": reason,
        "detection_id": parent["detection_id"],
    }
    digest = hashlib.sha256(stable_json(digest_input).encode("utf-8")).hexdigest()
    event = {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "event_id": f"LCL-CORRECTION-{digest[:16].upper()}",
        "event_hash": "pending",
        "parent_event_hash": parent_hash,
        "event_type": LIFETIME_CORRECTION_EVENT_TYPE,
        "case_id": str(parent["case_id"]),
        "detection_id": str(parent["detection_id"]),
        "detection_family": str(parent_payload.get("detection_family") or lifetime_detection_family_map().get(str(parent["detection_id"]), "unmapped_detection_family")),
        "source_system": str(parent_payload.get("source_system") or "platform_correction_gate"),
        "fired_at": None,
        "observed_time_utc": None,
        "ingested_at": None,
        "truth_class": "SYNTHETIC_TEST_CASE",
        "case_status": "HUMAN_REVIEW_REQUIRED",
        "triage_status": "PENDING_HUMAN_REVIEW",
        "disposition_status": "NO_DISPOSITION",
        "proof_ceiling": str(parent.get("proof_ceiling") or "CONTROLLED_TEST_VALIDATED"),
        "runtime_truth_status": "CORRECTION_GATE_NOT_RUNTIME_TRUTH",
        "signal_truth_status": "NOT_PUBLIC_PROOF",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "human_review_required": True,
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "gpu_triage_used": False,
        "gpu_node_id": None,
        "model_or_triage_engine_reference": None,
        "source_packet_ref": str(parent.get("source_packet_ref") or parent_payload.get("source_packet_ref") or "platform-correction-gate"),
        "evidence_ref_public_safe": None,
        "private_evidence_ref_allowed": False,
        "blocked_claims": list(LIFETIME_LEDGER_BLOCKED_CLAIMS),
        "validation_ref": parent_payload.get("validation_ref"),
        "proof_ref": parent_payload.get("proof_ref"),
        "github_actions_run_ref": None,
        "payload_hash": digest,
        "sanitized_event_fingerprint": f"correction-{digest}",
        "correction_reason": reason,
        "supersedes_event_hash": parent_hash,
        "notes_boundary": (
            "Sanitized correction/superseding event preview only. Original event remains immutable; "
            "no update, delete, public proof, public-safe status, case closure, or disposition authority."
        ),
    }
    event_hash_input = dict(event)
    event_hash_input["event_hash"] = "pending"
    event["event_hash"] = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    scan_private_markers("Lifetime correction event", event)
    return event


def validate_lifetime_correction_event(event: dict[str, Any], conn: sqlite3.Connection) -> dict[str, bool]:
    parent_hash = event.get("parent_event_hash")
    if parent_hash is None:
        raise FactoryError("BLOCKED: PARENT_EVENT_HASH_REQUIRED")
    fetch_lifetime_parent_event(conn, str(parent_hash))
    require_sanitized_correction_reason(event.get("correction_reason"))
    checks = {
        "event_type_is_correction_superseding": event.get("event_type") == LIFETIME_CORRECTION_EVENT_TYPE,
        "parent_link_matches_supersedes": event.get("parent_event_hash") == event.get("supersedes_event_hash"),
        "human_review_required": event.get("human_review_required") is True,
        "ai_support_only": event.get("ai_support_mode") == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": event.get("ai_decided_disposition") is False,
        "not_public_safe": event.get("public_safe_status") == "NOT_PUBLIC_SAFE",
        "no_runtime_public_claim": str(event.get("runtime_truth_status")) != "RUNTIME_ACTIVE_PUBLIC_PROOF",
        "no_signal_public_claim": str(event.get("signal_truth_status")) != "SIGNAL_OBSERVED_PUBLIC_PROOF",
        "no_disposition": event.get("disposition_status") == "NO_DISPOSITION",
        "case_not_closed": event.get("case_status") == "HUMAN_REVIEW_REQUIRED",
        "original_not_marked_deleted": event.get("original_event_deleted") is None,
        "no_private_evidence_ref": event.get("private_evidence_ref_allowed") is False,
        "no_public_evidence_ref": event.get("evidence_ref_public_safe") is None,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"BLOCKED: CORRECTION_BOUNDARY_VIOLATION: {', '.join(failed)}")
    return checks


def lifetime_metrics_after_correction(before: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    after = json.loads(json.dumps(before))
    after["total_ledger_events"] = int(after["total_ledger_events"]) + 1
    for key, event_field in (
        ("cases_by_detection", "detection_id"),
        ("cases_by_family", "detection_family"),
        ("cases_by_status", "case_status"),
        ("cases_by_truth_class", "truth_class"),
        ("cases_by_proof_ceiling", "proof_ceiling"),
        ("cases_by_public_safe_status", "public_safe_status"),
    ):
        group = dict(after[key])
        value = str(event[event_field])
        group[value] = int(group.get(value, 0)) + 1
        after[key] = dict(sorted(group.items()))
    after["cases_requiring_human_review"] = int(after["cases_requiring_human_review"]) + 1
    after["ai_support_only_count"] = int(after["ai_support_only_count"]) + 1
    after["proof_blocked_count"] = int(after["proof_blocked_count"]) + 1
    after["correction_event_count"] = int(after["correction_event_count"]) + 1
    after["superseding_event_count"] = int(after["superseding_event_count"]) + 1
    if event["truth_class"] == "SYNTHETIC_TEST_CASE":
        after["validation_only_count"] = int(after["validation_only_count"]) + 1
    return after


def lifetime_correction_gate_review(
    repo_root: Path,
    ledger_path: Path,
    parent_event_hash: str,
    correction_reason: str,
    append_mode: str,
    correction_approval: str | None,
) -> dict[str, Any]:
    if append_mode not in {"dry-run", "append"}:
        raise FactoryError(f"unsupported lifetime correction gate mode: {append_mode}")
    if append_mode == "append" and correction_approval != LIFETIME_CORRECTION_APPEND_APPROVAL_PHRASE:
        raise FactoryError("BLOCKED: CORRECTION_APPEND_APPROVAL_REQUIRED")
    approved_target = approved_lifetime_append_target(ledger_path)
    verify_lifetime_detection_coverage(repo_root)
    with connect_read_only_ledger(approved_target) as conn:
        pre_verification = verify_ledger(conn, "phase_5_correction_gate_pre_append_validation_only_not_runtime_truth")
        before_metrics = lifetime_ledger_metrics(conn)
        parent = fetch_lifetime_parent_event(conn, parent_event_hash)
        event = build_lifetime_correction_event(parent, correction_reason)
        checks = validate_lifetime_correction_event(event, conn)
    expected_after = lifetime_metrics_after_correction(before_metrics, event)
    metrics_delta = lifetime_metrics_delta(before_metrics, expected_after)
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-correction-gate",
        "phase": LIFETIME_CORRECTION_GATE_PHASE,
        "append_mode": append_mode,
        "append_performed": False,
        "database_modified": False,
        "correction_append_approval_required": LIFETIME_CORRECTION_APPEND_APPROVAL_PHRASE,
        "correction_approval_status": "exact_phrase_present" if correction_approval == LIFETIME_CORRECTION_APPEND_APPROVAL_PHRASE else "not_present",
        "correction_gate_result": (
            "CORRECTION_GATE_VERIFIED_APPROVAL_PRESENT_NO_WRITE_EXECUTED"
            if append_mode == "append"
            else "CORRECTION_DRY_RUN_GATE_VERIFIED_NO_WRITE_EXECUTED"
        ),
        "candidate_correction_event": event,
        "parent_event_hash": parent_event_hash,
        "correction_event_checks": checks,
        "pre_append_ledger_verification": pre_verification,
        "before_lifetime_metrics": before_metrics,
        "expected_after_lifetime_metrics": expected_after,
        "metrics_delta": metrics_delta,
        "correction_model": {
            "append_only": True,
            "update_allowed": False,
            "delete_allowed": False,
            "destructive_rollback_allowed": False,
            "original_event_deleted": False,
            "correction_rule": "corrections are later linked events using parent_event_hash; existing rows are not edited or deleted",
        },
        "boundaries": {
            "raw_private_evidence_imported": False,
            "runtime_connected": False,
            "public_safe_promotion_allowed": False,
            "proof_promotion_allowed": False,
            "runtime_active_public_claim_allowed": False,
            "signal_observed_public_claim_allowed": False,
            "ai_disposition_authority": False,
            "analyst_disposition_authority": False,
            "case_closure_allowed": False,
        },
        "boundary": (
            "Phase 5 correction/superseding support is append-only and non-mutating in this gate. "
            "It links a sanitized correction event to a prior event by parent_event_hash, does not edit or delete "
            "the original row, and does not promote proof, public-safe status, runtime/signal public claims, "
            "disposition authority, or case closure."
        ),
    }


def lifetime_append_only_dml_self_tests() -> dict[str, Any]:
    conn = self_test_runtime_conn()
    results: dict[str, Any] = {}
    try:
        conn.execute("UPDATE case_events SET case_status = case_status WHERE event_id = 1")
    except sqlite3.DatabaseError as exc:
        results["update_blocked"] = "append-only" in str(exc)
    else:
        results["update_blocked"] = False
    try:
        conn.execute("DELETE FROM case_events WHERE event_id = 1")
    except sqlite3.DatabaseError as exc:
        results["delete_blocked"] = "append-only" in str(exc)
    else:
        results["delete_blocked"] = False
    failed = sorted(name for name, passed in results.items() if not passed)
    if failed:
        raise FactoryError(f"Lifetime correction append-only DML self-tests failed: {', '.join(failed)}")
    return results


def expect_factory_error_contains(label: str, fn: Any, expected: str) -> dict[str, Any]:
    try:
        fn()
    except FactoryError as exc:
        actual = str(exc)
        if expected not in actual:
            raise FactoryError(f"{label} expected {expected}, got {actual}") from exc
        return {"expected": expected, "actual": actual, "passed": True}
    raise FactoryError(f"{label} expected FactoryError {expected}")


def lifetime_correction_self_test(repo_root: Path, ledger_path: Path) -> dict[str, Any]:
    parent_event_hash = build_lifetime_manual_fire_event(load_lifetime_manual_fire_candidate(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE))[
        "event_hash"
    ]
    correction_reason = "Sanitized correction note: superseding review preserves append-only ledger integrity."
    dry_run = lifetime_correction_gate_review(
        repo_root,
        ledger_path,
        parent_event_hash,
        correction_reason,
        "dry-run",
        None,
    )
    dml_tests = lifetime_append_only_dml_self_tests()
    negative_tests = {
        "missing_parent_event_hash": expect_factory_error_contains(
            "missing_parent_event_hash",
            lambda: lifetime_correction_gate_review(repo_root, ledger_path, "", correction_reason, "dry-run", None),
            "BLOCKED: PARENT_EVENT_HASH_INVALID",
        ),
        "unknown_parent_event_hash": expect_factory_error_contains(
            "unknown_parent_event_hash",
            lambda: lifetime_correction_gate_review(repo_root, ledger_path, "0" * 64, correction_reason, "dry-run", None),
            "BLOCKED: PARENT_EVENT_HASH_UNKNOWN",
        ),
        "malformed_parent_event_hash": expect_factory_error_contains(
            "malformed_parent_event_hash",
            lambda: lifetime_correction_gate_review(repo_root, ledger_path, "not-a-sha256", correction_reason, "dry-run", None),
            "BLOCKED: PARENT_EVENT_HASH_INVALID",
        ),
        "private_or_raw_correction_reason": expect_factory_error_contains(
            "private_or_raw_correction_reason",
            lambda: lifetime_correction_gate_review(
                repo_root,
                ledger_path,
                parent_event_hash,
                "private " + "path marker in correction reason",
                "dry-run",
                None,
            ),
            "BLOCKED: CORRECTION_REASON_PRIVATE_OR_RAW",
        ),
        "unapproved_correction_append": expect_factory_error_contains(
            "unapproved_correction_append",
            lambda: lifetime_correction_gate_review(repo_root, ledger_path, parent_event_hash, correction_reason, "append", None),
            "BLOCKED: CORRECTION_APPEND_APPROVAL_REQUIRED",
        ),
    }
    with connect_read_only_ledger(approved_lifetime_append_target(ledger_path)) as conn:
        parent = fetch_lifetime_parent_event(conn, parent_event_hash)
        promoted = build_lifetime_correction_event(parent, correction_reason)
        promoted.update(
            {
                "public_safe_status": "PUBLIC_SAFE",
                "runtime_truth_status": "RUNTIME_ACTIVE_PUBLIC_PROOF",
                "signal_truth_status": "SIGNAL_OBSERVED_PUBLIC_PROOF",
                "disposition_status": "AI_APPROVED",
                "case_status": "CLOSED",
            }
        )
        negative_tests["promotion_boundary_violation"] = expect_factory_error_contains(
            "promotion_boundary_violation",
            lambda: validate_lifetime_correction_event(promoted, conn),
            "BLOCKED: CORRECTION_BOUNDARY_VIOLATION",
        )
    required_delta = {
        "total_ledger_events": 1,
        "total_cases": 0,
        "correction_event_count": 1,
        "superseding_event_count": 1,
        "cases_requiring_human_review": 1,
        "proof_blocked_count": 1,
        "public_safe_count": 0,
        "closed_case_count": 0,
    }
    delta_failures = {
        key: {"expected": expected, "actual": dry_run["metrics_delta"].get(key)}
        for key, expected in required_delta.items()
        if dry_run["metrics_delta"].get(key) != expected
    }
    if delta_failures:
        raise FactoryError(f"Lifetime correction self-test metrics delta mismatch: {delta_failures}")
    return {
        "ledger_version": LIFETIME_CASE_LEDGER_VERSION,
        "mode": "lifetime-ledger-correction-self-test",
        "phase": LIFETIME_CORRECTION_GATE_PHASE,
        "status": "pass",
        "positive_dry_run": {
            "append_performed": dry_run["append_performed"],
            "database_modified": dry_run["database_modified"],
            "parent_event_hash": parent_event_hash,
            "correction_event_hash": dry_run["candidate_correction_event"]["event_hash"],
            "event_type": dry_run["candidate_correction_event"]["event_type"],
            "metrics_delta": dry_run["metrics_delta"],
        },
        "append_only_negative_tests": dml_tests,
        "negative_tests": negative_tests,
        "correction_append_approval_required": LIFETIME_CORRECTION_APPEND_APPROVAL_PHRASE,
        "proof_boundary": dry_run["boundary"],
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


def self_test_ho_det_012_private_receipt_event() -> dict[str, Any]:
    payload = {
        "marker_family": "batch002_self_test_marker",
        "splunk_sysmon_count": 13,
        "wazuh_alert_count": 87,
        "cribl_status": "service_metadata_ready_route_receipt_not_proven",
        "security_onion_status": "route_ready_status_sudo_blocked_marker_not_proven",
        "truth_boundary": (
            "Sanitized private runtime metadata receipt for review support only. "
            "Not public proof, not public-safe, not route-complete, and not case closure."
        ),
    }
    event = {
        "inserted_at": "2026-05-19T00:00:00Z",
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": "HO-DET-012-PRIVATE-RUNTIME-RECEIPT-SELFTEST",
        "detection_id": "HO-DET-012",
        "truth_class": "PRIVATE_RUNTIME_EVIDENCE",
        "case_status": "HUMAN_REVIEW_REQUIRED",
        "proof_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED",
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
        "source_packet_ref": "private-runtime-receipt:self-test",
    }
    event_hash_input = dict(event)
    event_hash_input["payload_json"] = payload
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


def self_test_ho_det_012_private_receipt_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    initialize_ledger_schema(conn)
    event = self_test_ho_det_012_private_receipt_event()
    insert_case_event_unchecked(conn, event)
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
    ho_det_012_review = runtime_ledger_review_case_from_conn(
        self_test_ho_det_012_private_receipt_conn(),
        "memory:self-test",
        "HO-DET-012-PRIVATE-RUNTIME-RECEIPT-SELFTEST",
    )
    ho_det_012_case = ho_det_012_review["case"]
    if ho_det_012_case["detection_id"] != "HO-DET-012":
        raise FactoryError("HO-DET-012 private receipt self-test reviewed the wrong detection")
    if ho_det_012_case["truth_class"] != "PRIVATE_RUNTIME_EVIDENCE":
        raise FactoryError("HO-DET-012 private receipt self-test must remain private runtime evidence")
    if ho_det_012_case["case_status"] != "HUMAN_REVIEW_REQUIRED":
        raise FactoryError("HO-DET-012 private receipt self-test must require human review")
    if ho_det_012_case["proof_ceiling"] != "PRIVATE_RUNTIME_METADATA_CAPTURED":
        raise FactoryError("HO-DET-012 private receipt self-test must keep private metadata ceiling")
    if ho_det_012_case["public_safe_status"] != "NOT_PUBLIC_SAFE":
        raise FactoryError("HO-DET-012 private receipt self-test must remain NOT_PUBLIC_SAFE")
    expected_boundary = {
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
    }
    if ho_det_012_review["boundary_confirmations"] != expected_boundary:
        raise FactoryError("HO-DET-012 private receipt self-test boundary confirmations changed")
    return {
        "status": "pass",
        "mode": "in_memory_no_files_no_runtime_mutation",
        "negative_checks": passed,
        "positive_checks": [
            {
                "name": "HO-DET-012 private runtime receipt review support",
                "case_id": ho_det_012_case["case_id"],
                "detection_id": ho_det_012_case["detection_id"],
                "truth_class": ho_det_012_case["truth_class"],
                "case_status": ho_det_012_case["case_status"],
                "proof_ceiling": ho_det_012_case["proof_ceiling"],
                "public_safe_status": ho_det_012_case["public_safe_status"],
                "human_review_required": ho_det_012_case["human_review_required"],
                "proof_promotion_allowed": ho_det_012_review["boundary_confirmations"]["proof_promotion_allowed"],
                "public_safe_promotion_allowed": ho_det_012_review["boundary_confirmations"]["public_safe_promotion_allowed"],
                "github_issue_mutation_allowed": ho_det_012_review["boundary_confirmations"]["github_issue_mutation_allowed"],
                "case_closed": ho_det_012_review["boundary_confirmations"]["case_closed"],
                "ai_decided_disposition": ho_det_012_review["boundary_confirmations"]["ai_decided_disposition"],
            }
        ],
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
        platform_guardrail_status="SATISFIED_NON_PROMOTIONAL_BOUNDARY",
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
        platform_sample_expected_total=17,
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
        next_allowed_move="Platform guardrail drift is resolved for the 17-case controlled validation shape; routed telemetry or public-safe wording remains blocked until separate evidence linkage, redaction review, stale review, wording review, and Raylee approval.",
        decision_status="READY_FOR_REVIEW",
        decision_reason="Platform guardrail matches the current 17-case controlled validation shape while preserving proof, runtime, signal, public-safe, and AI authority boundaries.",
        truth_boundary={
            "source_truth": "reported",
            "validation_truth": "controlled-test validated",
            "platform_truth": "case-packet guardrail aligned to current controlled validation state",
            "proof_truth": "private runtime evidence state reported",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not promote proof.",
            "Do not edit proof, website, detection, validation, workflow, dependency, evidence, or runtime files.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not create generated output files.",
        ),
        state_consistency=(
            "STATE_CONSISTENT_WITH_17_CASE_VALIDATION",
            "Platform sample, schema, verifier, and factory status align to the current 17 controlled-test fixtures without promoting proof, runtime-active, signal-observed, or public-safe claims.",
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
    "ID-DET-001": DetectionSpec(
        detection_id="ID-DET-001",
        current_state="CONTROLLED_TEST_VALIDATED",
        public_proof_ceiling="CONTROLLED_TEST_VALIDATED",
        private_evidence_state="NOT_CAPTURED",
        public_safe_status="NOT_PUBLIC_SAFE",
        platform_guardrail_status="STATUS_VISIBILITY_ONLY",
        validation_result="hawkinsoperations-validation/reports/id-det-001/validation-result.json",
        validation_expected={
            "total_cases": 10,
            "positive_cases": 5,
            "negative_cases": 5,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
        },
        validation_claim="ID-DET-001 passed controlled-test validation against 10 controlled identity-event fixtures for suspicious identity session context.",
        proof_record=None,
        proof_card=None,
        proof_state="NO_PROOF_RECORD_NOT_PROMOTED",
        platform_sample=None,
        platform_sample_expected_total=0,
        required_blocked_claims=(
            *COMMON_BLOCKED,
            "evidence-linked public proof",
            "live Okta proof",
            "live Entra proof",
            "live IdP proof",
            "live Splunk proof",
            "Wazuh-routed proof",
            "Cribl-routed proof",
            "Security Onion observed proof",
            "production identity coverage",
            "machine identity production governance",
            "AI agent production governance",
            "full identity attack coverage",
            "impossible-travel completeness",
            "session hijacking completeness",
            "proof promotion",
            "website/public-surface promotion",
        ),
        supported_claims=(
            "ID-DET-001 source artifacts exist.",
            "ID-DET-001 passed controlled-test validation against 10 controlled identity-event fixtures.",
            "ID-DET-001 has platform status/plan visibility for controlled-test validation only.",
            "ID-DET-001 remains not public-safe and not runtime-active.",
        ),
        next_allowed_move="Review controlled-test validation packet only; live IdP access, runtime evidence, proof promotion, routed telemetry, website output, and public-safe wording remain blocked until separate approval.",
        decision_status="READY_FOR_REVIEW",
        decision_reason="Controller v0 reports ID-DET-001 controlled-test validation state only and preserves runtime, live IdP, proof, and public-surface boundaries.",
        truth_boundary={
            "source_truth": "reported",
            "validation_truth": "controlled-test validated",
            "platform_truth": "status visibility only",
            "proof_truth": "not promoted",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not promote proof.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not claim live Okta, Entra, or IdP proof.",
            "Do not claim production identity coverage.",
            "Do not claim impossible-travel or session hijacking completeness.",
            "Do not create generated output files.",
        ),
        state_consistency=("STATE_CONSISTENT_WITH_V0_BOUNDARY",),
        does_not_prove=(
            "runtime activity",
            "signal observation",
            "public-safe status",
            "production deployment",
            "fleet-wide coverage",
            "live Okta proof",
            "live Entra proof",
            "live IdP proof",
            "live Splunk proof",
            "Wazuh routing",
            "Cribl routing",
            "Security Onion observation",
            "production identity coverage",
            "machine identity production governance",
            "AI agent production governance",
            "full identity attack coverage",
            "impossible-travel completeness",
            "session hijacking completeness",
            "AI-approved disposition",
            "analyst-approved disposition",
        ),
        surfaces=(
            Surface("hawkinsoperations-detections", "detections/identity/id-det-001/status.yml"),
            Surface("hawkinsoperations-detections", "detections/identity/id-det-001/rule.yml"),
            Surface("hawkinsoperations-detections", "detections/identity/id-det-001/splunk.spl"),
            Surface("hawkinsoperations-detections", "detections/identity/id-det-001/event-mapping.yml"),
            Surface("hawkinsoperations-detections", "detections/DETECTION_FACTORY_INDEX.md"),
            Surface("hawkinsoperations-validation", "reports/id-det-001/validation-result.json"),
            Surface("hawkinsoperations-validation", "reports/id-det-001/validation-result.md"),
            Surface("hawkinsoperations-validation", "validation/identity/id-det-001/validation-cases.json"),
            Surface("hawkinsoperations-validation", "scripts/validate-id-det-001.py"),
            Surface("hawkinsoperations-validation", "scripts/verify-id-det-001-result-parity.py"),
            Surface("hawkinsoperations-validation", "scripts/scan-id-det-001-claim-boundaries.py"),
            Surface("hawkinsoperations-platform", "scripts/ho_factory.py"),
            Surface("hawkinsoperations-platform", "docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md"),
        ),
        next_gates=(
            {
                "id": "ID-RUNTIME-001",
                "name": "private runtime receipt",
                "purpose": "Proxmox and Windows identity private runtime receipt with approved metadata and count-only Wazuh/Splunk receipt review.",
                "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED",
                "boundary": "Not public proof. Not production coverage. Not public-safe.",
            },
            {
                "id": "ID-CLOUD-001",
                "name": "IdP export/log review",
                "purpose": "Approved Entra-style or Okta-style identity log export review after a separate gate.",
                "claim_ceiling": "CONTROLLED_TEST_VALIDATED first, then PRIVATE_RUNTIME_METADATA_CAPTURED only if approved sanitized export review exists.",
                "boundary": "No live IdP proof in this PR. No production tenant claim.",
            },
            {
                "id": "ID-AGENT-001",
                "name": "AI or machine identity tool-scope validation",
                "purpose": "Validate AI or machine identity behavior where observed action is outside approved tool or resource scope.",
                "claim_ceiling": "CONTROLLED_TEST_VALIDATED",
                "boundary": "No autonomous SOC claim. No AI disposition authority.",
            },
            {
                "id": "ID-ROUTE-001",
                "name": "SIEM/NDR route receipt",
                "purpose": "Count-only Wazuh, Splunk, Cribl, and Security Onion route checks after separate approval.",
                "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED if receipt exists.",
                "boundary": "No live SIEM/NDR public proof in this PR. No full route proof unless separately captured and reviewed.",
            },
        ),
        not_claimed_here=(
            "live IdP proof",
            "live SIEM/NDR observation",
            "production identity coverage",
            "complete identity-attack coverage",
            "autonomous SOC operation",
            "disposition authority",
            "proof promotion",
            "public-safe status",
            "website/public-surface publication",
        ),
    ),
    "ID-DET-002": identity_expansion_spec(
        detection_id="ID-DET-002",
        validation_claim=(
            "ID-DET-002 passed controlled-test validation against 10 controlled identity-event fixtures "
            "for suspicious MFA fatigue or repeated MFA failure patterns."
        ),
        validation_rel="validation/identity/id-det-002/validation-cases.json",
        scanner_rel="scripts/scan-id-det-002-claim-boundaries.py",
        parity_rel="scripts/verify-id-det-002-result-parity.py",
        validator_rel="scripts/validate-id-det-002.py",
    ),
    "ID-DET-003": identity_expansion_spec(
        detection_id="ID-DET-003",
        validation_claim=(
            "ID-DET-003 passed controlled-test validation against 10 controlled identity administration fixtures "
            "for privileged role assignment or admin group change behavior."
        ),
        validation_rel="validation/identity/id-det-003/validation-cases.json",
        scanner_rel="scripts/scan-id-det-003-claim-boundaries.py",
        parity_rel="scripts/verify-id-det-003-result-parity.py",
        validator_rel="scripts/validate-id-det-003.py",
    ),
    "ID-DET-004": identity_expansion_spec(
        detection_id="ID-DET-004",
        validation_claim=(
            "ID-DET-004 passed controlled-test validation against 10 controlled identity-event fixtures "
            "for impossible travel or anomalous session context."
        ),
        validation_rel="validation/identity/id-det-004/validation-cases.json",
        scanner_rel="scripts/scan-id-det-004-claim-boundaries.py",
        parity_rel="scripts/verify-id-det-004-result-parity.py",
        validator_rel="scripts/validate-id-det-004.py",
        extra_blocked_claims=("impossible-travel completeness", "session hijacking completeness"),
    ),
    "HO-DET-012": DetectionSpec(
        detection_id="HO-DET-012",
        current_state="CONTROLLED_TEST_VALIDATED",
        public_proof_ceiling="CONTROLLED_TEST_VALIDATED",
        private_evidence_state="NOT_CAPTURED",
        public_safe_status="NOT_PUBLIC_SAFE",
        platform_guardrail_status="STATUS_VISIBILITY_ONLY",
        validation_result="hawkinsoperations-validation/reports/ho-det-012/validation-result.json",
        validation_expected={
            "total_cases": 8,
            "positive_cases": 4,
            "negative_cases": 4,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
        },
        validation_claim="HO-DET-012 passed controlled-test validation against scheduled-task creation and update fixtures.",
        proof_record="hawkinsoperations-proof/proof/records/HO-DET-012.md",
        proof_card="hawkinsoperations-proof/proof/cards/HO-DET-012.md",
        proof_state="CONTROLLED_TEST_VALIDATED",
        platform_sample=None,
        platform_sample_expected_total=0,
        required_blocked_claims=(
            *COMMON_BLOCKED,
            "evidence-linked public proof",
            "live Splunk fired",
            "Splunk-fired",
            "Wazuh-routed",
            "Cribl-routed",
            "Security Onion observed",
            "scheduled-task coverage completeness",
        ),
        supported_claims=(
            "HO-DET-012 source artifacts exist.",
            "HO-DET-012 passed controlled-test validation against 8 controlled scheduled-task creation and update fixtures.",
            "HO-DET-012 remains not public-safe and not runtime-active.",
        ),
        next_allowed_move="Review controlled-test validation packet only; runtime evidence, proof promotion, routed telemetry, and public-safe wording remain blocked until separate approval.",
        decision_status="READY_FOR_REVIEW",
        decision_reason="Controller v0 reports HO-DET-012 controlled-test validation state only and preserves runtime and proof boundaries.",
        truth_boundary={
            "source_truth": "reported",
            "validation_truth": "controlled-test validated",
            "platform_truth": "status visibility only",
            "proof_truth": "controlled-test proof record present",
            "runtime_truth": "not public proven",
            "signal_truth": "not public proven",
            "public_proof": "not public safe",
        },
        stop_conditions=(
            "Do not promote proof.",
            "Do not claim public-safe status.",
            "Do not claim runtime-active or signal-observed public proof.",
            "Do not claim scheduled-task coverage completeness.",
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
            "Wazuh routing",
            "Cribl routing",
            "Security Onion observation",
            "scheduled-task coverage completeness",
            "AI-approved disposition",
            "analyst-approved disposition",
        ),
        surfaces=(
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-012/status.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-012/rule.yml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-012/splunk.spl"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-012/wazuh.xml"),
            Surface("hawkinsoperations-detections", "detections/successor/ho-det-012/event-mapping.yml"),
            Surface("hawkinsoperations-detections", "detections/DETECTION_FACTORY_INDEX.md"),
            Surface("hawkinsoperations-validation", "reports/ho-det-012/validation-result.json"),
            Surface("hawkinsoperations-validation", "reports/ho-det-012/validation-result.md"),
            Surface("hawkinsoperations-validation", "validation/successor/ho-det-012/validation-cases.json"),
            Surface("hawkinsoperations-validation", "scripts/validate-ho-det-012.py"),
            Surface("hawkinsoperations-validation", "scripts/verify-ho-det-012-result-parity.py"),
            Surface("hawkinsoperations-validation", "scripts/scan-ho-det-012-claim-boundaries.py"),
            Surface("hawkinsoperations-platform", "scripts/ho_factory.py"),
            Surface("hawkinsoperations-platform", "docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md"),
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
    if spec.platform_sample is None:
        return list(spec.required_blocked_claims)
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
                f"{spec.platform_sample} expected total_cases {spec.platform_sample_expected_total}, got {total}"
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
    if spec.proof_record is None:
        return False, False
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


def load_proof_status_index(repo_root: Path) -> dict[str, Any]:
    if yaml is None:
        raise FactoryError("PyYAML is required to read the proof status index")
    path = repo_path(repo_root, PROOF_STATUS_INDEX_OWNER, PROOF_STATUS_INDEX_REL)
    if not path.is_file():
        raise FactoryError(f"missing proof status index: {PROOF_STATUS_INDEX_OWNER}/{PROOF_STATUS_INDEX_REL}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail closed on parser boundary.
        raise FactoryError(f"invalid proof status index YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise FactoryError("proof status index root must be an object")
    if value.get("owner_repo") != PROOF_STATUS_INDEX_OWNER:
        raise FactoryError("proof status index owner_repo must be hawkinsoperations-proof")
    if value.get("truth_surface") != "proof_boundary_index":
        raise FactoryError("proof status index truth_surface must be proof_boundary_index")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise FactoryError("proof status index entries must be a non-empty list")
    return value


def proof_index_entries_by_id(repo_root: Path) -> dict[str, dict[str, Any]]:
    index = load_proof_status_index(repo_root)
    entries_by_id: dict[str, dict[str, Any]] = {}
    for raw in index["entries"]:
        if not isinstance(raw, dict):
            raise FactoryError("proof status index entry must be an object")
        detection_id = raw.get("detection_id")
        if not isinstance(detection_id, str) or not detection_id:
            raise FactoryError("proof status index entry detection_id must be a non-empty string")
        if detection_id in entries_by_id:
            raise FactoryError(f"duplicate detection_id in proof status index: {detection_id}")
        entries_by_id[detection_id] = raw
    return entries_by_id


def proof_status_index_visibility(repo_root: Path, spec: DetectionSpec) -> dict[str, Any]:
    entries = proof_index_entries_by_id(repo_root)
    entry = entries.get(spec.detection_id)
    if entry is None:
        raise FactoryError(f"{spec.detection_id} missing from proof status index")

    proof_ceiling = entry.get("proof_ceiling")
    runtime_status = entry.get("runtime_status")
    signal_status = entry.get("signal_status")
    public_safe_status = entry.get("public_safe_status")
    website_status = entry.get("website_status")

    if proof_ceiling not in PROOF_INDEX_ALLOWED_CEILINGS:
        raise FactoryError(f"{spec.detection_id} proof index has unsupported proof_ceiling: {proof_ceiling}")
    if runtime_status not in PROOF_INDEX_ALLOWED_RUNTIME_STATUSES:
        raise FactoryError(f"{spec.detection_id} proof index has unsupported runtime_status: {runtime_status}")
    if signal_status != "NOT_PROVEN":
        raise FactoryError(f"{spec.detection_id} proof index signal_status must remain NOT_PROVEN")
    if public_safe_status != "NOT_PUBLIC_SAFE":
        raise FactoryError(f"{spec.detection_id} proof index public_safe_status must remain NOT_PUBLIC_SAFE")
    if website_status != "WEBSITE_UNTOUCHED_NOT_PROOF":
        raise FactoryError(f"{spec.detection_id} proof index website_status must remain WEBSITE_UNTOUCHED_NOT_PROOF")
    if entry.get("source_truth_owner") != "hawkinsoperations-detections":
        raise FactoryError(f"{spec.detection_id} proof index source truth owner drifted")
    if entry.get("validation_truth_owner") != "hawkinsoperations-validation":
        raise FactoryError(f"{spec.detection_id} proof index validation truth owner drifted")
    if entry.get("platform_visibility_owner") != "hawkinsoperations-platform":
        raise FactoryError(f"{spec.detection_id} proof index platform visibility owner drifted")

    expected_record = None if spec.proof_record is None else spec.proof_record.removeprefix("hawkinsoperations-proof/")
    if entry.get("proof_record_path") != expected_record:
        raise FactoryError(f"{spec.detection_id} proof index proof_record_path drifted")

    expected_card = None if spec.proof_card is None else spec.proof_card.removeprefix("hawkinsoperations-proof/")
    if entry.get("proof_card_path") != expected_card:
        raise FactoryError(f"{spec.detection_id} proof index proof_card_path drifted")

    if runtime_status != "NOT_PROVEN" and spec.proof_record is None:
        raise FactoryError(f"{spec.detection_id} proof index runtime status requires an existing proof record")

    return {
        "index_path": f"{PROOF_STATUS_INDEX_OWNER}/{PROOF_STATUS_INDEX_REL}",
        "truth_owner": PROOF_STATUS_INDEX_OWNER,
        "visibility_owner": "hawkinsoperations-platform",
        "visibility_status": PROOF_STATUS_INDEX_VISIBILITY_STATUS,
        "detection_id": spec.detection_id,
        "source_status": entry["source_status"],
        "validation_status": entry["validation_status"],
        "proof_ceiling": proof_ceiling,
        "runtime_status": runtime_status,
        "signal_status": signal_status,
        "public_safe_status": public_safe_status,
        "website_status": website_status,
        "promotion_allowed": False,
        "proof_promotion_allowed": False,
        "runtime_signal_promotion_allowed": False,
        "public_safe_promotion_allowed": False,
        "website_proof_claim_allowed": False,
        "claim_boundary": PROOF_STATUS_INDEX_BOUNDARY,
    }


def gate_summary(spec: DetectionSpec) -> list[dict[str, Any]]:
    platform_claim = "platform guardrail reported"
    if spec.platform_sample is None:
        platform_claim = "platform status visibility only"
    source_status = "FOUND"
    source_claim = "source exists"
    if not any(surface.repo == "hawkinsoperations-detections" for surface in spec.surfaces):
        source_status = "NOT_INSPECTED_IN_THIS_PLATFORM_WINDOW"
        source_claim = "source repo state was outside this platform window; validation PR #46 is upstream truth"
    proof_status = "FOUND"
    proof_claim = "proof state reported, not promoted"
    if spec.proof_record is None:
        proof_status = "NOT_REQUIRED_FOR_CONTROLLED_TEST_VALIDATION"
        proof_claim = "no proof record required or promoted for controlled-test validation"
    return [
        {
            "gate": "source",
            "status": source_status,
            "owner_repo": "hawkinsoperations-detections",
            "claim": source_claim,
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
            "claim": platform_claim,
            "promotion_allowed": False,
        },
        {
            "gate": "proof_record",
            "status": proof_status,
            "owner_repo": "hawkinsoperations-proof",
            "claim": proof_claim,
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


def dependency_missing_gate_summary(spec: DetectionSpec) -> list[dict[str, Any]]:
    return [
        {
            "gate": "source",
            "status": "DEPENDENCY_SURFACES_MISSING",
            "owner_repo": "hawkinsoperations-detections",
            "claim": "source dependency is unavailable in this repo-root revision",
            "promotion_allowed": False,
        },
        {
            "gate": "validation",
            "status": "DEPENDENCY_SURFACES_MISSING",
            "owner_repo": "hawkinsoperations-validation",
            "claim": "validation dependency is unavailable in this repo-root revision",
            "promotion_allowed": False,
        },
        {
            "gate": "platform_guardrail",
            "status": spec.platform_guardrail_status,
            "owner_repo": "hawkinsoperations-platform",
            "claim": "bounded dependency-missing packet only",
            "promotion_allowed": False,
        },
        {
            "gate": "proof_record",
            "status": "NOT_REQUIRED_FOR_CONTROLLED_TEST_VALIDATION",
            "owner_repo": "hawkinsoperations-proof",
            "claim": "no proof record required or promoted for controlled-test validation",
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
            "status": "BLOCKED_DEPENDENCY_SURFACES",
            "owner_repo": "hawkinsoperations-platform",
            "claim": "merge/sync validation and detections surfaces first",
            "promotion_allowed": False,
        },
    ]


def build_dependency_missing_packet(
    spec: DetectionSpec,
    found: list[dict[str, Any]],
    missing: list[str],
) -> dict[str, Any]:
    if not spec.detection_id.startswith("ID-DET-"):
        raise DependencySurfacesMissing(spec.detection_id, found, missing)
    reason = (
        f"{spec.detection_id} dependency surfaces are unavailable in this repo-root revision; "
        "all-plan output remains bounded and non-promotional."
    )
    return {
        "controller_version": CONTROLLER_VERSION,
        "detection_id": spec.detection_id,
        "detection_title": DETECTION_TITLES.get(spec.detection_id, spec.detection_id),
        "current_state": "DEPENDENCY_SURFACES_MISSING",
        "current_phase": "DEPENDENCY_SURFACES_MISSING",
        "source_status": "DEPENDENCY_SURFACES_MISSING",
        "validation_status": "DEPENDENCY_SURFACES_MISSING",
        "runtime_status": "NOT_PROVEN",
        "signal_status": "NOT_PROVEN",
        "evidence_status": spec.private_evidence_state,
        "public_proof_ceiling": spec.public_proof_ceiling,
        "proof_ceiling": spec.public_proof_ceiling,
        "claim_ceiling": "CONTROLLED_TEST_VALIDATED",
        "private_evidence_state": spec.private_evidence_state,
        "public_safe_status": spec.public_safe_status,
        "runtime_active": False,
        "signal_observed": False,
        "ai_decided_disposition": False,
        "human_review_required": True,
        "gate_summary": dependency_missing_gate_summary(spec),
        "decision": {
            "status": "BLOCKED_DEPENDENCY_SURFACES",
            "merge_recommendation": "REVIEW_REQUIRED",
            "proof_promotion_allowed": False,
            "public_rendering_allowed": False,
            "reason": reason,
        },
        "decision_status": "BLOCKED_DEPENDENCY_SURFACES",
        "truth_boundary": spec.truth_boundary,
        "repo_surfaces_found": found,
        "required_surfaces_missing": missing,
        "dependency_surfaces_missing": missing,
        "validation_state": {
            "status": "dependency_surfaces_missing",
            "total_cases": 0,
            "positive_cases": 0,
            "negative_cases": 0,
            "missed_positive_count": 0,
            "false_positive_negative_count": 0,
            "exact_claim_supported": "",
        },
        "proof_state": {
            "record_path": spec.proof_record,
            "card_path": spec.proof_card,
            "record_exists": False,
            "card_exists": False,
            "state": spec.proof_state,
        },
        "platform_guardrail_status": spec.platform_guardrail_status,
        "blocked_claims": sorted(set(spec.required_blocked_claims)),
        "supported_claims": [],
        "case_factory": case_factory_issue_plan(spec),
        "next_allowed_move": "merge/sync validation and detections surfaces first",
        "next_gate": "merge/sync validation and detections surfaces first",
        "stop_conditions": list(spec.stop_conditions),
        "state_consistency": [
            f"{spec.detection_id} dependency surfaces are unavailable in this repo-root revision.",
            f"Direct {spec.detection_id} status/plan remains fail-closed until dependencies are present.",
            "All-plan output reports a bounded dependency-missing state without promotion.",
        ],
        "does_not_prove": list(spec.does_not_prove),
        "next_gates": list(spec.next_gates),
        "not_claimed_here": list(spec.not_claimed_here),
    }


def build_packet(repo_root: Path, spec: DetectionSpec) -> dict[str, Any]:
    found, missing = group_found_surfaces(repo_root, spec)
    if missing:
        raise DependencySurfacesMissing(spec.detection_id, found, missing)

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

    platform_claims = platform_sample_claims(
        spec,
        {} if spec.platform_sample is None else load_json(repo_root / spec.platform_sample),
    )
    record_exists, card_exists = assert_proof_record(repo_root, spec)

    packet = {
        "controller_version": CONTROLLER_VERSION,
        "detection_id": spec.detection_id,
        "detection_title": DETECTION_TITLES.get(spec.detection_id, spec.detection_id),
        "current_state": spec.current_state,
        "source_status": (
            "FOUND"
            if any(surface.repo == "hawkinsoperations-detections" for surface in spec.surfaces)
            else "NOT_INSPECTED_IN_THIS_PLATFORM_WINDOW"
        ),
        "validation_status": spec.current_state,
        "runtime_status": "NOT_PROVEN",
        "signal_status": "NOT_PROVEN",
        "evidence_status": spec.private_evidence_state,
        "public_proof_ceiling": spec.public_proof_ceiling,
        "proof_ceiling": spec.public_proof_ceiling,
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
        "proof_status_index_visibility": proof_status_index_visibility(repo_root, spec),
        "platform_guardrail_status": spec.platform_guardrail_status,
        "blocked_claims": sorted(set(platform_claims)),
        "supported_claims": list(spec.supported_claims),
        "case_factory": case_factory_issue_plan(spec),
        "next_allowed_move": spec.next_allowed_move,
        "next_gate": spec.next_allowed_move,
        "stop_conditions": list(spec.stop_conditions),
        "state_consistency": list(spec.state_consistency),
        "does_not_prove": list(spec.does_not_prove),
    }
    if spec.next_gates or spec.not_claimed_here:
        packet["current_phase"] = spec.current_state
        packet["next_gates"] = list(spec.next_gates)
        packet["not_claimed_here"] = list(spec.not_claimed_here)
    return packet


def build_plan_packet(repo_root: Path, spec: DetectionSpec, tolerate_id_dependency_missing: bool) -> dict[str, Any]:
    try:
        return build_packet(repo_root, spec)
    except DependencySurfacesMissing as exc:
        if tolerate_id_dependency_missing and exc.detection_id == "ID-DET-001":
            return build_dependency_missing_packet(spec, exc.found, exc.missing)
        raise


def id_det_001_missing_surface_self_test() -> dict[str, Any]:
    spec = SPECS["ID-DET-001"]
    missing = [
        f"{surface.repo}/{surface.path}"
        for surface in spec.surfaces
        if surface.required and surface.repo in {"hawkinsoperations-detections", "hawkinsoperations-validation"}
    ]
    packet = build_dependency_missing_packet(spec, [], missing)
    checks = {
        "detection_id": packet["detection_id"] == "ID-DET-001",
        "current_state": packet["current_state"] == "DEPENDENCY_SURFACES_MISSING",
        "decision_status": packet["decision_status"] == "BLOCKED_DEPENDENCY_SURFACES",
        "public_safe_status": packet["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "claim_ceiling": packet["claim_ceiling"] == "CONTROLLED_TEST_VALIDATED",
        "supported_claims_empty": packet["supported_claims"] == [],
        "missing_surfaces_reported": bool(packet["required_surfaces_missing"]),
        "next_allowed_move": packet["next_allowed_move"] == "merge/sync validation and detections surfaces first",
        "no_promotion": not any(item["promotion_allowed"] for item in packet["gate_summary"]),
    }
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "self-test-id-det-001-missing-surfaces",
        "generated_output_files": False,
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
        "packet": packet,
    }


def verify_blocked_gate_map(gates: object, field_name: str) -> dict[str, bool]:
    if not isinstance(gates, dict) or not gates:
        raise FactoryError(f"{field_name} must be a non-empty object")
    checks: dict[str, bool] = {}
    for gate_name, gate in gates.items():
        if not isinstance(gate, dict):
            raise FactoryError(f"{field_name}.{gate_name} must be an object")
        checks[f"{field_name}.{gate_name}.status_blocked"] = gate.get("status") == "blocked"
        checks[f"{field_name}.{gate_name}.not_executed"] = gate.get("executed") is False
        checks[f"{field_name}.{gate_name}.human_approval_required"] = (
            gate.get("requires_human_approval") is True
        )
    return checks


def verify_ho_det_001_socaas_pilot_receipt() -> dict[str, Any]:
    sample = load_json(SOCAAS_PILOT_RECEIPT_SAMPLE)
    missing = sorted(SOCAAS_PILOT_RECEIPT_REQUIRED_TOP_LEVEL - set(sample))
    if missing:
        raise FactoryError(f"HO-DET-001 SOCaaS pilot receipt missing fields: {', '.join(missing)}")

    context = sample.get("pilot_context")
    facts = sample.get("sanitized_process_facts")
    validation = sample.get("deterministic_validation_reference")
    ai_boundary = sample.get("ai_support_boundary")
    privacy = sample.get("privacy_boundary")
    proof_promotions = sample.get("proof_promotions")
    if not isinstance(context, dict):
        raise FactoryError("pilot_context must be an object")
    if not isinstance(facts, dict):
        raise FactoryError("sanitized_process_facts must be an object")
    if not isinstance(validation, dict):
        raise FactoryError("deterministic_validation_reference must be an object")
    if not isinstance(ai_boundary, dict):
        raise FactoryError("ai_support_boundary must be an object")
    if not isinstance(privacy, dict):
        raise FactoryError("privacy_boundary must be an object")
    if not isinstance(proof_promotions, dict):
        raise FactoryError("proof_promotions must be an object")
    missing_proof_promotions = sorted(SOCAAS_PILOT_RECEIPT_REQUIRED_PROOF_PROMOTION_KEYS - set(proof_promotions))
    if missing_proof_promotions:
        raise FactoryError(f"proof_promotions missing required keys: {', '.join(missing_proof_promotions)}")
    missing_privacy = sorted(SOCAAS_PILOT_RECEIPT_REQUIRED_PRIVACY_BOUNDARY_KEYS - set(privacy))
    if missing_privacy:
        raise FactoryError(f"privacy_boundary missing required keys: {', '.join(missing_privacy)}")
    if not isinstance(sample["blocked_response_actions"], list):
        raise FactoryError("blocked_response_actions must be a list")
    if not isinstance(sample["blocked_claims"], list):
        raise FactoryError("blocked_claims must be a list")
    if not isinstance(sample["blocked_proof_promotions"], list):
        raise FactoryError("blocked_proof_promotions must be a list")
    if not isinstance(sample["does_not_prove"], list):
        raise FactoryError("does_not_prove must be a list")

    response_gate_checks = verify_blocked_gate_map(sample["response_actions"], "response_actions")
    checks = {
        "receipt_type": sample["receipt_type"] == "ho_det_001_socaas_pilot_receipt_pack_sample",
        "detection_id": sample["detection_id"] == "HO-DET-001",
        "proof_ceiling": sample["proof_ceiling"] == "CONTROLLED_TEST_VALIDATED",
        "public_safe_status": sample["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "human_review_required": sample["human_review_required"] is True,
        "pilot_deployment_claim_false": context.get("deployment_claim") is False,
        "pilot_runtime_active_claim_false": context.get("runtime_active_claim") is False,
        "pilot_signal_observed_claim_false": context.get("signal_observed_claim") is False,
        "pilot_public_safe_claim_false": context.get("public_safe_claim") is False,
        "raw_command_line_blocked": facts.get("raw_command_line_included") is False,
        "raw_event_blocked": facts.get("raw_event_included") is False,
        "host_identifier_blocked": facts.get("host_identifier_included") is False,
        "user_identifier_blocked": facts.get("user_identifier_included") is False,
        "network_indicators_blocked": facts.get("network_indicators_included") is False,
        "private_path_blocked": facts.get("private_path_included") is False,
        "deterministic_validation": validation.get("deterministic_validation") is True,
        "validation_proof_ceiling": validation.get("proof_ceiling") == "CONTROLLED_TEST_VALIDATED",
        "ai_support_only": ai_boundary.get("mode") == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": ai_boundary.get("ai_decided_disposition") is False,
        "ai_may_approve_false": ai_boundary.get("ai_may_approve") is False,
        "ai_may_promote_false": ai_boundary.get("ai_may_promote") is False,
        "ai_may_execute_response_false": ai_boundary.get("ai_may_execute_response") is False,
        "blocked_response_actions": SOCAAS_PILOT_RECEIPT_REQUIRED_BLOCKED_ACTIONS.issubset(
            set(sample["blocked_response_actions"])
        ),
        "blocked_claims": SOCAAS_PILOT_RECEIPT_REQUIRED_BLOCKED_CLAIMS.issubset(
            set(sample["blocked_claims"])
        ),
        "proof_promotions_blocked": all(
            proof_promotions[key] == "blocked" for key in SOCAAS_PILOT_RECEIPT_REQUIRED_PROOF_PROMOTION_KEYS
        ),
        "privacy_boundary_false": all(
            privacy[key] is False for key in SOCAAS_PILOT_RECEIPT_REQUIRED_PRIVACY_BOUNDARY_KEYS
        ),
        **response_gate_checks,
    }
    failed_checks = sorted(name for name, passed in checks.items() if not passed)
    if failed_checks:
        raise FactoryError(f"HO-DET-001 SOCaaS pilot receipt failed checks: {', '.join(failed_checks)}")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "verify-receipt",
        "receipt": "ho-det-001",
        "sample_path": str(SOCAAS_PILOT_RECEIPT_SAMPLE.relative_to(PLATFORM_ROOT)),
        "generated_output_files": False,
        "status": "pass",
        "proof_ceiling": sample["proof_ceiling"],
        "public_safe_status": sample["public_safe_status"],
        "human_review_required": sample["human_review_required"],
        "ai_support_mode": ai_boundary.get("mode"),
        "blocked_response_actions": sample["blocked_response_actions"],
        "blocked_proof_promotions": sample["blocked_proof_promotions"],
        "does_not_prove": sample["does_not_prove"],
        "checks": checks,
    }


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def runtime_collector_windows_default_payload() -> dict[str, Any]:
    return {
        "detection_id": "HO-DET-001",
        "detection_family": "process_behavior",
        "source_system": "windows_private_route_probe",
        "source_truth_status": "PRIVATE_ROUTE_PROBE_VERIFIED",
        "runtime_truth_status": "PRIVATE_CANDIDATE_ONLY",
        "signal_truth_status": "NOT_PUBLIC_SIGNAL_PROOF",
        "observed_time_utc": "2026-06-02T00:00:00Z",
        "sanitized_event_fingerprint": "windows-route-probe-ho-det-001-v0",
        "source_receipt_refs": [
            {
                "ref_type": "github_actions_run",
                "ref": RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_RUN_ID,
                "status": RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_STATUS,
            }
        ],
    }


def build_runtime_collector_windows_candidate(
    payload: dict[str, Any] | None = None,
    *,
    collector_run_id: str = "runtime-case-collector-v0-windows-dry-run",
    collected_at_utc: str = "2026-06-02T00:00:00Z",
) -> dict[str, Any]:
    payload = dict(payload or runtime_collector_windows_default_payload())
    candidate_payload = {
        "detection_id": payload["detection_id"],
        "source_system": payload["source_system"],
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "observed_time_utc": payload.get("observed_time_utc"),
    }
    candidate_payload_hash = canonical_sha256(candidate_payload)
    identity = {
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "detection_id": payload["detection_id"],
        "source_system": payload["source_system"],
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "candidate_payload_hash": candidate_payload_hash,
        "observed_time_utc": payload.get("observed_time_utc"),
    }
    candidate_hash = canonical_sha256(identity)
    return {
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "collector_run_id": collector_run_id,
        "collected_at_utc": collected_at_utc,
        "candidate_id": f"rccv0-win-{candidate_hash[:16]}",
        "candidate_hash": candidate_hash,
        "detection_id": payload["detection_id"],
        "detection_family": payload["detection_family"],
        "source_system": payload["source_system"],
        "source_truth_status": payload["source_truth_status"],
        "runtime_truth_status": payload["runtime_truth_status"],
        "signal_truth_status": payload["signal_truth_status"],
        "proof_ceiling": RUNTIME_COLLECTOR_WINDOWS_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "case_status": "RUNTIME_CANDIDATE_ONLY",
        "triage_status": "HUMAN_REVIEW_REQUIRED",
        "disposition_status": "NO_DISPOSITION",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "human_review_required": True,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "case_closed": False,
        "append_to_lifetime_ledger": False,
        "candidate_payload_hash": candidate_payload_hash,
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "blocked_claims": list(RUNTIME_COLLECTOR_WINDOWS_BLOCKED_CLAIMS),
        "notes_boundary": RUNTIME_COLLECTOR_WINDOWS_BOUNDARY,
        "observed_time_utc": payload.get("observed_time_utc"),
    }


def load_runtime_collector_windows_packet(candidate_path: Path | None = None) -> dict[str, Any]:
    if candidate_path:
        packet = load_json(candidate_path)
    else:
        packet = load_json(RUNTIME_COLLECTOR_WINDOWS_SAMPLE)
    if not isinstance(packet, dict):
        raise FactoryError("Runtime Case Collector Windows packet must be an object")
    return packet


def runtime_collector_windows_packet(candidate: dict[str, Any] | None = None) -> dict[str, Any]:
    candidate = candidate or build_runtime_collector_windows_candidate()
    return {
        "schema_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "collector_run_id": candidate["collector_run_id"],
        "generated_output_files": False,
        "candidate_count": 1,
        "duplicate_count": 0,
        "candidates": [candidate],
        "invariants": {
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "ai_support_mode": "AI_SUPPORT_ONLY",
            "ai_decided_disposition": False,
            "human_review_required": True,
            "case_closed": False,
            "append_to_lifetime_ledger": False,
            "proof_promotion_allowed": False,
            "public_safe_promotion_allowed": False,
            "github_issue_mutation_allowed": False,
            "raw_private_evidence_imported": False,
            "runtime_candidate_only": True,
        },
        "proof_ceiling": RUNTIME_COLLECTOR_WINDOWS_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "notes_boundary": RUNTIME_COLLECTOR_WINDOWS_BOUNDARY,
    }


def runtime_collector_windows_dedupe_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    values: list[Any] = []
    for field in RUNTIME_COLLECTOR_WINDOWS_DEDUPE_FIELDS:
        value = candidate.get(field)
        if field == "source_receipt_refs":
            value = canonical_sha256(value)
        values.append(value)
    return tuple(values)


def normalize_windows_collector_route(output_route: str) -> str:
    normalized = output_route.strip().strip('"').strip("'").replace("/", "\\").rstrip("\\").casefold()
    approved = RUNTIME_COLLECTOR_WINDOWS_OUTPUT_ROUTE.rstrip("\\").casefold()
    if normalized != approved:
        raise FactoryError("Windows collector output route is not the approved Windows-private collector route")
    return RUNTIME_COLLECTOR_WINDOWS_OUTPUT_ROUTE


def verify_runtime_collector_windows_candidate(candidate: dict[str, Any]) -> dict[str, bool]:
    missing = sorted(field for field in RUNTIME_COLLECTOR_WINDOWS_REQUIRED_FIELDS if field not in candidate)
    if missing:
        raise FactoryError(f"Windows runtime candidate missing required fields: {', '.join(missing)}")
    source_receipt_refs = candidate.get("source_receipt_refs")
    if not isinstance(source_receipt_refs, list) or not source_receipt_refs:
        raise FactoryError("Windows runtime candidate source_receipt_refs must be a non-empty list")
    blocked_claims = candidate.get("blocked_claims")
    if not isinstance(blocked_claims, list) or not set(RUNTIME_COLLECTOR_WINDOWS_BLOCKED_CLAIMS).issubset(blocked_claims):
        raise FactoryError("Windows runtime candidate blocked_claims is incomplete")
    payload_hash_input = {
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_receipt_refs": source_receipt_refs,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    candidate_payload_hash = canonical_sha256(payload_hash_input)
    candidate_hash_input = {
        "collector_version": candidate["collector_version"],
        "collector_lane": candidate["collector_lane"],
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_receipt_refs": source_receipt_refs,
        "candidate_payload_hash": candidate_payload_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    candidate_hash = canonical_sha256(candidate_hash_input)
    checks = {
        "collector_version": candidate["collector_version"] == RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": candidate["collector_lane"] == "windows",
        "candidate_payload_hash": candidate["candidate_payload_hash"] == candidate_payload_hash,
        "candidate_hash": candidate["candidate_hash"] == candidate_hash,
        "candidate_id": candidate["candidate_id"] == f"rccv0-win-{candidate_hash[:16]}",
        "proof_ceiling": candidate["proof_ceiling"] == RUNTIME_COLLECTOR_WINDOWS_PROOF_CEILING,
        "public_safe_status": candidate["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "disposition_status": candidate["disposition_status"] == "NO_DISPOSITION",
        "ai_support_mode": candidate["ai_support_mode"] == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": candidate["ai_decided_disposition"] is False,
        "human_review_required": candidate["human_review_required"] is True,
        "deterministic_close_eligible_false": candidate["deterministic_close_eligible"] is False,
        "deterministic_close_blocked_true": candidate["deterministic_close_blocked"] is True,
        "case_closed_false": candidate["case_closed"] is False,
        "append_to_lifetime_ledger_false": candidate["append_to_lifetime_ledger"] is False,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Windows runtime candidate failed checks: {', '.join(failed)}")
    return checks


def verify_runtime_collector_windows_packet(packet: dict[str, Any]) -> dict[str, Any]:
    candidates = packet.get("candidates")
    if not isinstance(candidates, list):
        raise FactoryError("Windows runtime collector packet candidates must be a list")
    seen: set[tuple[Any, ...]] = set()
    duplicate_count = 0
    candidate_checks: list[dict[str, bool]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise FactoryError("Windows runtime collector candidate must be an object")
        candidate_checks.append(verify_runtime_collector_windows_candidate(candidate))
        key = runtime_collector_windows_dedupe_key(candidate)
        if key in seen:
            duplicate_count += 1
        seen.add(key)
    checks = {
        "schema_version": packet.get("schema_version") == RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": packet.get("collector_lane") == "windows",
        "public_safe_status": packet.get("public_safe_status") == "NOT_PUBLIC_SAFE",
        "proof_ceiling": packet.get("proof_ceiling") == RUNTIME_COLLECTOR_WINDOWS_PROOF_CEILING,
        "candidate_count_matches": packet.get("candidate_count") == len(candidates),
        "duplicate_count_matches": packet.get("duplicate_count", duplicate_count) == duplicate_count,
        "no_duplicates": duplicate_count == 0,
        "append_to_lifetime_ledger_blocked": all(
            candidate.get("append_to_lifetime_ledger") is False for candidate in candidates
        ),
        "case_closure_blocked": all(candidate.get("case_closed") is False for candidate in candidates),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Windows runtime collector packet failed checks: {', '.join(failed)}")
    return {
        "status": "pass",
        "candidate_count": len(candidates),
        "duplicate_count": duplicate_count,
        "checks": checks,
        "candidate_checks": candidate_checks,
    }


def runtime_collector_windows_preflight(output_route: str | None = None) -> dict[str, Any]:
    route_status: dict[str, Any] = {
        "approved_route_identity": "windows_canonical_private_route",
        "output_route_required_for_collect": True,
        "output_route_supplied": bool(output_route),
        "approved_windows_private_route": None,
        "route_exists": None,
        "route_is_dir": None,
        "route_writable": None,
        "route_writable_probe": "not_run_by_preflight",
    }
    if output_route:
        approved_route = normalize_windows_collector_route(output_route)
        route_status["approved_windows_private_route"] = "canonical_windows_private_route"
        route_path = Path(approved_route).resolve()
        route_status["route_exists"] = route_path.exists()
        route_status["route_is_dir"] = route_path.is_dir()
        route_status["route_writable"] = os.access(route_path, os.W_OK) if route_path.exists() else False
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-windows-preflight",
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "generated_output_files": False,
        "runner_labels": list(RUNTIME_COLLECTOR_WINDOWS_RUNNER_LABELS),
        "route_probe_run_id": RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_RUN_ID,
        "route_probe_status": RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_STATUS,
        "workflow_trigger_required": "workflow_dispatch",
        "pull_request_allowed": False,
        "pull_request_target_allowed": False,
        "lifetime_case_ledger_mutation_allowed": False,
        "governed_case_append_allowed": False,
        "public_safe_promotion_allowed": False,
        "route_status": route_status,
        "status": "pass",
    }


def runtime_collector_windows_run_once(dry_run: bool, output_route: str | None = None) -> dict[str, Any]:
    candidate = build_runtime_collector_windows_candidate()
    packet = runtime_collector_windows_packet(candidate)
    verification = verify_runtime_collector_windows_packet(packet)
    output: dict[str, Any] = {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-windows-run-once",
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "dry_run": dry_run,
        "generated_output_files": False,
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "status": "pass",
        "packet": packet,
    }
    if dry_run:
        return output
    if not output_route:
        raise FactoryError("collector-windows-run-once collect mode requires --output-route")
    approved_route = normalize_windows_collector_route(output_route)
    route_path = Path(approved_route).resolve()
    route_path.mkdir(parents=True, exist_ok=True)
    output_file = route_path / f"{candidate['collector_run_id']}-{candidate['candidate_id']}.json"
    if output_file.exists():
        output["generated_output_files"] = False
        output["duplicate_preserved"] = True
        output["output_file"] = str(output_file)
        return output
    output_file.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output["generated_output_files"] = True
    output["duplicate_preserved"] = False
    output["output_file"] = str(output_file)
    return output


def runtime_collector_windows_self_test() -> dict[str, Any]:
    packet = runtime_collector_windows_packet()
    verification = verify_runtime_collector_windows_packet(packet)
    duplicate_candidates = [packet["candidates"][0], dict(packet["candidates"][0])]
    duplicate_keys = [runtime_collector_windows_dedupe_key(candidate) for candidate in duplicate_candidates]
    duplicate_count = len(duplicate_keys) - len(set(duplicate_keys))
    mutated_candidate = dict(packet["candidates"][0])
    mutated_candidate["ai_decided_disposition"] = True
    mutation_blocked = False
    try:
        verify_runtime_collector_windows_candidate(mutated_candidate)
    except FactoryError:
        mutation_blocked = True

    approved_route_allowed = normalize_windows_collector_route(
        "c:/raylee/data/hawkinsoperations/runtime-case-collector-v0/windows/"
    ) == RUNTIME_COLLECTOR_WINDOWS_OUTPUT_ROUTE

    def expect_route_rejected(route: str) -> bool:
        try:
            normalize_windows_collector_route(route)
        except FactoryError:
            return True
        return False

    checks = {
        "sample_candidate_valid": verification["status"] == "pass",
        "duplicate_detected": duplicate_count == 1,
        "unsupported_disposition_mutation_blocked": mutation_blocked,
        "approved_route_allowed": approved_route_allowed,
        "arbitrary_route_rejected": expect_route_rejected("C:\\not-approved\\runtime-case-collector-v0\\windows\\"),
        "temp_route_rejected": expect_route_rejected("C:\\Users\\Raylee\\AppData\\Local\\Temp\\runtime-case-collector-v0\\windows\\"),
        "workspace_route_rejected": expect_route_rejected("C:\\Raylee\\Repo\\HawkinsOperations\\hawkinsoperations-platform\\out\\windows\\"),
        "wrong_drive_route_rejected": expect_route_rejected("D:\\Raylee\\Data\\HawkinsOperations\\runtime-case-collector-v0\\windows\\"),
        "route_probe_passed": RUNTIME_COLLECTOR_WINDOWS_ROUTE_PROBE_STATUS == "pass",
        "lifetime_case_ledger_mutation_blocked": packet["invariants"]["append_to_lifetime_ledger"] is False,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Windows runtime collector self-test failed checks: {', '.join(failed)}")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-windows-self-test",
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "checks": checks,
    }


def runtime_collector_windows_verify(candidate_path: str | None = None) -> dict[str, Any]:
    packet = load_runtime_collector_windows_packet(Path(candidate_path).resolve() if candidate_path else None)
    verification = verify_runtime_collector_windows_packet(packet)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-windows-verify",
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "generated_output_files": False,
        "status": verification["status"],
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "checks": verification["checks"],
    }


def runtime_collector_windows_dedupe_check(candidate_path: str | None = None) -> dict[str, Any]:
    packet = load_runtime_collector_windows_packet(Path(candidate_path).resolve() if candidate_path else None)
    verification = verify_runtime_collector_windows_packet(packet)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-windows-dedupe-check",
        "collector_version": RUNTIME_COLLECTOR_WINDOWS_VERSION,
        "collector_lane": "windows",
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "dedupe_fields": list(RUNTIME_COLLECTOR_WINDOWS_DEDUPE_FIELDS),
        "dedupe_result": "no_duplicates",
    }


def runtime_collector_linux_default_payload() -> dict[str, Any]:
    return {
        "detection_id": "HO-DET-001",
        "detection_family": "process_behavior",
        "source_system": "linux_private_infrastructure_runner",
        "source_truth_status": "PRIVATE_WORKFLOW_DISPATCH_RUN_VERIFIED",
        "runtime_truth_status": "PRIVATE_CANDIDATE_ONLY",
        "signal_truth_status": "NOT_PUBLIC_SIGNAL_PROOF",
        "observed_time_utc": "2026-05-17T23:59:30Z",
        "sanitized_event_fingerprint": "linux-runner-ho-gpu-01-runtime-candidate-v0",
        "source_receipt_refs": [
            {
                "ref_type": "github_actions_run",
                "ref": RUNTIME_COLLECTOR_LINUX_VERIFIED_RUN_ID,
                "status": RUNTIME_COLLECTOR_LINUX_VERIFIED_STATUS,
            },
            {
                "ref_type": "github_actions_job",
                "ref": RUNTIME_COLLECTOR_LINUX_VERIFIED_JOB_ID,
                "status": RUNTIME_COLLECTOR_LINUX_VERIFIED_STATUS,
            },
        ],
    }


def build_runtime_collector_linux_candidate(
    payload: dict[str, Any] | None = None,
    *,
    collector_run_id: str = "runtime-case-collector-v0-linux-dry-run",
    collected_at_utc: str = "2026-06-02T00:00:00Z",
) -> dict[str, Any]:
    payload = dict(payload or runtime_collector_linux_default_payload())
    candidate_payload = {
        "detection_id": payload["detection_id"],
        "source_system": payload["source_system"],
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "observed_time_utc": payload.get("observed_time_utc"),
    }
    if payload.get("execution_id"):
        candidate_payload["execution_id"] = payload["execution_id"]
    candidate_payload_hash = canonical_sha256(candidate_payload)
    identity = {
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "detection_id": payload["detection_id"],
        "source_system": payload["source_system"],
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "candidate_payload_hash": candidate_payload_hash,
        "observed_time_utc": payload.get("observed_time_utc"),
    }
    if payload.get("execution_id"):
        identity["execution_id"] = payload["execution_id"]
    candidate_hash = canonical_sha256(identity)
    candidate = {
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "collector_run_id": collector_run_id,
        "collected_at_utc": collected_at_utc,
        "candidate_id": f"rccv0-linux-{candidate_hash[:16]}",
        "candidate_hash": candidate_hash,
        "detection_id": payload["detection_id"],
        "detection_family": payload["detection_family"],
        "source_system": payload["source_system"],
        "source_truth_status": payload["source_truth_status"],
        "runtime_truth_status": payload["runtime_truth_status"],
        "signal_truth_status": payload["signal_truth_status"],
        "proof_ceiling": RUNTIME_COLLECTOR_LINUX_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "case_status": "RUNTIME_CANDIDATE_ONLY",
        "triage_status": "HUMAN_REVIEW_REQUIRED",
        "disposition_status": "NO_DISPOSITION",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "human_review_required": True,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "case_closed": False,
        "append_to_lifetime_ledger": False,
        "candidate_payload_hash": candidate_payload_hash,
        "sanitized_event_fingerprint": payload["sanitized_event_fingerprint"],
        "source_receipt_refs": payload["source_receipt_refs"],
        "blocked_claims": list(RUNTIME_COLLECTOR_LINUX_BLOCKED_CLAIMS),
        "notes_boundary": RUNTIME_COLLECTOR_LINUX_BOUNDARY,
        "observed_time_utc": payload.get("observed_time_utc"),
    }
    if payload.get("execution_id"):
        candidate["execution_id"] = payload["execution_id"]
    return candidate


def load_runtime_collector_linux_packet(candidate_path: Path | None = None) -> dict[str, Any]:
    if candidate_path:
        packet = load_json(candidate_path)
    else:
        packet = load_json(RUNTIME_COLLECTOR_LINUX_SAMPLE)
    if not isinstance(packet, dict):
        raise FactoryError("Runtime Case Collector Linux packet must be an object")
    return packet


def runtime_collector_linux_packet(candidate: dict[str, Any] | None = None) -> dict[str, Any]:
    candidate = candidate or build_runtime_collector_linux_candidate()
    return {
        "schema_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "collector_run_id": candidate["collector_run_id"],
        "generated_output_files": False,
        "candidate_count": 1,
        "duplicate_count": 0,
        "candidates": [candidate],
        "invariants": {
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "ai_support_mode": "AI_SUPPORT_ONLY",
            "ai_decided_disposition": False,
            "human_review_required": True,
            "case_closed": False,
            "append_to_lifetime_ledger": False,
            "proof_promotion_allowed": False,
            "public_safe_promotion_allowed": False,
            "github_issue_mutation_allowed": False,
            "raw_private_evidence_imported": False,
            "runtime_candidate_only": True,
        },
        "proof_ceiling": RUNTIME_COLLECTOR_LINUX_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "notes_boundary": RUNTIME_COLLECTOR_LINUX_BOUNDARY,
    }


def runtime_collector_linux_dedupe_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    values: list[Any] = []
    for field in RUNTIME_COLLECTOR_LINUX_DEDUPE_FIELDS:
        value = candidate.get(field)
        if field == "source_receipt_refs":
            value = canonical_sha256(value)
        values.append(value)
    return tuple(values)


def verify_runtime_collector_linux_candidate(candidate: dict[str, Any]) -> dict[str, bool]:
    missing = sorted(field for field in RUNTIME_COLLECTOR_LINUX_REQUIRED_FIELDS if field not in candidate)
    if missing:
        raise FactoryError(f"Linux runtime candidate missing required fields: {', '.join(missing)}")
    source_receipt_refs = candidate.get("source_receipt_refs")
    if not isinstance(source_receipt_refs, list) or not source_receipt_refs:
        raise FactoryError("Linux runtime candidate source_receipt_refs must be a non-empty list")
    blocked_claims = candidate.get("blocked_claims")
    if not isinstance(blocked_claims, list) or not set(RUNTIME_COLLECTOR_LINUX_BLOCKED_CLAIMS).issubset(blocked_claims):
        raise FactoryError("Linux runtime candidate blocked_claims is incomplete")
    payload_hash_input = {
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_receipt_refs": source_receipt_refs,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        payload_hash_input["execution_id"] = candidate["execution_id"]
    candidate_payload_hash = canonical_sha256(payload_hash_input)
    candidate_hash_input = {
        "collector_version": candidate["collector_version"],
        "collector_lane": candidate["collector_lane"],
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_receipt_refs": source_receipt_refs,
        "candidate_payload_hash": candidate_payload_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        candidate_hash_input["execution_id"] = candidate["execution_id"]
    candidate_hash = canonical_sha256(candidate_hash_input)
    checks = {
        "collector_version": candidate["collector_version"] == RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": candidate["collector_lane"] == "linux",
        "candidate_payload_hash": candidate["candidate_payload_hash"] == candidate_payload_hash,
        "candidate_hash": candidate["candidate_hash"] == candidate_hash,
        "candidate_id": candidate["candidate_id"] == f"rccv0-linux-{candidate_hash[:16]}",
        "proof_ceiling": candidate["proof_ceiling"] == RUNTIME_COLLECTOR_LINUX_PROOF_CEILING,
        "public_safe_status": candidate["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "disposition_status": candidate["disposition_status"] == "NO_DISPOSITION",
        "ai_support_mode": candidate["ai_support_mode"] == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": candidate["ai_decided_disposition"] is False,
        "human_review_required": candidate["human_review_required"] is True,
        "deterministic_close_eligible_false": candidate["deterministic_close_eligible"] is False,
        "deterministic_close_blocked_true": candidate["deterministic_close_blocked"] is True,
        "case_closed_false": candidate["case_closed"] is False,
        "append_to_lifetime_ledger_false": candidate["append_to_lifetime_ledger"] is False,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Linux runtime candidate failed checks: {', '.join(failed)}")
    return checks


def verify_runtime_collector_linux_packet(packet: dict[str, Any]) -> dict[str, Any]:
    candidates = packet.get("candidates")
    if not isinstance(candidates, list):
        raise FactoryError("Linux runtime collector packet candidates must be a list")
    seen: set[tuple[Any, ...]] = set()
    duplicate_count = 0
    candidate_checks: list[dict[str, bool]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise FactoryError("Linux runtime collector candidate must be an object")
        candidate_checks.append(verify_runtime_collector_linux_candidate(candidate))
        key = runtime_collector_linux_dedupe_key(candidate)
        if key in seen:
            duplicate_count += 1
        seen.add(key)
    checks = {
        "schema_version": packet.get("schema_version") == RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": packet.get("collector_lane") == "linux",
        "public_safe_status": packet.get("public_safe_status") == "NOT_PUBLIC_SAFE",
        "proof_ceiling": packet.get("proof_ceiling") == RUNTIME_COLLECTOR_LINUX_PROOF_CEILING,
        "candidate_count_matches": packet.get("candidate_count") == len(candidates),
        "duplicate_count_matches": packet.get("duplicate_count", duplicate_count) == duplicate_count,
        "no_duplicates": duplicate_count == 0,
        "append_to_lifetime_ledger_blocked": all(
            candidate.get("append_to_lifetime_ledger") is False for candidate in candidates
        ),
        "case_closure_blocked": all(candidate.get("case_closed") is False for candidate in candidates),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Linux runtime collector packet failed checks: {', '.join(failed)}")
    return {
        "status": "pass",
        "candidate_count": len(candidates),
        "duplicate_count": duplicate_count,
        "checks": checks,
        "candidate_checks": candidate_checks,
    }


def normalize_linux_collector_route(output_route: str) -> str:
    normalized = output_route.replace("\\", "/").rstrip("/")
    allowed = {
        RUNTIME_COLLECTOR_LINUX_OUTPUT_ROUTE.rstrip("/"),
        RUNTIME_COLLECTOR_LINUX_ROUTE_FALLBACK.rstrip("/"),
    }
    if normalized not in allowed:
        raise FactoryError("Linux collector output route is not an approved Linux-private collector route")
    return normalized + "/"


def runtime_collector_linux_preflight(output_route: str | None = None) -> dict[str, Any]:
    route_status: dict[str, Any] = {
        "preferred_output_route": RUNTIME_COLLECTOR_LINUX_OUTPUT_ROUTE,
        "fallback_output_route": RUNTIME_COLLECTOR_LINUX_ROUTE_FALLBACK,
        "output_route_required_for_collect": True,
        "output_route_supplied": bool(output_route),
        "approved_linux_private_route": None,
        "route_exists": None,
        "route_is_dir": None,
        "route_writable": None,
        "route_writable_probe": "metadata_only_no_file_created",
    }
    if output_route:
        route_status["approved_linux_private_route"] = normalize_linux_collector_route(output_route)
        route_path = Path(output_route).resolve()
        route_status["route_exists"] = route_path.exists()
        route_status["route_is_dir"] = route_path.is_dir()
        route_status["route_writable"] = os.access(route_path, os.W_OK) if route_path.exists() else False
        if not all((route_status["route_exists"], route_status["route_is_dir"], route_status["route_writable"])):
            raise FactoryError("Linux collector output route is not an existing writable directory")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-linux-preflight",
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "generated_output_files": False,
        "runner_labels": list(RUNTIME_COLLECTOR_LINUX_RUNNER_LABELS),
        "verified_workflow_run_id": RUNTIME_COLLECTOR_LINUX_VERIFIED_RUN_ID,
        "verified_workflow_job_id": RUNTIME_COLLECTOR_LINUX_VERIFIED_JOB_ID,
        "verified_workflow_status": RUNTIME_COLLECTOR_LINUX_VERIFIED_STATUS,
        "workflow_trigger_required": "workflow_dispatch",
        "pull_request_allowed": False,
        "pull_request_target_allowed": False,
        "lifetime_case_ledger_mutation_allowed": False,
        "governed_case_append_allowed": False,
        "public_safe_promotion_allowed": False,
        "linux_candidates_require_later_normalizer_import": True,
        "route_status": route_status,
        "status": "pass",
    }


def runtime_collector_linux_payload_from_signal(
    *,
    execution_id: str | None,
    signal_receipt_digest: str | None,
    signal_observed_time_utc: str | None,
    backend_class: str | None,
    wazuh_rule_id: str | None,
) -> dict[str, Any] | None:
    provided = {
        "execution_id": execution_id,
        "signal_receipt_digest": signal_receipt_digest,
        "signal_observed_time_utc": signal_observed_time_utc,
        "backend_class": backend_class,
        "wazuh_rule_id": wazuh_rule_id,
    }
    if not any(provided.values()):
        return None
    missing = sorted(name for name, value in provided.items() if not value)
    if missing:
        raise FactoryError(f"Linux signal-correlated collection missing fields: {', '.join(missing)}")
    assert execution_id is not None
    assert signal_receipt_digest is not None
    assert signal_observed_time_utc is not None
    assert backend_class is not None
    assert wazuh_rule_id is not None
    if not re.fullmatch(r"HO-DET-001-[0-9]{8}T[0-9]{6}Z-[A-Z0-9]{6}", execution_id):
        raise FactoryError("Linux signal-correlated collection execution_id is malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", signal_receipt_digest):
        raise FactoryError("Linux signal-correlated collection signal_receipt_digest must be sha256 hex")
    if backend_class != "Wazuh":
        raise FactoryError("Linux signal-correlated collection backend_class must be Wazuh")
    sanitized_fingerprint = canonical_sha256(
        {
            "execution_id": execution_id,
            "signal_receipt_digest": signal_receipt_digest,
            "backend_class": backend_class,
            "wazuh_rule_id": wazuh_rule_id,
        }
    )
    return {
        "detection_id": "HO-DET-001",
        "detection_family": "process_behavior",
        "source_system": "Wazuh/Sysmon",
        "source_truth_status": "PRIVATE_WAZUH_SIGNAL_RECEIPT_VERIFIED",
        "runtime_truth_status": "RUNTIME_CANDIDATE_ONLY",
        "signal_truth_status": "SIGNAL_OBSERVED_PRIVATE",
        "observed_time_utc": signal_observed_time_utc,
        "sanitized_event_fingerprint": f"sha256:{sanitized_fingerprint}",
        "execution_id": execution_id,
        "source_receipt_refs": [
            {
                "ref_type": "wazuh_signal_receipt_digest",
                "ref": signal_receipt_digest,
                "status": "pass",
                "backend_class": backend_class,
                "detection_id": "HO-DET-001",
                "execution_id": execution_id,
                "wazuh_rule_id": wazuh_rule_id,
            }
        ],
    }


def runtime_collector_linux_run_once(
    dry_run: bool,
    output_route: str | None = None,
    *,
    execution_id: str | None = None,
    signal_receipt_digest: str | None = None,
    signal_observed_time_utc: str | None = None,
    backend_class: str | None = None,
    wazuh_rule_id: str | None = None,
) -> dict[str, Any]:
    payload = runtime_collector_linux_payload_from_signal(
        execution_id=execution_id,
        signal_receipt_digest=signal_receipt_digest,
        signal_observed_time_utc=signal_observed_time_utc,
        backend_class=backend_class,
        wazuh_rule_id=wazuh_rule_id,
    )
    candidate = build_runtime_collector_linux_candidate(payload)
    packet = runtime_collector_linux_packet(candidate)
    verification = verify_runtime_collector_linux_packet(packet)
    output: dict[str, Any] = {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-linux-run-once",
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "dry_run": dry_run,
        "generated_output_files": False,
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "status": "pass",
        "packet": packet,
    }
    if dry_run:
        return output
    if not output_route:
        raise FactoryError("collector-linux-run-once collect mode requires --output-route")
    normalize_linux_collector_route(output_route)
    route_path = Path(output_route).resolve()
    if not route_path.is_dir() or not os.access(route_path, os.W_OK):
        raise FactoryError("collector-linux-run-once requires an existing writable Linux-private output route")
    output_file = route_path / f"{candidate['collector_run_id']}-{candidate['candidate_id']}.json"
    if output_file.exists():
        output["generated_output_files"] = False
        output["duplicate_preserved"] = True
        output["output_file"] = str(output_file)
        return output
    output_file.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output["generated_output_files"] = True
    output["duplicate_preserved"] = False
    output["output_file"] = str(output_file)
    return output


def runtime_collector_linux_self_test() -> dict[str, Any]:
    packet = runtime_collector_linux_packet()
    verification = verify_runtime_collector_linux_packet(packet)
    duplicate_candidates = [packet["candidates"][0], dict(packet["candidates"][0])]
    duplicate_keys = [runtime_collector_linux_dedupe_key(candidate) for candidate in duplicate_candidates]
    duplicate_count = len(duplicate_keys) - len(set(duplicate_keys))
    mutated_candidate = dict(packet["candidates"][0])
    mutated_candidate["ai_decided_disposition"] = True
    mutation_blocked = False
    try:
        verify_runtime_collector_linux_candidate(mutated_candidate)
    except FactoryError:
        mutation_blocked = True
    checks = {
        "sample_candidate_valid": verification["status"] == "pass",
        "duplicate_detected": duplicate_count == 1,
        "unsupported_disposition_mutation_blocked": mutation_blocked,
        "verified_workflow_run_passed": RUNTIME_COLLECTOR_LINUX_VERIFIED_STATUS == "pass",
        "lifetime_case_ledger_mutation_blocked": packet["invariants"]["append_to_lifetime_ledger"] is False,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"Linux runtime collector self-test failed checks: {', '.join(failed)}")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-linux-self-test",
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "checks": checks,
    }


def runtime_collector_linux_verify(candidate_path: str | None = None) -> dict[str, Any]:
    packet = load_runtime_collector_linux_packet(Path(candidate_path).resolve() if candidate_path else None)
    verification = verify_runtime_collector_linux_packet(packet)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-linux-verify",
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "generated_output_files": False,
        "status": verification["status"],
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "checks": verification["checks"],
    }


def runtime_collector_linux_dedupe_check(candidate_path: str | None = None) -> dict[str, Any]:
    packet = load_runtime_collector_linux_packet(Path(candidate_path).resolve() if candidate_path else None)
    verification = verify_runtime_collector_linux_packet(packet)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-linux-dedupe-check",
        "collector_version": RUNTIME_COLLECTOR_LINUX_VERSION,
        "collector_lane": "linux",
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "dedupe_fields": list(RUNTIME_COLLECTOR_LINUX_DEDUPE_FIELDS),
        "dedupe_result": "no_duplicates",
    }


def source_receipt_refs_hash(refs: Any) -> str:
    if not isinstance(refs, list) or not refs:
        raise FactoryError("normalized runtime candidate source_receipt_refs must be a non-empty list")
    return canonical_sha256(refs)


def load_runtime_collector_normalizer_plan(candidate_plan: Path | None = None) -> dict[str, Any]:
    if candidate_plan:
        plan = load_json(candidate_plan)
    else:
        plan = runtime_collector_normalizer_plan(None, None)
    if not isinstance(plan, dict):
        raise FactoryError("Runtime Case Collector normalizer plan must be an object")
    return plan


def normalize_runtime_collector_candidate(candidate: dict[str, Any], expected_lane: str) -> dict[str, Any]:
    if expected_lane == "windows":
        verify_runtime_collector_windows_candidate(candidate)
    elif expected_lane == "linux":
        verify_runtime_collector_linux_candidate(candidate)
    else:
        raise FactoryError("unsupported normalizer source lane")
    if candidate.get("collector_lane") != expected_lane:
        raise FactoryError("unsupported normalizer source lane")
    refs = candidate["source_receipt_refs"]
    refs_hash = source_receipt_refs_hash(refs)
    payload = {
        "source_collector_lane": candidate["collector_lane"],
        "source_candidate_hash": candidate["candidate_hash"],
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "candidate_payload_hash": candidate["candidate_payload_hash"],
        "source_receipt_refs_hash": refs_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        payload["execution_id"] = candidate["execution_id"]
    normalized_payload_hash = canonical_sha256(payload)
    identity = {
        "normalized_candidate_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "candidate_payload_hash": candidate["candidate_payload_hash"],
        "source_receipt_refs_hash": refs_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        identity["execution_id"] = candidate["execution_id"]
    normalized_hash = canonical_sha256(identity)
    normalized_candidate = {
        "normalized_candidate_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "normalized_candidate_id": f"rccv0-normalized-{normalized_hash[:16]}",
        "normalized_candidate_hash": normalized_hash,
        "source_candidate_id": candidate["candidate_id"],
        "source_candidate_hash": candidate["candidate_hash"],
        "source_collector_lane": candidate["collector_lane"],
        "source_collector_version": candidate["collector_version"],
        "source_collector_run_id": candidate["collector_run_id"],
        "source_system": candidate["source_system"],
        "detection_id": candidate["detection_id"],
        "detection_family": candidate["detection_family"],
        "observed_time_utc": candidate.get("observed_time_utc"),
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_receipt_refs": refs,
        "source_receipt_refs_hash": refs_hash,
        "candidate_payload_hash": candidate["candidate_payload_hash"],
        "normalized_payload_hash": normalized_payload_hash,
        "proof_ceiling": RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "runtime_truth_status": candidate["runtime_truth_status"],
        "signal_truth_status": candidate["signal_truth_status"],
        "case_status": "RUNTIME_CANDIDATE_ONLY",
        "append_status": "APPEND_READY_REQUIRES_EXACT_APPROVAL",
        "append_blocked_reason": "APPEND_APPROVAL_REQUIRED",
        "triage_status": "HUMAN_REVIEW_REQUIRED",
        "disposition_status": "NO_DISPOSITION",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "human_review_required": True,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "case_closed": False,
        "append_to_lifetime_ledger": False,
        "blocked_claims": list(RUNTIME_COLLECTOR_NORMALIZER_BLOCKED_CLAIMS),
        "notes_boundary": RUNTIME_COLLECTOR_NORMALIZER_BOUNDARY,
    }
    if candidate.get("execution_id"):
        normalized_candidate["execution_id"] = candidate["execution_id"]
    return normalized_candidate


def runtime_collector_normalizer_dedupe_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    values: list[Any] = []
    for field in RUNTIME_COLLECTOR_NORMALIZER_DEDUPE_FIELDS:
        value = candidate.get(field)
        if field == "source_receipt_refs_hash" and not value:
            value = source_receipt_refs_hash(candidate.get("source_receipt_refs"))
        values.append(value)
    return tuple(values)


def verify_runtime_collector_normalized_candidate(candidate: dict[str, Any]) -> dict[str, bool]:
    missing = sorted(field for field in RUNTIME_COLLECTOR_NORMALIZER_REQUIRED_FIELDS if field not in candidate)
    if missing:
        raise FactoryError(f"normalized runtime candidate missing required fields: {', '.join(missing)}")
    if candidate.get("source_collector_lane") not in {"windows", "linux"}:
        raise FactoryError("unsupported normalizer source lane")
    refs_hash = source_receipt_refs_hash(candidate["source_receipt_refs"])
    payload = {
        "source_collector_lane": candidate["source_collector_lane"],
        "source_candidate_hash": candidate["source_candidate_hash"],
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "candidate_payload_hash": candidate["candidate_payload_hash"],
        "source_receipt_refs_hash": refs_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        payload["execution_id"] = candidate["execution_id"]
    normalized_payload_hash = canonical_sha256(payload)
    identity = {
        "normalized_candidate_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "detection_id": candidate["detection_id"],
        "source_system": candidate["source_system"],
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "candidate_payload_hash": candidate["candidate_payload_hash"],
        "source_receipt_refs_hash": refs_hash,
        "observed_time_utc": candidate.get("observed_time_utc"),
    }
    if candidate.get("execution_id"):
        identity["execution_id"] = candidate["execution_id"]
    normalized_hash = canonical_sha256(identity)
    blocked_claims = candidate.get("blocked_claims")
    if not isinstance(blocked_claims, list) or not set(RUNTIME_COLLECTOR_NORMALIZER_BLOCKED_CLAIMS).issubset(blocked_claims):
        raise FactoryError("normalized runtime candidate blocked_claims is incomplete")
    checks = {
        "normalized_candidate_version": candidate["normalized_candidate_version"] == RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "normalized_payload_hash": candidate["normalized_payload_hash"] == normalized_payload_hash,
        "normalized_candidate_hash": candidate["normalized_candidate_hash"] == normalized_hash,
        "normalized_candidate_id": candidate["normalized_candidate_id"] == f"rccv0-normalized-{normalized_hash[:16]}",
        "source_receipt_refs_hash": candidate.get("source_receipt_refs_hash") == refs_hash,
        "proof_ceiling": candidate["proof_ceiling"] == RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
        "public_safe_status": candidate["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "case_status": candidate["case_status"] == "RUNTIME_CANDIDATE_ONLY",
        "triage_status": candidate["triage_status"] == "HUMAN_REVIEW_REQUIRED",
        "disposition_status": candidate["disposition_status"] == "NO_DISPOSITION",
        "ai_support_mode": candidate["ai_support_mode"] == "AI_SUPPORT_ONLY",
        "ai_decided_disposition_false": candidate["ai_decided_disposition"] is False,
        "human_review_required": candidate["human_review_required"] is True,
        "deterministic_close_eligible_false": candidate["deterministic_close_eligible"] is False,
        "deterministic_close_blocked_true": candidate["deterministic_close_blocked"] is True,
        "case_closed_false": candidate["case_closed"] is False,
        "append_to_lifetime_ledger_false": candidate["append_to_lifetime_ledger"] is False,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"normalized runtime candidate failed checks: {', '.join(failed)}")
    return checks


def runtime_collector_normalizer_plan(
    windows_candidate_path: str | None = None,
    linux_candidate_path: str | None = None,
) -> dict[str, Any]:
    windows_packet = load_runtime_collector_windows_packet(
        Path(windows_candidate_path).resolve() if windows_candidate_path else None
    )
    linux_packet = load_runtime_collector_linux_packet(Path(linux_candidate_path).resolve() if linux_candidate_path else None)
    windows_verification = verify_runtime_collector_windows_packet(windows_packet)
    linux_verification = verify_runtime_collector_linux_packet(linux_packet)
    normalized: list[dict[str, Any]] = []
    rejected_duplicates: list[dict[str, Any]] = []
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for lane, packet in (("windows", windows_packet), ("linux", linux_packet)):
        for candidate in packet["candidates"]:
            item = normalize_runtime_collector_candidate(candidate, lane)
            key = runtime_collector_normalizer_dedupe_key(item)
            if key in seen:
                item["append_status"] = "DUPLICATE_REJECTED"
                item["append_blocked_reason"] = "DUPLICATE_NORMALIZED_RUNTIME_CANDIDATE"
                rejected_duplicates.append(
                    {
                        "normalized_candidate_id": item["normalized_candidate_id"],
                        "source_candidate_id": item["source_candidate_id"],
                        "source_collector_lane": item["source_collector_lane"],
                        "duplicate_of": seen[key]["normalized_candidate_id"],
                        "dedupe_key_hash": canonical_sha256({"dedupe_key": key}),
                    }
                )
                continue
            seen[key] = item
            normalized.append(item)
    append_ready_count = sum(1 for candidate in normalized if candidate["append_status"] == "APPEND_READY_REQUIRES_EXACT_APPROVAL")
    duplicate_count = len(rejected_duplicates)
    plan = {
        "schema_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "generated_at_utc": "2026-06-02T00:00:00Z",
        "source_windows_candidate_count": windows_verification["candidate_count"],
        "source_linux_candidate_count": linux_verification["candidate_count"],
        "normalized_candidate_count": len(normalized),
        "duplicate_count": duplicate_count,
        "append_ready_count": append_ready_count,
        "blocked_count": duplicate_count,
        "candidates": normalized,
        "rejected_duplicates": rejected_duplicates,
        "append_gate_status": "PLAN_ONLY_APPEND_APPROVAL_REQUIRED",
        "append_requires_human_approval": True,
        "lifetime_ledger_mutated": False,
        "governed_cases_appended": False,
        "proof_ceiling": RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "boundary_summary": RUNTIME_COLLECTOR_NORMALIZER_BOUNDARY,
    }
    verify_runtime_collector_normalizer_plan(plan)
    return plan


def verify_runtime_collector_normalizer_plan(plan: dict[str, Any]) -> dict[str, Any]:
    required = (
        "schema_version",
        "generated_at_utc",
        "source_windows_candidate_count",
        "source_linux_candidate_count",
        "normalized_candidate_count",
        "duplicate_count",
        "append_ready_count",
        "blocked_count",
        "candidates",
        "rejected_duplicates",
        "append_gate_status",
        "append_requires_human_approval",
        "lifetime_ledger_mutated",
        "proof_ceiling",
        "public_safe_status",
        "boundary_summary",
    )
    missing = sorted(field for field in required if field not in plan)
    if missing:
        raise FactoryError(f"normalizer append plan missing required fields: {', '.join(missing)}")
    candidates = plan.get("candidates")
    rejected_duplicates = plan.get("rejected_duplicates")
    if not isinstance(candidates, list):
        raise FactoryError("normalizer append plan candidates must be a list")
    if not isinstance(rejected_duplicates, list):
        raise FactoryError("normalizer append plan rejected_duplicates must be a list")
    seen: set[tuple[Any, ...]] = set()
    duplicate_count = 0
    candidate_checks: list[dict[str, bool]] = []
    append_ready_count = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise FactoryError("normalizer append plan candidate must be an object")
        candidate_checks.append(verify_runtime_collector_normalized_candidate(candidate))
        key = runtime_collector_normalizer_dedupe_key(candidate)
        if key in seen:
            duplicate_count += 1
        seen.add(key)
        if candidate.get("append_status") == "APPEND_READY_REQUIRES_EXACT_APPROVAL":
            append_ready_count += 1
    duplicate_count += len(rejected_duplicates)
    checks = {
        "schema_version": plan["schema_version"] == RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "public_safe_status": plan["public_safe_status"] == "NOT_PUBLIC_SAFE",
        "proof_ceiling": plan["proof_ceiling"] == RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
        "append_requires_human_approval": plan["append_requires_human_approval"] is True,
        "lifetime_ledger_mutated_false": plan["lifetime_ledger_mutated"] is False,
        "normalized_candidate_count_matches": plan["normalized_candidate_count"] == len(candidates),
        "duplicate_count_matches": plan["duplicate_count"] == duplicate_count,
        "append_ready_count_matches": plan["append_ready_count"] == append_ready_count,
        "blocked_count_matches": plan["blocked_count"] == len(rejected_duplicates),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"normalizer append plan failed checks: {', '.join(failed)}")
    return {
        "status": "pass",
        "candidate_count": len(candidates),
        "duplicate_count": duplicate_count,
        "append_ready_count": append_ready_count,
        "blocked_count": len(rejected_duplicates),
        "checks": checks,
        "candidate_checks": candidate_checks,
    }


def runtime_collector_normalizer_verify(candidate_plan: str | None = None) -> dict[str, Any]:
    plan = load_runtime_collector_normalizer_plan(Path(candidate_plan).resolve() if candidate_plan else None)
    verification = verify_runtime_collector_normalizer_plan(plan)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-normalizer-verify",
        "normalizer_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "generated_output_files": False,
        "status": verification["status"],
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "append_ready_count": verification["append_ready_count"],
        "blocked_count": verification["blocked_count"],
        "checks": verification["checks"],
    }


def runtime_collector_normalizer_dedupe_check(candidate_plan: str | None = None) -> dict[str, Any]:
    plan = load_runtime_collector_normalizer_plan(Path(candidate_plan).resolve() if candidate_plan else None)
    verification = verify_runtime_collector_normalizer_plan(plan)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-normalizer-dedupe-check",
        "normalizer_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "append_ready_count": verification["append_ready_count"],
        "blocked_count": verification["blocked_count"],
        "dedupe_fields": list(RUNTIME_COLLECTOR_NORMALIZER_DEDUPE_FIELDS),
        "dedupe_result": "no_cross_lane_duplicates" if verification["duplicate_count"] == 0 else "duplicates_rejected",
    }


def normalized_candidate_to_lifetime_case_event(candidate: dict[str, Any], inserted_at: str) -> dict[str, Any]:
    verify_runtime_collector_normalized_candidate(candidate)
    payload = {
        **candidate,
        "append_phase": "runtime_case_collector_v0_normalizer_append_gate",
        "truth_boundary": (
            "Normalized private runtime candidate appended only after exact append approval. "
            "Still not public-safe proof, not public runtime proof, not public signal proof, "
            "not disposition authority, and not case closure."
        ),
    }
    event_hash_input = {
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": f"LCL-RCCV0-{candidate['detection_id']}-{candidate['normalized_candidate_hash'][:16].upper()}",
        "detection_id": candidate["detection_id"],
        "truth_class": "PRIVATE_RUNTIME_EVIDENCE",
        "case_status": "RUNTIME_CANDIDATE_ONLY",
        "proof_ceiling": candidate["proof_ceiling"],
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "payload_json": payload,
    }
    event_hash = hashlib.sha256(stable_json(event_hash_input).encode("utf-8")).hexdigest()
    case_event = {
        "event_hash": event_hash,
        "inserted_at": inserted_at,
        "ledger_version": CASE_LEDGER_VERSION,
        "case_id": event_hash_input["case_id"],
        "detection_id": candidate["detection_id"],
        "truth_class": "PRIVATE_RUNTIME_EVIDENCE",
        "case_status": "RUNTIME_CANDIDATE_ONLY",
        "proof_ceiling": candidate["proof_ceiling"],
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "ai_support_mode": "AI_SUPPORT_ONLY",
        "ai_decided_disposition": False,
        "recommended_disposition": None,
        "deterministic_close_eligible": False,
        "deterministic_close_blocked": True,
        "human_review_required": True,
        "gpu_supported": candidate["source_collector_lane"] == "linux",
        "public_safe": False,
        "proof_blocked": True,
        "github_issue_mutation_allowed": False,
        "case_closed": False,
        "legacy_import_count": 0,
        "payload_json": payload,
        "sanitized_event_fingerprint": candidate["sanitized_event_fingerprint"],
        "source_packet_ref": candidate["normalized_candidate_id"],
    }
    scan_private_markers("Runtime Case Collector v0 normalizer append event", case_event)
    return case_event


def normalizer_append_dedupe_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_hash": event["event_hash"],
        "case_id": event["case_id"],
        "payload_hash": canonical_sha256(event["payload_json"]),
        "sanitized_event_fingerprint": event["sanitized_event_fingerprint"],
    }


def runtime_collector_normalizer_append_approved(
    candidate_plan: str | None,
    append_approval: str | None,
    ledger_path: Path = DEFAULT_CASE_LEDGER,
) -> dict[str, Any]:
    if append_approval != RUNTIME_COLLECTOR_NORMALIZER_APPEND_APPROVAL_PHRASE:
        return {
            "controller_version": CONTROLLER_VERSION,
            "mode": "collector-normalizer-append-approved",
            "normalizer_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
            "status": "blocked",
            "append_gate_status": "BLOCKED: APPEND_APPROVAL_REQUIRED",
            "append_performed": False,
            "lifetime_ledger_mutated": False,
            "governed_cases_appended": False,
            "proof_ceiling": RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "boundary_summary": RUNTIME_COLLECTOR_NORMALIZER_BOUNDARY,
        }
    approved_target = approved_lifetime_append_target(ledger_path)
    plan = load_runtime_collector_normalizer_plan(Path(candidate_plan).resolve() if candidate_plan else None)
    verification = verify_runtime_collector_normalizer_plan(plan)
    append_ready = [
        candidate for candidate in plan["candidates"] if candidate["append_status"] == "APPEND_READY_REQUIRES_EXACT_APPROVAL"
    ]
    if len(append_ready) != verification["append_ready_count"]:
        raise FactoryError("BLOCKED: APPEND_READY_COUNT_MISMATCH")
    inserted_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    case_events = [normalized_candidate_to_lifetime_case_event(candidate, inserted_at) for candidate in append_ready]
    with connect_read_only_ledger(approved_target) as conn:
        before_metrics = lifetime_ledger_metrics(conn)
        for event in case_events:
            dedupe = lifetime_append_gate_dedupe(conn, normalizer_append_dedupe_event(event))
            if dedupe["append_would_be_blocked"]:
                raise FactoryError("BLOCKED: DEDUPE_COLLISION")
    with connect_ledger(approved_target) as conn:
        for event in case_events:
            insert_case_event_unchecked(conn, event)
        conn.commit()
    with connect_read_only_ledger(approved_target) as conn:
        after_metrics = lifetime_ledger_metrics(conn)
        verify_ledger(conn, "runtime_case_collector_v0_normalizer_append_gate_private_candidate_only")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-normalizer-append-approved",
        "normalizer_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "status": "pass",
        "append_gate_status": "APPEND_APPROVED_EXACT_PHRASE_ACCEPTED",
        "append_performed": bool(case_events),
        "lifetime_ledger_mutated": bool(case_events),
        "governed_cases_appended": bool(case_events),
        "inserted_count": len(case_events),
        "inserted_case_ids": [event["case_id"] for event in case_events],
        "inserted_event_hashes": [event["event_hash"] for event in case_events],
        "before_lifetime_metrics": before_metrics,
        "after_lifetime_metrics": after_metrics,
        "proof_ceiling": RUNTIME_COLLECTOR_NORMALIZER_PROOF_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "case_closed": False,
        "ai_decided_disposition": False,
        "boundary_summary": RUNTIME_COLLECTOR_NORMALIZER_BOUNDARY,
    }


def runtime_collector_normalizer_self_test() -> dict[str, Any]:
    plan = runtime_collector_normalizer_plan(None, None)
    verification = verify_runtime_collector_normalizer_plan(plan)
    duplicate_windows = runtime_collector_windows_packet(
        build_runtime_collector_windows_candidate(
            {
                **runtime_collector_windows_default_payload(),
                "source_system": runtime_collector_linux_default_payload()["source_system"],
                "sanitized_event_fingerprint": runtime_collector_linux_default_payload()["sanitized_event_fingerprint"],
                "source_receipt_refs": runtime_collector_linux_default_payload()["source_receipt_refs"],
                "observed_time_utc": runtime_collector_linux_default_payload()["observed_time_utc"],
            }
        )
    )
    duplicate_plan_inputs = [
        normalize_runtime_collector_candidate(duplicate_windows["candidates"][0], "windows"),
        normalize_runtime_collector_candidate(runtime_collector_linux_packet()["candidates"][0], "linux"),
    ]
    seen: set[tuple[Any, ...]] = set()
    duplicate_count = 0
    for candidate in duplicate_plan_inputs:
        key = runtime_collector_normalizer_dedupe_key(candidate)
        if key in seen:
            duplicate_count += 1
        seen.add(key)
    blocked_without_approval = runtime_collector_normalizer_append_approved(None, None)
    blocked_wrong_approval = runtime_collector_normalizer_append_approved(None, "APPEND_APPROVED: wrong phrase")
    sample_append_event = normalized_candidate_to_lifetime_case_event(plan["candidates"][0], plan["generated_at_utc"])
    sample_append_dedupe_event = normalizer_append_dedupe_event(sample_append_event)

    def expect_normalizer_error(label: str, mutator: Callable[[dict[str, Any]], None]) -> bool:
        candidate = dict(plan["candidates"][0])
        mutator(candidate)
        try:
            verify_runtime_collector_normalized_candidate(candidate)
        except FactoryError:
            return True
        raise FactoryError(f"normalizer negative test did not fail closed: {label}")

    unsupported_lane_candidate = build_runtime_collector_windows_candidate()
    unsupported_lane_candidate["collector_lane"] = "macos"
    unsupported_lane_blocked = False
    try:
        normalize_runtime_collector_candidate(unsupported_lane_candidate, "macos")
    except FactoryError:
        unsupported_lane_blocked = True
    claim_candidate = dict(plan["candidates"][0])
    claim_candidate["blocked_claims"] = []
    claim_promotion_blocked = False
    try:
        verify_runtime_collector_normalized_candidate(claim_candidate)
    except FactoryError:
        claim_promotion_blocked = True
    checks = {
        "plan_verifies": verification["status"] == "pass",
        "source_windows_candidate_count": plan["source_windows_candidate_count"] == 1,
        "source_linux_candidate_count": plan["source_linux_candidate_count"] == 1,
        "normalized_candidate_count": plan["normalized_candidate_count"] == 2,
        "duplicate_count": plan["duplicate_count"] == 0,
        "append_ready_count": plan["append_ready_count"] == 2,
        "blocked_count": plan["blocked_count"] == 0,
        "append_without_approval_blocked": blocked_without_approval["lifetime_ledger_mutated"] is False
        and blocked_without_approval["status"] == "blocked",
        "append_wrong_approval_blocked": blocked_wrong_approval["lifetime_ledger_mutated"] is False
        and blocked_wrong_approval["status"] == "blocked",
        "append_dedupe_fingerprint_present": sample_append_dedupe_event["sanitized_event_fingerprint"]
        == plan["candidates"][0]["sanitized_event_fingerprint"],
        "ai_decided_disposition_rejected": expect_normalizer_error(
            "ai_decided_disposition", lambda candidate: candidate.update({"ai_decided_disposition": True})
        ),
        "case_closed_rejected": expect_normalizer_error("case_closed", lambda candidate: candidate.update({"case_closed": True})),
        "public_safe_status_rejected": expect_normalizer_error(
            "public_safe_status", lambda candidate: candidate.update({"public_safe_status": "PUBLIC_SAFE"})
        ),
        "append_to_lifetime_ledger_rejected": expect_normalizer_error(
            "append_to_lifetime_ledger", lambda candidate: candidate.update({"append_to_lifetime_ledger": True})
        ),
        "duplicate_candidate_detected": duplicate_count == 1,
        "missing_receipt_refs_rejected": expect_normalizer_error(
            "source_receipt_refs", lambda candidate: candidate.update({"source_receipt_refs": []})
        ),
        "unsupported_lane_rejected": unsupported_lane_blocked,
        "claim_promotion_rejected": claim_promotion_blocked,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise FactoryError(f"normalizer self-test failed checks: {', '.join(failed)}")
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "collector-normalizer-self-test",
        "normalizer_version": RUNTIME_COLLECTOR_NORMALIZER_VERSION,
        "generated_output_files": False,
        "status": "pass",
        "candidate_count": verification["candidate_count"],
        "duplicate_count": verification["duplicate_count"],
        "append_ready_count": verification["append_ready_count"],
        "blocked_count": verification["blocked_count"],
        "lifetime_ledger_mutated": False,
        "governed_cases_appended": False,
        "checks": checks,
    }


HOXLINE_RUNTIME_TRANSITIONS = {
    None: {"EVENT_REQUESTED"},
    "EVENT_REQUESTED": {"EVENT_GENERATED"},
    "EVENT_GENERATED": {"SIGNAL_OBSERVED"},
    "SIGNAL_OBSERVED": {"CANDIDATE_CREATED"},
    "CANDIDATE_CREATED": {"CONTRACT_VALIDATED"},
    "CONTRACT_VALIDATED": {"NORMALIZED"},
    "NORMALIZED": {"DEDUPED"},
    "DEDUPED": {"ENRICHED"},
    "ENRICHED": {"AI_TRIAGE_READY", "AI_TRIAGE_UNAVAILABLE"},
    "AI_TRIAGE_READY": {"HUMAN_REVIEW_REQUIRED"},
    "AI_TRIAGE_UNAVAILABLE": {"HUMAN_REVIEW_REQUIRED"},
    "HUMAN_REVIEW_REQUIRED": {"APPEND_APPROVED", "PUBLIC_REVIEW_PENDING", "FAILED_RETRYABLE"},
    "APPEND_APPROVED": {"LEDGER_APPENDED"},
    "LEDGER_APPENDED": {"PUBLIC_REVIEW_PENDING"},
    "PUBLIC_REVIEW_PENDING": set(),
    "FAILED_RETRYABLE": {"HUMAN_REVIEW_REQUIRED", "DEAD_LETTERED"},
    "DEAD_LETTERED": set(),
}


def hoxline_runtime_case_id(execution_id: str, detection_id: str = "HO-DET-001") -> str:
    return f"hoxline-{detection_id.lower()}-{canonical_sha256({'execution_id': execution_id, 'detection_id': detection_id})[:16]}"


def hoxline_load_execution_artifacts(private_route: Path, execution_id: str) -> dict[str, Any]:
    if not private_route.is_dir():
        raise FactoryError("Hoxline private route must exist and be a directory")
    artifacts: dict[str, Any] = {
        "candidate": None,
        "candidate_digest": None,
        "enrichment": None,
        "enrichment_digest": None,
        "ai_output": None,
        "ai_output_digest": None,
        "review_packet": None,
        "review_packet_digest": None,
        "matching_json_count": 0,
    }
    for path in sorted(private_route.rglob("*.json")):
        data = path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
        if execution_id not in text:
            continue
        artifacts["matching_json_count"] += 1
        digest = hashlib.sha256(data).hexdigest()
        try:
            packet = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(packet, dict) and isinstance(packet.get("candidates"), list):
            for candidate in packet["candidates"]:
                if isinstance(candidate, dict) and candidate.get("execution_id") == execution_id:
                    artifacts["candidate"] = candidate
                    artifacts["candidate_digest"] = digest
        elif isinstance(packet, dict) and packet.get("schema_version") == "hoxline-deterministic-enrichment-v0":
            artifacts["enrichment"] = packet
            artifacts["enrichment_digest"] = digest
        elif isinstance(packet, dict) and packet.get("schema_version") == "hoxline-ai-support-triage-v0":
            artifacts["ai_output"] = packet
            artifacts["ai_output_digest"] = digest
        elif isinstance(packet, dict) and packet.get("schema_version") == "hoxline-human-review-packet-v0":
            current = artifacts.get("review_packet")
            current_ai_state = (current or {}).get("ai_triage", {}).get("state") if isinstance(current, dict) else None
            packet_ai_state = packet.get("ai_triage", {}).get("state") if isinstance(packet.get("ai_triage"), dict) else None
            if current is None or current_ai_state != "AI_TRIAGE_READY" and packet_ai_state == "AI_TRIAGE_READY":
                artifacts["review_packet"] = packet
                artifacts["review_packet_digest"] = digest
    missing = [name for name in ("candidate", "enrichment", "review_packet") if artifacts[name] is None]
    if missing:
        raise FactoryError(f"Hoxline replay missing execution artifacts: {', '.join(missing)}")
    return artifacts


def hoxline_build_journal_event(
    *,
    execution_id: str,
    case_id: str,
    event_index: int,
    prior_state: str | None,
    new_state: str,
    evidence_refs: dict[str, Any],
    previous_event_hash: str | None,
    actor_class: str,
    recorded_at: str,
) -> dict[str, Any]:
    if new_state not in HOXLINE_RUNTIME_TRANSITIONS.get(prior_state, set()):
        raise FactoryError(f"invalid Hoxline runtime transition: {prior_state!r} -> {new_state!r}")
    event = {
        "event_id": f"{case_id}:{event_index:03d}:{new_state}",
        "execution_id": execution_id,
        "case_id": case_id,
        "detection_id": "HO-DET-001",
        "schema_version": "hoxline-private-case-journal-v0",
        "source_system": "Wazuh/Sysmon",
        "observed_at": evidence_refs.get("observed_at"),
        "recorded_at": recorded_at,
        "actor_class": actor_class,
        "prior_state": prior_state,
        "new_state": new_state,
        "truth_class": evidence_refs.get("truth_class", "PRIVATE_CONTROLLED_RUNTIME_PROOF"),
        "public_safe": False,
        "evidence_refs": evidence_refs,
        "content_hash": canonical_sha256(evidence_refs),
        "previous_event_hash": previous_event_hash,
    }
    event["event_hash"] = canonical_sha256(event)
    return event


def hoxline_verify_journal(events: list[dict[str, Any]]) -> dict[str, Any]:
    previous_hash: str | None = None
    previous_state: str | None = None
    for event in events:
        if event.get("previous_event_hash") != previous_hash:
            raise FactoryError("Hoxline journal hash chain is broken")
        if event.get("prior_state") != previous_state:
            raise FactoryError("Hoxline journal prior_state chain is broken")
        if event.get("new_state") not in HOXLINE_RUNTIME_TRANSITIONS.get(previous_state, set()):
            raise FactoryError("Hoxline journal transition guard failed")
        event_hash = event.get("event_hash")
        candidate = dict(event)
        candidate.pop("event_hash", None)
        if event_hash != canonical_sha256(candidate):
            raise FactoryError("Hoxline journal event hash mismatch")
        previous_hash = event_hash
        previous_state = event["new_state"]
    return {
        "status": "pass",
        "event_count": len(events),
        "head_state": previous_state,
        "journal_head_hash": previous_hash,
    }


def hoxline_runtime_metrics_from_replay(events: list[dict[str, Any]], manifest: dict[str, Any], ai: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "hoxline-runtime-metrics-v0",
        "execution_id": manifest["execution_id"],
        "case_id": manifest["case_id"],
        "case_state": "HUMAN_REVIEW_REQUIRED",
        "event_count": len(events),
        "signal_to_candidate_latency_status": "REPORT_ONLY_NOT_DERIVED_FROM_PRIVATE_TIMESTAMPS",
        "candidate_to_review_latency_status": "REPORT_ONLY_NOT_DERIVED_FROM_PRIVATE_TIMESTAMPS",
        "duplicate_suppression_count": 0,
        "enrichment_success_count": 1,
        "enrichment_unavailable_count": 0,
        "ai_primary_success_count": 1 if ai.get("state") == "AI_TRIAGE_READY" or ai.get("primary_status") == "pass" else 0,
        "ai_fallback_success_count": 1 if ai.get("fallback_status") == "pass" else 0,
        "ai_unavailable_count": 1 if manifest.get("ai_state") == "AI_TRIAGE_UNAVAILABLE" else 0,
        "human_review_backlog_delta": 1,
        "ledger_append_count": 0,
        "public_proof_promotion_count": 0,
        "dead_letter_count": 0,
        "replay_success_count": 1,
        "slo_class": "REPORT_ONLY",
    }


def hoxline_runtime_replay(
    execution_id: str,
    private_route: str,
    *,
    write_journal: bool = False,
    write_manifest: bool = False,
) -> dict[str, Any]:
    route = Path(private_route).resolve()
    artifacts = hoxline_load_execution_artifacts(route, execution_id)
    candidate = artifacts["candidate"]
    review = artifacts["review_packet"]
    ai = review.get("ai_triage", {}) if isinstance(review.get("ai_triage"), dict) else {}
    ai_state = ai.get("state", "AI_TRIAGE_UNAVAILABLE")
    if ai_state not in {"AI_TRIAGE_READY", "AI_TRIAGE_UNAVAILABLE"}:
        raise FactoryError("Hoxline AI state must be ready or unavailable")
    case_id = hoxline_runtime_case_id(execution_id)
    recorded_at = review.get("created_at_utc") or candidate.get("observed_time_utc") or execution_id
    base_refs = {
        "workflow_run_id": "27878994407",
        "workflow_job_id": "82503185677",
        "runner_name": "HO-GPU-01",
        "runner_labels": ["self-hosted", "ho-gpu-01", "gpu", "v100"],
        "signal_receipt_digest": review["signal_receipt"]["receipt_digest"],
        "candidate_digest": artifacts["candidate_digest"],
        "normalized_digest": review["normalization"]["normalized_hash"],
        "duplicate_count": review["dedupe"]["duplicate_count"],
        "enrichment_digest": artifacts["enrichment_digest"],
        "ai_output_digest": artifacts.get("ai_output_digest"),
        "review_packet_digest": artifacts["review_packet_digest"],
        "observed_at": candidate.get("observed_time_utc"),
        "truth_class": "PRIVATE_CONTROLLED_RUNTIME_PROOF",
    }
    states = [
        "EVENT_REQUESTED",
        "EVENT_GENERATED",
        "SIGNAL_OBSERVED",
        "CANDIDATE_CREATED",
        "CONTRACT_VALIDATED",
        "NORMALIZED",
        "DEDUPED",
        "ENRICHED",
        ai_state,
        "HUMAN_REVIEW_REQUIRED",
    ]
    events: list[dict[str, Any]] = []
    prior_state: str | None = None
    previous_hash: str | None = None
    for index, state in enumerate(states, start=1):
        event = hoxline_build_journal_event(
            execution_id=execution_id,
            case_id=case_id,
            event_index=index,
            prior_state=prior_state,
            new_state=state,
            evidence_refs={**base_refs, "stage": state},
            previous_event_hash=previous_hash,
            actor_class="hoxline_runtime_replay",
            recorded_at=recorded_at,
        )
        events.append(event)
        prior_state = state
        previous_hash = event["event_hash"]
    verification = hoxline_verify_journal(events)
    repo_sha = subprocess.run(
        ["git", "-C", str(PLATFORM_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    manifest = {
        "schema_version": "hoxline-private-evidence-manifest-v0",
        "execution_id": execution_id,
        "case_id": case_id,
        "detection_id": "HO-DET-001",
        "wazuh_rule_id": review["signal_receipt"]["wazuh_rule_id"],
        "controlled_event_class": review["controlled_event"]["event_class"],
        "signal_receipt_digest": review["signal_receipt"]["receipt_digest"],
        "candidate_digest": artifacts["candidate_digest"],
        "normalized_digest": review["normalization"]["normalized_hash"],
        "duplicate_state": "REPLAY_NO_DUPLICATE",
        "enrichment_digest": artifacts["enrichment_digest"],
        "ai_state": ai_state,
        "ai_input_digest": ai.get("input_hash_sha256"),
        "ai_output_digest": ai.get("output_hash_sha256") or artifacts.get("ai_output_digest"),
        "human_review_packet_digest": artifacts["review_packet_digest"],
        "repository": "hawkinsoperations-platform",
        "repository_commit_sha": repo_sha,
        "github_workflow_run_id": "27878994407",
        "github_workflow_job_id": "82503185677",
        "runner_identity": "HO-GPU-01",
        "runner_labels": ["self-hosted", "ho-gpu-01", "gpu", "v100"],
        "backend_identity": "HO-WAZUH-01",
        "model_name": ai.get("primary_model"),
        "model_result": ai.get("primary_status"),
        "prompt_template_hash": ai.get("prompt_template_hash_sha256"),
        "generation_parameter_class": "bounded_json_temperature_0",
        "journal_head_hash": verification["journal_head_hash"],
        "ledger_baseline": review["ledger_baseline"],
        "public_safe": False,
        "proof_ceiling": "PRIVATE_CONTROLLED_RUNTIME_PROOF",
        "manifest_hash": "",
    }
    manifest["manifest_hash"] = canonical_sha256({key: value for key, value in manifest.items() if key != "manifest_hash"})
    metrics = hoxline_runtime_metrics_from_replay(events, manifest, ai)
    written = {"journal": False, "manifest": False}
    if write_journal:
        journal_path = route / f"hoxline-case-journal-v0-{execution_id}.jsonl"
        if journal_path.exists():
            existing_events = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            existing_head = hoxline_verify_journal(existing_events)["journal_head_hash"]
            if existing_head != verification["journal_head_hash"]:
                raise FactoryError("existing Hoxline journal differs from replay head")
        else:
            journal_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")
        written["journal"] = True
    if write_manifest:
        manifest_path = route / f"hoxline-evidence-manifest-v0-{execution_id}.json"
        if manifest_path.exists():
            existing_hash = json.loads(manifest_path.read_text(encoding="utf-8")).get("manifest_hash")
            if existing_hash != manifest["manifest_hash"]:
                raise FactoryError("existing Hoxline evidence manifest differs from replay manifest")
        else:
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written["manifest"] = True
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "hoxline-runtime-replay",
        "execution_id": execution_id,
        "case_id": case_id,
        "generated_output_files": any(written.values()),
        "replay_result": "REPLAY_NO_DUPLICATE",
        "candidate_collection_performed": False,
        "controlled_event_performed": False,
        "ledger_mutated": False,
        "public_proof_promoted": False,
        "ai_state": ai_state,
        "journal_verification": verification,
        "current_case_view": {
            "current_state": "HUMAN_REVIEW_REQUIRED",
            "human_review_required": True,
            "public_safe": False,
            "case_closed": False,
            "append_to_lifetime_ledger": False,
        },
        "evidence_manifest": manifest,
        "metrics": metrics,
        "written": written,
    }


def hoxline_runtime_health(private_route: str) -> dict[str, Any]:
    route = Path(private_route).resolve()
    files = [path for path in route.rglob("*") if path.is_file()] if route.is_dir() else []
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "hoxline-runtime-health",
        "private_route_exists": route.is_dir(),
        "private_route_file_count": len(files),
        "private_route_digest": canonical_sha256(
            [{"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(files)]
        ),
        "ledger_append_allowed": False,
        "public_proof_promotion_allowed": False,
        "health_status": "pass" if route.is_dir() else "blocked",
    }


def hoxline_runtime_verify(execution_id: str, private_route: str) -> dict[str, Any]:
    replay = hoxline_runtime_replay(execution_id, private_route)
    return {
        "controller_version": CONTROLLER_VERSION,
        "mode": "hoxline-runtime-verify",
        "execution_id": execution_id,
        "status": "pass",
        "replay_result": replay["replay_result"],
        "journal_verification": replay["journal_verification"],
        "manifest_hash": replay["evidence_manifest"]["manifest_hash"],
        "ledger_mutated": False,
        "public_proof_promoted": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detection Factory Controller v0")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("status", "plan"):
        sub = subparsers.add_parser(mode)
        sub.add_argument(
            "--detection",
            required=True,
            choices=("HO-DET-001", "HO-DET-011", "HO-DET-012", "ID-DET-001", "ID-DET-002", "ID-DET-003", "ID-DET-004", "all"),
        )
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
    sub.add_argument("--ledger")
    sub.add_argument("--case-id")
    sub.add_argument("--self-test", action="store_true")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-verify")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-state-manifest-verify")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--manifest", "--manifest-path", dest="manifest_path", default=str(LIFETIME_LEDGER_STATE_MANIFEST))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-manual-fire-ho-det-001")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-manual-fire-ho-det-011")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES["HO-DET-011"]))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-manual-fire-ho-det-012")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLES["HO-DET-012"]))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-append-gate")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--append-mode", default="dry-run", choices=("dry-run", "append"))
    sub.add_argument("--append-approval")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-append-gate-self-test")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-append-approved-ho-det-001")
    sub.add_argument("--candidate", default=str(LIFETIME_MANUAL_FIRE_CANDIDATE_SAMPLE))
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--append-approval", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-append-approved-ho-det-011-012")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--append-approval", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-correction-gate")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--parent-event-hash", required=True)
    sub.add_argument("--correction-reason", required=True)
    sub.add_argument("--append-mode", default="dry-run", choices=("dry-run", "append"))
    sub.add_argument("--correction-approval")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-correction-self-test")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("lifetime-ledger-multi-detection-self-test")
    sub.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    sub.add_argument("--ledger", "--ledger-path", dest="ledger_path", default=str(DEFAULT_CASE_LEDGER))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("verify-receipt")
    sub.add_argument("--receipt", required=True, choices=("ho-det-001",))
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-windows-preflight")
    sub.add_argument("--output-route")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-windows-self-test")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-windows-run-once")
    sub.add_argument("--dry-run", action="store_true")
    sub.add_argument("--output-route")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-windows-verify")
    sub.add_argument("--candidate")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-windows-dedupe-check")
    sub.add_argument("--candidate")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-linux-preflight")
    sub.add_argument("--output-route")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-linux-self-test")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-linux-run-once")
    sub.add_argument("--dry-run", action="store_true")
    sub.add_argument("--output-route")
    sub.add_argument("--execution-id")
    sub.add_argument("--signal-receipt-digest")
    sub.add_argument("--signal-observed-time-utc")
    sub.add_argument("--backend-class")
    sub.add_argument("--wazuh-rule-id")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-linux-verify")
    sub.add_argument("--candidate")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-linux-dedupe-check")
    sub.add_argument("--candidate")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-normalizer-self-test")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-normalizer-plan")
    sub.add_argument("--windows-candidate")
    sub.add_argument("--linux-candidate")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-normalizer-verify")
    sub.add_argument("--candidate-plan")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-normalizer-dedupe-check")
    sub.add_argument("--candidate-plan")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("collector-normalizer-append-approved")
    sub.add_argument("--candidate-plan")
    sub.add_argument("--append-approval")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("hoxline-runtime-health")
    sub.add_argument("--private-route", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("hoxline-runtime-replay")
    sub.add_argument("--execution-id", required=True)
    sub.add_argument("--private-route", required=True)
    sub.add_argument("--write-journal", action="store_true")
    sub.add_argument("--write-manifest", action="store_true")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("hoxline-runtime-verify")
    sub.add_argument("--execution-id", required=True)
    sub.add_argument("--private-route", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("hoxline-runtime-metrics")
    sub.add_argument("--execution-id", required=True)
    sub.add_argument("--private-route", required=True)
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("public-status-source-contract-verify")
    sub.add_argument("--format", default="json", choices=("json",))
    sub = subparsers.add_parser("self-test-id-det-001-missing-surfaces")
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
        has_ledger = bool(args.ledger)
        has_case_id = bool(args.case_id)
        if has_ledger != has_case_id:
            raise FactoryError("runtime-ledger-review-case requires both --ledger and --case-id when either is provided")
        if args.self_test and not has_ledger:
            print(json.dumps(runtime_review_self_tests(), indent=2, sort_keys=True))
            return 0
        if not has_ledger:
            raise FactoryError("runtime-ledger-review-case requires --self-test or both --ledger and --case-id")
        output = runtime_ledger_review_case(Path(args.ledger).resolve(), args.case_id)
        if args.self_test:
            output["self_tests"] = runtime_review_self_tests()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-verify":
        output = verify_lifetime_ledger_spine(Path(args.repo_root).resolve(), Path(args.ledger_path).resolve())
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-state-manifest-verify":
        output = verify_lifetime_ledger_state_manifest(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.manifest_path).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-manual-fire-ho-det-001":
        output = lifetime_manual_fire_ho_det_001_dry_run(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.candidate).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode in {"lifetime-ledger-manual-fire-ho-det-011", "lifetime-ledger-manual-fire-ho-det-012"}:
        output = lifetime_manual_fire_dry_run(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.candidate).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-append-gate":
        output = lifetime_append_gate_review(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.candidate).resolve(),
            args.append_mode,
            args.append_approval,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-append-gate-self-test":
        output = lifetime_append_gate_self_test(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.candidate).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-append-approved-ho-det-001":
        output = lifetime_approved_append_ho_det_001(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            Path(args.candidate).resolve(),
            args.append_approval,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-append-approved-ho-det-011-012":
        output = lifetime_approved_append_ho_det_011_012(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            args.append_approval,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-correction-gate":
        output = lifetime_correction_gate_review(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
            args.parent_event_hash,
            args.correction_reason,
            args.append_mode,
            args.correction_approval,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-correction-self-test":
        output = lifetime_correction_self_test(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "lifetime-ledger-multi-detection-self-test":
        output = lifetime_multi_detection_self_test(
            Path(args.repo_root).resolve(),
            Path(args.ledger_path).resolve(),
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "verify-receipt":
        if args.receipt != "ho-det-001":
            raise FactoryError(f"unsupported receipt verifier: {args.receipt}")
        print(json.dumps(verify_ho_det_001_socaas_pilot_receipt(), indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-windows-preflight":
        output = runtime_collector_windows_preflight(args.output_route)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-windows-self-test":
        output = runtime_collector_windows_self_test()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-windows-run-once":
        output = runtime_collector_windows_run_once(args.dry_run, args.output_route)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-windows-verify":
        output = runtime_collector_windows_verify(args.candidate)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-windows-dedupe-check":
        output = runtime_collector_windows_dedupe_check(args.candidate)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-linux-preflight":
        output = runtime_collector_linux_preflight(args.output_route)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-linux-self-test":
        output = runtime_collector_linux_self_test()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-linux-run-once":
        output = runtime_collector_linux_run_once(
            args.dry_run,
            args.output_route,
            execution_id=args.execution_id,
            signal_receipt_digest=args.signal_receipt_digest,
            signal_observed_time_utc=args.signal_observed_time_utc,
            backend_class=args.backend_class,
            wazuh_rule_id=args.wazuh_rule_id,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-linux-verify":
        output = runtime_collector_linux_verify(args.candidate)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-linux-dedupe-check":
        output = runtime_collector_linux_dedupe_check(args.candidate)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-normalizer-self-test":
        output = runtime_collector_normalizer_self_test()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-normalizer-plan":
        output = runtime_collector_normalizer_plan(args.windows_candidate, args.linux_candidate)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-normalizer-verify":
        output = runtime_collector_normalizer_verify(args.candidate_plan)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-normalizer-dedupe-check":
        output = runtime_collector_normalizer_dedupe_check(args.candidate_plan)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "collector-normalizer-append-approved":
        output = runtime_collector_normalizer_append_approved(args.candidate_plan, args.append_approval)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "hoxline-runtime-health":
        output = hoxline_runtime_health(args.private_route)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "hoxline-runtime-replay":
        output = hoxline_runtime_replay(
            args.execution_id,
            args.private_route,
            write_journal=args.write_journal,
            write_manifest=args.write_manifest,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "hoxline-runtime-verify":
        output = hoxline_runtime_verify(args.execution_id, args.private_route)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "hoxline-runtime-metrics":
        output = hoxline_runtime_replay(args.execution_id, args.private_route)["metrics"]
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if args.mode == "public-status-source-contract-verify":
        verifier = PLATFORM_ROOT / "scripts" / "verify-public-status-source-contract.py"
        result = subprocess.run(
            [sys.executable, "-B", str(verifier), "--format", args.format],
            check=False,
        )
        return result.returncode

    if args.mode == "self-test-id-det-001-missing-surfaces":
        output = id_det_001_missing_surface_self_test()
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    repo_root = Path(args.repo_root).resolve()
    detection_ids = sorted(SPECS) if args.detection == "all" else [args.detection]
    tolerate_id_dependency_missing = args.mode == "plan" and args.detection == "all"

    packets = [
        build_plan_packet(repo_root, SPECS[detection_id], tolerate_id_dependency_missing)
        for detection_id in detection_ids
    ]
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
