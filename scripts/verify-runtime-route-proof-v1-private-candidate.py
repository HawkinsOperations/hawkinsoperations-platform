#!/usr/bin/env python3
"""Verify the Runtime Route Proof v1 private-candidate packet boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKET = ROOT / "contracts" / "examples" / "runtime-route-proof-v1-private-candidate.sample.json"

EXPECTED = {
    "schema_version": "runtime-route-proof-v1-private-candidate-v1",
    "marker_id": "HO-RUNTIME-V1-20260601T120922Z-BATCH764",
    "private_route": ["Wazuh", "Cribl", "Splunk"],
    "deterministic_verifier_status": "PASS_ROUTE_RECEIPTS",
    "manifest_verified": True,
    "lifetime_governed_cases": 4,
    "public_safe_count": 0,
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "proof_ceiling": "PRIVATE_RUNTIME_ROUTE_PROOF_V1_CANDIDATE",
    "preservation_ceiling": "PRIVATE_RUNTIME_ROUTE_PROOF_V1_CANDIDATE_PRESERVED",
}

EXPECTED_RECEIPTS = {
    "wazuh": "PASS",
    "cribl": "PASS",
    "splunk": "PASS",
}

EXPECTED_PACKET = {
    "filename": "HO-RUNTIME-ROUTE-PROOF-V1-PRIVATE-REVIEWER-SAFE-2026-06-01.zip",
    "sha256": "3a1d4472bffcce68cff6e101c54e06b5a67528338bda174e6fef209fa9b1b278",
    "raw_private_evidence_in_repo": False,
}

EXPECTED_BOUNDARY = {
    "public_safe_runtime_proof": False,
    "production_soc_operation": False,
    "autonomous_soc_operation": False,
    "ai_decided_disposition": False,
    "lifetime_governed_case_mutation": False,
    "public_publication_approved": False,
    "human_review_required": True,
}

LEAK_PATTERNS = {
    "windows_absolute_path": re.compile(r"\b[A-Z]:[\\/]"),
    "unc_path": re.compile(r"\\\\[^\\\s]+\\[^\\\s]+"),
    "lan_ip": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    "secret_assignment": re.compile(r"(?i)\b(secret|token|api[_-]?key|password|authorization|cookie)\s*[:=]\s*\S+"),
    "raw_payload_label": re.compile(r"(?i)\b(raw_payload|command_line_raw|event_body_raw|full_log_raw)\b"),
}

PROMOTED_CLAIM_PATTERNS = {
    "public_safe_approval": re.compile(r"(?i)\bPUBLIC_SAFE_APPROVED\b|\bpublic-safe approved\b"),
    "production_soc": re.compile(r"(?i)\bPRODUCTION_SOC_PROVEN\b|\bproduction SOC operation proven\b"),
    "autonomous_soc": re.compile(r"(?i)\bAUTONOMOUS_SOC_PROVEN\b|\bautonomous SOC operation proven\b"),
    "ai_decided": re.compile(r"(?i)\bAI_DECIDED_DISPOSITION\s*[:=]\s*true\b"),
    "lifetime_mutation": re.compile(r"(?i)\bLIFETIME_GOVERNED_CASE_CREATED\b|\blifetime_governed_case_mutation\s*[:=]\s*true\b"),
}


def fail(message: str) -> None:
    print(f"runtime route proof v1 private candidate verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_packet(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        fail("packet root must be an object")
    return data


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def assert_equal(actual, expected, label: str) -> None:
    if actual != expected:
        fail(f"{label} expected {expected!r} but got {actual!r}")


def scan_text(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for label, pattern in LEAK_PATTERNS.items():
        if pattern.search(text):
            fail(f"{label} pattern found in {path}")
    for label, pattern in PROMOTED_CLAIM_PATTERNS.items():
        if pattern.search(text):
            fail(f"{label} pattern found in {path}")


def verify(path: Path) -> dict:
    scan_text(path)
    packet = load_packet(path)
    for key, expected in EXPECTED.items():
        assert_equal(packet.get(key), expected, key)
    assert_equal(packet.get("receipts"), EXPECTED_RECEIPTS, "receipts")
    assert_equal(packet.get("reviewer_safe_packet"), EXPECTED_PACKET, "reviewer_safe_packet")
    assert_equal(packet.get("claim_boundary"), EXPECTED_BOUNDARY, "claim_boundary")
    return {
        "status": "PASS",
        "packet": display_path(path),
        "marker_id": packet["marker_id"],
        "deterministic_verifier_status": packet["deterministic_verifier_status"],
        "manifest_verified": packet["manifest_verified"],
        "lifetime_governed_cases": packet["lifetime_governed_cases"],
        "public_safe_count": packet["public_safe_count"],
        "public_safe_status": packet["public_safe_status"],
        "proof_ceiling": packet["proof_ceiling"],
        "raw_private_evidence_in_repo": packet["reviewer_safe_packet"]["raw_private_evidence_in_repo"],
        "ai_decided_disposition": packet["claim_boundary"]["ai_decided_disposition"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    args = parser.parse_args()
    result = verify(args.packet.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
