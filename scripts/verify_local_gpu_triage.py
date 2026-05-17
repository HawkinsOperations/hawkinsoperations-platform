#!/usr/bin/env python3
"""Verify Local GPU Triage Pipeline v0 packets stay claim-bounded."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "schemas" / "local-gpu-triage-support-v0.schema.json"

EXPECTED = {
    "packet_type": "local_gpu_triage_support_v0",
    "contract_version": "0.1.0",
    "pipeline_phase": "PHASE_A_CONTRACT_VERIFIER_ONLY",
    "ai_support_mode": "AI_SUPPORT_ONLY",
    "local_gpu_runtime_status": "PRIVATE_RUNTIME_SUPPORT_CONFIRMED",
    "local_gpu_runtime_label": "LOCAL_GPU_SUPPORT_NODE",
    "true_gpu_ci_status": "PENDING_RUNNER_CONFIRMATION",
    "human_review_required": True,
    "ai_decided_disposition": False,
    "recommended_disposition": None,
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "public_proof_ceiling": "CONTROLLED_TEST_VALIDATED",
    "runtime_active_public_proof": False,
    "signal_observed_public_proof": False,
    "production_ready": False,
}

REQUIRED_BLOCKED_CLAIMS = {
    "public-safe promotion",
    "runtime-active public proof",
    "signal-observed public proof",
    "production status",
    "fleet deployment",
    "autonomous operation",
    "AI-approved disposition",
    "analyst-approved disposition",
    "final disposition decision",
    "true GPU CI implemented",
}

PRIVATE_GPU_NODE_PATTERN = r"\b" + "HO" + r"-" + "GPU" + r"-" + "01" + r"\b"

FORBIDDEN_VALUE_PATTERNS = [
    PRIVATE_GPU_NODE_PATTERN,
    r"\b[A-Za-z]{2,}-GPU-\d+\b",
    r"\b[A-Za-z]:\\",
    r"C:/",
    r"/home/",
    r"/var/",
    r"/etc/",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b(secret|token|api[_ -]?key|password|credential)\b",
    r"raw model output",
    r"private evidence filename",
]

PROMOTED_SUPPORTED_CLAIM_PATTERNS = [
    r"\bpublic-safe\b",
    r"\bruntime-active\b",
    r"\bsignal-observed\b",
    r"\bproduction-ready\b",
    r"\bproduction\s+ready\b",
    r"\bfleet-wide\b",
    r"\bfleet\s+deployment\b",
    r"\bautonomous\b",
    r"\bAI-approved\b",
    r"\banalyst-approved\b",
    r"\bfinal\s+disposition\b",
    r"\btrue\s+GPU\s+CI\s+(is\s+)?(implemented|proven|ready)\b",
]


def fail(message: str) -> None:
    print(f"LOCAL_GPU_TRIAGE=fail: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")

    if not isinstance(data, dict):
        fail("packet must be a JSON object")
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


def iter_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_string_values(child)


def require_expected_values(packet: dict[str, Any]) -> None:
    for key, expected in EXPECTED.items():
        actual = packet.get(key)
        if actual != expected:
            fail(f"{key} expected {expected!r}, got {actual!r}")


def require_nested_boundaries(packet: dict[str, Any]) -> None:
    privacy = packet.get("privacy_boundary")
    if not isinstance(privacy, dict):
        fail("privacy_boundary must be an object")
    for key, actual in privacy.items():
        if actual is not False:
            fail(f"privacy_boundary.{key} must be false")

    github_ci = packet.get("github_ci_truth")
    if not isinstance(github_ci, dict):
        fail("github_ci_truth must be an object")
    required_false = ("self_hosted_runner_proven", "runner_labels_proven", "workflow_created")
    for key in required_false:
        if github_ci.get(key) is not False:
            fail(f"github_ci_truth.{key} must be false")
    if github_ci.get("true_gpu_ci_status") != "PENDING_RUNNER_CONFIRMATION":
        fail("github_ci_truth.true_gpu_ci_status must remain pending")

    model_support = packet.get("model_support")
    if not isinstance(model_support, dict):
        fail("model_support must be an object")
    if model_support.get("raw_model_output_included") is not False:
        fail("model_support.raw_model_output_included must be false")


def reject_private_or_host_values(packet: dict[str, Any]) -> None:
    for value in iter_string_values(packet):
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            if re.search(pattern, value, flags=re.IGNORECASE):
                fail(f"forbidden private or host-like value found: {pattern}")


def require_blocked_claims(packet: dict[str, Any]) -> None:
    blocked = packet.get("blocked_claims")
    if not isinstance(blocked, list):
        fail("blocked_claims must be a list")
    missing = sorted(REQUIRED_BLOCKED_CLAIMS - set(str(item) for item in blocked))
    if missing:
        fail(f"missing blocked_claims entries: {', '.join(missing)}")


def reject_promoted_supported_claims(packet: dict[str, Any]) -> None:
    supported = packet.get("supported_claims")
    if not isinstance(supported, list) or not supported:
        fail("supported_claims must be a non-empty list")

    for claim in supported:
        normalized = str(claim)
        for pattern in PROMOTED_SUPPORTED_CLAIM_PATTERNS:
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                if "pending runner confirmation" in normalized.lower():
                    continue
                fail(f"supported_claims promotes blocked wording: {claim!r}")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: verify_local_gpu_triage.py <packet.json>", file=sys.stderr)
        return 2

    packet_path = Path(argv[0])
    if not packet_path.is_absolute():
        packet_path = ROOT / packet_path

    packet = load_json(packet_path)
    schema = load_json(SCHEMA_PATH)

    validate_schema_if_possible(packet, schema)
    require_expected_values(packet)
    require_nested_boundaries(packet)
    require_blocked_claims(packet)
    reject_promoted_supported_claims(packet)
    reject_private_or_host_values(packet)

    print("LOCAL_GPU_TRIAGE=pass")
    print("AI_SUPPORT_MODE=AI_SUPPORT_ONLY")
    print("LOCAL_GPU_RUNTIME_STATUS=PRIVATE_RUNTIME_SUPPORT_CONFIRMED")
    print("TRUE_GPU_CI_STATUS=PENDING_RUNNER_CONFIRMATION")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("AI_DECIDED_DISPOSITION=false")
    print("HUMAN_REVIEW_REQUIRED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
