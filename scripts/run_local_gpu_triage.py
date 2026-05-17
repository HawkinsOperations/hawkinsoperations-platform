#!/usr/bin/env python3
"""Print the Local GPU Triage Pipeline v0 Phase A status packet."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


PACKET: dict[str, Any] = {
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
    "runtime_truth": {
        "runtime_support_class": "PRIVATE_RUNTIME_SUPPORT",
        "gpu_visible_private_support": True,
        "local_model_service_present": True,
        "runtime_refresh_required_for_new_claims": True,
        "public_runtime_claim_allowed": False,
    },
    "model_support": {
        "local_model_available_private_support": True,
        "model_family": "local_ollama_qwen_support",
        "raw_model_output_included": False,
        "allowed_ai_actions": [
            "summarize",
            "list_uncertainty",
            "recommend_next_checks",
            "map_evidence_fields",
        ],
        "blocked_ai_actions": [
            "approve",
            "promote",
            "close",
            "decide_disposition",
            "mark_public_safe",
            "claim_compromise",
        ],
    },
    "github_ci_truth": {
        "self_hosted_runner_proven": False,
        "runner_labels_proven": False,
        "workflow_created": False,
        "true_gpu_ci_status": "PENDING_RUNNER_CONFIRMATION",
    },
    "privacy_boundary": {
        "real_host_identifier_included": False,
        "local_paths_included": False,
        "internal_ips_included": False,
        "secrets_included": False,
        "raw_model_output_included": False,
        "private_evidence_filenames_included": False,
    },
    "blocked_claims": [
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
    ],
    "supported_claims": [
        "private local GPU support status can be reported with sanitized labels",
        "local model support remains advisory",
        "human review remains required",
        "GitHub GPU CI remains pending runner confirmation",
    ],
    "does_not_prove": [
        "public-safe status",
        "runtime-active public proof",
        "signal-observed public proof",
        "production status",
        "fleet deployment",
        "autonomous operation",
        "AI or analyst disposition authority",
        "true GPU CI",
    ],
    "next_allowed_move": "HUMAN_REVIEW_BEFORE_ANY_RUNTIME_OR_WORKFLOW_EXTENSION",
    "stop_conditions": [
        "real host identifier would be needed",
        "local path or internal IP would be included",
        "model response body would be included",
        "workflow creation would be required",
        "runtime command execution would be required",
        "proof or public-safe promotion would be implied",
    ],
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local GPU Triage Pipeline v0 Phase A status runner"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--format", choices=["json", "receipt"], default="json")
    return parser.parse_args(argv)


def print_receipt() -> None:
    print("LOCAL_GPU_TRIAGE_STATUS_PACKET=pass")
    print("AI_SUPPORT_MODE=support_only")
    print("PUBLIC_SAFE_STATUS=not_public_safe")
    print("PROOF_CEILING=controlled_test_validated")
    print("HUMAN_REVIEW_REQUIRED=true")
    print("MODEL_EXECUTION_IN_CI=false")
    print("OLLAMA_PROMPT_EXECUTION_IN_CI=false")
    print("ARTIFACT_UPLOAD=false")
    print("PUBLIC_PROOF_PROMOTION=false")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.command != "status":
        print("LOCAL_GPU_TRIAGE=fail: unsupported command", file=sys.stderr)
        return 2

    if args.format == "receipt":
        print_receipt()
    else:
        print(json.dumps(PACKET, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
