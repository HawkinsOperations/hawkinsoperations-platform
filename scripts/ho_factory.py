#!/usr/bin/env python3
"""Detection Factory Controller v0.

Read-only status and plan packets for selected HawkinsOperations detections.
The controller prints to stdout only and does not create generated output files.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONTROLLER_VERSION = "0.1.0"
PLATFORM_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO_ROOT = PLATFORM_ROOT.parent


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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
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
