#!/usr/bin/env python3
"""Verify the platform-owned public status source contract v1."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "public-status-source-contract-v1.json"
UNKNOWN = "UNKNOWN_SOURCE_NOT_CAPTURED"
ALLOWED_SOURCE_STATUSES = {
    "SOURCE_CAPTURED",
    "SOURCE_CAPTURED_PENDING_PR",
    "SOURCE_CAPTURED_DIRECT_V1_PATHS_PENDING_PR",
    "SOURCE_PENDING_UNMERGED_PR",
    "UNKNOWN_SOURCE_NOT_CAPTURED",
    "BOUNDARY_DEFAULT_NOT_PROMOTED",
}
PENDING_SOURCE_STATUSES = {
    "SOURCE_CAPTURED_PENDING_PR",
    "SOURCE_CAPTURED_DIRECT_V1_PATHS_PENDING_PR",
    "SOURCE_PENDING_UNMERGED_PR",
}

REQUIRED_TOP_LEVEL_FIELDS = {
    "manifest_id",
    "version",
    "owner_repo",
    "consumer",
    "generated_at",
    "freshness_window_days",
    "platform_role",
    "source_repos",
    "source_paths",
    "public_rendering_contract",
    "public_fields",
    "freshness_policy",
    "proof_ceiling_policy",
    "public_safe_policy",
    "reviewer_actions_source_routes",
    "future_generated_status_v1_extraction",
    "verifier",
}

PLATFORM_FIELDS = {
    "lifetime_governed_cases",
    "lifetime_ledger_events",
    "append_ready_runtime_candidates",
    "closed_case_count",
    "source_repos",
    "source_paths",
    "generated_at",
    "freshness_window_days",
    "reviewer_actions_source_routes",
}
VALIDATION_FIELDS = {
    "detection_activity_count",
    "controlled_validation_fire_count",
    "validation_case_count",
}
PROOF_FIELDS = {
    "proof_record_count",
    "blocked_claim_count",
    "proof_ceiling",
    "public_safe_count",
    "public_safe_state",
}
DETECTIONS_FIELDS = {"detection_source_truth"}
HOXLINE_FIELDS = {"hoxline_product_status", "hoxline_gauntlet_status", "hoxline_v1_source_manifest"}
VALIDATION_BRIDGE_FIELDS = {"validation_bridge_status"}
PROOF_BRIDGE_FIELDS = {"proof_bridge_status"}
REQUIRED_PUBLIC_FIELDS = (
    PLATFORM_FIELDS
    | VALIDATION_FIELDS
    | PROOF_FIELDS
    | DETECTIONS_FIELDS
    | HOXLINE_FIELDS
    | VALIDATION_BRIDGE_FIELDS
    | PROOF_BRIDGE_FIELDS
)

REQUIRED_SOURCE_PATH_KEYS = {
    "hoxline_v1_source_manifest",
    "hoxline_gauntlet_run_v1",
    "hoxline_gauntlet_run_v1_overclaim",
    "hoxline_evidence_graph_v1",
    "hoxline_proofcard_v1",
    "hoxline_claim_decision_v1",
    "hoxline_gauntlet_run_v1_schema",
    "hoxline_evidence_graph_v1_schema",
    "hoxline_proofcard_v1_schema",
    "hoxline_claim_authority_decision_v1_schema",
    "hoxline_gauntlet_v1_doc",
    "hoxline_proofcard_v1_doc",
    "hoxline_claim_authority_v1_doc",
    "validation_hoxline_gauntlet_bridge_v1_json",
    "validation_hoxline_gauntlet_bridge_v1_md",
    "validation_hoxline_gauntlet_bridge_v1_verifier",
    "proof_hoxline_gauntlet_bridge_v1_json",
    "proof_hoxline_gauntlet_bridge_v1_md",
    "proof_hoxline_gauntlet_proof_map_v1_json",
    "proof_hoxline_gauntlet_proof_map_v1_md",
    "proof_hoxline_gauntlet_bridge_v1_verifier",
}

DENIED_TEXT = [
    ("C:\\Raylee\\Work", re.compile(r"C:\\Raylee\\Work", re.IGNORECASE)),
    ("C:\\Raylee\\work", re.compile(r"C:\\Raylee\\work", re.IGNORECASE)),
    ("private evidence path", re.compile(r"(?:[A-Za-z]:\\[^\\\n]*private[^\\\n]*\\|/[^/\n]*private[^/\n]*/)", re.IGNORECASE)),
    ("private output path", re.compile(r"(?:private[_-]?output|raw[_-]?private|private[_-]?evidence)", re.IGNORECASE)),
    ("secret marker", re.compile(r"\b(secret|password|credential|api[_-]?key|token)\b", re.IGNORECASE)),
]

PROMOTION_PHRASES = [
    "runtime-active",
    "signal-observed",
    "public-safe runtime proof",
    "public-safe status",
    "production readiness",
    "production deployment",
    "customer deployment",
    "SOCaaS deployment",
    "AI-approved disposition",
    "analyst-approved disposition",
    "final authorization",
    "case closure",
]
NEGATIVE_BOUNDARY_MARKERS = [
    "not ",
    "no ",
    "never ",
    "does not",
    "must not",
    "blocked",
    "without",
    "unless",
    "false",
    "UNKNOWN_SOURCE_NOT_CAPTURED",
    "boundary",
]


class VerificationError(Exception):
    """Raised when the public status source contract violates v1 rules."""


def fail(message: str) -> None:
    raise VerificationError(message)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing public status source contract: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"malformed public status source contract: {exc}")
    if not isinstance(data, dict):
        fail("contract root must be an object")
    return data


def iter_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            strings.extend(iter_strings(key))
            strings.extend(iter_strings(nested))
    elif isinstance(value, list):
        for nested in value:
            strings.extend(iter_strings(nested))
    elif isinstance(value, str):
        strings.append(value)
    return strings


def scan_denied_text(data: dict[str, Any]) -> None:
    for text in iter_strings(data):
        for name, pattern in DENIED_TEXT:
            if pattern.search(text):
                fail(f"contract contains blocked text: {name}")


def verify_no_promotional_claims(data: dict[str, Any]) -> None:
    for text in iter_strings(data):
        lowered = text.lower()
        for phrase in PROMOTION_PHRASES:
            if phrase.lower() not in lowered:
                continue
            if not any(marker.lower() in lowered for marker in NEGATIVE_BOUNDARY_MARKERS):
                fail(f"promotional phrase appears outside negative boundary context: {phrase}")


def require_owner(public_fields: dict[str, Any], field: str, owner: str) -> None:
    entry = public_fields.get(field)
    if not isinstance(entry, dict):
        fail(f"public field {field} must be an object")
    if entry.get("owner_repo") != owner:
        fail(f"public field {field} must be owned by {owner}")
    if "source_path" not in entry:
        fail(f"public field {field} missing source_path")
    if "render_allowed" not in entry:
        fail(f"public field {field} missing render_allowed")


def verify_unknown_field(public_fields: dict[str, Any], field: str) -> None:
    entry = public_fields.get(field)
    if not isinstance(entry, dict):
        fail(f"public field {field} must be an object")
    if entry.get("source_status") != UNKNOWN:
        fail(f"public field {field} must use {UNKNOWN} source_status")
    if entry.get("current_value") != UNKNOWN:
        fail(f"public field {field} must use {UNKNOWN} current_value")
    if entry.get("source_path") != UNKNOWN:
        fail(f"public field {field} must use {UNKNOWN} source_path")
    if entry.get("render_allowed") is not False:
        fail(f"public field {field} must not be renderable until sourced")


def verify_pending_source(entry: dict[str, Any], field: str, status: str) -> None:
    if status not in PENDING_SOURCE_STATUSES:
        return
    if not isinstance(entry.get("source_pr"), int) or entry["source_pr"] <= 0:
        fail(f"pending public field {field} must include source_pr")
    if not isinstance(entry.get("source_branch"), str) or not entry["source_branch"]:
        fail(f"pending public field {field} must include source_branch")
    if entry.get("source_path") == UNKNOWN:
        fail(f"pending public field {field} must include a concrete source_path")


def verify_pending_route(route: dict[str, Any]) -> None:
    status = route.get("source_status")
    if status not in PENDING_SOURCE_STATUSES:
        return
    if not isinstance(route.get("source_pr"), int) or route["source_pr"] <= 0:
        fail(f"pending route {route.get('route')} must include source_pr")
    if not isinstance(route.get("source_branch"), str) or not route["source_branch"]:
        fail(f"pending route {route.get('route')} must include source_branch")


def verify_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    contract = load_json(path)
    scan_denied_text(contract)
    verify_no_promotional_claims(contract)

    missing = REQUIRED_TOP_LEVEL_FIELDS - set(contract)
    if missing:
        fail(f"contract missing top-level fields: {sorted(missing)}")
    if contract.get("manifest_id") != "PUBLIC_STATUS_SOURCE_CONTRACT_V1":
        fail("manifest_id must be PUBLIC_STATUS_SOURCE_CONTRACT_V1")
    if contract.get("version") != "public_status_source_contract_v1":
        fail("version must be public_status_source_contract_v1")
    if contract.get("owner_repo") != "hawkinsoperations-platform":
        fail("owner_repo must be hawkinsoperations-platform")
    if contract.get("consumer") != "hawkinsoperations-website":
        fail("consumer must be hawkinsoperations-website")

    platform_role = contract.get("platform_role")
    if not isinstance(platform_role, dict):
        fail("platform_role must be an object")
    if platform_role.get("source_contract") is not True:
        fail("platform must own source-contract role")
    for key in ("website_rendering_authority", "proof_authority", "runtime_authority", "signal_authority"):
        if platform_role.get(key) is not False:
            fail(f"platform_role.{key} must be false")

    rendering = contract.get("public_rendering_contract")
    if not isinstance(rendering, dict):
        fail("public_rendering_contract must be an object")
    if rendering.get("website_rendering_is_proof") is not False:
        fail("website rendering must not be proof")
    must_not_source = rendering.get("website_must_not_source_from_website_only_data")
    if not isinstance(must_not_source, list) or not must_not_source:
        fail("website-only forbidden field list must be non-empty")
    if "proof_ceiling" not in must_not_source or "public_safe_state" not in must_not_source:
        fail("proof ceiling and public-safe state must not source from website-only data")

    public_fields = contract.get("public_fields")
    if not isinstance(public_fields, dict):
        fail("public_fields must be an object")
    missing_fields = REQUIRED_PUBLIC_FIELDS - set(public_fields)
    if missing_fields:
        fail(f"public_fields missing required fields: {sorted(missing_fields)}")
    for field, entry in public_fields.items():
        if not isinstance(entry, dict):
            fail(f"public field {field} must be an object")
        if not entry.get("owner_repo"):
            fail(f"public field {field} missing owner_repo")
        status = entry.get("source_status")
        if not status:
            fail(f"public field {field} missing source_status")
        if status not in ALLOWED_SOURCE_STATUSES:
            fail(f"public field {field} has unsupported source_status: {status}")
        verify_pending_source(entry, field, status)

    for field in PLATFORM_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-platform")
    for field in VALIDATION_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-validation")
    for field in PROOF_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-proof")
    for field in DETECTIONS_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-detections")
    for field in HOXLINE_FIELDS:
        require_owner(public_fields, field, "hoxline/aevumguard")
    for field in VALIDATION_BRIDGE_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-validation")
    for field in PROOF_BRIDGE_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-proof")
    verify_unknown_field(public_fields, "hoxline_v1_source_manifest")

    if public_fields["hoxline_product_status"].get("source_status") != "SOURCE_CAPTURED_DIRECT_V1_PATHS_PENDING_PR":
        fail("hoxline_product_status must be captured as direct v1 paths pending PR")
    if public_fields["hoxline_gauntlet_status"].get("source_status") != "SOURCE_CAPTURED_DIRECT_V1_PATHS_PENDING_PR":
        fail("hoxline_gauntlet_status must be captured as direct v1 paths pending PR")
    gauntlet_value = public_fields["hoxline_gauntlet_status"].get("current_value")
    if not isinstance(gauntlet_value, dict):
        fail("hoxline_gauntlet_status current_value must be bounded metadata")
    if gauntlet_value.get("hoxline_gauntlet_v1_public_safe") is not False:
        fail("Hoxline Gauntlet v1 metadata must keep public_safe false")
    if gauntlet_value.get("hoxline_gauntlet_v1_public_safe_state") != "blocked":
        fail("Hoxline Gauntlet v1 metadata must keep public-safe state blocked")
    if gauntlet_value.get("hoxline_gauntlet_v1_proof_ceiling") != "CONTROLLED_TEST_VALIDATED":
        fail("Hoxline Gauntlet v1 metadata must keep controlled-test proof ceiling")
    if public_fields["validation_bridge_status"].get("source_status") != "SOURCE_CAPTURED_PENDING_PR":
        fail("validation_bridge_status must be pending PR source")
    if public_fields["proof_bridge_status"].get("source_status") != "SOURCE_CAPTURED_PENDING_PR":
        fail("proof_bridge_status must be pending PR source")

    public_safe_policy = contract.get("public_safe_policy")
    proof_ceiling_policy = contract.get("proof_ceiling_policy")
    if not isinstance(public_safe_policy, dict) or not isinstance(proof_ceiling_policy, dict):
        fail("public_safe_policy and proof_ceiling_policy must be objects")
    if public_safe_policy.get("public_safe") is not False:
        fail("public_safe must remain false")
    if public_safe_policy.get("public_safe_state") != "NOT_PUBLIC_SAFE":
        fail("public_safe_state must remain NOT_PUBLIC_SAFE")
    if public_safe_policy.get("public_safe_source_required") != "hawkinsoperations-proof":
        fail("public_safe source must be hawkinsoperations-proof")
    if proof_ceiling_policy.get("no_proof_promotion") is not True:
        fail("proof ceiling policy must prohibit proof promotion")
    if proof_ceiling_policy.get("website_rendering_is_proof") is not False:
        fail("proof ceiling policy must keep website rendering non-proof")
    if proof_ceiling_policy.get("public_safe_count") != 0:
        fail("public_safe_count must remain 0 unless proof source says otherwise")
    if proof_ceiling_policy.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("public_safe_status must remain NOT_PUBLIC_SAFE")

    if public_fields["public_safe_count"].get("current_value") != 0:
        fail("public_safe_count field must remain 0")
    if public_fields["public_safe_state"].get("current_value") != "NOT_PUBLIC_SAFE":
        fail("public_safe_state field must remain NOT_PUBLIC_SAFE")
    if public_fields["proof_ceiling"].get("current_value") != "SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY":
        fail("proof_ceiling field must remain SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY")

    source_paths = contract.get("source_paths")
    if not isinstance(source_paths, dict):
        fail("source_paths must be an object")
    missing_source_path_keys = REQUIRED_SOURCE_PATH_KEYS - set(source_paths)
    if missing_source_path_keys:
        fail(f"source_paths missing Hoxline/bridge routes: {sorted(missing_source_path_keys)}")
    if source_paths.get("hoxline_v1_source_manifest") != UNKNOWN:
        fail(f"hoxline_v1_source_manifest must remain {UNKNOWN} until captured")
    for key, value in source_paths.items():
        if not isinstance(value, str) or not value:
            fail(f"source path {key} must be a string")
        if re.match(r"^[A-Za-z]:\\", value):
            fail(f"source path {key} must not be an absolute local path")

    extraction = contract.get("future_generated_status_v1_extraction")
    if not isinstance(extraction, dict):
        fail("future_generated_status_v1_extraction must be an object")
    extractor_should = extraction.get("extractor_should")
    extractor_must_not = extraction.get("extractor_must_not")
    if not isinstance(extractor_should, list) or not isinstance(extractor_must_not, list):
        fail("future extraction plan must include should and must_not lists")
    if not any(UNKNOWN in str(item) for item in extractor_should):
        fail("future extraction plan must require UNKNOWN_SOURCE_NOT_CAPTURED for missing sources")
    if not any("website-only" in str(item) for item in extractor_must_not):
        fail("future extraction plan must forbid website-only authority")
    if not any("SOURCE_CAPTURED_PENDING_PR" in str(item) for item in extractor_should):
        fail("future extraction plan must preserve pending PR status")

    routes = contract.get("reviewer_actions_source_routes")
    if not isinstance(routes, list):
        fail("reviewer_actions_source_routes must be a list")
    required_routes = {
        "hoxline-gauntlet-v1-verify",
        "hoxline-gauntlet-v1-summarize",
        "hoxline-claim-authority-v1-decide",
        "hoxline-proofcard-v1-render",
        "hoxline-gauntlet-v1-overclaim-verify",
        "hoxline-gauntlet-validation-bridge-v1-verify",
        "hoxline-gauntlet-proof-bridge-v1-verify",
    }
    seen_routes = set()
    for route in routes:
        if not isinstance(route, dict):
            fail("reviewer action route entries must be objects")
        if route.get("source_status") and route["source_status"] not in ALLOWED_SOURCE_STATUSES:
            fail(f"reviewer route {route.get('route')} has unsupported source_status")
        verify_pending_route(route)
        if isinstance(route.get("route"), str):
            seen_routes.add(route["route"])
    missing_routes = required_routes - seen_routes
    if missing_routes:
        fail(f"reviewer_actions_source_routes missing routes: {sorted(missing_routes)}")

    return {
        "status": "pass",
        "contract_path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "consumer": contract["consumer"],
        "fields_verified": sorted(REQUIRED_PUBLIC_FIELDS),
        "unknown_fields": sorted(
            field for field, entry in public_fields.items()
            if isinstance(entry, dict) and entry.get("source_status") == UNKNOWN
        ),
        "pending_fields": sorted(
            field for field, entry in public_fields.items()
            if isinstance(entry, dict) and entry.get("source_status") in PENDING_SOURCE_STATUSES
        ),
        "proof_ceiling": public_fields["proof_ceiling"]["current_value"],
        "public_safe_state": public_fields["public_safe_state"]["current_value"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--format", choices={"text", "json"}, default="text")
    args = parser.parse_args(argv)

    try:
        result = verify_contract(args.contract)
    except VerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS: public status source contract is proof-bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
