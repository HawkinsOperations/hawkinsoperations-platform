#!/usr/bin/env python3
"""Verify the platform-owned public status source contract v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

try:
    import yaml
except ImportError:  # pragma: no cover - cross-repo value check is unavailable without PyYAML.
    yaml = None


def sanitized_git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.casefold().startswith("git_")
    }
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "public-status-source-contract-v1.json"
SOURCE_MANIFEST_PATH = ROOT / "contracts" / "hoxline-case-growth-source-manifest-v1.json"
PROOF_CURRENT_STATUS_INDEX = ROOT.parent / "hawkinsoperations-proof" / "proof" / "indexes" / "DETECTION_PROOF_STATUS_INDEX.yml"
PROOF_REPO = Path(
    os.environ.get("HAWKINS_PROOF_REPO", ROOT.parent / "hawkinsoperations-proof")
).resolve()
PROOF_INDEX_GIT_PATH = "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml"
PROOF_CANONICAL_ORIGIN = "github.com/HawkinsOperations/hawkinsoperations-proof"
UNKNOWN = "UNKNOWN_SOURCE_NOT_CAPTURED"
HOXLINE_SOURCE_MANIFEST_PATH = "../hoxline/examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json"
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
    "public_safe_candidate_reviews",
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

SAFE_ALLOWED_CANDIDATE_CLAIM = (
    "HO-DET-001 has controlled validation evidence and remains under governed "
    "public-safe candidate review."
)
REQUIRED_CANDIDATE_REVIEW_FIELDS = {
    "artifact_id",
    "review_lane",
    "review_version",
    "source_artifact",
    "evidence_authority_surface",
    "privacy_review",
    "stale_review",
    "evidence_linkage_review",
    "wording_approval",
    "public_safe_status",
    "runtime_active",
    "signal_observed",
    "human_review_required",
    "proof_ceiling",
    "allowed_claims",
    "blocked_claims",
    "promotion_blockers",
}
REQUIRED_HO_DET_001_REVIEW = {
    "artifact_id": "HO-DET-001",
    "review_lane": "PUBLIC_SAFE_CANDIDATE_REVIEW_V1",
    "review_version": "v1",
    "source_artifact": "contracts/public-status-source-contract-v1.json",
    "evidence_authority_surface": "PLATFORM_CONTRACT_ENFORCEMENT_ONLY",
    "privacy_review": "PENDING",
    "stale_review": "PENDING",
    "evidence_linkage_review": "PENDING",
    "wording_approval": "PENDING",
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "runtime_active": False,
    "signal_observed": False,
    "human_review_required": True,
    "proof_ceiling": "CONTROLLED_VALIDATION_ONLY",
}
REVIEW_MARKERS = {"PENDING", "PASS", "FAIL", "BLOCKED"}
REQUIRED_CANDIDATE_BLOCKED_CLAIMS = {
    "runtime active",
    "runtime proven",
    "signal observed",
    "public-safe approved",
    "public-safe proof",
    "production ready",
    "production SOC",
    "SOC deployed",
    "SOCaaS deployed",
    "customer deployed",
    "customer validated",
    "analyst approved",
    "AI approved",
    "autonomous approval",
    "final human authorization",
    "case closed",
    "green CI as approval",
    "website rendering as proof",
    "GitHub rendering as proof",
}
REQUIRED_CANDIDATE_PROMOTION_BLOCKERS = {
    "privacy_review_pending",
    "stale_review_pending",
    "evidence_linkage_review_pending",
    "wording_approval_pending",
    "human_review_required",
    "proof_ceiling_controlled_validation_only",
}

REQUIRED_SOURCE_PATH_KEYS = {
    "proof_current_status_index",
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
    (
        "sensitive material marker",
        re.compile(
            r"\b(se" r"cret|pass" r"word|credential|api[_-]?key|to" r"ken)\b",
            re.IGNORECASE,
        ),
    ),
]

def unnegated_promotional_phrases(value: str) -> list[str]:
    """Find claim promotions without letting a distant negation launder them."""
    phrase_patterns = {
        "runtime active": r"\bruntime[\s_-]+active\b",
        "runtime proven": r"\bruntime[\s_-]+proven\b",
        "signal observed": r"\bsignal[\s_-]+observed\b",
        "public safe": r"\bpublic\s+safe\b",
        "public-safe promotion": r"\bpublic[\s_-]+safe[\s_-]+(?:approved|proof|status)\b",
        "production": r"\bproduction[\s_-]+(?:ready|readiness|deployment|status|soc)\b",
        "customer": r"\bcustomer[\s_-]+(?:deployed|deployment|validated)\b",
        "SOC deployment": r"\b(?:soc|socaas)[\s_-]+(?:deployed|deployment)\b",
        "AI authority": r"\bai[\s_-]+(?:approved|authority)\b",
        "analyst authority": r"\banalyst[\s_-]+(?:approved|authority)\b",
        "autonomous approval": r"\bautonomous[\s_-]+approval\b",
        "final authorization": r"\bfinal(?:[\s_-]+human)?[\s_-]+authorization\b",
        "case closure": r"\bcase[\s_-]+(?:closed|closure)\b",
        "green CI as approval": r"\bgreen[\s_-]+ci[\s_-]+(?:as|is)[\s_-]+approval\b",
        "website as proof": r"\bwebsite(?:[\s_-]+rendering)?[\s_-]+(?:as|is)[\s_-]+proof\b",
        "GitHub as proof": r"\bgithub(?:[\s_-]+rendering)?[\s_-]+(?:as|is)[\s_-]+proof\b",
    }
    clause_negation = re.compile(
        r"(?:"
        r"\b(?:not|never|no|without|missing|blocked)\b"
        r"|\b(?:does|do|must|is|are|was|were|can|cannot|could|should|will|would)\s+not\b"
        r"|\bnot\s+(?:authorized|approved|promoted)\b"
        r")",
        flags=re.IGNORECASE,
    )
    found: list[str] = []
    clauses = re.split(
        r"(?:[.;!?\r\n]+|\b(?:but|however|although|yet)\b)",
        value,
        flags=re.IGNORECASE,
    )
    for clause in clauses:
        bounded_clause = clause_negation.search(clause) is not None
        for label, pattern in phrase_patterns.items():
            for match in re.finditer(pattern, clause, flags=re.IGNORECASE):
                if bounded_clause:
                    continue
                found.append(label)
    return found


class VerificationError(Exception):
    """Raised when the public status source contract violates v1 rules."""


def fail(message: str) -> None:
    raise VerificationError(message)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        folded = key.casefold()
        if any(existing.casefold() == folded for existing in result):
            fail(f"duplicate JSON key is not allowed: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing public status source contract: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        fail(f"malformed public status source contract: {exc}")
    if not isinstance(data, dict):
        fail("contract root must be an object")
    return data


def load_yaml_bytes(raw: bytes, *, source: str) -> dict[str, Any]:
    if yaml is None:
        fail("PyYAML is required")

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in loader.construct_pairs(node, deep=deep):
            if not isinstance(key, str):
                fail(f"{source} mapping keys must be strings")
            if key.casefold() in {existing.casefold() for existing in result}:
                fail(f"{source} contains duplicate YAML key: {key}")
            result[key] = value
        return result

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        fail(f"{source} is malformed YAML: {exc}")
    if not isinstance(value, dict):
        fail(f"{source} root must be an object")
    return value


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


def iter_leaves(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    leaves: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            leaves.extend(iter_leaves(nested, (*path, str(key))))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            leaves.extend(iter_leaves(nested, (*path, str(index))))
    else:
        leaves.append((path, value))
    return leaves


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


PROMOTION_KEY_EXPECTATIONS = {
    "runtimeactive": False,
    "runtimeproven": False,
    "signalobserved": False,
    "publicsafe": False,
    "publicsafeapproved": False,
    "productionready": False,
    "customerdeployed": False,
    "customerdeployment": False,
    "socaasdeployed": False,
    "socaasdeployment": False,
    "aiauthority": False,
    "aidispositionauthority": False,
    "analystapproved": False,
    "finalauthorization": False,
    "caseclosed": False,
    "caseclosure": False,
    "websiterenderingisproof": False,
    "greenciisapproval": False,
}
ALLOWED_PUBLIC_FIELD_KEYS = {
    "owner_repo",
    "source_path",
    "upstream_source_path",
    "source_json_pointer",
    "source_revision",
    "source_observed_head_sha",
    "current_observed_head_sha",
    "source_observation_kind",
    "source_git_blob_sha",
    "source_fingerprint_sha256",
    "source_semantic_fingerprint_sha256",
    "derivation_method",
    "historical_snapshot",
    "current_authority",
    "current_value",
    "render_allowed",
    "source_status",
    "source_pr",
    "source_branch",
    "freshness_policy",
}

NEGATIVE_POLICY_PATHS = {
    "blockedclaims",
    "explicitlyblockedclaims",
    "extractormustnot",
    "mustnotsource",
    "promotionblockers",
    "websitemustnotsourcefromwebsiteonlydata",
    "sourcejsonpointer",
}


def scan_denied_text(data: dict[str, Any]) -> None:
    for text in iter_strings(data):
        for name, pattern in DENIED_TEXT:
            if pattern.search(text):
                fail(f"contract contains blocked text: {name}")


def verify_no_promotional_claims(data: dict[str, Any]) -> None:
    blocked_policy_strings = {claim.lower() for claim in REQUIRED_CANDIDATE_BLOCKED_CLAIMS}
    for path, value in iter_leaves(data):
        if path:
            key = normalized_key(path[-1])
            expected = PROMOTION_KEY_EXPECTATIONS.get(key)
            if expected is False and value not in (False, None, "NOT_PUBLIC_SAFE", "BLOCKED", "UNKNOWN"):
                fail(f"authority field must remain blocked at {'/'.join(path)}")
        if not isinstance(value, str):
            continue
        text = value
        lowered = text.lower()
        policy_context = any(normalized_key(part) in NEGATIVE_POLICY_PATHS for part in path)
        if policy_context and lowered in blocked_policy_strings:
            continue
        if policy_context:
            continue
        promotions = unnegated_promotional_phrases(text)
        if promotions:
            fail(
                "promotional phrase appears outside negative boundary context: "
                + promotions[0]
            )


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
        text=True,
        env=sanitized_git_env(),
    )
    if result.returncode != 0:
        fail(f"git {' '.join(args)} failed for {repo.name}: {result.stderr.strip()}")
    return result.stdout.strip()


def git_is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
        text=True,
        env=sanitized_git_env(),
    )
    if result.returncode not in (0, 1):
        fail(
            "git merge-base authority relationship check failed for "
            f"{repo.name}: {result.stderr.strip()}"
        )
    return result.returncode == 0


def git_tree_sha(repo: Path, revision: str) -> str:
    return git_output(repo, "rev-parse", f"{revision}^{{tree}}")


def normalized_origin(value: str) -> str:
    origin = value.strip().replace("\\", "/")
    origin = re.sub(r"^git@", "", origin)
    origin = origin.replace(":", "/", 1) if origin.startswith("github.com:") else origin
    origin = re.sub(r"^(?:https?|ssh)://", "", origin, flags=re.IGNORECASE)
    origin = origin.removesuffix(".git").rstrip("/")
    return origin.casefold()


def semantic_fingerprint_yaml(raw: bytes) -> str:
    try:
        parsed = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        fail(f"proof-owned index is not valid UTF-8 YAML: {exc}")
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_proof_source_identity(proof_count: dict[str, Any]) -> tuple[bytes, str]:
    if not PROOF_REPO.is_dir():
        fail("proof_record_count source repository is missing")
    origin_result = subprocess.run(
        [
            "git",
            "-C",
            str(PROOF_REPO),
            "config",
            "--local",
            "--null",
            "--get-all",
            "remote.origin.url",
        ],
        capture_output=True,
        check=False,
        text=True,
        env=sanitized_git_env(),
    )
    if origin_result.returncode != 0:
        fail(
            "proof_record_count source repository stored origin is unavailable: "
            f"{origin_result.stderr.strip()}"
        )
    stored_origins = origin_result.stdout.split("\0")
    if stored_origins and stored_origins[-1] == "":
        stored_origins.pop()
    stored_origins = [origin.strip() for origin in stored_origins]
    if len(stored_origins) != 1 or not stored_origins[0]:
        fail(
            "proof_record_count source repository must store exactly one "
            "nonempty origin URL"
        )
    origin = normalized_origin(stored_origins[0])
    if origin != PROOF_CANONICAL_ORIGIN.casefold():
        fail("proof_record_count source repository origin is not canonical")
    tracked_dirty = git_output(PROOF_REPO, "status", "--porcelain", "--untracked-files=no")
    if tracked_dirty:
        fail("proof_record_count authority source has tracked dirty state")

    current_head = git_output(PROOF_REPO, "rev-parse", "HEAD")
    current_ref = git_output(PROOF_REPO, "branch", "--show-current")
    source_manifest = load_json(SOURCE_MANIFEST_PATH)
    entries = source_manifest.get("repositories")
    if not isinstance(entries, dict) or set(entries) != {
        ".github",
        "hawkinsoperations-detections",
        "hawkinsoperations-validation",
        "hawkinsoperations-platform",
        "hawkinsoperations-proof",
        "hawkinsoperations-website",
        "hoxline",
    }:
        fail("immutable source manifest must enumerate exactly seven canonical repositories")
    proof_manifest_entry = entries.get("hawkinsoperations-proof")
    if (
        not isinstance(proof_manifest_entry, dict)
        or set(proof_manifest_entry) != {"repository", "revision"}
        or proof_manifest_entry.get("repository")
        != "HawkinsOperations/hawkinsoperations-proof"
        or re.fullmatch(
            r"[0-9a-f]{40}", str(proof_manifest_entry.get("revision", ""))
        )
        is None
    ):
        fail("proof source manifest entry must contain the canonical owner and immutable revision")
    immutable_manifest_sha = proof_manifest_entry["revision"]
    immutable_manifest_commit = subprocess.run(
        [
            "git",
            "-C",
            str(PROOF_REPO),
            "cat-file",
            "-e",
            f"{immutable_manifest_sha}^{{commit}}",
        ],
        capture_output=True,
        check=False,
        env=sanitized_git_env(),
    )
    if immutable_manifest_commit.returncode != 0:
        fail("proof source manifest revision is unreachable in the canonical proof repository")
    if not current_ref and immutable_manifest_sha != current_head:
        current_is_historical_ancestor = git_is_ancestor(
            PROOF_REPO, current_head, immutable_manifest_sha
        )
        if current_is_historical_ancestor:
            fail(
                "detached proof authority is an older historical ancestor of "
                "the immutable manifest selection"
            )
        reviewed_is_ancestor = git_is_ancestor(
            PROOF_REPO, immutable_manifest_sha, current_head
        )
        tree_is_reviewed_equivalent = (
            git_tree_sha(PROOF_REPO, immutable_manifest_sha)
            == git_tree_sha(PROOF_REPO, current_head)
        )
        if not (reviewed_is_ancestor or tree_is_reviewed_equivalent):
            fail(
                "detached proof authority requires the reviewed revision as an "
                "ancestor or an exact reviewed repository tree"
            )

    current_blob = git_output(PROOF_REPO, "rev-parse", f"HEAD:{PROOF_INDEX_GIT_PATH}")
    blob_bytes = subprocess.run(
        ["git", "-C", str(PROOF_REPO), "cat-file", "blob", current_blob],
        capture_output=True,
        check=False,
        env=sanitized_git_env(),
    )
    if blob_bytes.returncode != 0:
        fail("current proof authority blob cannot be read")

    expected_blob = proof_count.get("source_git_blob_sha")
    if expected_blob != current_blob:
        fail("proof_record_count source_git_blob_sha does not match the authoritative path in the checked current tree")
    semantic = semantic_fingerprint_yaml(blob_bytes.stdout)
    if proof_count.get("source_semantic_fingerprint_sha256") != semantic:
        fail("proof_record_count semantic fingerprint does not match the checked current authority")

    observed_sha = proof_count.get("source_observed_head_sha") or proof_count.get("source_revision")
    if re.fullmatch(r"[0-9a-f]{40}", str(observed_sha or "")) is None:
        fail("proof_record_count must record a full source_observed_head_sha")
    observed_commit = subprocess.run(
        ["git", "-C", str(PROOF_REPO), "cat-file", "-e", f"{observed_sha}^{{commit}}"],
        capture_output=True,
        check=False,
        env=sanitized_git_env(),
    )
    if observed_sha != immutable_manifest_sha:
        fail("proof observation must equal the separately reviewed immutable source manifest revision")
    if observed_commit.returncode != 0:
        fail("proof observation is unreachable in the canonical proof repository")
    observed_blob = subprocess.run(
        ["git", "-C", str(PROOF_REPO), "rev-parse", f"{observed_sha}:{PROOF_INDEX_GIT_PATH}"],
        capture_output=True,
        check=False,
        text=True,
        env=sanitized_git_env(),
    )
    if observed_blob.returncode != 0 or observed_blob.stdout.strip() != current_blob:
        fail("recorded proof observation does not carry the checked current authority blob")
    if proof_count.get("source_observation_kind") != "reviewed_immutable_commit":
        fail("proof observation must declare reviewed_immutable_commit")

    if proof_count.get("source_revision") != observed_sha:
        fail("legacy source_revision must equal source_observed_head_sha")
    if proof_count.get("current_observed_head_sha") != observed_sha:
        fail("recorded current_observed_head_sha must equal the reviewed observation")
    if proof_count.get("source_fingerprint_sha256") != hashlib.sha256(blob_bytes.stdout).hexdigest():
        fail("proof_record_count source fingerprint does not match the current authoritative blob bytes")
    return blob_bytes.stdout, current_head


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


def require_list_of_strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        fail(f"{label} must be a list")
    if not all(isinstance(item, str) and item for item in value):
        fail(f"{label} must contain non-empty strings")
    return value


def verify_candidate_review(review: dict[str, Any]) -> None:
    missing = REQUIRED_CANDIDATE_REVIEW_FIELDS - set(review)
    if missing:
        fail(f"candidate review missing fields: {sorted(missing)}")
    for field, expected in REQUIRED_HO_DET_001_REVIEW.items():
        if review.get(field) != expected:
            fail(f"HO-DET-001 candidate review {field} must be {expected!r}")
    for field in ("privacy_review", "stale_review", "evidence_linkage_review", "wording_approval"):
        if review.get(field) not in REVIEW_MARKERS:
            fail(f"HO-DET-001 candidate review {field} uses unsupported marker")

    allowed_claims = require_list_of_strings(review.get("allowed_claims"), "candidate review allowed_claims")
    if allowed_claims != [SAFE_ALLOWED_CANDIDATE_CLAIM]:
        fail("HO-DET-001 candidate review allowed_claims must preserve the controlled-validation-only wording")
    for claim in allowed_claims:
        lowered = claim.lower()
        for blocked in REQUIRED_CANDIDATE_BLOCKED_CLAIMS:
            if blocked.lower() in lowered:
                fail(f"candidate review allowed claim contains blocked claim: {blocked}")

    blocked_claims = set(require_list_of_strings(review.get("blocked_claims"), "candidate review blocked_claims"))
    missing_claims = REQUIRED_CANDIDATE_BLOCKED_CLAIMS - blocked_claims
    if missing_claims:
        fail(f"HO-DET-001 candidate review missing blocked claims: {sorted(missing_claims)}")

    blockers = set(require_list_of_strings(review.get("promotion_blockers"), "candidate review promotion_blockers"))
    missing_blockers = REQUIRED_CANDIDATE_PROMOTION_BLOCKERS - blockers
    if missing_blockers:
        fail(f"HO-DET-001 candidate review missing promotion blockers: {sorted(missing_blockers)}")


def verify_public_safe_candidate_reviews(contract: dict[str, Any]) -> None:
    reviews = contract.get("public_safe_candidate_reviews")
    if not isinstance(reviews, list) or not reviews:
        fail("public_safe_candidate_reviews must be a non-empty list")
    ho_det_001_reviews = []
    for review in reviews:
        if not isinstance(review, dict):
            fail("public_safe_candidate_reviews entries must be objects")
        if review.get("artifact_id") == "HO-DET-001":
            ho_det_001_reviews.append(review)
    if len(ho_det_001_reviews) != 1:
        fail("public_safe_candidate_reviews must contain exactly one HO-DET-001 review")
    verify_candidate_review(ho_det_001_reviews[0])


def verify_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    if yaml is None:
        fail("PyYAML is required; proof-owned count parity cannot be skipped")
    contract = load_json(path)
    scan_denied_text(contract)
    verify_no_promotional_claims(contract)

    missing = REQUIRED_TOP_LEVEL_FIELDS - set(contract)
    if missing:
        fail(f"contract missing top-level fields: {sorted(missing)}")
    unknown_top_level = set(contract) - REQUIRED_TOP_LEVEL_FIELDS
    if unknown_top_level:
        fail(f"contract contains unknown top-level fields: {sorted(unknown_top_level)}")
    if contract.get("manifest_id") != "PUBLIC_STATUS_SOURCE_CONTRACT_V1":
        fail("manifest_id must be PUBLIC_STATUS_SOURCE_CONTRACT_V1")
    if contract.get("version") != "public_status_source_contract_v1":
        fail("version must be public_status_source_contract_v1")
    if contract.get("owner_repo") != "hawkinsoperations-platform":
        fail("owner_repo must be hawkinsoperations-platform")
    if contract.get("consumer") != "hawkinsoperations-website":
        fail("consumer must be hawkinsoperations-website")
    generated_at = contract.get("generated_at")
    freshness_window_days = contract.get("freshness_window_days")
    try:
        generated_time = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        fail("generated_at must be a parseable UTC timestamp")
    if generated_time.tzinfo is None:
        fail("generated_at must include a timezone")
    now = datetime.now(timezone.utc)
    generated_time = generated_time.astimezone(timezone.utc)
    if generated_time > now:
        fail("generated_at must not be in the future")
    if not isinstance(freshness_window_days, (int, float)) or freshness_window_days <= 0:
        fail("freshness_window_days must be a positive number")
    if (now - generated_time).total_seconds() > freshness_window_days * 86400:
        fail("public status source contract is stale")

    platform_role = contract.get("platform_role")
    if not isinstance(platform_role, dict):
        fail("platform_role must be an object")
    if platform_role.get("source_contract") is not True:
        fail("platform must own source-contract role")
    for key in ("website_rendering_authority", "proof_authority", "runtime_authority", "signal_authority"):
        if platform_role.get(key) is not False:
            fail(f"platform_role.{key} must be false")

    source_repos = contract.get("source_repos")
    expected_source_repos = {
        ".github",
        "hawkinsoperations-detections",
        "hawkinsoperations-validation",
        "hawkinsoperations-platform",
        "hawkinsoperations-proof",
        "hawkinsoperations-website",
        "hoxline",
    }
    if not isinstance(source_repos, list) or len(source_repos) != 7:
        fail("source_repos must contain exactly seven canonical owner records")
    observed_source_repos: list[str] = []
    for entry in source_repos:
        if not isinstance(entry, dict):
            fail("source_repos entries must be objects")
        repo = entry.get("repo")
        if not isinstance(repo, str):
            fail("source_repos entry missing canonical repo")
        observed_source_repos.append(repo)
        if not isinstance(entry.get("role"), str) or not entry["role"]:
            fail(f"source_repos role missing for {repo}")
        if not isinstance(entry.get("authority_boundary"), str) or not entry["authority_boundary"]:
            fail(f"source_repos authority boundary missing for {repo}")
    if set(observed_source_repos) != expected_source_repos:
        fail(
            "source_repos must name exactly the seven canonical repositories: "
            f"{sorted(observed_source_repos)}"
        )
    if len(observed_source_repos) != len(set(observed_source_repos)):
        fail("source_repos contains duplicate canonical owners")

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
        unknown_keys = set(entry) - ALLOWED_PUBLIC_FIELD_KEYS
        if unknown_keys:
            fail(f"public field {field} contains unknown fields: {sorted(unknown_keys)}")
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
        require_owner(public_fields, field, "hoxline")
    for field in VALIDATION_BRIDGE_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-validation")
    for field in PROOF_BRIDGE_FIELDS:
        require_owner(public_fields, field, "hawkinsoperations-proof")
    if public_fields["hoxline_product_status"].get("source_status") != "SOURCE_CAPTURED":
        fail("hoxline_product_status must be captured from landed PR #15 source")
    if public_fields["hoxline_gauntlet_status"].get("source_status") != "SOURCE_CAPTURED":
        fail("hoxline_gauntlet_status must be captured from landed PR #15 source")
    hoxline_source_manifest = public_fields["hoxline_v1_source_manifest"]
    if hoxline_source_manifest.get("source_status") != "SOURCE_CAPTURED":
        fail("hoxline_v1_source_manifest must be captured from landed PR #15 source")
    if hoxline_source_manifest.get("source_pr") != 15:
        fail("hoxline_v1_source_manifest must reference PR #15")
    if hoxline_source_manifest.get("source_branch") != "feature/hoxline-gauntlet-v1-engine":
        fail("hoxline_v1_source_manifest must reference the Hoxline Gauntlet v1 branch")
    if hoxline_source_manifest.get("source_path") != HOXLINE_SOURCE_MANIFEST_PATH:
        fail("hoxline_v1_source_manifest must point to the Hoxline v1 source manifest")
    if hoxline_source_manifest.get("current_value") != "SEE_HOXLINE_V1_SOURCE_MANIFEST":
        fail("hoxline_v1_source_manifest must render only bounded source-route metadata")
    if hoxline_source_manifest.get("render_allowed") is not True:
        fail("hoxline_v1_source_manifest must be renderable as bounded source-route metadata")
    gauntlet_value = public_fields["hoxline_gauntlet_status"].get("current_value")
    if not isinstance(gauntlet_value, dict):
        fail("hoxline_gauntlet_status current_value must be bounded metadata")
    if gauntlet_value.get("hoxline_gauntlet_v1_public_safe") is not False:
        fail("Hoxline Gauntlet v1 metadata must keep public_safe false")
    if gauntlet_value.get("hoxline_gauntlet_v1_public_safe_state") != "blocked":
        fail("Hoxline Gauntlet v1 metadata must keep public-safe state blocked")
    if gauntlet_value.get("hoxline_gauntlet_v1_proof_ceiling") != "CONTROLLED_TEST_VALIDATED":
        fail("Hoxline Gauntlet v1 metadata must keep controlled-test proof ceiling")
    if public_fields["validation_bridge_status"].get("source_status") != "SOURCE_CAPTURED":
        fail("validation_bridge_status must be captured from landed PR #67 source")
    if public_fields["proof_bridge_status"].get("source_status") != "SOURCE_CAPTURED":
        fail("proof_bridge_status must be captured from landed PR #81 source")

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
    verify_public_safe_candidate_reviews(contract)

    if public_fields["public_safe_count"].get("current_value") != 0:
        fail("public_safe_count field must remain 0")
    if public_fields["public_safe_state"].get("current_value") != "NOT_PUBLIC_SAFE":
        fail("public_safe_state field must remain NOT_PUBLIC_SAFE")
    proof_count = public_fields["proof_record_count"]
    if proof_count.get("source_path") != "../hawkinsoperations-proof/proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml":
        fail("proof_record_count must source from the proof-owned current status index")
    if proof_count.get("source_json_pointer") != "/current_authority/derived_counts/proof_record_count":
        fail("proof_record_count must use the proof-owned derived count pointer")
    if re.fullmatch(r"[0-9a-f]{40}", str(proof_count.get("source_revision", ""))) is None:
        fail("proof_record_count must record a full proof source revision")
    proof_blob, proof_head = verify_proof_source_identity(proof_count)
    if proof_count.get("derivation_method") != "count non-null unique proof_record_path values":
        fail("proof_record_count must declare its deterministic derivation method")
    if proof_count.get("historical_snapshot") is not False or proof_count.get("current_authority") is not True:
        fail("proof_record_count must be classified as current authority, not historical")
    if not isinstance(proof_count.get("current_value"), int) or proof_count["current_value"] < 0:
        fail("proof_record_count current_value must be a non-negative integer")
    proof_index = load_yaml_bytes(proof_blob, source="proof-owned current status index")
    proof_entries = proof_index.get("entries") if isinstance(proof_index, dict) else None
    if not isinstance(proof_entries, list):
        fail("proof-owned current status index entries must be a list")
    record_paths = [
        entry.get("proof_record_path")
        for entry in proof_entries
        if isinstance(entry, dict) and entry.get("proof_record_path") is not None
    ]
    normalized_record_paths = {str(Path(value)).replace("\\", "/").casefold() for value in record_paths}
    if len(record_paths) != len(normalized_record_paths):
        fail("proof-owned current status index contains duplicate proof_record_path ownership")
    if proof_count.get("current_value") != len(record_paths):
        fail("proof_record_count must match the current proof-owned derived count")
    if public_fields["proof_ceiling"].get("current_value") != "SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY":
        fail("proof_ceiling field must remain SCHEMA_CONTRACT_VERIFIER_EXISTS_ONLY")
    if public_fields["generated_at"].get("current_value") != generated_at:
        fail("public_fields.generated_at must equal the root generated_at observation")
    if public_fields["freshness_window_days"].get("current_value") != freshness_window_days:
        fail("public_fields.freshness_window_days must equal the root freshness_window_days")

    source_paths = contract.get("source_paths")
    if not isinstance(source_paths, dict):
        fail("source_paths must be an object")
    missing_source_path_keys = REQUIRED_SOURCE_PATH_KEYS - set(source_paths)
    if missing_source_path_keys:
        fail(f"source_paths missing Hoxline/bridge routes: {sorted(missing_source_path_keys)}")
    for key, value in source_paths.items():
        if not isinstance(value, str) or not value:
            fail(f"source path {key} must be a string")
        decoded = value
        for _ in range(3):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        normalized = decoded.replace("\\", "/")
        parts = normalized.split("/")
        sibling_route = (
            len(parts) >= 3
            and parts[0] == ".."
            and parts[1]
            in {
                ".github",
                "hawkinsoperations-detections",
                "hawkinsoperations-validation",
                "hawkinsoperations-platform",
                "hawkinsoperations-proof",
                "hawkinsoperations-website",
                "hoxline",
            }
            and ".." not in parts[2:]
        )
        local_route = ".." not in parts
        if (
            re.match(r"^[A-Za-z]:", decoded)
            or decoded.startswith("\\\\")
            or normalized.startswith("/")
            or "\x00" in decoded
            or ("/" in decoded and "\\" in decoded)
            or not (local_route or sibling_route)
        ):
            fail(f"source path {key} must be a safe repository-relative route")
    if source_paths.get("hoxline_v1_source_manifest") != HOXLINE_SOURCE_MANIFEST_PATH:
        fail("source_paths.hoxline_v1_source_manifest must point to the Hoxline v1 source manifest")
    if source_paths.get("proof_current_status_index") != "../hawkinsoperations-proof/proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml":
        fail("source_paths.proof_current_status_index must point to the proof-owned current index")
    if source_paths.get("website_generated_status_consumer") != (
        "../hawkinsoperations-website/schemas/public-status-v0.schema.json"
    ):
        fail(
            "source_paths.website_generated_status_consumer must point to the "
            "website rendering schema, never generated consumer output"
        )

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
        "proof_source_identity": {
            "current_observed_head_sha": proof_head,
            "authoritative_git_blob_sha": proof_count["source_git_blob_sha"],
            "authoritative_content_fingerprint": proof_count["source_semantic_fingerprint_sha256"],
        },
        "candidate_reviews_verified": [
            review["artifact_id"] for review in contract["public_safe_candidate_reviews"]
        ],
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
