from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ho_factory.py"

spec = importlib.util.spec_from_file_location("ho_factory_case_growth", SCRIPT_PATH)
ho_factory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ho_factory
spec.loader.exec_module(ho_factory)


def run_workflow_vocabulary_guard(workflow_path: Path, files: dict[str, bytes]):
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Reject retired fixture vocabulary"
    )
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        subprocess.run(["git", "add", "--", *files], cwd=root, check=True)
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            capture_output=True,
            text=True,
        )


class HoxlineCaseGrowthConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.org_root = Path(self.temp_dir.name)
        for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS:
            (self.org_root / repo).mkdir(parents=True)
            (self.org_root / repo / ".git").mkdir()
        self.sha = "a" * 40
        self.snapshot_path = self.org_root / "hoxline/examples/case-growth/current-case-growth-index.json"
        self.proof_index_path = self.org_root / "hawkinsoperations-proof/proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml"
        self.detection_path = self.org_root / "hawkinsoperations-detections/detections/DETECTION_PROMOTION_MATRIX.yml"
        self.validation_path = self.org_root / "hawkinsoperations-validation/validation/VALIDATION_REGISTRY.yml"
        self.website_path = self.org_root / "hawkinsoperations-website/public/data/public-status.json"
        self.contract_path = self.org_root / "hawkinsoperations-platform/contracts/public-status-source-contract-v1.json"
        self.source_manifest_path = (
            self.org_root
            / "hawkinsoperations-platform/contracts/hoxline-case-growth-source-manifest-v1.json"
        )
        self.review_manifest_path = (
            self.org_root
            / ".github/governance/CONVERGENCE_SOURCE_MANIFEST.json"
        )
        self.authority_paths = {
            repo: self.org_root / repo / relative_path
            for repo, relative_path in ho_factory.HOXLINE_CASE_GROWTH_AUTHORITY_PATHS.items()
        }
        for path in (
            self.snapshot_path,
            self.proof_index_path,
            self.detection_path,
            self.validation_path,
            self.website_path,
            self.contract_path,
            self.source_manifest_path,
            self.review_manifest_path,
            *self.authority_paths.values(),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
        record = self.org_root / "hawkinsoperations-proof/proof/records/CASE-001.md"
        card = self.org_root / "hawkinsoperations-proof/proof/cards/CASE-001.md"
        record.parent.mkdir(parents=True)
        card.parent.mkdir(parents=True)
        record.write_text("CASE-001 NOT_PUBLIC_SAFE CONTROLLED_TEST_VALIDATED", encoding="utf-8")
        card.write_text("CASE-001 NOT_PUBLIC_SAFE CONTROLLED_TEST_VALIDATED", encoding="utf-8")
        self.snapshot = {
            "historical_snapshot": False,
            "current_authority": True,
            "source_revisions": {
                repo: {
                    "source_commit_sha": self.sha,
                    "source_observed_head_sha": self.sha,
                    "current_observed_head_sha": self.sha,
                    "source_observation_kind": "reviewed_immutable_commit",
                    "source_path": ho_factory.HOXLINE_CASE_GROWTH_AUTHORITY_PATHS[repo],
                    "source_git_blob_sha": "b" * 40,
                }
                for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS
            },
            "summary": {"proof_records_count": 1, "proofcards_count": 1},
        }
        self.proof_index = {
            "current_authority": {
                "derived_counts": {
                    "indexed_case_count": 1,
                    "proof_record_count": 1,
                    "proof_card_count": 1,
                    "missing_proof_record_count": 0,
                    "missing_proof_card_count": 0,
                }
            },
            "entries": [
                {
                    "detection_id": "CASE-001",
                    "validation_status": "CONTROLLED_TEST_VALIDATED",
                    "proof_record_path": "proof/records/CASE-001.md",
                    "proof_card_path": "proof/cards/CASE-001.md",
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                }
            ],
        }
        self.detection = {"entries": [{"detection_id": "CASE-001"}]}
        self.validation = {"packages": [{"detection_id": "CASE-001"}]}
        self.website = {
            "generated_at": "2026-07-22T12:00:00Z",
            "freshness": {"status": "fresh", "max_age_hours": 336},
            "metrics": {
                "proof_records": {
                    "value": 1,
                    "source_repo": "HawkinsOperations/hawkinsoperations-proof",
                    "source_path": "proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml",
                }
            },
        }
        self.contract = {
            "generated_at": "2026-07-22T12:00:00Z",
            "freshness_window_days": 14,
            "public_fields": {
                "proof_record_count": {
                    "current_value": 1,
                    "source_path": "../hawkinsoperations-proof/proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml",
                    "source_revision": self.sha,
                    "source_observed_head_sha": self.sha,
                    "source_git_blob_sha": "b" * 40,
                    "historical_snapshot": False,
                    "current_authority": True,
                }
            },
        }
        self.source_manifest = {
            "manifest_id": "HOXLINE_CASE_GROWTH_SOURCE_MANIFEST_V1",
            "version": 1,
            "owner_repo": "hawkinsoperations-platform",
            "purpose": (
                "Pin the seven repository observations used by the read-only "
                "Hoxline Case Growth convergence verifier."
            ),
            "proof_ceiling": (
                "CONTROLLED_REPO_CONVERGENCE_AND_LOCAL_FIXTURE_REVIEW_ONLY"
            ),
            "repositories": {
                repo: (
                    {
                        "repository": f"HawkinsOperations/{repo}",
                        "revision_source": "checked_platform_observation",
                    }
                    if repo == "hawkinsoperations-platform"
                    else {
                        "repository": f"HawkinsOperations/{repo}",
                        "revision": self.sha,
                    }
                )
                for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS
            },
            "constraints": {
                "exact_repository_count": 7,
                "read_only": True,
                "allow_default_branch_substitution": False,
                "allow_detached_authority_substitution": False,
                "allow_dirty_authority_source": False,
                "website_is_authority": False,
                "hoxline_is_cross_domain_authority": False,
            },
        }
        self.review_manifest = {
            "schema": "hawkinsoperations-convergence-source-manifest-v1",
            "manifest_id": "HAWKINSOPERATIONS_SEVEN_SOURCE_PR_HEAD_MATRIX_V1",
            "repositories": [
                (
                    {
                        "repository": repo,
                        "canonical_repository": f"HawkinsOperations/{repo}",
                        "revision_source": "github_event_sha",
                        "tree_source": "github_event_tree",
                        "authority_content_revision": self.sha,
                    }
                    if repo == ".github"
                    else {
                        "repository": repo,
                        "canonical_repository": f"HawkinsOperations/{repo}",
                        "revision": self.sha,
                        "authority_content_revision": self.sha,
                        "reviewed_tree_sha": "e" * 40,
                    }
                )
                for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS
            ],
            "constraints": {
                "exact_repository_count": 7,
                "read_only": True,
                "default_branch_fallback": False,
                "require_detached_exact_revision": True,
                "record_checked_revisions": True,
                "consumer_outputs_are_not_authority": True,
                "proof_ceiling": (
                    "CONTROLLED_REPO_CONVERGENCE_AND_LOCAL_FIXTURE_REVIEW_ONLY"
                ),
            },
        }
        self.write_sources()

    def write_sources(self) -> None:
        self.proof_index_path.write_text(yaml.safe_dump(self.proof_index), encoding="utf-8")
        self.detection_path.write_text(yaml.safe_dump(self.detection), encoding="utf-8")
        self.validation_path.write_text(yaml.safe_dump(self.validation), encoding="utf-8")
        self.website_path.write_text(json.dumps(self.website), encoding="utf-8")
        self.authority_paths[".github"].write_text('{"invariants":[]}', encoding="utf-8")
        self.authority_paths["hawkinsoperations-website"].write_text('{"type":"object"}', encoding="utf-8")
        self.authority_paths["hoxline"].write_text("# controlled collector source\n", encoding="utf-8")
        proof_semantic = ho_factory.hoxline_case_growth_semantic_fingerprint(
            ho_factory.HOXLINE_CASE_GROWTH_AUTHORITY_PATHS["hawkinsoperations-proof"],
            self.proof_index_path.read_bytes(),
        )
        self.contract["public_fields"]["proof_record_count"]["source_semantic_fingerprint_sha256"] = proof_semantic
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        self.source_manifest_path.write_text(
            json.dumps(self.source_manifest), encoding="utf-8"
        )
        self.review_manifest_path.write_text(
            json.dumps(self.review_manifest), encoding="utf-8"
        )
        revisions = self.snapshot["source_revisions"]
        revision_map = (
            revisions
            if isinstance(revisions, dict)
            else {
                str(item.get("repo") or item.get("repository")): item
                for item in revisions
                if isinstance(item, dict)
            }
        )
        for repo, authority_path in self.authority_paths.items():
            raw = authority_path.read_bytes()
            semantic = ho_factory.hoxline_case_growth_semantic_fingerprint(
                ho_factory.HOXLINE_CASE_GROWTH_AUTHORITY_PATHS[repo], raw
            )
            if repo in revision_map:
                revision_map[repo]["source_semantic_fingerprint_sha256"] = semantic
        self.snapshot_path.write_text(json.dumps(self.snapshot), encoding="utf-8")

    def verify(
        self,
        *,
        origin_override: str | None = None,
        dirty: bool = False,
        branch: str = "feature/test",
        head: str | None = None,
        blob_overrides: dict[tuple[str, str], str] | None = None,
        missing_commits: set[str] | None = None,
        ancestor_pairs: set[tuple[str, str]] | None = None,
        direct_parent_pairs: set[tuple[str, str]] | None = None,
        tree_overrides: dict[str, str | None] | None = None,
        changed_paths_overrides: dict[tuple[str, str, str], set[str] | None]
        | None = None,
    ) -> dict:
        resolved_head = head or self.sha
        selected_blob_overrides = blob_overrides or {}
        selected_missing_commits = missing_commits or set()
        selected_ancestor_pairs = ancestor_pairs or set()
        selected_direct_parent_pairs = direct_parent_pairs or set()
        selected_tree_overrides = tree_overrides or {}
        selected_changed_paths_overrides = changed_paths_overrides or {}

        def git_blob(repo_path: Path, revision: str, relative_path: str) -> tuple[str, bytes]:
            blob_sha = selected_blob_overrides.get(
                (repo_path.name, revision), "b" * 40
            )
            return blob_sha, (repo_path / relative_path).read_bytes()

        with mock.patch.object(
            ho_factory,
            "hoxline_case_growth_git_state",
            side_effect=lambda path: {
                "branch": branch,
                "head": resolved_head,
                "origin": origin_override or f"https://github.com/HawkinsOperations/{path.name}.git",
                "dirty": dirty,
            },
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_commit_exists",
            side_effect=lambda _repo_path, commit_sha: (
                commit_sha not in selected_missing_commits
            ),
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_git_blob",
            side_effect=git_blob,
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_is_ancestor",
            side_effect=lambda _repo_path, ancestor, descendant: (
                (ancestor, descendant) in selected_ancestor_pairs
            ),
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_is_direct_parent",
            side_effect=lambda _repo_path, parent, child: (
                (parent, child) in selected_direct_parent_pairs
            ),
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_tree_sha",
            side_effect=lambda _repo_path, revision: selected_tree_overrides.get(
                revision, "e" * 40
            ),
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_changed_paths",
            side_effect=lambda repo_path, older, newer: (
                None
                if selected_changed_paths_overrides.get(
                    (repo_path.name, older, newer), set()
                )
                is None
                else frozenset(
                    selected_changed_paths_overrides.get(
                        (repo_path.name, older, newer), set()
                    )
                )
            ),
        ):
            return ho_factory.hoxline_case_growth_convergence_verify(
                self.org_root, now=datetime(2026, 7, 22, 18, tzinfo=timezone.utc)
            )

    def test_current_sources_pass_without_mutation(self) -> None:
        before = {
            path: path.read_bytes()
            for path in (
                self.snapshot_path,
                self.proof_index_path,
                self.detection_path,
                self.validation_path,
                self.website_path,
                self.contract_path,
            )
        }
        result = self.verify()
        self.assertEqual(result["status"], "pass")
        self.assertEqual([], result["drift"])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_unreachable_current_observation_fails_closed(self) -> None:
        forged_observation = "f" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = forged_observation
        self.write_sources()
        result = self.verify(missing_commits={forged_observation})
        self.assertIn(
            "SOURCE_REVISION_UNRESOLVED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_missing_current_observation_fails_closed(self) -> None:
        del self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ]
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "SOURCE_REVISION_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_malformed_current_observation_fails_closed(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = "not-a-commit"
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "SOURCE_REVISION_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_current_observation_content_mismatch_fails_closed(self) -> None:
        reviewed_observation = "f" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = reviewed_observation
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == "hawkinsoperations-proof":
                entry["revision"] = reviewed_observation
        self.write_sources()
        result = self.verify(
            blob_overrides={
                ("hawkinsoperations-proof", reviewed_observation): "c" * 40,
            },
        )
        self.assertIn(
            "SOURCE_OBSERVATION_CONTENT_MISMATCH",
            {item["code"] for item in result["contradictions"]},
        )

    def test_convergence_has_no_filesystem_mutation_primitive(self) -> None:
        with mock.patch.object(
            Path, "write_text", side_effect=AssertionError("write_text forbidden")
        ), mock.patch.object(
            Path, "write_bytes", side_effect=AssertionError("write_bytes forbidden")
        ), mock.patch.object(
            Path, "unlink", side_effect=AssertionError("unlink forbidden")
        ), mock.patch.object(
            Path, "replace", side_effect=AssertionError("replace forbidden")
        ), mock.patch.object(
            Path, "rename", side_effect=AssertionError("rename forbidden")
        ):
            result = self.verify()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["runtime_mutated"])
        self.assertFalse(result["public_proof_promoted"])

    def test_manifest_selected_stale_head_with_same_authority_blob_is_bounded(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = "b" * 40
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == "hawkinsoperations-proof":
                entry["revision"] = "b" * 40
        self.write_sources()
        result = self.verify(ancestor_pairs={("b" * 40, self.sha)})
        self.assertEqual(result["status"], "pass")
        self.assertIn(
            "SOURCE_HEAD_OBSERVATION_STALE_CONTENT_CURRENT",
            {item["code"] for item in result["drift"]},
        )

    def test_detached_rewritten_tip_with_manifest_selected_same_blob_passes(self) -> None:
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "current_observed_head_sha"
        ] = rewritten_head
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(branch="", head=rewritten_head)
        self.assertEqual(result["status"], "pass")
        self.assertNotIn(
            "DETACHED_SOURCE_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_historical_same_blob_ancestor_cannot_masquerade_as_current(self) -> None:
        historical_head = "c" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": historical_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=historical_head,
                ancestor_pairs={(historical_head, self.sha)},
            )
        codes = {item["code"] for item in result["contradictions"]}
        self.assertIn("SOURCE_MANIFEST_OBSERVATION_RELATIONSHIP_INVALID", codes)
        self.assertIn("DETACHED_SOURCE_NOT_MANIFEST_SELECTED", codes)

    def test_rewritten_same_blob_requires_exact_reviewed_repository_tree(self) -> None:
        rewritten_head = "d" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                tree_overrides={
                    rewritten_head: "c" * 40,
                    self.sha: "e" * 40,
                },
            )
        self.assertIn(
            "SOURCE_MANIFEST_OBSERVATION_RELATIONSHIP_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_reviewed_ancestor_of_current_same_blob_merge_passes(self) -> None:
        merge_head = "d" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "current_observed_head_sha"
        ] = merge_head
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": merge_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=merge_head,
                ancestor_pairs={(self.sha, merge_head)},
                tree_overrides={
                    merge_head: "c" * 40,
                    self.sha: "e" * 40,
                },
            )
        self.assertEqual("pass", result["status"])

    def test_platform_snapshot_reviewed_ancestor_of_current_is_accepted(self) -> None:
        merge_head = "d" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": merge_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=merge_head,
                ancestor_pairs={(self.sha, merge_head)},
            )
        self.assertEqual("pass", result["status"])

    def test_exact_content_head_equality_is_not_misclassified_as_future(self) -> None:
        self.write_sources()
        result = self.verify(
            ancestor_pairs={(self.sha, self.sha)},
        )
        self.assertEqual("pass", result["status"])
        self.assertNotIn(
            "SOURCE_AUTHORITY_CONTENT_RELATIONSHIP_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_platform_snapshot_exact_tree_survives_rewritten_identity(self) -> None:
        rewritten_head = "d" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                tree_overrides={
                    rewritten_head: "e" * 40,
                    self.sha: "e" * 40,
                },
            )
        self.assertEqual("pass", result["status"])

    def test_content_commit_survives_rewritten_final_reviewed_tree(self) -> None:
        content_commit = "c" * 40
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "source_commit_sha"
        ] = content_commit
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "source_observed_head_sha"
        ] = content_commit
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "current_observed_head_sha"
        ] = rewritten_head
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == "hawkinsoperations-platform":
                entry["authority_content_revision"] = content_commit
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                ancestor_pairs={(content_commit, self.sha)},
                tree_overrides={
                    content_commit: "c" * 40,
                    self.sha: "e" * 40,
                    rewritten_head: "e" * 40,
                },
            )
        self.assertEqual("pass", result["status"])

    def test_command_center_content_survives_squash_identity(self) -> None:
        content_commit = "c" * 40
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"][".github"]["source_commit_sha"] = (
            content_commit
        )
        self.snapshot["source_revisions"][".github"][
            "source_observed_head_sha"
        ] = content_commit
        self.snapshot["source_revisions"][".github"][
            "current_observed_head_sha"
        ] = rewritten_head
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == ".github":
                entry["authority_content_revision"] = content_commit
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                tree_overrides={
                    content_commit: "c" * 40,
                    self.sha: "e" * 40,
                    rewritten_head: "e" * 40,
                },
            )
        self.assertEqual("pass", result["status"])
        self.assertNotIn(
            "SOURCE_AUTHORITY_CONTENT_RELATIONSHIP_INVALID",
            {
                item["code"]
                for item in result["contradictions"]
                if item.get("repo") == ".github"
            },
        )

    def test_rewritten_tree_rejects_content_outside_reviewed_lineage(self) -> None:
        content_commit = "c" * 40
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "source_commit_sha"
        ] = content_commit
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "source_observed_head_sha"
        ] = content_commit
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "current_observed_head_sha"
        ] = rewritten_head
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == "hawkinsoperations-platform":
                entry["authority_content_revision"] = content_commit
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                tree_overrides={
                    content_commit: "c" * 40,
                    self.sha: "e" * 40,
                    rewritten_head: "e" * 40,
                },
            )
        self.assertIn(
            "SOURCE_AUTHORITY_CONTENT_RELATIONSHIP_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_platform_snapshot_current_ancestor_of_reviewed_is_rejected(self) -> None:
        historical_head = "c" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": historical_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=historical_head,
                ancestor_pairs={(historical_head, self.sha)},
            )
        codes = {item["code"] for item in result["contradictions"]}
        self.assertIn("SOURCE_MANIFEST_OBSERVATION_RELATIONSHIP_INVALID", codes)
        self.assertIn("SOURCE_AUTHORITY_CONTENT_RELATIONSHIP_INVALID", codes)

    def test_platform_snapshot_unrelated_detached_revision_is_rejected(self) -> None:
        rewritten_head = "d" * 40
        unrelated_review = "f" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-platform"][
            "current_observed_head_sha"
        ] = unrelated_review
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": rewritten_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=rewritten_head,
                tree_overrides={
                    rewritten_head: "e" * 40,
                    self.sha: "e" * 40,
                    unrelated_review: "c" * 40,
                },
            )
        self.assertIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_command_center_reviewed_tree_mismatch_fails_closed(self) -> None:
        for entry in self.review_manifest["repositories"]:
            if entry["repository"] == "hawkinsoperations-platform":
                entry["reviewed_tree_sha"] = "c" * 40
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "SOURCE_REVIEW_MANIFEST_TREE_MISMATCH",
            {item["code"] for item in result["contradictions"]},
        )

    def test_missing_command_center_review_manifest_fails_closed(self) -> None:
        self.review_manifest_path.unlink()
        result = self.verify()
        self.assertIn(
            "MALFORMED_SOURCE",
            {item["code"] for item in result["contradictions"]},
        )

    def test_command_center_self_content_revision_is_required(self) -> None:
        del self.review_manifest["repositories"][0]["authority_content_revision"]
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "MALFORMED_SOURCE",
            {item["code"] for item in result["contradictions"]},
        )

    def test_command_center_self_content_revision_resolves_from_full_history(
        self,
    ) -> None:
        current_head = "d" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": current_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=current_head,
                ancestor_pairs={(self.sha, current_head)},
            )
        self.assertEqual("pass", result["status"])

    def test_command_center_same_content_survives_rewritten_event_tree(
        self,
    ) -> None:
        content_commit = "c" * 40
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"][".github"][
            "source_commit_sha"
        ] = content_commit
        self.snapshot["source_revisions"][".github"][
            "source_observed_head_sha"
        ] = content_commit
        self.snapshot["source_revisions"][".github"][
            "current_observed_head_sha"
        ] = rewritten_head
        self.review_manifest["repositories"][0][
            "authority_content_revision"
        ] = content_commit
        self.write_sources()
        result = self.verify(
            branch="feature/test",
            head=rewritten_head,
            ancestor_pairs={(self.sha, rewritten_head)},
            tree_overrides={
                content_commit: "c" * 40,
                self.sha: "e" * 40,
                rewritten_head: "e" * 40,
            },
        )
        self.assertEqual("pass", result["status"])

    def test_command_center_rewritten_event_rejects_changed_authority_blob(
        self,
    ) -> None:
        content_commit = "c" * 40
        rewritten_head = "d" * 40
        self.snapshot["source_revisions"][".github"][
            "source_commit_sha"
        ] = content_commit
        self.snapshot["source_revisions"][".github"][
            "source_observed_head_sha"
        ] = content_commit
        self.snapshot["source_revisions"][".github"][
            "current_observed_head_sha"
        ] = rewritten_head
        self.review_manifest["repositories"][0][
            "authority_content_revision"
        ] = content_commit
        self.write_sources()
        result = self.verify(
            branch="rehearsal-squash",
            head=rewritten_head,
            blob_overrides={
                (".github", content_commit): "c" * 40,
                (".github", rewritten_head): "b" * 40,
            },
            tree_overrides={
                content_commit: "c" * 40,
                self.sha: "e" * 40,
                rewritten_head: "e" * 40,
            },
        )
        self.assertIn(
            "SOURCE_AUTHORITY_CONTENT_REVISION_STALE",
            {item["code"] for item in result["contradictions"]},
        )

    def test_command_center_self_future_content_revision_is_rejected(self) -> None:
        historical_head = "c" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": historical_head},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head=historical_head,
                ancestor_pairs={(historical_head, self.sha)},
            )
        self.assertIn(
            "SOURCE_AUTHORITY_CONTENT_RELATIONSHIP_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_source_workflow_fetches_full_history_for_all_seven_repositories(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/hoxline-source-checks.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(7, workflow.count("fetch-depth: 0"))
        self.assertNotIn("fetch-depth: 1", workflow)
        self.assertIn('retired = "".join(("syn", "thetic"))', workflow)
        self.assertIn('unicodedata.normalize("NFKC"', workflow)
        self.assertIn('["git", "ls-files", "-z"]', workflow)
        self.assertIn('["git", "show", f":{relative}"]', workflow)
        self.assertIn("tracked non-binary content contains NUL", workflow)
        self.assertGreaterEqual(workflow.count("check=True"), 2)
        self.assertNotIn("git grep", workflow)

    def test_platform_source_manifest_matches_reviewed_command_center_matrix(
        self,
    ) -> None:
        source_manifest = json.loads(
            (
                ROOT
                / "contracts"
                / "hoxline-case-growth-source-manifest-v1.json"
            ).read_text(encoding="utf-8")
        )
        command_center_manifest_path = (
            ROOT.parent
            / ".github"
            / "governance"
            / "CONVERGENCE_SOURCE_MANIFEST.json"
        )
        if not command_center_manifest_path.is_file():
            self.skipTest("command-center sibling checkout is unavailable")
        command_center_manifest = json.loads(
            command_center_manifest_path.read_text(encoding="utf-8")
        )
        reviewed = {
            entry["repository"]: entry
            for entry in command_center_manifest["repositories"]
        }
        for repository, entry in source_manifest["repositories"].items():
            if repository in {".github", "hawkinsoperations-platform"}:
                continue
            self.assertEqual(
                reviewed[repository]["revision"],
                entry["revision"],
                f"{repository} must use the reviewed immutable revision",
            )

    def test_source_workflow_vocabulary_guard_rejects_nfkc_utf16_and_git_errors(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/hoxline-source-checks.yml"
        retired = "".join(("syn", "thetic"))
        fullwidth = "".join(chr(ord(character) + 0xFEE0) for character in retired)
        self.assertEqual(
            retired,
            unicodedata.normalize("NFKC", fullwidth).casefold(),
        )
        result = run_workflow_vocabulary_guard(
            workflow_path,
            {
                f"fixture-{fullwidth}.txt": b"controlled-test\n",
                "content-fixture.txt": f"{fullwidth}\n".encode(),
                "utf16-fixture.md": f"{retired}\n".encode("utf-16-le"),
            },
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("utf16-fixture.md", result.stderr + result.stdout)
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        step = next(
            item
            for item in next(iter(workflow["jobs"].values()))["steps"]
            if item.get("name") == "Reject retired fixture vocabulary"
        )
        source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            operational = subprocess.run(
                [sys.executable, "-c", source],
                cwd=temp,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, operational.returncode)

    def test_source_workflow_vocabulary_guard_classifies_sqlite_as_binary(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/hoxline-source-checks.yml"
        sqlite = run_workflow_vocabulary_guard(
            workflow_path,
            {
                "evidence/autosoc-case-ledger-v0.sqlite": (
                    b"SQLite format 3\x00\x10\x00\x01\x01"
                ),
            },
        )
        self.assertEqual(0, sqlite.returncode, sqlite.stderr + sqlite.stdout)

        unknown_binary = run_workflow_vocabulary_guard(
            workflow_path,
            {"evidence/unclassified-ledger.payload": b"binary\x00content"},
        )
        self.assertNotEqual(0, unknown_binary.returncode)
        self.assertIn(
            "tracked non-binary content contains NUL",
            unknown_binary.stderr + unknown_binary.stdout,
        )

    def test_controlled_test_truth_class_replaces_retired_factory_token(self) -> None:
        factory = SCRIPT_PATH.read_text(encoding="utf-8")
        controller = (
            ROOT / "docs/factory/DETECTION_FACTORY_CONTROLLER_V0.md"
        ).read_text(encoding="utf-8")
        retired = "SYN" + "THETIC_TEST_CASE"
        self.assertIn("CONTROLLED_TEST_CASE", factory)
        self.assertIn("CONTROLLED_TEST_CASE", controller)
        self.assertNotIn(retired, factory)
        self.assertNotIn(retired, controller)

    def test_arbitrary_same_blob_observation_not_selected_by_manifest_fails_closed(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = "c" * 40
        self.write_sources()
        result = self.verify(
            ancestor_pairs={("c" * 40, self.sha)},
            tree_overrides={"c" * 40: "d" * 40},
        )
        self.assertIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_hoxline_generated_pair_selects_its_exact_content_parent(self) -> None:
        content_commit = "c" * 40
        self.snapshot["source_revisions"]["hoxline"][
            "current_observed_head_sha"
        ] = content_commit
        self.write_sources()
        result = self.verify(
            direct_parent_pairs={(content_commit, self.sha)},
        )
        self.assertEqual("pass", result["status"])
        self.assertNotIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_rewritten_head_accepts_exact_reviewed_consumer_projection(self) -> None:
        stated_sha = "c" * 40
        rewritten_head = "d" * 40
        reviewed_tree = "f" * 40
        self.snapshot["source_revisions"]["hoxline"][
            "current_observed_head_sha"
        ] = stated_sha
        for entry in self.review_manifest["repositories"]:
            if "reviewed_tree_sha" in entry:
                entry["reviewed_tree_sha"] = reviewed_tree
        self.write_sources()
        result = self.verify(
            head=rewritten_head,
            ancestor_pairs={
                (self.sha, stated_sha),
                (self.sha, rewritten_head),
            },
            tree_overrides={
                stated_sha: "1" * 40,
                rewritten_head: reviewed_tree,
                self.sha: reviewed_tree,
            },
            changed_paths_overrides={
                ("hoxline", stated_sha, rewritten_head): {
                    "examples/case-growth/current-case-growth-index.json",
                    "examples/case-growth/current-case-growth-index.md",
                }
            },
        )
        self.assertEqual("pass", result["status"], result)
        self.assertNotIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_rewritten_head_rejects_foreign_exact_path_projection(self) -> None:
        stated_sha = "c" * 40
        rewritten_head = "d" * 40
        reviewed_tree = "f" * 40
        self.snapshot["source_revisions"]["hoxline"][
            "current_observed_head_sha"
        ] = stated_sha
        for entry in self.review_manifest["repositories"]:
            if "reviewed_tree_sha" in entry:
                entry["reviewed_tree_sha"] = reviewed_tree
        self.write_sources()
        result = self.verify(
            head=rewritten_head,
            ancestor_pairs={(self.sha, rewritten_head)},
            tree_overrides={
                stated_sha: "1" * 40,
                rewritten_head: reviewed_tree,
                self.sha: reviewed_tree,
            },
            changed_paths_overrides={
                ("hoxline", stated_sha, rewritten_head): {
                    "examples/case-growth/current-case-growth-index.json",
                    "examples/case-growth/current-case-growth-index.md",
                }
            },
        )
        self.assertIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_rewritten_command_center_accepts_exact_manifest_projection(self) -> None:
        stated_sha = "c" * 40
        rewritten_head = "d" * 40
        reviewed_tree = "f" * 40
        self.snapshot["source_revisions"][".github"][
            "current_observed_head_sha"
        ] = stated_sha
        for entry in self.review_manifest["repositories"]:
            if "reviewed_tree_sha" in entry:
                entry["reviewed_tree_sha"] = reviewed_tree
        self.write_sources()
        result = self.verify(
            head=rewritten_head,
            ancestor_pairs={
                (self.sha, stated_sha),
                (self.sha, rewritten_head),
            },
            tree_overrides={
                stated_sha: "1" * 40,
                rewritten_head: reviewed_tree,
                self.sha: reviewed_tree,
            },
            changed_paths_overrides={
                (".github", stated_sha, rewritten_head): {
                    "governance/CONVERGENCE_SOURCE_MANIFEST.json",
                }
            },
        )
        self.assertEqual("pass", result["status"], result)
        self.assertNotIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_rewritten_head_rejects_projection_with_extra_path(self) -> None:
        stated_sha = "c" * 40
        rewritten_head = "d" * 40
        reviewed_tree = "f" * 40
        self.snapshot["source_revisions"]["hoxline"][
            "current_observed_head_sha"
        ] = stated_sha
        for entry in self.review_manifest["repositories"]:
            if "reviewed_tree_sha" in entry:
                entry["reviewed_tree_sha"] = reviewed_tree
        self.write_sources()
        result = self.verify(
            head=rewritten_head,
            ancestor_pairs={
                (self.sha, stated_sha),
                (self.sha, rewritten_head),
            },
            tree_overrides={
                stated_sha: "1" * 40,
                rewritten_head: reviewed_tree,
                self.sha: reviewed_tree,
            },
            changed_paths_overrides={
                ("hoxline", stated_sha, rewritten_head): {
                    "examples/case-growth/current-case-growth-index.json",
                    "examples/case-growth/current-case-growth-index.md",
                    "src/hoxline/case_growth/collector.py",
                }
            },
        )
        self.assertIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_detached_arbitrary_third_same_blob_observation_fails_closed(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = "c" * 40
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": "d" * 40},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head="d" * 40,
                tree_overrides={"c" * 40: "b" * 40},
            )
        self.assertIn(
            "SOURCE_OBSERVATION_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_detached_foreign_or_unreachable_observation_fails_closed(self) -> None:
        foreign_sha = "f" * 40
        self.snapshot["source_revisions"]["hawkinsoperations-proof"][
            "current_observed_head_sha"
        ] = foreign_sha
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": "d" * 40},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head="d" * 40,
                missing_commits={foreign_sha},
            )
        self.assertIn(
            "SOURCE_REVISION_UNRESOLVED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_detached_manifest_selected_changed_blob_fails_closed(self) -> None:
        self.write_sources()
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": "d" * 40},
            clear=True,
        ):
            result = self.verify(
                branch="",
                head="d" * 40,
                blob_overrides={
                    ("hawkinsoperations-proof", self.sha): "c" * 40,
                },
            )
        codes = {item["code"] for item in result["contradictions"]}
        self.assertIn("SOURCE_MANIFEST_CONTENT_STALE", codes)
        self.assertIn("DETACHED_SOURCE_NOT_MANIFEST_SELECTED", codes)

    def test_detached_platform_without_exact_checked_observation_fails(self) -> None:
        self.write_sources()
        with mock.patch.dict(ho_factory.os.environ, {}, clear=True):
            result = self.verify(branch="", head="d" * 40)
        self.assertIn(
            "DETACHED_SOURCE_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_arbitrary_observation_cannot_override_current_authority_blob(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"]["source_git_blob_sha"] = "c" * 40
        self.write_sources()
        result = self.verify()
        self.assertIn("SOURCE_AUTHORITY_BLOB_DRIFT", {item["code"] for item in result["contradictions"]})

    def test_forged_hoxline_proof_count_fails_closed(self) -> None:
        self.snapshot["summary"]["proof_records_count"] = 99
        self.write_sources()
        result = self.verify()
        self.assertIn("HOXLINE_PROOF_COUNT_DRIFT", {item["code"] for item in result["contradictions"]})

    def test_encoded_proof_path_escape_fails_closed(self) -> None:
        self.proof_index["entries"][0]["proof_record_path"] = (
            "proof/records/%252e%252e/private.md"
        )
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "UNSAFE_PROOF_PATH",
            {item["code"] for item in result["contradictions"]},
        )

    def test_stale_website_labeled_fresh_fails_closed(self) -> None:
        self.website["generated_at"] = "2026-06-01T00:00:00Z"
        self.write_sources()
        result = self.verify()
        self.assertIn("WEBSITE_FRESHNESS_CONTRADICTION", {item["code"] for item in result["contradictions"]})

    def test_stale_platform_contract_fails_closed(self) -> None:
        self.contract["generated_at"] = "2026-06-01T00:00:00Z"
        self.write_sources()
        result = self.verify()
        self.assertIn("PLATFORM_CONTRACT_STALE", {item["code"] for item in result["contradictions"]})

    def test_duplicate_source_revision_entry_fails_closed(self) -> None:
        self.snapshot["source_revisions"] = [
            {"repo": repo, "source_commit_sha": self.sha} for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS
        ]
        self.snapshot["source_revisions"].append({"repo": "hoxline", "source_commit_sha": self.sha})
        self.write_sources()
        result = self.verify()
        self.assertIn("SOURCE_REVISION_SET_INVALID", {item["code"] for item in result["contradictions"]})

    def test_website_owner_suffix_bypass_fails_closed(self) -> None:
        self.website["metrics"]["proof_records"]["source_repo"] = "evil-hawkinsoperations-proof"
        self.write_sources()
        result = self.verify()
        self.assertIn("WEBSITE_PROOF_OWNER_INVALID", {item["code"] for item in result["contradictions"]})

    def test_repository_owner_suffix_spoof_fails_closed(self) -> None:
        result = self.verify(origin_override="https://github.com/evil/hawkinsoperations-proof.git")
        self.assertIn(
            "SOURCE_REPOSITORY_IDENTITY_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_dirty_authority_sources_fail_closed(self) -> None:
        result = self.verify(dirty=True)
        self.assertIn("SOURCE_WORKTREE_DIRTY", {item["code"] for item in result["contradictions"]})

    def test_detached_platform_requires_exact_checked_observation_sha(self) -> None:
        with mock.patch.dict(ho_factory.os.environ, {}, clear=True):
            result = self.verify(branch="")
        self.assertIn(
            "DETACHED_SOURCE_NOT_MANIFEST_SELECTED",
            {item["code"] for item in result["contradictions"]},
        )

    def test_detached_platform_rejects_another_repository_event_sha(self) -> None:
        with mock.patch.dict(
            ho_factory.os.environ,
            {"HAWKINS_PLATFORM_IMMUTABLE_OBSERVED_SHA": "f" * 40},
            clear=True,
        ):
            result = self.verify(branch="", head="d" * 40)
        self.assertIn(
            "SOURCE_PLATFORM_OBSERVATION_MISMATCH",
            {item["code"] for item in result["contradictions"]},
        )

    def test_future_generated_at_fails_closed(self) -> None:
        self.website["generated_at"] = "2026-07-23T12:00:00Z"
        self.contract["generated_at"] = "2026-07-23T12:00:00Z"
        self.write_sources()
        result = self.verify()
        codes = {item["code"] for item in result["contradictions"]}
        self.assertIn("WEBSITE_GENERATED_AT_FUTURE", codes)
        self.assertIn("PLATFORM_CONTRACT_GENERATED_AT_FUTURE", codes)

    def test_nested_authority_promotion_fails_closed(self) -> None:
        attacks = (
            ("ai-authority", True),
            ("production_active", True),
            ("production_live", {"enabled": True}),
            ("customer_deployment", True),
            ("socaas_deployment", True),
            ("runtime_status", "active"),
            ("signal_status", "observed"),
            ("approval_status", "approved"),
            ("closure_status", "closed"),
            ("case_status", "closed"),
            ("public_safe_runtime", True),
            ("final_authorized", True),
            ("%70roduction_active", True),
        )
        for key, value in attacks:
            with self.subTest(key=key):
                self.website["extensions"] = {"opaque": [{key: value}]}
                self.write_sources()
                result = self.verify()
                self.assertIn(
                    "NESTED_AUTHORITY_PROMOTION",
                    {item["code"] for item in result["contradictions"]},
                )

    def test_split_and_direct_authority_state_paths_fail_closed(self) -> None:
        attacks = (
            {"runtime": {"state": True}},
            {"signal": {"observed": True}},
            {"public": {"safe": True}},
            {"approval": {"status": True}},
            {"production": {"active": True}},
            {"customer": {"deployed": True}},
            {"socaas": {"deployed": True}},
            {"ai": {"authority": True}},
            {"analyst": {"approval": True}},
            {"review": {"disposition": "APPROVED"}},
            {"final": {"authorization": True}},
            {"case": {"closed": True}},
            {"extensions": [{"final": {"authorization": True}}]},
            {"runtime": {"metadata": {"state": True}}},
            {"final": {"review": {"authorization": True}}},
            {"ai": {"metadata": {"authority": True}}},
            {"customer": {"review": {"deployed": True}}},
            {"review": {"metadata": {"disposition": "APPROVED"}}},
            {"production_live": {"enabled": True}},
            {"ai_authority": {"enabled": True}},
            {"review_disposition": {"approved": True}},
            {"final_authorization": {"granted": True}},
            {"runtime_state": True},
            {"approval_state": True},
            {"production_state": True},
            {"customer_state": True},
            {"socaas_state": True},
            {"final_authority": True},
            {"case_state": True},
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                self.assertTrue(
                    ho_factory.hoxline_case_growth_authority_violations(attack)
                )

    def test_split_and_direct_authority_state_bounded_controls_pass(self) -> None:
        controls = (
            {"runtime": {"state": False}},
            {"signal": {"observed": False}},
            {"public": {"safe": "NOT_PUBLIC_SAFE"}},
            {"approval": {"status": "NOT_APPROVED"}},
            {"production": {"active": "BLOCKED"}},
            {"customer": {"deployed": False}},
            {"socaas": {"deployed": False}},
            {"ai": {"authority": False}},
            {"analyst": {"approval": "NOT_APPROVED"}},
            {"review": {"disposition": "NOT_APPROVED"}},
            {"final": {"authorization": "BLOCKED"}},
            {"case": {"closed": False}},
            {"extensions": [{"final": {"authorization": "BLOCKED"}}]},
            {"runtime_state": False},
            {"approval_state": "NOT_APPROVED"},
            {"production_state": "BLOCKED"},
            {"customer_state": False},
            {"socaas_state": False},
            {"final_authority": False},
            {"case_state": False},
            {"production_live": {"enabled": False}},
            {"ai_authority": {"enabled": False}},
            {"review_disposition": {"approved": "NOT_APPROVED"}},
            {"final_authorization": {"granted": "BLOCKED"}},
        )
        for control in controls:
            with self.subTest(control=control):
                self.assertEqual(
                    [],
                    ho_factory.hoxline_case_growth_authority_violations(control),
                )

    def test_compound_owned_context_names_remain_bounded(self) -> None:
        self.assertEqual(
            [],
            ho_factory.hoxline_case_growth_authority_violations(
                {
                    "runtime_truth_spine": {
                        "runtime_truth": {
                            "state": "RUNTIME_EVIDENCE_VERIFIED_PRIVATE"
                        }
                    },
                    "socaas_pilot_receipt_flow": {
                        "pilot_status": "EXISTING_FLOW_CANDIDATE"
                    },
                }
            ),
        )

    def test_current_hoxline_snapshot_bounded_states_do_not_promote(self) -> None:
        current_snapshot_authority_surface = {
            "case_growth_health": {
                "not_public_safe_percent": 100.0,
            },
            "cases": [
                {
                    "case_state": "BLOCKED_WAITING_NEXT_GATE",
                    "runtime_candidate_status": "PRIVATE_RUNTIME_CANDIDATE",
                },
                {
                    "case_state": "BLOCKED_WAITING_NEXT_GATE",
                    "runtime_candidate_status": "NOT_INDEXED",
                },
                {
                    "case_state": "BLOCKED_WAITING_NEXT_GATE",
                    "runtime_candidate_status": "LISTED_ONLY",
                    "notes": [
                        (
                            "Controlled fixture validation only. This does not prove "
                            "runtime-active, signal-observed, production-ready, or "
                            "public-safe status."
                        )
                    ],
                },
                {
                    "case_state": "BLOCKED_WAITING_NEXT_GATE",
                    "runtime_candidate_status": "TELEMETRY_CONTRACT_ONLY",
                },
            ],
        }

        self.assertEqual(
            [],
            ho_factory.hoxline_case_growth_authority_violations(
                current_snapshot_authority_surface
            ),
        )

    def test_authority_violation_diagnostics_are_deduplicated(self) -> None:
        violations = ho_factory.hoxline_case_growth_authority_violations(
            {"case_state": "CLOSED"}
        )

        self.assertEqual([("case_state", "CLOSED")], violations)

    def test_bounded_contract_metadata_does_not_inherit_public_safe_promotion(self) -> None:
        contract_metadata = {
            "public_safe_state": {
                "owner_repo": "hawkinsoperations-proof",
                "source_path": "proof/index.json",
                "render_allowed": True,
                "source_status": "BOUNDARY_DEFAULT_NOT_PROMOTED",
                "freshness_policy": (
                    "Remain NOT_PUBLIC_SAFE unless proof-owned authority changes it."
                ),
            },
            "public_safe_candidate_reviews": [
                {
                    "artifact_id": "HO-DET-001",
                    "review_lane": "PUBLIC_SAFE_CANDIDATE_REVIEW_V1",
                    "human_review_required": True,
                    "allowed_claims": [
                        "Controlled validation remains under public-safe candidate review."
                    ],
                    "blocked_claims": ["runtime active", "case closed"],
                }
            ],
        }

        self.assertEqual(
            [],
            ho_factory.hoxline_case_growth_authority_violations(
                contract_metadata
            ),
        )

    def test_exact_public_safe_source_owner_pointer_is_bounded(self) -> None:
        bounded = {
            "public_safe_policy": {
                "public_safe_source_required": "hawkinsoperations-proof"
            }
        }
        self.assertEqual(
            [],
            ho_factory.hoxline_case_growth_authority_violations(bounded),
        )
        for hostile in ("PUBLIC_SAFE", True):
            with self.subTest(hostile=hostile):
                attack = {
                    "public_safe_policy": {
                        "public_safe_source_required": hostile
                    }
                }
                self.assertTrue(
                    ho_factory.hoxline_case_growth_authority_violations(attack)
                )

    def test_negative_metadata_paths_do_not_exempt_structured_laundering(self) -> None:
        attacks = (
            {"freshness_policy": {"production_live": True}},
            {"blocked_claims": [{"ai_authority": {"enabled": True}}]},
            {
                "no_proof_promotion_statement": {
                    "public_safe_status": "PUBLIC_SAFE"
                }
            },
        )

        for attack in attacks:
            with self.subTest(attack=attack):
                self.assertTrue(
                    ho_factory.hoxline_case_growth_authority_violations(attack)
                )

    def test_nested_authority_string_laundering_fails_closed(self) -> None:
        self.website["extensions"] = {
            "opaque": [{"note": "customer deployed and production ready"}]
        }
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "NESTED_AUTHORITY_PROMOTION",
            {item["code"] for item in result["contradictions"]},
        )

    def test_nested_authority_vocabulary_variants_fail_closed(self) -> None:
        attacks = (
            "deployed to customer Acme",
            "customer environment deployed",
            "production is live",
            "analyst approved this disposition",
            "final authorization received",
            "case closure complete",
            "runtime is active",
            "signal was observed",
            "public safe for release",
            "SOCaaS is deployed",
        )
        for prose in attacks:
            with self.subTest(prose=prose):
                self.website["extensions"] = {"opaque": [{"note": prose}]}
                self.write_sources()
                result = self.verify()
                self.assertIn(
                    "NESTED_AUTHORITY_PROMOTION",
                    {item["code"] for item in result["contradictions"]},
                )

    def test_blocked_claim_container_cannot_exempt_nested_prose(self) -> None:
        self.website["extensions"] = {
            "blocked_claims": [{"detail": "customer deployment is active"}]
        }
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "NESTED_AUTHORITY_PROMOTION",
            {item["code"] for item in result["contradictions"]},
        )

    def test_nested_plain_public_safe_and_ai_authority_prose_fails_closed(self) -> None:
        for prose in ("public safe", "AI authority enabled"):
            with self.subTest(prose=prose):
                self.website["extensions"] = {"opaque": [{"note": prose}]}
                self.write_sources()
                result = self.verify()
                self.assertIn(
                    "NESTED_AUTHORITY_PROMOTION",
                    {item["code"] for item in result["contradictions"]},
                )

    def test_clause_local_negative_prose_remains_bounded(self) -> None:
        for prose in (
            "does not prove customer deployed",
            "missing production ready",
            (
                "This does not prove runtime-active status, signal-observed "
                "status, production-ready status, public-safe status, "
                "AI-approved status, or analyst-approved status."
            ),
            (
                "Render only bounded metadata; never treat rendering as proof, "
                "runtime truth, public-safe status, final authorization, or "
                "case closure."
            ),
            (
                "Runtime, signal, public-safe, production, customer, AI "
                "approval, final authorization, and case closure claims "
                "remain blocked."
            ),
            "Café résumé – reviewer note.",
        ):
            with self.subTest(prose=prose):
                self.website["extensions"] = {"opaque": [{"note": prose}]}
                self.write_sources()
                result = self.verify()
                self.assertNotIn(
                    "NESTED_AUTHORITY_PROMOTION",
                    {item["code"] for item in result["contradictions"]},
                )

    def test_negation_cannot_launder_later_adversative_promotion(self) -> None:
        attacks = (
            "does not prove customer deployed, but public safe",
            "does not prove runtime, customer deployment is active",
            "does not prove runtime, AI authority is enabled",
            "does not prove runtime, analyst approval granted",
            "does not prove runtime, public safe is confirmed",
            "does not prove runtime, final authorization received",
            "does not prove runtime, case closure approved",
            "does not prove runtime and customer deployment is active",
            "does not prove runtime plus public safe is confirmed",
            "does not prove runtime though case closure is approved",
            "public\u200b safe is confirmed",
            "case\u200b closure approved",
            "AI\u200b authority is enabled",
            "runtime\u200b is active",
            "pending documentation, production is live",
            "unsupported note — customer environment deployed",
            "future issue: signal was observed",
            "missing receipt while production is live",
            "no proof currently, customer environment deployed",
            "not approved / production is live",
        )
        for prose in attacks:
            with self.subTest(prose=prose):
                self.website["extensions"] = {"opaque": [{"note": prose}]}
                self.write_sources()
                result = self.verify()
                self.assertIn(
                    "NESTED_AUTHORITY_PROMOTION",
                    {item["code"] for item in result["contradictions"]},
                )

    def test_combining_mark_obfuscation_in_nested_shapes_fails_closed(self) -> None:
        templates = (
            "public\\u{code} safe is confirmed",
            "case\\u{code} closure approved",
            "runtime\\u{code} is active",
            "AI\\u{code} authority is enabled",
        )
        for code in ("034f", "0301", "fe0f", "0000", "0008", "001f", "007f"):
            for template in templates:
                attack = json.loads(
                    '{"opaque":[{"notes":[{"deep":"'
                    + template.format(code=code)
                    + '"}]}]}'
                )
                with self.subTest(code=code, template=template):
                    self.website["extensions"] = attack
                    self.write_sources()
                    result = self.verify()
                    self.assertIn(
                        "NESTED_AUTHORITY_PROMOTION",
                        {item["code"] for item in result["contradictions"]},
                    )

        self.website["extensions"] = {
            "opaque": [
                {
                    "notes": [
                        "Café résumé – reviewer note.",
                        {"deep": "Reviewer 👩‍💻️ note."},
                        {"multiline": "Reviewer note.\n\tStill bounded."},
                    ]
                }
            ]
        }
        self.write_sources()
        result = self.verify()
        self.assertNotIn(
            "NESTED_AUTHORITY_PROMOTION",
            {item["code"] for item in result["contradictions"]},
        )

    def test_connector_independent_and_trailing_negation_attacks_fail(self) -> None:
        connectors = (
            ",", "and", "plus", "though", "because", "therefore",
            "meanwhile", "furthermore", "also", "nevertheless",
            "nonetheless", "except", "despite that", "in fact", "so",
            "consequently", "moreover", "then", "still", "even though",
        )
        attacks = [
            (
                f"does not prove runtime{connector} customer deployment is active"
                if connector == ","
                else f"does not prove runtime {connector} customer deployment is active"
            )
            for connector in connectors
        ]
        attacks.extend(
            (
                "customer deployment is active and not a typo",
                "runtime is active and not simulated",
                "final authorization received and no objections",
                "AI authority is enabled and not revoked",
                "public safe is confirmed and not disputed",
                "case closure approved and not provisional",
                "production is ready and not delayed",
                "signal is observed and not inferred",
                "customer deployment is active without ambiguity",
            )
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                self.assertTrue(
                    ho_factory.hoxline_case_growth_authority_violations(
                        {"notes": attack}
                    )
                )

    def test_unhashable_nested_public_safe_shape_fails_closed_without_crashing(self) -> None:
        self.website["extensions"] = {
            "opaque": [{"public_safe_status": ["NOT_PUBLIC_SAFE", "PUBLIC_SAFE"]}]
        }
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "NESTED_AUTHORITY_PROMOTION",
            {item["code"] for item in result["contradictions"]},
        )

    def test_malformed_detection_entries_fail_closed_without_crashing(self) -> None:
        self.detection["entries"] = {"CASE-001": {"detection_id": "CASE-001"}}
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "DETECTION_ENTRIES_INVALID",
            {item["code"] for item in result["contradictions"]},
        )

    def test_malformed_validation_packages_fail_closed_without_crashing(self) -> None:
        self.validation["packages"] = "CASE-001"
        self.write_sources()
        result = self.verify()
        self.assertIn(
            "VALIDATION_PACKAGES_INVALID",
            {item["code"] for item in result["contradictions"]},
        )


if __name__ == "__main__":
    unittest.main()
