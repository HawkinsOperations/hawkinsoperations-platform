from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
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
                        "revision_source": "github_event_sha",
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
    ) -> dict:
        resolved_head = head or self.sha
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
            ho_factory, "hoxline_case_growth_commit_exists", return_value=True
        ), mock.patch.object(
            ho_factory,
            "hoxline_case_growth_git_blob",
            side_effect=lambda repo_path, revision, relative_path: (
                "b" * 40,
                (repo_path / relative_path).read_bytes(),
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
        self.assertTrue(result["read_only"])
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})

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

    def test_stale_head_observation_with_same_authority_blob_is_bounded(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"]["source_commit_sha"] = "b" * 40
        self.write_sources()
        result = self.verify()
        self.assertEqual(result["status"], "pass")
        self.assertIn(
            "SOURCE_HEAD_OBSERVATION_STALE_CONTENT_CURRENT",
            {item["code"] for item in result["drift"]},
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

    def test_detached_platform_sha_requires_exact_github_event_sha(self) -> None:
        with mock.patch.dict(ho_factory.os.environ, {}, clear=True):
            result = self.verify(branch="")
        self.assertIn(
            "DETACHED_SOURCE_NOT_MANIFEST_SELECTED",
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
        self.website["extensions"] = {"opaque": [{"ai-authority": True}]}
        self.write_sources()
        result = self.verify()
        self.assertIn("NESTED_AUTHORITY_PROMOTION", {item["code"] for item in result["contradictions"]})

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
