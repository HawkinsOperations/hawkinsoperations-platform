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
        self.sha = "a" * 40
        self.snapshot_path = self.org_root / "hoxline/examples/case-growth/current-case-growth-index.json"
        self.proof_index_path = self.org_root / "hawkinsoperations-proof/proof/indexes/DETECTION_PROOF_STATUS_INDEX.yml"
        self.detection_path = self.org_root / "hawkinsoperations-detections/detections/DETECTION_PROMOTION_MATRIX.yml"
        self.validation_path = self.org_root / "hawkinsoperations-validation/validation/VALIDATION_REGISTRY.yml"
        self.website_path = self.org_root / "hawkinsoperations-website/public/data/public-status.json"
        self.contract_path = self.org_root / "hawkinsoperations-platform/contracts/public-status-source-contract-v1.json"
        for path in (
            self.snapshot_path,
            self.proof_index_path,
            self.detection_path,
            self.validation_path,
            self.website_path,
            self.contract_path,
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
                repo: {"source_commit_sha": self.sha} for repo in ho_factory.HOXLINE_CASE_GROWTH_REPOS
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
                    "historical_snapshot": False,
                    "current_authority": True,
                }
            },
        }
        self.write_sources()

    def write_sources(self) -> None:
        self.snapshot_path.write_text(json.dumps(self.snapshot), encoding="utf-8")
        self.proof_index_path.write_text(yaml.safe_dump(self.proof_index), encoding="utf-8")
        self.detection_path.write_text(yaml.safe_dump(self.detection), encoding="utf-8")
        self.validation_path.write_text(yaml.safe_dump(self.validation), encoding="utf-8")
        self.website_path.write_text(json.dumps(self.website), encoding="utf-8")
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")

    def verify(self) -> dict:
        with mock.patch.object(
            ho_factory,
            "hoxline_case_growth_git_state",
            return_value={"branch": "feature/test", "head": self.sha, "dirty": False},
        ), mock.patch.object(ho_factory, "hoxline_case_growth_commit_exists", return_value=True):
            return ho_factory.hoxline_case_growth_convergence_verify(
                self.org_root, now=datetime(2026, 7, 22, 18, tzinfo=timezone.utc)
            )

    def test_current_sources_pass_without_mutation(self) -> None:
        result = self.verify()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])

    def test_stale_source_revision_fails_closed(self) -> None:
        self.snapshot["source_revisions"]["hawkinsoperations-proof"]["source_commit_sha"] = "b" * 40
        self.write_sources()
        result = self.verify()
        self.assertIn("SOURCE_REVISION_DRIFT", {item["code"] for item in result["contradictions"]})

    def test_forged_hoxline_proof_count_fails_closed(self) -> None:
        self.snapshot["summary"]["proof_records_count"] = 99
        self.write_sources()
        result = self.verify()
        self.assertIn("HOXLINE_PROOF_COUNT_DRIFT", {item["code"] for item in result["contradictions"]})

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

    def test_future_generated_at_fails_closed(self) -> None:
        self.website["generated_at"] = "2026-07-23T12:00:00Z"
        self.contract["generated_at"] = "2026-07-23T12:00:00Z"
        self.write_sources()
        result = self.verify()
        codes = {item["code"] for item in result["contradictions"]}
        self.assertIn("WEBSITE_GENERATED_AT_FUTURE", codes)
        self.assertIn("PLATFORM_CONTRACT_GENERATED_AT_FUTURE", codes)


if __name__ == "__main__":
    unittest.main()
