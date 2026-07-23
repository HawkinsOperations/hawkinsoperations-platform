from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "verify-public-status-source-contract.py"
CONTRACT_PATH = ROOT / "contracts" / "public-status-source-contract-v1.json"

spec = importlib.util.spec_from_file_location("verify_public_status_source_contract", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verifier)


class PublicStatusSourceContractTests(unittest.TestCase):
    def load_contract(self) -> dict:
        return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def verify_contract_copy(self, contract: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public-status-source-contract-v1.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            return verifier.verify_contract(path)

    def ho_det_001_review(self, contract: dict) -> dict:
        reviews = contract["public_safe_candidate_reviews"]
        return next(review for review in reviews if review["artifact_id"] == "HO-DET-001")

    def test_ho_det_001_candidate_review_is_bounded(self) -> None:
        result = verifier.verify_contract(CONTRACT_PATH)

        self.assertEqual(result["status"], "pass")
        self.assertIn("HO-DET-001", result["candidate_reviews_verified"])

    def test_rejects_runtime_active_candidate_review(self) -> None:
        contract = self.load_contract()
        self.ho_det_001_review(contract)["runtime_active"] = True

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_public_safe_candidate_review(self) -> None:
        contract = self.load_contract()
        self.ho_det_001_review(contract)["public_safe_status"] = "PUBLIC_SAFE"

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_missing_blocked_claim(self) -> None:
        contract = self.load_contract()
        review = self.ho_det_001_review(contract)
        review["blocked_claims"].remove("website rendering as proof")

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_promoted_allowed_claim(self) -> None:
        contract = self.load_contract()
        review = self.ho_det_001_review(contract)
        review["allowed_claims"] = ["HO-DET-001 is public-safe approved."]

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_non_pending_initial_review_marker(self) -> None:
        contract = copy.deepcopy(self.load_contract())
        self.ho_det_001_review(contract)["privacy_review"] = "PASS"

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_forged_current_proof_count(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["proof_record_count"]["current_value"] = 99

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_historical_proof_summary_as_current_source(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["proof_record_count"]["source_path"] = (
            "../hawkinsoperations-proof/proof/records/reviewer-metrics-pipeline-v1-summary.json"
        )

        with self.assertRaises(verifier.VerificationError):
            self.verify_contract_copy(contract)

    def test_rejects_forged_source_revision(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["proof_record_count"]["source_revision"] = "f" * 40
        with self.assertRaisesRegex(verifier.VerificationError, "legacy source_revision"):
            self.verify_contract_copy(contract)

    def test_rejects_forged_source_fingerprint(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["proof_record_count"]["source_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(verifier.VerificationError, "fingerprint"):
            self.verify_contract_copy(contract)

    def test_rejects_future_generated_at(self) -> None:
        contract = self.load_contract()
        contract["generated_at"] = "2999-01-01T00:00:00Z"
        with self.assertRaisesRegex(verifier.VerificationError, "future"):
            self.verify_contract_copy(contract)

    def test_rejects_nested_alternate_authority_field(self) -> None:
        contract = self.load_contract()
        contract["future_generated_status_v1_extraction"]["extension"] = {
            "nested": [{"ai-authority": True}]
        }
        with self.assertRaisesRegex(verifier.VerificationError, "authority field must remain blocked"):
            self.verify_contract_copy(contract)

    def test_negative_boundary_sibling_cannot_launder_promotion(self) -> None:
        contract = self.load_contract()
        contract["future_generated_status_v1_extraction"]["extension"] = {
            "note": "blocked",
            "claim": "customer deployment complete",
        }
        with self.assertRaisesRegex(verifier.VerificationError, "promotional phrase"):
            self.verify_contract_copy(contract)

    def test_blocked_claim_text_is_not_allowed_outside_blocked_claims(self) -> None:
        for prose in ("customer deployed", "public safe", "AI authority enabled"):
            with self.subTest(prose=prose):
                contract = self.load_contract()
                contract["future_generated_status_v1_extraction"]["extension"] = {
                    "note": prose
                }
                with self.assertRaisesRegex(
                    verifier.VerificationError, "promotional phrase"
                ):
                    self.verify_contract_copy(contract)

    def test_clause_local_negative_claim_text_remains_bounded(self) -> None:
        for prose in (
            "does not prove customer deployed",
            "missing production ready",
        ):
            with self.subTest(prose=prose):
                contract = self.load_contract()
                contract["future_generated_status_v1_extraction"]["extension"] = {
                    "note": prose
                }
                result = self.verify_contract_copy(contract)
                self.assertEqual(result["status"], "pass")

    def test_distant_negation_does_not_launder_later_public_safe_claim(self) -> None:
        contract = self.load_contract()
        contract["future_generated_status_v1_extraction"]["extension"] = {
            "note": "does not prove customer deployed, but public safe"
        }
        with self.assertRaisesRegex(verifier.VerificationError, "promotional phrase"):
            self.verify_contract_copy(contract)

    def test_rejects_case_folded_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text('{"manifest_id":"A","Manifest_ID":"B"}', encoding="utf-8")
            with self.assertRaisesRegex(verifier.VerificationError, "duplicate JSON key"):
                verifier.load_json(path)

    def test_rejects_duplicate_canonical_source_owner(self) -> None:
        contract = self.load_contract()
        contract["source_repos"][0]["repo"] = "hawkinsoperations-platform"
        with self.assertRaisesRegex(
            verifier.VerificationError, "exactly the seven canonical repositories"
        ):
            self.verify_contract_copy(contract)

    def test_rejects_encoded_source_path_traversal(self) -> None:
        contract = self.load_contract()
        contract["source_paths"]["website_generated_status_consumer"] = (
            "..%252f..%252fprivate%252fevidence.json"
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "safe repository-relative route"
        ):
            self.verify_contract_copy(contract)

    def test_rejects_mixed_separator_source_path(self) -> None:
        contract = self.load_contract()
        contract["source_paths"]["website_generated_status_consumer"] = (
            "..\\hawkinsoperations-website/public\\data/status.json"
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "safe repository-relative route"
        ):
                self.verify_contract_copy(contract)

    def test_rejects_nested_generated_at_pointer_drift(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["generated_at"]["current_value"] = (
            "2026-06-16T22:06:47.5510594-05:00"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must equal the root generated_at"):
            self.verify_contract_copy(contract)

    def test_rejects_generated_website_consumer_as_authority_source(self) -> None:
        contract = self.load_contract()
        contract["source_paths"]["website_generated_status_consumer"] = (
            "../hawkinsoperations-website/public/data/public-status.json"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "website rendering schema"):
            self.verify_contract_copy(contract)

    def test_rejects_unknown_public_field_shape(self) -> None:
        contract = self.load_contract()
        contract["public_fields"]["proof_record_count"]["opaque_extension"] = {
            "looks_harmless": True
        }
        with self.assertRaisesRegex(verifier.VerificationError, "contains unknown fields"):
            self.verify_contract_copy(contract)

    def test_rejects_duplicate_keys_in_proof_yaml(self) -> None:
        with self.assertRaisesRegex(
            verifier.VerificationError, "duplicate YAML key"
        ):
            verifier.load_yaml_bytes(
                b"entries: []\nEntries: []\n",
                source="proof-owned current status index",
            )

    def test_detached_historical_authority_is_rejected_even_with_same_blob(self) -> None:
        proof_count = self.load_contract()["public_fields"]["proof_record_count"]
        real_git_output = verifier.git_output

        def fake_git_output(repo: Path, *args: str) -> str:
            if args == ("branch", "--show-current"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return "f" * 40
            return real_git_output(repo, *args)

        with mock.patch.object(
            verifier, "git_output", side_effect=fake_git_output
        ), mock.patch.object(
            verifier,
            "git_is_ancestor",
            side_effect=lambda _repo, ancestor, descendant: ancestor == "f" * 40,
        ):
            with self.assertRaisesRegex(verifier.VerificationError, "older historical ancestor"):
                verifier.verify_proof_source_identity(proof_count)

    def test_detached_rewritten_authority_accepts_exact_reviewed_tree(self) -> None:
        proof_count = self.load_contract()["public_fields"]["proof_record_count"]
        real_git_output = verifier.git_output

        def fake_git_output(repo: Path, *args: str) -> str:
            if args == ("branch", "--show-current"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return "f" * 40
            return real_git_output(repo, *args)

        with mock.patch.object(
            verifier, "git_output", side_effect=fake_git_output
        ), mock.patch.object(
            verifier, "git_is_ancestor", return_value=False
        ), mock.patch.object(
            verifier, "git_tree_sha", return_value="e" * 40
        ):
            raw, observed_head = verifier.verify_proof_source_identity(proof_count)
        self.assertTrue(raw)
        self.assertEqual("f" * 40, observed_head)

    def test_reviewed_classification_cannot_launder_unreachable_observation(self) -> None:
        proof_count = self.load_contract()["public_fields"]["proof_record_count"]
        proof_count["source_revision"] = "f" * 40
        proof_count["source_observed_head_sha"] = "f" * 40
        proof_count["current_observed_head_sha"] = "f" * 40
        manifest = json.loads(verifier.SOURCE_MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["repositories"]["hawkinsoperations-proof"]["revision"] = "f" * 40
        with mock.patch.object(verifier, "load_json", return_value=manifest):
            with self.assertRaisesRegex(verifier.VerificationError, "unreachable"):
                verifier.verify_proof_source_identity(proof_count)


if __name__ == "__main__":
    unittest.main()
