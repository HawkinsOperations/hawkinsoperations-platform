from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
