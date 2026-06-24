from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ho_factory.py"

spec = importlib.util.spec_from_file_location("ho_factory", SCRIPT_PATH)
ho_factory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ho_factory
spec.loader.exec_module(ho_factory)


class HoxlineMultiDetectionRuntimeTests(unittest.TestCase):
    def verify(self, detection_id: str) -> dict[str, object]:
        return ho_factory.hoxline_multi_detection_runtime_verify(
            repo_root=ROOT,
            detection_id=detection_id,
            execution_id=None,
            private_route=None,
            fixture=True,
        )

    def test_supported_detection_fixtures_pass(self) -> None:
        for detection_id in ("HO-DET-001", "HO-DET-010", "HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                result = self.verify(detection_id)

                self.assertEqual(result["status"], "pass")
                self.assertEqual(result["detection_id"], detection_id)
                self.assertEqual(result["proof_ceiling"], "PRIVATE_CONTROLLED_RUNTIME_PROOF")
                self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")
                self.assertFalse(result["schedule_enabled"])

    def test_unsupported_detection_fails_closed(self) -> None:
        with self.assertRaises(ho_factory.FactoryError):
            self.verify("HO-DET-999")

    def test_missing_required_fields_fail_closed(self) -> None:
        missing_010 = ho_factory.hoxline_multi_detection_runtime_fixture(
            "HO-DET-010",
            omit_candidate_field="member_user_hash",
        )
        missing_011 = ho_factory.hoxline_multi_detection_runtime_fixture(
            "HO-DET-011",
            omit_candidate_field="service_name_hash",
        )
        missing_012 = ho_factory.hoxline_multi_detection_runtime_fixture(
            "HO-DET-012",
            omit_candidate_field="task_name_hash",
        )

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_multi_detection_fixture_packet(missing_010)
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_multi_detection_fixture_packet(missing_011)
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_multi_detection_fixture_packet(missing_012)

    def test_wrong_wazuh_rule_fails_closed(self) -> None:
        wrong_rule = ho_factory.hoxline_multi_detection_runtime_fixture(
            "HO-DET-011",
            wazuh_rule_id="910021",
        )

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_multi_detection_fixture_packet(wrong_rule)

    def test_duplicate_and_no_new_signal_are_safe_for_each_detection(self) -> None:
        for detection_id in ("HO-DET-001", "HO-DET-010", "HO-DET-011", "HO-DET-012"):
            result = self.verify(detection_id)

            self.assertTrue(result["checks"]["duplicate_signal_suppressed"])
            self.assertTrue(result["checks"]["no_new_signal_no_candidate"])

    def test_count_separation_per_detection(self) -> None:
        results = {detection_id: self.verify(detection_id) for detection_id in ("HO-DET-001", "HO-DET-010", "HO-DET-011", "HO-DET-012")}

        self.assertEqual({key: value["metrics"]["runtime_candidate_count"] for key, value in results.items()}, {
            "HO-DET-001": 1,
            "HO-DET-010": 1,
            "HO-DET-011": 1,
            "HO-DET-012": 1,
        })
        for result in results.values():
            self.assertNotEqual(result["metrics"]["runtime_candidate_count"], result["metrics"]["lifetime_ledger_case_count"])
            self.assertEqual(result["ledger_append_count"], 0)
            self.assertEqual(result["public_proof_promotion_count"], 0)

    def test_fixture_hashes_are_deterministic(self) -> None:
        fields = (
            "result_hash",
            "log_head_hash",
            "checkpoint_hash",
            "evidence_graph_hash",
            "candidate_hash",
            "normalization_hash",
            "dedupe_key_hash",
        )
        for detection_id in ("HO-DET-001", "HO-DET-010", "HO-DET-011", "HO-DET-012"):
            first = self.verify(detection_id)
            second = self.verify(detection_id)
            for field in fields:
                with self.subTest(detection_id=detection_id, field=field):
                    self.assertEqual(first[field], second[field])

    def test_claim_authority_blocks_unsafe_claims_and_allows_bounded_scope(self) -> None:
        cases = {
            "HO-DET-010": ["HO-DET-010 production SOC", "AI approved HO-DET-010"],
            "HO-DET-011": ["HO-DET-011 production SOC", "AI approved HO-DET-011"],
            "HO-DET-012": ["HO-DET-012 public-safe runtime proof", "analyst approved HO-DET-012"],
        }
        for detection_id, blocked_claims in cases.items():
            replay = ho_factory.hoxline_runtime_replay_fixture(
                execution_id=ho_factory.hoxline_multi_detection_default_execution_id(detection_id),
                detection_id=detection_id,
            )
            graph = ho_factory.hoxline_build_evidence_graph(replay)
            promotion = ho_factory.hoxline_promotion_state_from_graph(graph)
            for claim in blocked_claims:
                with self.subTest(claim=claim):
                    self.assertEqual(ho_factory.hoxline_claim_authority_check(graph, promotion, claim)["decision"], "BLOCKED")
            bounded = ho_factory.hoxline_claim_authority_check(
                graph,
                promotion,
                ho_factory.hoxline_bounded_runtime_claim(detection_id),
            )
            self.assertEqual(bounded["decision"], "ALLOWED_WITH_SCOPE")

    def test_no_raw_private_fields_and_governance_boundaries(self) -> None:
        result = self.verify("HO-DET-011")
        result["raw_alert"] = "blocked"

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_assert_no_raw_private_fields(result)

        clean = self.verify("HO-DET-012")
        self.assertFalse(clean["ledger_mutated"])
        self.assertFalse(clean["public_proof_promoted"])
        self.assertFalse(clean["schedule_enabled"])
        self.assertFalse(clean["ai_disposition_authority"])
        self.assertTrue(clean["human_review_required"])
        self.assertFalse(clean["case_closed"])

    def test_multi_detection_self_test(self) -> None:
        result = ho_factory.hoxline_multi_detection_runtime_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["schedule_enabled"])
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)


if __name__ == "__main__":
    unittest.main()
