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


class HoxlineControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = ho_factory.hoxline_build_evidence_graph(ho_factory.hoxline_runtime_replay_fixture())
        self.promotion = ho_factory.hoxline_promotion_state_from_graph(self.graph)

    def claim(self, text: str) -> dict[str, object]:
        return ho_factory.hoxline_claim_authority_check(self.graph, self.promotion, text)

    def test_graph_promotion_and_proofcard_hashes_are_deterministic(self) -> None:
        graph_again = ho_factory.hoxline_build_evidence_graph(ho_factory.hoxline_runtime_replay_fixture())
        promotion_again = ho_factory.hoxline_promotion_state_from_graph(graph_again)
        proofcard = ho_factory.hoxline_proofcard_draft(self.graph, self.promotion)
        proofcard_again = ho_factory.hoxline_proofcard_draft(graph_again, promotion_again)

        self.assertEqual(self.graph["graph_hash"], graph_again["graph_hash"])
        self.assertEqual(self.promotion["promotion_hash"], promotion_again["promotion_hash"])
        self.assertEqual(proofcard["proofcard_draft_hash"], proofcard_again["proofcard_draft_hash"])
        self.assertFalse(proofcard["public_proof_promoted"])
        self.assertEqual(proofcard["public_safe_status"], "NOT_PUBLIC_SAFE")

    def test_unsafe_claims_are_blocked(self) -> None:
        blocked_claims = [
            "Hoxline is production SOC",
            "Hoxline is SOCaaS deployed",
            "AI approved the case",
            "analyst approved the case",
            "public-safe runtime proof exists",
            "schedule enabled",
            "ledger appended",
            "case closed",
        ]

        for text in blocked_claims:
            with self.subTest(text=text):
                self.assertEqual(self.claim(text)["decision"], "BLOCKED")

    def test_exact_bounded_private_runtime_claim_is_allowed_with_scope(self) -> None:
        result = self.claim(ho_factory.HOXLINE_BOUNDED_ALLOWED_CLAIM)

        self.assertEqual(result["decision"], "ALLOWED_WITH_SCOPE")
        self.assertEqual(result["allowed_claim_text"], ho_factory.HOXLINE_BOUNDED_ALLOWED_CLAIM)
        self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertTrue(result["human_review_required"])

    def test_out_of_scope_claim_requires_constrained_rewrite(self) -> None:
        result = self.claim("Hoxline has private runtime evidence.")

        self.assertEqual(result["decision"], "CONSTRAINED_REWRITE_REQUIRED")
        self.assertEqual(result["allowed_claim_text"], ho_factory.HOXLINE_BOUNDED_ALLOWED_CLAIM)

    def test_missing_wazuh_receipt_blocks_graph_build(self) -> None:
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_build_evidence_graph(
                ho_factory.hoxline_runtime_replay_fixture(include_signal_receipt=False)
            )

    def test_missing_human_review_packet_keeps_promotion_blocked(self) -> None:
        graph = ho_factory.hoxline_build_evidence_graph(
            ho_factory.hoxline_runtime_replay_fixture(include_human_review_packet=False)
        )
        promotion = ho_factory.hoxline_promotion_state_from_graph(graph)

        self.assertEqual(promotion["stage_statuses"]["HUMAN_REVIEW_REQUIRED"], "BLOCKED")
        self.assertEqual(promotion["current_state"], "BLOCKED_MISSING_HUMAN_REVIEW_PACKET")
        self.assertTrue(promotion["human_review_required"])

    def test_raw_private_payload_field_fails_closed(self) -> None:
        graph = dict(self.graph)
        graph["raw_alert"] = "blocked"

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_evidence_graph_shape(graph)

    def test_stale_graph_blocks_claim_decision(self) -> None:
        graph = dict(self.graph)
        graph["graph_hash"] = "0" * 64

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_claim_authority_check(graph, self.promotion, ho_factory.HOXLINE_BOUNDED_ALLOWED_CLAIM)

    def test_runtime_counts_are_separate_from_lifetime_ledger_counts(self) -> None:
        metrics_node = next(node for node in self.graph["nodes"] if node["node_type"] == "runtime_metrics")
        metrics = metrics_node["evidence"]

        self.assertEqual(metrics["runtime_candidate_count"], 1)
        self.assertEqual(metrics["lifetime_ledger_case_count"], 6)
        self.assertNotEqual(metrics["runtime_candidate_count"], metrics["lifetime_ledger_case_count"])
        self.assertEqual(metrics["ledger_append_count"], 0)
        self.assertEqual(metrics["public_proof_promotion_count"], 0)
        self.assertEqual(metrics["schedule_enabled"], 0)

    def test_ai_output_remains_support_only(self) -> None:
        ai_node = next(node for node in self.graph["nodes"] if node["node_type"] == "ai_support_result")

        self.assertFalse(ai_node["evidence"]["ai_decided_disposition"])
        self.assertTrue(self.promotion["human_review_required"])

    def test_control_plane_self_test(self) -> None:
        result = ho_factory.hoxline_control_plane_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)
        self.assertFalse(result["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
