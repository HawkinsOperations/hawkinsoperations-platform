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


class HoxlineControlledSchedulePilotTests(unittest.TestCase):
    def pilot(self, **kwargs: object) -> dict[str, object]:
        return ho_factory.hoxline_controlled_schedule_pilot(repo_root=ROOT, fixture=True, **kwargs)

    def test_pilot_state_hash_is_deterministic_and_final_disabled(self) -> None:
        first = self.pilot(cycle_count=2)
        second = self.pilot(cycle_count=2)

        self.assertEqual(first["pilot_hash"], second["pilot_hash"])
        self.assertEqual(first["pilot_verdict"], "PILOT_PASS_DISABLED_AFTER")
        self.assertFalse(first["schedule_enabled_before"])
        self.assertTrue(first["schedule_enabled_during_pilot"])
        self.assertFalse(first["schedule_enabled_after"])
        self.assertFalse(first["active_cron_trigger"])

    def test_more_than_two_cycles_fails_closed(self) -> None:
        blocked = self.pilot(cycle_count=3)

        self.assertEqual(blocked["pilot_verdict"], "BLOCKED_BACKPRESSURE")
        self.assertIn("MAX_PILOT_CYCLES_EXCEEDED", blocked["blocked_reasons"])
        self.assertFalse(blocked["schedule_enabled_after"])
        self.assertEqual(blocked["ledger_append_count"], 0)

    def test_no_new_signal_cycle_succeeds_without_candidate(self) -> None:
        result = self.pilot(cycle_count=1, cycle_outcomes=["NO_NEW_SIGNAL_NO_CANDIDATE"])

        self.assertEqual(result["pilot_verdict"], "PILOT_PASS_NO_NEW_SIGNAL_DISABLED_AFTER")
        self.assertEqual(result["no_new_signal_count"], 1)
        self.assertEqual(result["new_candidate_count"], 0)
        self.assertEqual(result["human_review_packet_count"], 0)

    def test_duplicate_cycle_succeeds_with_suppression(self) -> None:
        result = self.pilot(cycle_count=1, cycle_outcomes=["DUPLICATE_SIGNAL_SUPPRESSED"])

        self.assertEqual(result["pilot_verdict"], "PILOT_PASS_DUPLICATES_SUPPRESSED_DISABLED_AFTER")
        self.assertEqual(result["duplicate_signal_suppression_count"], 1)
        self.assertEqual(result["new_candidate_count"], 0)

    def test_new_candidate_remains_private_and_does_not_mutate_public_surfaces(self) -> None:
        result = self.pilot(cycle_count=1, cycle_outcomes=["NEW_SIGNAL_CANDIDATE_CREATED"])

        self.assertEqual(result["new_candidate_count"], 1)
        self.assertEqual(result["human_review_packet_count"], 1)
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)
        self.assertEqual(result["public_safe_case_count"], 0)
        self.assertEqual(result["closed_case_count"], 0)
        self.assertFalse(result["ai_disposition_authority"])
        self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")

    def test_final_enabled_and_dead_letter_cap_fail_disabled_after(self) -> None:
        final_enabled = self.pilot(cycle_count=1, schedule_enabled_after=True)
        dead_letter_cap = self.pilot(
            cycle_count=1,
            cycle_outcomes=["DEAD_LETTERED_FINAL"],
            dead_letter_count_override=ho_factory.hoxline_pilot_backpressure_policy()["max_dead_letters_per_run"] + 1,
        )

        self.assertEqual(final_enabled["pilot_verdict"], "BLOCKED_GOVERNANCE_RISK")
        self.assertFalse(final_enabled["schedule_enabled_after"])
        self.assertEqual(dead_letter_cap["pilot_verdict"], "PILOT_FAIL_DISABLED_AFTER")
        self.assertFalse(dead_letter_cap["schedule_enabled_after"])

    def test_emergency_disable_and_repo_variable_restoration_are_verified(self) -> None:
        result = self.pilot(cycle_count=2)

        self.assertTrue(result["emergency_disable_verified"])
        self.assertTrue(result["repo_variable_gate_disabled_after"])
        self.assertEqual(result["max_allowed_cycles"], 2)

    def test_claim_authority_blocks_unsafe_claims_and_allows_bounded_pilot_claim(self) -> None:
        graph = ho_factory.hoxline_build_evidence_graph(ho_factory.hoxline_runtime_replay_fixture())
        promotion = ho_factory.hoxline_promotion_state_from_graph(graph)

        blocked_claims = [
            "schedule is enabled",
            "production continuous SOC",
            "SOCaaS deployed",
            "customer deployed",
            "public-safe runtime proof",
            "AI approved the case",
            "analyst approved the case",
            "case closed",
        ]
        for claim in blocked_claims:
            with self.subTest(claim=claim):
                self.assertEqual(ho_factory.hoxline_claim_authority_check(graph, promotion, claim)["decision"], "BLOCKED")

        bounded = ho_factory.hoxline_claim_authority_check(
            graph,
            promotion,
            ho_factory.HOXLINE_BOUNDED_SCHEDULE_PILOT_CLAIM,
        )
        self.assertEqual(bounded["decision"], "ALLOWED_WITH_SCOPE")

    def test_raw_private_fields_fail_closed(self) -> None:
        result = self.pilot(cycle_count=1)
        result["raw_candidate"] = "blocked"

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_assert_no_raw_private_fields(result)

    def test_schedule_pilot_self_test(self) -> None:
        result = ho_factory.hoxline_schedule_pilot_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["pilot_verdict"], "PILOT_PASS_DISABLED_AFTER")
        self.assertFalse(result["schedule_enabled_after"])
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)


if __name__ == "__main__":
    unittest.main()
