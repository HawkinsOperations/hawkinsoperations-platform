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


class HoxlineScheduleReadinessTests(unittest.TestCase):
    def readiness(self, **kwargs: object) -> dict[str, object]:
        policy = ho_factory.hoxline_backpressure_policy()
        parts = ho_factory.hoxline_schedule_readiness_fixture(**kwargs)
        return ho_factory.hoxline_schedule_readiness_state(**parts, backpressure_policy=policy)

    def test_fixture_readiness_is_deterministic_and_does_not_enable_schedule(self) -> None:
        first = ho_factory.hoxline_schedule_readiness(repo_root=ROOT, execution_id=None, private_route=None, fixture=True)
        second = ho_factory.hoxline_schedule_readiness(repo_root=ROOT, execution_id=None, private_route=None, fixture=True)

        self.assertEqual(first["readiness_hash"], second["readiness_hash"])
        self.assertEqual(first["readiness_verdict"], "READY_FOR_SEPARATE_SCHEDULE_APPROVAL")
        self.assertFalse(first["schedule_enabled"])
        self.assertFalse(first["active_cron_trigger"])
        self.assertEqual(first["public_safe_status"], "NOT_PUBLIC_SAFE")

    def test_active_cron_and_schedule_enabled_fail_readiness(self) -> None:
        active_cron = self.readiness(active_cron_trigger=True)
        schedule_enabled = self.readiness(schedule_enabled=True)

        self.assertEqual(active_cron["readiness_verdict"], "NOT_READY_GOVERNANCE_RISK")
        self.assertIn("SCHEDULE_GOVERNANCE_RISK", active_cron["blocked_enable_reasons"])
        self.assertEqual(schedule_enabled["readiness_verdict"], "NOT_READY_GOVERNANCE_RISK")
        self.assertFalse(schedule_enabled["schedule_enabled"])

    def test_no_new_signal_and_duplicate_signal_are_success_states(self) -> None:
        ready = self.readiness()

        self.assertEqual(ready["no_new_signal_decision"]["decision"], "NO_NEW_SIGNAL_NO_CANDIDATE")
        self.assertFalse(ready["no_new_signal_decision"]["candidate_created"])
        self.assertEqual(ready["duplicate_signal_decision"]["decision"], "DUPLICATE_SIGNAL_SUPPRESSED")
        self.assertFalse(ready["duplicate_signal_decision"]["candidate_created"])

    def test_backpressure_limits_fail_closed(self) -> None:
        policy = ho_factory.hoxline_backpressure_policy()
        too_many_candidates = self.readiness(candidate_count=policy["max_candidates_per_run"] + 1)
        too_many_dead_letters = self.readiness(dead_letter_count=policy["max_dead_letters_per_run"] + 1)

        self.assertEqual(too_many_candidates["readiness_verdict"], "NOT_READY_BACKPRESSURE_MISSING")
        self.assertIn("MAX_CANDIDATES_PER_RUN_EXCEEDED", too_many_candidates["blocked_enable_reasons"])
        self.assertEqual(too_many_dead_letters["readiness_verdict"], "NOT_READY_BACKPRESSURE_MISSING")
        self.assertIn("MAX_DEAD_LETTERS_PER_RUN_EXCEEDED", too_many_dead_letters["blocked_enable_reasons"])

    def test_missing_health_or_claim_authority_is_not_ready(self) -> None:
        self.assertEqual(
            self.readiness(include_runner_health=False)["readiness_verdict"],
            "NOT_READY_RUNNER_HEALTH_MISSING",
        )
        self.assertEqual(
            self.readiness(include_wazuh_health=False)["readiness_verdict"],
            "NOT_READY_WAZUH_HEALTH_MISSING",
        )
        self.assertEqual(
            self.readiness(include_private_route_health=False)["readiness_verdict"],
            "NOT_READY_PRIVATE_ROUTE_MISSING",
        )
        self.assertEqual(
            self.readiness(include_evidence_graph=False)["readiness_verdict"],
            "NOT_READY_CLAIM_AUTHORITY_MISSING",
        )

    def test_emergency_disable_drill_blocks_collection_without_failure(self) -> None:
        result = ho_factory.hoxline_schedule_emergency_disable_drill()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["decision"], "EMERGENCY_DISABLE_ACTIVE")
        self.assertFalse(result["candidate_created"])
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertFalse(result["schedule_enabled"])

    def test_recovery_drill_dead_letters_exhausted_retry_and_suppresses_duplicate(self) -> None:
        result = ho_factory.hoxline_schedule_recovery_drill()

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertFalse(result["schedule_enabled"])
        self.assertIn("MAX_RETRIES_PER_EXECUTION_ID_EXCEEDED", result["backpressure_check"]["violations"])
        self.assertEqual(result["duplicate_signal_decision"]["decision"], "DUPLICATE_SIGNAL_SUPPRESSED")

    def test_claim_authority_blocks_schedule_and_production_claims(self) -> None:
        graph = ho_factory.hoxline_build_evidence_graph(ho_factory.hoxline_runtime_replay_fixture())
        promotion = ho_factory.hoxline_promotion_state_from_graph(graph)

        schedule_claim = ho_factory.hoxline_claim_authority_check(graph, promotion, "schedule enabled")
        production_claim = ho_factory.hoxline_claim_authority_check(graph, promotion, "production continuous SOC")
        bounded = ho_factory.hoxline_claim_authority_check(graph, promotion, ho_factory.HOXLINE_BOUNDED_ALLOWED_CLAIM)

        self.assertEqual(schedule_claim["decision"], "BLOCKED")
        self.assertEqual(production_claim["decision"], "BLOCKED")
        self.assertEqual(bounded["decision"], "ALLOWED_WITH_SCOPE")

    def test_raw_private_fields_fail_closed(self) -> None:
        ready = self.readiness()
        ready["raw_alert"] = "blocked"

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_assert_no_raw_private_fields(ready)

    def test_schedule_readiness_self_test(self) -> None:
        result = ho_factory.hoxline_schedule_readiness_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["readiness_verdict"], "READY_FOR_SEPARATE_SCHEDULE_APPROVAL")
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)
        self.assertFalse(result["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
