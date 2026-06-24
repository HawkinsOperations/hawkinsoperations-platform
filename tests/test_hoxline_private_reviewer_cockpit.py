from __future__ import annotations

import importlib.util
import os
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


class HoxlinePrivateReviewerCockpitTests(unittest.TestCase):
    def cockpit(self) -> dict[str, object]:
        return ho_factory.hoxline_private_reviewer_cockpit(ROOT, write_report=False)

    def detections(self, cockpit: dict[str, object]) -> dict[str, dict[str, object]]:
        return {item["detection_id"]: item for item in cockpit["detections"]}

    def test_self_test_passes(self) -> None:
        result = ho_factory.hoxline_private_reviewer_cockpit_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertFalse(result["schedule_enabled"])

    def test_schema_contract_accepts_sample_output_shape(self) -> None:
        cockpit = self.cockpit()
        schema = ho_factory.json.loads(ho_factory.HOXLINE_PRIVATE_REVIEWER_COCKPIT_SCHEMA.read_text(encoding="utf-8"))

        for field in schema["required"]:
            self.assertIn(field, cockpit)
        ho_factory.hoxline_validate_private_reviewer_cockpit(cockpit)
        self.assertEqual(cockpit["schema_version"], schema["properties"]["schema_version"]["const"])

    def test_ho_det_001_canonical_ai_recovered_state(self) -> None:
        ho_det_001 = self.detections(self.cockpit())["HO-DET-001"]

        self.assertTrue(ho_det_001["private_runtime_candidate"])
        self.assertEqual(ho_det_001["ai_status"], "AI_TRIAGE_RECOVERED_AND_CANONICAL")
        self.assertEqual(
            ho_det_001["canonical_human_review_packet_digest"],
            "589e4220b73cc26115629281f29fe34c17950e539454881734802392729ec2f9",
        )

    def test_historical_packet_is_not_canonical(self) -> None:
        ho_det_001 = self.detections(self.cockpit())["HO-DET-001"]

        self.assertEqual(
            ho_det_001["historical_noncanonical_packet_digest"],
            "78100a2e72b5ca5f1866f4bfba48d3b48dc0512eef8620d0eed1fe3c854cc891",
        )
        self.assertNotEqual(
            ho_det_001["historical_noncanonical_packet_digest"],
            ho_det_001["canonical_human_review_packet_digest"],
        )

    def test_standing_private_collector_detections_are_represented(self) -> None:
        detections = self.detections(self.cockpit())

        for detection_id in ho_factory.HOXLINE_STANDING_PRIVATE_COLLECTOR_SCOPE:
            with self.subTest(detection_id=detection_id):
                self.assertEqual(detections[detection_id]["private_runtime_packet"], "verified_private_packet")
                self.assertTrue(detections[detection_id]["scheduled_collection_included"])
                self.assertEqual(detections[detection_id]["public_safe_status"], "NOT_PUBLIC_SAFE")
                self.assertFalse(detections[detection_id]["ai_disposition_authority"])

    def test_global_governance_state_remains_private(self) -> None:
        global_state = self.cockpit()["global_state"]

        self.assertEqual(global_state["lifetime_ledger_cases"], 6)
        self.assertEqual(global_state["lifetime_ledger_events"], 6)
        self.assertEqual(global_state["public_safe_count"], 0)
        self.assertFalse(global_state["schedule_enabled"])
        self.assertTrue(global_state["standing_private_collector_enabled"])
        self.assertEqual(tuple(global_state["scheduled_collection_scope"]), ho_factory.HOXLINE_STANDING_PRIVATE_COLLECTOR_SCOPE)
        self.assertEqual(global_state["remote_lab_authority_rule"], "present")
        self.assertEqual(global_state["remote_default_mode"], "read_only")

    def test_remote_lab_authority_ci_fallback_is_bounded(self) -> None:
        original_path = ho_factory.HOXLINE_AGENTS_RULES
        original_env = os.environ.get("GITHUB_ACTIONS")
        try:
            ho_factory.HOXLINE_AGENTS_RULES = ROOT / "missing-agents-rules.md"
            os.environ.pop("GITHUB_ACTIONS", None)
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.hoxline_remote_lab_authority_state()

            os.environ["GITHUB_ACTIONS"] = "true"
            state = ho_factory.hoxline_remote_lab_authority_state()

            self.assertEqual(state["remote_lab_authority_rule"], "present")
            self.assertEqual(state["remote_default_mode"], "read_only")
            self.assertEqual(state["rule_source"], "github_actions_ci_fallback")
        finally:
            ho_factory.HOXLINE_AGENTS_RULES = original_path
            if original_env is None:
                os.environ.pop("GITHUB_ACTIONS", None)
            else:
                os.environ["GITHUB_ACTIONS"] = original_env

    def test_evidence_product_convergence_self_test_passes(self) -> None:
        result = ho_factory.hoxline_evidence_to_product_convergence_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(tuple(result["scheduled_collection_scope"]), ho_factory.HOXLINE_STANDING_PRIVATE_COLLECTOR_SCOPE)
        self.assertTrue(result["checks"]["private_reviewer_has_ho_det_010"])
        self.assertTrue(result["checks"]["scheduled_scope_exact"])
        self.assertTrue(result["checks"]["github_artifact_upload_absent"])
        self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertTrue(result["human_review_required"])
        self.assertFalse(result["ai_disposition_authority"])
    def test_no_forbidden_private_keys(self) -> None:
        cockpit = self.cockpit()
        forbidden = [
            key
            for key in ho_factory.hoxline_iter_keys(cockpit)
            if key.lower() in ho_factory.HOXLINE_PRIVATE_REVIEWER_FORBIDDEN_KEYS
        ]

        self.assertEqual(forbidden, [])

    def test_unsafe_claim_classes_blocked(self) -> None:
        blocked = self.cockpit()["claim_boundaries"]["blocked_claim_classes"]

        for claim_class in (
            "PUBLIC_SAFE",
            "PRODUCTION",
            "SOCAAS",
            "CUSTOMER_DEPLOYED",
            "AI_APPROVED",
            "ANALYST_APPROVED",
            "CASE_CLOSED",
            "FLEET_WIDE",
        ):
            with self.subTest(claim_class=claim_class):
                self.assertIn(claim_class, blocked)


if __name__ == "__main__":
    unittest.main()
