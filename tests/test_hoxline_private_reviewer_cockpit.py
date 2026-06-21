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

    def test_operator_detections_wait_for_real_input(self) -> None:
        detections = self.detections(self.cockpit())

        for detection_id in ("HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                self.assertTrue(detections[detection_id]["fixture_private_runtime_path"])
                self.assertEqual(detections[detection_id]["real_operator_receipt"], "missing")
                self.assertEqual(detections[detection_id]["operator_evidence_package"], "ready_for_real_input")

    def test_global_governance_state_remains_private(self) -> None:
        global_state = self.cockpit()["global_state"]

        self.assertEqual(global_state["lifetime_ledger_cases"], 6)
        self.assertEqual(global_state["lifetime_ledger_events"], 6)
        self.assertEqual(global_state["public_safe_count"], 0)
        self.assertFalse(global_state["schedule_enabled"])
        self.assertEqual(global_state["remote_lab_authority_rule"], "present")
        self.assertEqual(global_state["remote_default_mode"], "read_only")

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
