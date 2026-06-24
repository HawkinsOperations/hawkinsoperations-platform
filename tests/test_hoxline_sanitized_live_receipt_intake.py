from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ho_factory.py"

spec = importlib.util.spec_from_file_location("ho_factory", SCRIPT_PATH)
ho_factory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ho_factory
spec.loader.exec_module(ho_factory)


class HoxlineSanitizedLiveReceiptIntakeTests(unittest.TestCase):
    def write_receipt(self, receipt: dict[str, object]) -> str:
        path = Path(tempfile.gettempdir()) / f"test-hoxline-receipt-{receipt['detection_id']}-{receipt['receipt_hash']}.json"
        path.write_text(ho_factory.json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def test_operator_receipts_are_accepted_for_target_detections(self) -> None:
        for detection_id in ("HO-DET-009", "HO-DET-010", "HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                receipt = ho_factory.hoxline_sanitized_live_receipt_sample(detection_id)
                result = ho_factory.hoxline_sanitized_live_receipt_intake(self.write_receipt(receipt))

                self.assertTrue(result["receipt_valid"])
                self.assertTrue(result["live_receipt_accepted"])
                self.assertFalse(result["fixture_receipt"])
                self.assertEqual(result["detection_id"], detection_id)

    def test_fixture_receipt_is_accepted_only_as_non_live(self) -> None:
        receipt = ho_factory.hoxline_sanitized_live_receipt_sample(
            "HO-DET-011",
            receipt_source_class="FIXTURE_DRY_RUN_RECEIPT",
        )
        result = ho_factory.hoxline_runtime_from_sanitized_receipt(
            receipt_path=self.write_receipt(receipt),
            fixture_private_route="fixture",
        )

        self.assertTrue(result["fixture_receipt"])
        self.assertFalse(result["live_receipt_accepted"])
        self.assertIsNone(result["allowed_claim_text"])

    def test_untrusted_and_missing_attestation_fail_closed(self) -> None:
        untrusted = ho_factory.hoxline_sanitized_live_receipt_sample(
            "HO-DET-011",
            receipt_source_class="UNTRUSTED_RECEIPT",
            generated_by_hoxline=False,
            operator_supplied=False,
            fixture_mode=False,
        )
        missing = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011")
        missing["source_attestation"] = None

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_sanitized_live_receipt(untrusted)
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_sanitized_live_receipt(missing)

    def test_raw_and_generated_live_receipts_fail_closed(self) -> None:
        alert = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011")
        alert["raw_alert_included"] = True
        alert["receipt_hash"] = ho_factory.hoxline_sanitized_receipt_hash(alert)
        command = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-012")
        command["raw_command_included"] = True
        command["receipt_hash"] = ho_factory.hoxline_sanitized_receipt_hash(command)
        generated = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011", generated_by_hoxline=True)

        for receipt in (alert, command, generated):
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.hoxline_validate_sanitized_live_receipt(receipt)

    def test_unsupported_detection_and_fixture_digest_fail_closed(self) -> None:
        unsupported = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011")
        unsupported["detection_id"] = "HO-DET-001"
        unsupported["receipt_hash"] = ho_factory.hoxline_sanitized_receipt_hash(unsupported)
        fixture_digest = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-012")
        fixture_digest["receipt_digest"] = ho_factory.hashlib.sha256(
            f"{fixture_digest['execution_id']}:signal-receipt".encode("utf-8")
        ).hexdigest()
        fixture_digest["receipt_hash"] = ho_factory.hoxline_sanitized_receipt_hash(fixture_digest)

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_sanitized_live_receipt(unsupported)
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_sanitized_live_receipt(fixture_digest)

    def test_receipt_to_runtime_builds_private_control_plane_outputs(self) -> None:
        for detection_id in ("HO-DET-009", "HO-DET-010", "HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                result = ho_factory.hoxline_runtime_from_sanitized_receipt(
                    receipt_path=self.write_receipt(ho_factory.hoxline_sanitized_live_receipt_sample(detection_id)),
                )

                self.assertEqual(result["status"], "pass")
                self.assertTrue(result["live_receipt_accepted"])
                self.assertEqual(result["ledger_append_count"], 0)
                self.assertEqual(result["public_proof_promotion_count"], 0)
                self.assertFalse(result["schedule_enabled"])
                self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")
                self.assertIsNotNone(result["evidence_graph_hash"])
                self.assertIsNotNone(result["proofcard_draft_hash"])

    def test_claim_authority_allows_only_exact_operator_receipt_scope(self) -> None:
        receipt = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011")
        replay = ho_factory.hoxline_replay_from_sanitized_receipt(receipt)
        graph = ho_factory.hoxline_build_evidence_graph(replay)
        promotion = ho_factory.hoxline_promotion_state_from_graph(graph)

        allowed = ho_factory.hoxline_claim_authority_check(
            graph,
            promotion,
            ho_factory.hoxline_bounded_sanitized_live_receipt_claim("HO-DET-011"),
        )
        runtime_claim = ho_factory.hoxline_claim_authority_check(
            graph,
            promotion,
            ho_factory.hoxline_bounded_runtime_claim("HO-DET-011"),
        )
        blocked_claims = [
            "Hoxline generated live proof for HO-DET-011",
            "Hoxline safely created a service",
            "Hoxline safely created a scheduled task",
            "HO-DET-011 production SOC",
            "AI approved HO-DET-011",
        ]

        self.assertEqual(allowed["decision"], "ALLOWED_WITH_SCOPE")
        self.assertEqual(runtime_claim["decision"], "CONSTRAINED_REWRITE_REQUIRED")
        for claim in blocked_claims:
            with self.subTest(claim=claim):
                self.assertEqual(ho_factory.hoxline_claim_authority_check(graph, promotion, claim)["decision"], "BLOCKED")

    def test_self_test_passes(self) -> None:
        result = ho_factory.hoxline_sanitized_live_receipt_intake_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["schedule_enabled"])
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)


if __name__ == "__main__":
    unittest.main()
