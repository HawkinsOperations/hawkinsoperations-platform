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


class HoxlineOperatorReceiptCollectionTests(unittest.TestCase):
    def write_json(self, name: str, payload: object) -> str:
        path = Path(tempfile.gettempdir()) / f"{name}-{ho_factory.canonical_sha256(payload)[:12]}.json"
        path.write_text(ho_factory.json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def packet_for(self, detection_id: str) -> dict[str, object]:
        attestation = ho_factory.hoxline_operator_attestation_sample()
        receipt = ho_factory.hoxline_sanitized_live_receipt_sample(detection_id)
        return ho_factory.hoxline_operator_packet_from_receipt(receipt, operator_attestation=attestation)

    def collect_packet(self, detection_id: str) -> tuple[dict[str, object], str]:
        attestation = ho_factory.hoxline_operator_attestation_sample()
        attestation_path = self.write_json("operator-attestation", attestation)
        execution_id = ho_factory.hoxline_sanitized_live_receipt_sample(detection_id)["execution_id"]
        alerts_path = self.write_json(
            "operator-alerts",
            [ho_factory.hoxline_operator_wazuh_alert_sample(detection_id, execution_id=execution_id)],
        )
        packet_path = str(Path(tempfile.gettempdir()) / f"operator-packet-{detection_id}.json")
        ho_factory.hoxline_collect_operator_receipt_from_wazuh(
            detection_id=detection_id,
            execution_id=execution_id,
            alerts_json=alerts_path,
            time_window_start_utc=attestation["source_time_window_start_utc"],
            time_window_end_utc=attestation["source_time_window_end_utc"],
            operator_attestation_path=attestation_path,
            output_path=packet_path,
        )
        return ho_factory.load_json(Path(packet_path)), packet_path

    def test_valid_packets_verify_for_target_detections(self) -> None:
        for detection_id in ("HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                packet = self.packet_for(detection_id)
                result = ho_factory.hoxline_validate_operator_receipt_packet(packet)

                self.assertEqual(result["status"], "pass")
                self.assertEqual(result["receipt_count"], 1)
                self.assertEqual(result["receipts"][0]["detection_id"], detection_id)

    def test_collector_outputs_hash_only_packet_summary(self) -> None:
        packet, packet_path = self.collect_packet("HO-DET-011")

        verify = ho_factory.hoxline_operator_receipt_packet_verify(packet_path)
        self.assertEqual(verify["status"], "pass")
        self.assertFalse(verify["raw_alerts_included"])
        self.assertFalse(verify["raw_commands_included"])
        self.assertFalse(verify["generated_by_hoxline"])
        self.assertEqual(packet["packet_hash"], verify["packet_hash"])

    def test_packet_mutations_fail_closed(self) -> None:
        packet = self.packet_for("HO-DET-011")
        missing_attestation = dict(packet)
        missing_attestation.pop("operator_attestation")
        generated = dict(packet)
        generated["generated_by_hoxline"] = True
        generated["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(generated)
        raw_alert = dict(packet)
        raw_alert["raw_alerts_included"] = True
        raw_alert["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(raw_alert)
        raw_command = dict(packet)
        raw_command["raw_commands_included"] = True
        raw_command["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(raw_command)

        for candidate in (missing_attestation, generated, raw_alert, raw_command):
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.hoxline_validate_operator_receipt_packet(candidate)

    def test_hash_mismatches_fail_closed(self) -> None:
        packet = self.packet_for("HO-DET-012")
        packet_hash = dict(packet)
        packet_hash["packet_hash"] = "0" * 64
        attestation_hash = dict(packet)
        attestation_hash["operator_attestation"] = dict(attestation_hash["operator_attestation"])
        attestation_hash["operator_attestation"]["operator_attestation_hash"] = "0" * 64
        attestation_hash["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(attestation_hash)
        receipt_hash = dict(packet)
        receipt_hash["receipts"] = [dict(receipt_hash["receipts"][0])]
        receipt_hash["receipts"][0]["receipt_hash"] = "0" * 64
        receipt_hash["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(receipt_hash)

        for candidate in (packet_hash, attestation_hash, receipt_hash):
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.hoxline_validate_operator_receipt_packet(candidate)

    def test_fixture_and_unsupported_detection_fail_closed(self) -> None:
        fixture_packet = ho_factory.hoxline_operator_packet_from_receipt(
            ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011", receipt_source_class="FIXTURE_DRY_RUN_RECEIPT"),
            operator_attestation=ho_factory.hoxline_operator_attestation_sample(),
            fixture_mode=True,
        )
        unsupported = self.packet_for("HO-DET-011")
        unsupported["receipts"] = [dict(unsupported["receipts"][0])]
        unsupported["receipts"][0]["detection_id"] = "HO-DET-001"
        unsupported["receipts"][0]["receipt_hash"] = ho_factory.hoxline_sanitized_receipt_hash(unsupported["receipts"][0])
        unsupported["packet_hash"] = ho_factory.hoxline_operator_receipt_packet_hash(unsupported)

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_operator_receipt_packet(fixture_packet)
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_operator_receipt_packet(unsupported)

    def test_conflicting_duplicate_and_no_match_collector_fail_closed(self) -> None:
        attestation = ho_factory.hoxline_operator_attestation_sample()
        attestation_path = self.write_json("operator-attestation", attestation)
        execution_id = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-011")["execution_id"]
        duplicate_alerts = [
            ho_factory.hoxline_operator_wazuh_alert_sample("HO-DET-011", execution_id=execution_id),
            ho_factory.hoxline_operator_wazuh_alert_sample("HO-DET-011", execution_id=execution_id),
        ]
        no_match_alerts = [ho_factory.hoxline_operator_wazuh_alert_sample("HO-DET-012")]

        for label, alerts in (("duplicate", duplicate_alerts), ("no-match", no_match_alerts)):
            with self.subTest(label=label), self.assertRaises(ho_factory.FactoryError):
                ho_factory.hoxline_collect_operator_receipt_from_wazuh(
                    detection_id="HO-DET-011",
                    execution_id=execution_id,
                    alerts_json=self.write_json(f"{label}-alerts", alerts),
                    time_window_start_utc=attestation["source_time_window_start_utc"],
                    time_window_end_utc=attestation["source_time_window_end_utc"],
                    operator_attestation_path=attestation_path,
                    output_path=str(Path(tempfile.gettempdir()) / f"{label}-operator-packet.json"),
                )

    def test_runtime_from_operator_packet_for_target_detections(self) -> None:
        for detection_id in ("HO-DET-011", "HO-DET-012"):
            with self.subTest(detection_id=detection_id):
                _, packet_path = self.collect_packet(detection_id)
                result = ho_factory.hoxline_runtime_from_operator_receipt_packet(
                    packet_path=packet_path,
                    fixture_private_route="fixture",
                )

                self.assertEqual(result["status"], "pass")
                self.assertEqual(result["receipt_count"], 1)
                self.assertEqual(result["ledger_append_count"], 0)
                self.assertEqual(result["public_proof_promotion_count"], 0)
                self.assertFalse(result["schedule_enabled"])
                self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")

    def test_claim_authority_boundaries_remain_blocked(self) -> None:
        packet = self.packet_for("HO-DET-011")
        receipt = packet["receipts"][0]
        graph = ho_factory.hoxline_build_evidence_graph(ho_factory.hoxline_replay_from_sanitized_receipt(receipt))
        promotion = ho_factory.hoxline_promotion_state_from_graph(graph)
        blocked_claims = [
            "Hoxline generated live proof for HO-DET-011",
            "Hoxline safely created a service",
            "Hoxline safely created a scheduled task",
            "Hoxline is SOCaaS deployed",
            "HO-DET-011 production SOC",
            "HO-DET-011 public-safe runtime proof",
            "AI approved HO-DET-011",
            "analyst approved HO-DET-011",
            "HO-DET-011 case closed",
        ]

        self.assertEqual(
            ho_factory.hoxline_claim_authority_check(
                graph,
                promotion,
                ho_factory.hoxline_bounded_sanitized_live_receipt_claim("HO-DET-011"),
            )["decision"],
            "ALLOWED_WITH_SCOPE",
        )
        for claim in blocked_claims:
            with self.subTest(claim=claim):
                self.assertEqual(ho_factory.hoxline_claim_authority_check(graph, promotion, claim)["decision"], "BLOCKED")

    def test_self_test_passes(self) -> None:
        result = ho_factory.hoxline_operator_receipt_collection_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)
        self.assertFalse(result["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
