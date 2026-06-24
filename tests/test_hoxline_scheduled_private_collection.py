from __future__ import annotations

import importlib.util
import json
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


class HoxlineScheduledPrivateCollectionTests(unittest.TestCase):
    def run_collector(self, tmp: Path, **kwargs: object) -> dict[str, object]:
        defaults = {
            "repo_root": ROOT,
            "route_root": tmp / "route",
            "state_path": tmp / "state" / "collector.sqlite",
            "detection_ids": ["HO-DET-009", "HO-DET-010", "HO-DET-011", "HO-DET-012"],
            "event_name": "workflow_dispatch",
            "enable_input": True,
            "repo_var_enabled": True,
            "emergency_disable": False,
            "trusted_runner": True,
            "fixture": True,
            "seed_receipts": [],
            "max_runtime_seconds": 720,
            "max_candidates": 4,
            "max_new_signals": 4,
            "max_duplicate_suppressions": 20,
            "max_retries": 2,
            "max_dead_letters": 3,
        }
        defaults.update(kwargs)
        return ho_factory.hoxline_scheduled_private_collection(**defaults)

    def test_emergency_disable_exits_before_query_or_lock(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            result = self.run_collector(Path(d), emergency_disable=True, trusted_runner=False)

        self.assertEqual(result["terminal_outcome"], "EMERGENCY_DISABLE_ACTIVE")
        self.assertFalse(result["wazuh_query_attempted"])
        self.assertFalse(result["lock_acquired"])
        self.assertFalse(result["checkpoint_advanced"])
        self.assertEqual(result["ledger_append_count"], 0)
        self.assertEqual(result["public_proof_promotion_count"], 0)

    def test_gate_disabled_exits_without_query(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            result = self.run_collector(Path(d), repo_var_enabled=False, trusted_runner=False)

        self.assertEqual(result["terminal_outcome"], "SCHEDULE_GATE_DISABLED")
        self.assertFalse(result["wazuh_query_attempted"])
        self.assertFalse(result["checkpoint_advanced"])

    def test_trusted_runner_required_after_gate(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ho_factory.FactoryError):
                self.run_collector(Path(d), trusted_runner=False)

    def test_fixture_creates_candidate_then_suppresses_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            first = self.run_collector(tmp)
            second = self.run_collector(tmp)

        self.assertEqual(first["terminal_outcome"], "NEW_SIGNAL_CANDIDATE_CREATED")
        self.assertEqual(first["candidate_count"], 4)
        self.assertTrue(first["checkpoint_advanced"])
        self.assertEqual(second["terminal_outcome"], "DUPLICATE_SIGNAL_SUPPRESSED")
        self.assertEqual(second["candidate_count"], 0)
        self.assertEqual(second["duplicate_suppression_count"], 4)

    def test_unknown_agent_blocks_and_dead_letters(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            receipt = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-009")
            seed = tmp / "seed.json"
            seed.write_text(
                json.dumps({"receipt": receipt, "agent_id_hash": "0" * 64, "source_digest": "1" * 64}),
                encoding="utf-8",
            )
            result = self.run_collector(tmp, fixture=False, seed_receipts=[str(seed)])

        self.assertEqual(result["terminal_outcome"], "BLOCKED_UNKNOWN_AGENT_OR_HOST")
        self.assertEqual(result["dead_letter_count"], 1)
        self.assertEqual(result["candidate_count"], 0)

    def test_unknown_rule_family_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            receipt = ho_factory.hoxline_sanitized_live_receipt_sample("HO-DET-009")
            receipt["rule_ref"] = "wazuh:999999"
            seed = tmp / "seed.json"
            seed.write_text(
                json.dumps(
                    {
                        "receipt": receipt,
                        "agent_id_hash": next(iter(ho_factory.HOXLINE_SCHEDULED_COLLECTION_ALLOWED_AGENT_HASHES)),
                        "source_digest": "2" * 64,
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_collector(tmp, fixture=False, seed_receipts=[str(seed)])

        self.assertEqual(result["terminal_outcome"], "BLOCKED_UNKNOWN_RULE_FAMILY")
        self.assertEqual(result["candidate_count"], 0)

    def test_ho_det_010_included_after_clean_runtime_packet(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            result = self.run_collector(Path(d), detection_ids=["HO-DET-010"])

        self.assertEqual(result["terminal_outcome"], "NEW_SIGNAL_CANDIDATE_CREATED")
        self.assertEqual(result["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
