from __future__ import annotations

import importlib.util
import hashlib
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


class HoxlineRuntimeOpsTests(unittest.TestCase):
    def test_runtime_ops_self_test(self) -> None:
        result = ho_factory.hoxline_runtime_ops_self_test(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["ledger_mutated"])
        self.assertFalse(result["public_proof_promoted"])
        self.assertFalse(result["schedule_enabled"])

    def test_schedule_gate_disabled_by_default(self) -> None:
        result = ho_factory.hoxline_schedule_gate(
            event_name="schedule",
            enable_input=False,
            repo_var_enabled=False,
            emergency_disable=False,
            signal_digest=None,
        )

        self.assertEqual(result["decision"], "SCHEDULE_GATE_DISABLED")
        self.assertEqual(result["schedule_enabled"], 0)

    def test_untrusted_pr_cannot_use_private_runtime(self) -> None:
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_runtime_job_guard(
                event_name="pull_request",
                runner_labels=["self-hosted", "ho-gpu-01"],
                trusted_runtime=False,
                uses_private_route=True,
            )

    def test_dead_letter_hash_verifies(self) -> None:
        record = ho_factory.hoxline_dead_letter_record(
            execution_id="HO-DET-001-20260620T173615Z-6ELQ03",
            detection_id="HO-DET-001",
            stage="AI_TRIAGE",
            failure_class="AI_TIMEOUT",
            retryable=True,
            retry_count=1,
            sanitized_error="timeout; private prompt omitted",
            evidence_hashes_available={
                "signal_receipt_digest": "9b44ac77420ec3f87d30c228bdb246875e2d7a263dad083cd3c7acab9e4d88b4"
            },
        )

        self.assertEqual(ho_factory.hoxline_verify_dead_letter(record)["status"], "pass")

    def test_workflow_safety_verify(self) -> None:
        result = ho_factory.hoxline_workflow_safety_verify(ROOT)

        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["pr_source_checks_github_hosted_only"])
        self.assertFalse(result["active_cron_trigger"])
        self.assertFalse(result["unrestricted_artifact_upload"])

    def test_canary_from_sanitized_receipts_builds_replay_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            route = Path(tmp) / "private-route"
            route.mkdir()
            receipts = []
            for index in range(1, 4):
                execution_id = f"HO-DET-001-20260620T173615Z-CAN00{index}"
                receipts.append(
                    {
                        "execution_id": execution_id,
                        "receipt_digest": hashlib.sha256(execution_id.encode("utf-8")).hexdigest(),
                        "observed_at_utc": f"2026-06-20T17:3{index}:00Z",
                        "wazuh_rule_id": "100204",
                        "backend_identity": "HO-WAZUH-01",
                        "event_class": "PowerShell_EncodedCommand",
                        "signal_count": 1,
                    }
                )
            receipts_path = Path(tmp) / "receipts.json"
            receipts_path.write_text(
                json.dumps({"schema_version": "hoxline-wazuh-signal-receipts-v0", "receipts": receipts}),
                encoding="utf-8",
            )

            result = ho_factory.hoxline_runtime_canary_from_receipts(
                str(receipts_path),
                str(route),
                allow_unapproved_test_route=True,
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["controlled_execution_count"], 3)
            self.assertFalse(result["ledger_mutated"])
            self.assertFalse(result["public_proof_promoted"])
            self.assertEqual({row["ai_state"] for row in result["canary_rows"]}, {"AI_TRIAGE_UNAVAILABLE"})

    def test_canary_receipt_rejects_raw_private_field(self) -> None:
        receipt = {
            "execution_id": "HO-DET-001-20260620T173615Z-CAN001",
            "receipt_digest": hashlib.sha256(b"receipt").hexdigest(),
            "observed_at_utc": "2026-06-20T17:31:00Z",
            "wazuh_rule_id": "100204",
            "backend_identity": "HO-WAZUH-01",
            "event_class": "PowerShell_EncodedCommand",
            "signal_count": 1,
            "raw_alert": "blocked",
        }

        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.hoxline_validate_canary_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
