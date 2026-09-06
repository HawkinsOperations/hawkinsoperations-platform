from __future__ import annotations

import importlib.util
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ho_factory.py"

spec = importlib.util.spec_from_file_location("ho_factory", SCRIPT_PATH)
ho_factory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ho_factory
spec.loader.exec_module(ho_factory)


class HoxlineRuntimeOpsTests(unittest.TestCase):
    def mutated_workflow_root(
        self, workflow_name: str, mutation: Callable[[str], str]
    ) -> tempfile.TemporaryDirectory:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        shutil.copytree(ROOT / ".github" / "workflows", root / ".github" / "workflows")
        workflow = root / ".github" / "workflows" / workflow_name
        workflow.write_text(mutation(workflow.read_text(encoding="utf-8")), encoding="utf-8")
        return temp_dir

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
        self.assertTrue(result["active_cron_trigger"])
        self.assertFalse(result["unrestricted_artifact_upload"])
        self.assertEqual(result["source_checkout_count"], 7)
        self.assertTrue(result["mandatory_convergence_unconditional"])
        self.assertTrue(result["ledger_pr_skip_independent"])

    def test_workflow_safety_rejects_ledger_condition_suffix_laundering(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "governance-gate.yml",
            lambda text: text.replace(
                "if: github.event_name != 'pull_request'",
                "if: github.event_name != 'pull_request' || true",
                1,
            ),
        )
        with self.assertRaisesRegex(
            ho_factory.FactoryError, "shell failure swallowing|intentional PR ledger skip"
        ):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_workflow_safety_requires_exact_ledger_skip_expression(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "governance-gate.yml",
            lambda text: text.replace(
                "if: github.event_name != 'pull_request'",
                "if: ${{ github.event_name != 'pull_request' }}",
                1,
            ),
        )
        with self.assertRaisesRegex(
            ho_factory.FactoryError, "intentional PR ledger skip"
        ):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_workflow_safety_rejects_false_or_true_neutralizer(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "hoxline-source-checks.yml",
            lambda text: text + "\n# hostile mutation\nrun: false || true\n",
        )
        with self.assertRaisesRegex(ho_factory.FactoryError, "shell failure swallowing"):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_workflow_safety_rejects_movable_checkout_tag(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "hoxline-source-checks.yml",
            lambda text: text.replace(
                f"actions/checkout@{ho_factory.HOXLINE_ACTIONS_CHECKOUT_SHA}",
                "actions/checkout@v4",
                1,
            ),
        )
        with self.assertRaisesRegex(ho_factory.FactoryError, "immutable SHA"):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_governance_gate_disables_persisted_checkout_credentials(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "governance-gate.yml"
        ).read_text(encoding="utf-8")
        checkout_count = workflow.count(
            f"uses: actions/checkout@{ho_factory.HOXLINE_ACTIONS_CHECKOUT_SHA}"
        )

        self.assertGreater(checkout_count, 0)
        self.assertEqual(
            workflow.count("persist-credentials: false"),
            checkout_count,
        )
        self.assertEqual(
            workflow.count("python -m pip install jsonschema==4.23.0"),
            2,
        )

    def test_workflow_safety_rejects_persisted_governance_credentials(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "governance-gate.yml",
            lambda text: text.replace(
                "persist-credentials: false",
                "persist-credentials: true",
                1,
            ),
        )
        with self.assertRaisesRegex(
            ho_factory.FactoryError,
            "governance checkout must disable persisted credentials",
        ):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_workflow_safety_rejects_unpinned_governance_dependency(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "governance-gate.yml",
            lambda text: text.replace(
                "jsonschema==4.23.0",
                "jsonschema",
                1,
            ),
        )
        with self.assertRaisesRegex(
            ho_factory.FactoryError,
            "must pin the reviewed jsonschema version",
        ):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

    def test_workflow_safety_rejects_ambiguous_process_working_directory(self) -> None:
        temp_dir = self.mutated_workflow_root(
            "hoxline-source-checks.yml",
            lambda text: text.replace(
                '"$GITHUB_WORKSPACE/source-set/hawkinsoperations-platform"',
                '"$PWD"',
                1,
            ),
        )
        with self.assertRaisesRegex(
            ho_factory.FactoryError,
            "explicit checked platform repository root",
        ):
            ho_factory.hoxline_workflow_safety_verify(Path(temp_dir.name))

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
