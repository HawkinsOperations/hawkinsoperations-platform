from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "verify-reviewer-metrics-pipeline.py"
STATE_PATH = ROOT / "contracts" / "reviewer-metrics-pipeline-v1-state.json"

spec = importlib.util.spec_from_file_location("verify_reviewer_metrics_pipeline", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verifier)


class ReviewerMetricsPipelineTests(unittest.TestCase):
    def test_repo_state_keeps_governed_cases_separate_from_detection_activity(self) -> None:
        result = verifier.verify_state(STATE_PATH, ROOT)

        metrics = result["metrics"]
        self.assertEqual(metrics["lifetime_governed_cases"], 4)
        self.assertEqual(metrics["lifetime_ledger_events"], 4)
        self.assertEqual(metrics["detection_activity_count"], 49)
        self.assertEqual(metrics["controlled_validation_fire_count"], 49)
        self.assertEqual(metrics["validation_case_count"], 106)
        self.assertEqual(metrics["proof_record_count"], 8)
        self.assertGreaterEqual(metrics["blocked_claim_count"], 17)
        self.assertEqual(metrics["runtime_public_safe_count"], 0)
        self.assertEqual(metrics["public_safe_count"], 0)

    def test_state_metrics_match_source_artifacts(self) -> None:
        source_metrics = verifier.source_metrics_from_state(STATE_PATH, ROOT)

        self.assertEqual(source_metrics["lifetime_governed_cases"], 4)
        self.assertEqual(source_metrics["lifetime_ledger_events"], 4)
        self.assertEqual(source_metrics["detection_activity_count"], 49)
        self.assertEqual(source_metrics["controlled_validation_fire_count"], 49)
        self.assertEqual(source_metrics["controlled_negative_test_count"], 57)
        self.assertEqual(source_metrics["validation_case_count"], 106)
        self.assertEqual(source_metrics["detection_activity_entry_count"], 10)

    def test_detection_activity_cannot_equal_governed_case_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            data["assertions"]["detection_activity_is_governed_case_count"] = True
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "detection activity must remain separate"):
                verifier.verify_state(path, ROOT)


if __name__ == "__main__":
    unittest.main()
