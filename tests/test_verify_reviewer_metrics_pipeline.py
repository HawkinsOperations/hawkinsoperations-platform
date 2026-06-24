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
    def write_platform_source_fixtures(self, root: Path, state: dict) -> Path:
        state_path = root / "contracts" / "reviewer-metrics-pipeline-v1-state.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text(json.dumps(state), encoding="utf-8")

        lifetime_path = root / state["source_artifacts"]["proof_lifetime_summary"]
        lifetime_path.parent.mkdir(parents=True)
        lifetime_path.write_text(
            json.dumps({"ledger_counts": {"total_cases": 4, "total_ledger_events": 4}}),
            encoding="utf-8",
        )

        validation_path = root / state["source_artifacts"]["validation_activity_ledger"]
        validation_path.parent.mkdir(parents=True)
        validation_path.write_text(
            json.dumps(
                {
                    "aggregate_metrics": {
                        "detection_activity_count": 49,
                        "controlled_validation_fire_count": 49,
                        "controlled_negative_test_count": 57,
                        "validation_case_count": 106,
                        "activity_entry_count": 10,
                        "runtime_public_safe_count": 0,
                        "public_safe_count": 0,
                    }
                }
            ),
            encoding="utf-8",
        )

        proof_map_path = root / state["source_artifacts"]["proof_reviewer_map"]
        proof_map_path.parent.mkdir(parents=True, exist_ok=True)
        proof_map_path.write_text(
            json.dumps(
                {
                    "trust_backup_checklist": [{"id": f"proof-{idx}"} for idx in range(8)],
                    "blocked_claims": [{"claim": f"proof-blocked-{idx}"} for idx in range(17)],
                }
            ),
            encoding="utf-8",
        )

        detections_path = root / state["source_artifacts"]["detections_promotion_matrix"]
        detections_path.parent.mkdir(parents=True, exist_ok=True)
        detections_path.write_text(
            "\n".join(
                [
                    "entries:",
                    "  - detection_family: hero",
                    "    blocked_claims:",
                    "      - det-blocked-1",
                    "      - det-blocked-2",
                    "      - det-blocked-3",
                    "  - detection_family: successor",
                    "    blocked_claims:",
                    "      - det-blocked-4",
                    "      - det-blocked-5",
                    "      - det-blocked-6",
                    "  - detection_family: identity",
                    "    blocked_claims:",
                    "      - det-blocked-7",
                    "      - det-blocked-8",
                    "  - detection_family: cloud",
                    "    blocked_claims:",
                    "      - det-blocked-9",
                    "      - det-blocked-10",
                    "  - detection_family: ndr",
                    "    blocked_claims:",
                    "      - det-blocked-11",
                    "      - det-blocked-12",
                    "  - detection_family: pipeline",
                    "    blocked_claims:",
                    "      - det-blocked-13",
                    "      - det-blocked-14",
                ]
            ),
            encoding="utf-8",
        )

        receipt_path = root / state["source_artifacts"]["github_project_reconciliation_source"]
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            "#8 standing control\n#10 blocked claims\nProject #2\nREPORT_ONLY not proof\n",
            encoding="utf-8",
        )
        return state_path

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
        self.assertEqual(source_metrics["detection_activity_count"], 59)
        self.assertEqual(source_metrics["controlled_validation_fire_count"], 59)
        self.assertEqual(source_metrics["controlled_negative_test_count"], 67)
        self.assertEqual(source_metrics["validation_case_count"], 126)
        self.assertEqual(source_metrics["detection_activity_entry_count"], 12)
        self.assertEqual(source_metrics["proof_record_count"], 8)
        self.assertEqual(source_metrics["blocked_claim_count"], 31)
        self.assertEqual(source_metrics["detection_family_count"], 6)
        self.assertEqual(source_metrics["runtime_public_safe_count"], 0)
        self.assertEqual(source_metrics["public_safe_count"], 0)

    def test_default_verifier_does_not_require_sibling_repo_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            state["source_artifacts"]["validation_activity_ledger"] = "../missing-validation/activity.json"
            state["source_artifacts"]["proof_lifetime_summary"] = "../missing-proof/summary.json"
            state["source_artifacts"]["proof_reviewer_map"] = "../missing-proof/map.json"
            state["source_artifacts"]["detections_promotion_matrix"] = "../missing-detections/matrix.yml"
            state["source_artifacts"]["github_project_reconciliation_source"] = "../missing-github/receipts.md"
            state_path = root / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")

            result = verifier.verify_state(state_path, root)

            self.assertEqual(result["metrics"]["detection_activity_count"], 49)

    def test_require_source_artifacts_fails_closed_when_sibling_sources_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            state_path.write_text(STATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "missing lifetime case ledger summary"):
                verifier.verify_state(state_path, root, require_source_artifacts=True)

    def test_source_metrics_cover_every_headline_source_backed_metric(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            state["source_artifacts"] = {
                "lifetime_case_ledger_manifest": "contracts/lifetime-case-ledger-v1-state-manifest.json",
                "validation_activity_ledger": "sources/validation/activity.json",
                "proof_lifetime_summary": "sources/proof/lifetime-summary.json",
                "proof_reviewer_map": "sources/proof/reviewer-map.json",
                "detections_promotion_matrix": "sources/detections/promotion-matrix.yml",
                "github_project_reconciliation_source": "sources/github/receipts.md",
            }
            state_path = self.write_platform_source_fixtures(root, state)

            source_metrics = verifier.source_metrics_from_state(state_path, root)

            for key in verifier.REQUIRED_METRICS:
                self.assertIn(key, source_metrics)
                self.assertEqual(source_metrics[key], state["metrics"][key])

    def test_project_reconciliation_is_backed_by_github_receipt_source(self) -> None:
        reconciliation = verifier.project_reconciliation_from_state(STATE_PATH, ROOT)

        self.assertTrue(reconciliation["standing_issue_8_present"])
        self.assertTrue(reconciliation["standing_issue_10_present"])
        self.assertTrue(reconciliation["project_2_route_present"])
        self.assertTrue(reconciliation["report_only_boundary_present"])
        self.assertFalse(reconciliation["project_metadata_is_proof_authority"])
        self.assertFalse(reconciliation["github_project_mutation_performed"])

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
