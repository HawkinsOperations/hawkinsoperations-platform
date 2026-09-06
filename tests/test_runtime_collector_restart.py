"""Execute the restart CLI against bounded receipts; never contact a backend."""
from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ho_factory.py"
SPEC = importlib.util.spec_from_file_location("restart_collector_under_test", SCRIPT)
factory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = factory
assert SPEC.loader
SPEC.loader.exec_module(factory)


class CollectorRestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="collector-rehearsal-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.route = self.work / "output"
        self.route.mkdir()
        self.receipt_path = self.work / "receipt.json"
        self.evidence_path = self.work / "evidence.json"
        observed = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=3)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.execution = "HO-DET-001-" + observed.strftime("%Y%m%dT%H%M%SZ") + "-TEST01"
        self.receipt = {
            "schema_version": "hoxline-collector-receipt-v1",
            "detection_id": "HO-DET-001", "telemetry_source_os": "Windows",
            "input_provenance": "CONTROLLED_TEST",
            "window_start_utc": stamp(observed - timedelta(seconds=10)),
            "window_end_utc": stamp(observed + timedelta(seconds=1)),
            "receipt": {"execution_id": self.execution, "observed_at_utc": stamp(observed),
                        "wazuh_rule_id": "100204", "backend_identity": "HO-WAZUH-01",
                        "event_class": "process_behavior", "signal_count": 1, "receipt_digest": ""},
        }
        self.write_inputs()

    def write_inputs(self):
        evidence = {key: value for key, value in self.receipt["receipt"].items() if key != "receipt_digest"}
        evidence["input_provenance"] = self.receipt["input_provenance"]
        raw = (json.dumps(evidence, sort_keys=True) + "\n").encode()
        self.evidence_path.write_bytes(raw)
        self.receipt["receipt"]["receipt_digest"] = hashlib.sha256(raw).hexdigest()
        self.receipt_path.write_text(json.dumps(self.receipt), encoding="utf-8")

    def arguments(self, lane="linux"):
        return [f"collector-{lane}-run-once", "--collect", "--test-only", "--output-route", str(self.route),
                "--receipt", str(self.receipt_path), "--evidence", str(self.evidence_path),
                "--execution-id", self.execution, "--source-ref", self.head]

    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], cwd=self.work,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected:
            self.assertNotIn(str(self.work), result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stdout + result.stderr)
            return result
        return json.loads(result.stdout)

    def target(self, lane="linux"):
        return self.route / f"collector-{lane}-{self.execution}.json"

    def verify(self, lane, digest, expected=0):
        return self.cli(f"collector-{lane}-verify", "--candidate", str(self.target(lane)),
                        "--execution-id", self.execution, "--source-ref", self.head,
                        "--packet-hash", digest, expected=expected)

    def test_default_no_action_and_preflight_do_not_write(self):
        before = set(self.work.rglob("*"))
        for lane in ("windows", "linux"):
            result = self.cli(f"collector-{lane}-run-once")
            self.assertFalse(result["collection_executed"])
            self.assertEqual(result["input_provenance"], "HISTORICAL_SAMPLE_DEMONSTRATION")
            preflight = self.cli(f"collector-{lane}-preflight", "--test-only", "--output-route", str(self.route))
            self.assertFalse(preflight["collection_authorized"])
            self.assertFalse(preflight["generated_output_files"])
        self.assertEqual(before, set(self.work.rglob("*")))

    def test_missing_runtime_health_route_propagates_failure(self):
        self.cli("hoxline-runtime-health", "--private-route", str(self.work / "missing-health"), expected=1)

    def test_both_lanes_execute_verify_and_replay_exact_current_packet(self):
        for lane in ("windows", "linux"):
            with self.subTest(lane=lane):
                self.route = self.work / lane
                self.route.mkdir()
                first = self.cli(*self.arguments(lane))
                self.assertEqual((first["candidate_count"], first["duplicate_count"]), (1, 0))
                self.assertEqual(first["ai_state"], "AI_UNAVAILABLE")
                self.assertFalse(first["actual_model_inference_executed"])
                self.assertTrue(self.verify(lane, first["packet_hash"])["current_output_verified"])
                original = self.target(lane).read_bytes()
                replay = self.cli(*self.arguments(lane))
                self.assertEqual(replay["duplicate_count"], 1)
                self.assertEqual(original, self.target(lane).read_bytes())
                packet = json.loads(original)
                self.assertEqual(packet["support_input"]["telemetry_source_os"], "Windows")
                self.assertEqual(packet["stages"]["provenance"], "CONTROLLED_TEST")
                self.assertFalse(packet["append_to_lifetime_ledger"])
                self.assertFalse(packet["proof_promoted"])

    def test_missing_required_collection_arguments_and_old_sample_never_substitute(self):
        for lane in ("windows", "linux"):
            self.cli(f"collector-{lane}-run-once", "--collect", expected=1)
            self.cli(f"collector-{lane}-verify", expected=1)
            self.cli(f"collector-{lane}-dedupe-check", expected=1)
            self.cli(f"collector-{lane}-run-once", "--receipt", str(self.receipt_path), expected=1)
            self.verify(lane, "0" * 64, expected=1)
        self.assertEqual(list(self.route.iterdir()), [])

    def test_failed_collection_cannot_be_verified_as_current_output(self):
        self.receipt["receipt"]["backend_identity"] = "OTHER-BACKEND"
        self.write_inputs()
        self.cli(*self.arguments(), expected=1)
        self.verify("linux", "0" * 64, expected=1)
        self.assertFalse(self.target().exists())

    def test_conflicting_replay_preserves_already_accepted_candidate(self):
        self.cli(*self.arguments())
        original = self.target().read_bytes()
        self.receipt["receipt"]["signal_count"] = 2
        self.write_inputs()
        result = self.cli(*self.arguments(), expected=1)
        self.assertIn("COLLECTOR_REPLAY_CONFLICT", result.stdout + result.stderr)
        self.assertEqual(original, self.target().read_bytes())

    def test_stale_receipt_with_internally_valid_window_is_rejected(self):
        observed = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)
        self.execution = "HO-DET-001-" + observed.strftime("%Y%m%dT%H%M%SZ") + "-TEST01"
        self.receipt["receipt"]["execution_id"] = self.execution
        self.receipt["receipt"]["observed_at_utc"] = observed.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.receipt["window_start_utc"] = (observed - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.receipt["window_end_utc"] = (observed + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.write_inputs()
        result = self.cli(*self.arguments(), expected=1)
        self.assertIn("COLLECTOR_RECEIPT_STALE_OR_FUTURE", result.stdout + result.stderr)

    def test_current_output_requires_expected_hash_execution_lane_and_source(self):
        result = self.cli(*self.arguments())
        self.verify("linux", "0" * 64, expected=1)
        for option, replacement in (("--execution-id", self.execution[:-1] + "2"), ("--source-ref", "0" * 40)):
            args = ["collector-linux-verify", "--candidate", str(self.target()), "--execution-id", self.execution,
                    "--source-ref", self.head, "--packet-hash", result["packet_hash"]]
            args[args.index(option) + 1] = replacement
            self.cli(*args, expected=1)
        self.cli("collector-windows-verify", "--candidate", str(self.target()), "--execution-id", self.execution,
                 "--source-ref", self.head, "--packet-hash", result["packet_hash"], expected=1)

    def test_rehashed_output_does_not_bypass_receipt_or_authority_verification(self):
        self.cli(*self.arguments())
        original = json.loads(self.target().read_text(encoding="utf-8"))
        for section, key, value in (("receipt", "window_end_utc", "invalid"),
                                    ("receipt", "detection_id", "HO-DET-011"),
                                    (None, "human_review_required", False),
                                    (None, "append_to_lifetime_ledger", True),
                                    (None, "proof_promoted", True)):
            with self.subTest(section=section, key=key):
                packet = copy.deepcopy(original)
                (packet[section] if section else packet)[key] = value
                packet["packet_hash"] = factory.canonical_sha256({k: v for k, v in packet.items() if k != "packet_hash"})
                self.target().write_text(json.dumps(packet), encoding="utf-8")
                self.verify("linux", packet["packet_hash"], expected=1)

    def test_source_change_during_handoff_prevents_checkpoint_commit(self):
        original = factory.collector_source_identity(self.head, test_only=True)
        changed = copy.deepcopy(original)
        changed["executed_content"]["scripts/ho_factory.py"] = "0" * 64
        with mock.patch.object(factory, "collector_source_identity", side_effect=[original, changed]):
            with self.assertRaisesRegex(factory.FactoryError, "SOURCE_CHANGED_DURING_RUN"):
                factory.collector_restart_run("linux", output_route=str(self.route),
                    receipt_path=str(self.receipt_path), evidence_path=str(self.evidence_path),
                    execution_id=self.execution, source_ref=self.head, test_only=True)
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            exists = connection.execute("SELECT count(*) FROM sqlite_master WHERE name='restart_receipts'").fetchone()[0]
            if exists:
                self.assertEqual(connection.execute("SELECT count(*) FROM restart_receipts").fetchone()[0], 0)

    def test_receipt_identity_time_provenance_and_digest_fail_closed(self):
        original = copy.deepcopy(self.receipt)
        changes = [
            ("detection_id", "HO-DET-011"), ("telemetry_source_os", "Linux"),
            ("input_provenance", "OPERATOR_ATTESTED_RECEIPT"),
            ("window_start_utc", "2000-01-01T00:00:00Z"), ("window_end_utc", "invalid"),
            ("receipt.backend_identity", "OTHER-BACKEND"), ("receipt.wazuh_rule_id", "910011"),
            ("receipt.execution_id", self.execution[:-1] + "2"), ("receipt.signal_count", True),
            ("receipt.observed_at_utc", "2000-01-01T00:00:00Z"),
            ("receipt.observed_at_utc", "2999-01-01T00:00:00Z"),
        ]
        for key, value in changes:
            with self.subTest(field=key, value=value):
                self.receipt = copy.deepcopy(original)
                if key.startswith("receipt."):
                    self.receipt["receipt"][key.split(".")[1]] = value
                else:
                    self.receipt[key] = value
                self.write_inputs()
                self.cli(*self.arguments(), expected=1)
                self.assertFalse(self.target().exists())
        self.receipt = original
        self.write_inputs()
        self.evidence_path.write_bytes(self.evidence_path.read_bytes() + b" ")
        self.cli(*self.arguments(), expected=1)

    def test_duplicate_keys_nonfinite_and_private_input_errors_are_bounded(self):
        for raw in ('{"schema_version":"one","schema_version":"two"}', '{"bad":NaN}',
                    '{"bad":Infinity}', '[1,2]', '{"private-marker":"', '{"bad":' + '1' * 5000 + '}'):
            with self.subTest(raw=raw[:40]):
                self.receipt_path.write_text(raw, encoding="utf-8")
                result = self.cli(*self.arguments(), expected=1)
                self.assertNotIn("private-marker", result.stdout + result.stderr)
                self.assertFalse(self.target().exists())

    def test_missing_nonexistent_relative_and_traversal_routes_are_blocked(self):
        for route in (self.work / "missing", self.receipt_path, Path("relative-output"), self.work / ".." / self.work.name / "output"):
            args = self.arguments()
            args[args.index("--output-route") + 1] = str(route)
            self.cli(*args, expected=1)
        args = self.arguments()
        args[args.index("--evidence") + 1] = str(self.work / "missing-evidence.json")
        self.cli(*args, expected=1)

    def test_shell_metacharacter_route_is_passed_as_literal_data(self):
        self.route = self.work / "output & echo SHELL_SENTINEL"
        self.route.mkdir()
        result = self.cli(*self.arguments())
        self.assertTrue(result["current_output_verified"])
        self.assertTrue(self.target().is_file())

    def test_symlink_receipt_is_rejected(self):
        linked = self.work / "linked-receipt.json"
        try:
            linked.symlink_to(self.receipt_path)
        except OSError as exc:
            self.skipTest(f"host lacks symlink creation privilege: {type(exc).__name__}")
        self.receipt_path = linked
        result = self.cli(*self.arguments(), expected=1)
        self.assertIn("COLLECTOR_LINK_PATH_BLOCKED", result.stderr + result.stdout)

    def test_hardlinked_inputs_and_database_sidecars_are_rejected_without_mutation(self):
        original = self.receipt_path.read_bytes()
        linked = self.work / "hardlinked-receipt.json"
        os.link(self.receipt_path, linked)
        self.receipt_path = linked
        result = self.cli(*self.arguments(), expected=1)
        self.assertIn("COLLECTOR_HARDLINK_PATH_BLOCKED", result.stdout + result.stderr)
        self.assertEqual(original, linked.read_bytes())
        # Retire only the test-created alias so the independent sidecar case has a normal input.
        linked.unlink()
        self.receipt_path = self.work / "receipt.json"
        protected = self.work / "protected-test-content"
        protected.write_bytes(b"controlled unchanged content")
        for suffix in ("", "-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                self.route = self.work / ("sidecar" + (suffix or "-database"))
                self.route.mkdir()
                os.link(protected, self.route / ("collector-restart.sqlite" + suffix))
                self.cli(*self.arguments(), expected=1)
                self.assertEqual(protected.read_bytes(), b"controlled unchanged content")

    def test_unrelated_database_is_preserved(self):
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
            connection.execute("INSERT INTO unrelated VALUES ('preserve')")
            connection.commit()
        result = self.cli(*self.arguments(), expected=1)
        self.assertIn("COLLECTOR_UNRELATED_DATABASE_BLOCKED", result.stdout + result.stderr)
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            self.assertEqual(connection.execute("SELECT * FROM unrelated").fetchall(), [("preserve",)])
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [("unrelated",)])

    def test_nested_actual_inference_claim_is_blocked_even_with_recomputed_hashes(self):
        self.cli(*self.arguments())
        packet = json.loads(self.target().read_text(encoding="utf-8"))
        packet["ai_support"]["execution_mode"] = "OPERATOR_SELECTED_MODEL"
        packet["ai_support"]["actual_model_inference_executed"] = True
        packet["ai_support"]["receipt_hash_sha256"] = factory.collector_ai_module().support_hash(
            {k: v for k, v in packet["ai_support"].items() if k != "receipt_hash_sha256"})
        packet["packet_hash"] = factory.canonical_sha256({k: v for k, v in packet.items() if k != "packet_hash"})
        self.target().write_text(json.dumps(packet), encoding="utf-8")
        result = self.verify("linux", packet["packet_hash"], expected=1)
        self.assertIn("COLLECTOR_INFERENCE_AUTHORITY_BLOCKED", result.stdout + result.stderr)

    def test_unwritable_wrong_os_and_missing_dependency_preflight(self):
        with mock.patch.object(factory.os, "access", return_value=False):
            with self.assertRaisesRegex(factory.FactoryError, "WRITABLE"):
                factory.collector_restart_preflight("linux", str(self.route), test_only=True)
        with mock.patch.object(factory, "yaml", None):
            with self.assertRaisesRegex(factory.FactoryError, "PYYAML_REQUIRED"):
                factory.collector_restart_preflight("linux", None, test_only=True)
        other = "linux" if sys.platform == "win32" else "windows"
        with self.assertRaisesRegex(factory.FactoryError, "HOST_OS_MISMATCH"):
            factory.collector_restart_preflight(other, None)

    def test_source_nonzero_and_changed_identity_block_collection(self):
        args = self.arguments()
        args[args.index("--source-ref") + 1] = "0" * 40
        self.cli(*args, expected=1)
        failed = subprocess.CompletedProcess([], 9, stdout="", stderr="private-marker")
        with mock.patch.object(factory.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(factory.FactoryError, "SOURCE_UNAVAILABLE"):
                factory.collector_source_identity(self.head, test_only=True)

    def test_test_transport_success_and_timeout_preserve_upstream(self):
        config = {"provider": "ollama", "endpoint": "http://127.0.0.1:1", "model": "controlled-test-model",
                  "model_digest": "a" * 64, "timeout_seconds": 1, "max_attempts": 1}
        support = {"summary": "Process behavior needs analyst context.", "uncertainty": ["Intent is unknown."],
                   "missing_context": ["Parent process context is unavailable."],
                   "suggested_checks": ["Review parent process context."]}
        calls = []

        def transport(selected_config, request_bytes):
            calls.append(json.loads(request_bytes))
            return json.dumps({"model": "controlled-test-model", "done": True,
                               "message": {"role": "assistant", "content": json.dumps(support)}}).encode()

        def unavailable(selected_config, request_bytes):
            raise TimeoutError("private-transport-detail")

        packets = []
        for label, injected, expected in (("available", transport, "AI_SUPPORT_AVAILABLE"),
                                           ("unavailable", unavailable, "AI_UNAVAILABLE")):
            with self.subTest(state=label):
                route = self.work / label
                route.mkdir()
                result = factory.collector_restart_run("linux", output_route=str(route),
                    receipt_path=str(self.receipt_path), evidence_path=str(self.evidence_path),
                    execution_id=self.execution, source_ref=self.head, test_only=True,
                    ai_config=config, transport=injected)
                self.assertEqual(result["ai_state"], expected)
                packet = json.loads((route / result["output_name"]).read_text(encoding="utf-8"))
                self.assertEqual(packet["ai_support"]["execution_mode"], "TEST_DOUBLE")
                self.assertFalse(packet["ai_support"]["actual_model_inference_executed"])
                self.assertEqual(packet["stages"]["normalization"], "VERIFIED")
                self.assertTrue(packet["human_review_required"])
                self.assertFalse(packet["append_to_lifetime_ledger"])
                self.assertNotIn("private-transport-detail", json.dumps(packet))
                packets.append(packet)
        self.assertEqual(len(calls), 1)
        for field in ("candidate", "normalized_candidate", "checkpoint", "support_input"):
            self.assertEqual(packets[0][field], packets[1][field], field)

    def test_resume_after_publication_before_checkpoint_commit(self):
        first = self.cli(*self.arguments())
        content = self.target().read_bytes()
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            connection.execute("DELETE FROM restart_receipts")
            connection.commit()
        resumed = self.cli(*self.arguments())
        self.assertEqual(first["packet_hash"], resumed["packet_hash"])
        self.assertEqual(content, self.target().read_bytes())
        self.assertEqual(self.cli(*self.arguments())["duplicate_count"], 1)

    def test_partial_output_blocks_and_missing_committed_output_requires_explicit_recovery(self):
        self.target().write_text('{"partial":', encoding="utf-8")
        self.cli(*self.arguments(), expected=1)
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            exists = connection.execute("SELECT count(*) FROM sqlite_master WHERE name='restart_receipts'").fetchone()[0]
            if exists:
                self.assertEqual(connection.execute("SELECT count(*) FROM restart_receipts").fetchone()[0], 0)
        self.target().rename(self.work / "partial-output-held.json")
        first = self.cli(*self.arguments())
        original = self.target().read_bytes()
        self.target().rename(self.work / "complete-output-held.json")
        self.verify("linux", first["packet_hash"], expected=1)
        recovered = self.cli(*self.arguments())
        self.assertTrue(recovered["recovered_output"])
        self.assertEqual(recovered["duplicate_count"], 1)
        self.assertEqual(original, self.target().read_bytes())
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM restart_receipts").fetchone()[0], 1)

    def test_concurrent_processes_accept_one_logical_candidate(self):
        command = [sys.executable, "-B", str(SCRIPT), *self.arguments()]
        processes = [subprocess.Popen(command, cwd=self.work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=45)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            results.append(json.loads(stdout))
        self.assertEqual(sorted(row["duplicate_count"] for row in results), [0, 1])
        self.assertEqual(len({row["packet_hash"] for row in results}), 1)
        with closing(sqlite3.connect(self.route / "collector-restart.sqlite")) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM restart_receipts").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
