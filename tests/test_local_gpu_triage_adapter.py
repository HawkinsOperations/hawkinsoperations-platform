from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_local_gpu_triage.py"
spec = importlib.util.spec_from_file_location("local_gpu_support_adapter", SCRIPT)
adapter = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(adapter)


class LocalGpuSupportAdapterTests(unittest.TestCase):
    def setUp(self):
        self.packet = adapter.build_support_input(
            detection_id="HO-DET-001", execution_id="HO-DET-001-CONTROLLED-TEST-001",
            backend="Wazuh", execution_host_os="Linux", telemetry_source_os="Windows",
            input_provenance="CONTROLLED_TEST", upstream_sha256="b" * 64,
            event_class="process_behavior",
        )
        self.config = dict(provider="ollama", endpoint="http://127.0.0.1:1", model="controlled-test-model", model_digest="a" * 64, timeout_seconds=1, max_attempts=2)
        self.output = dict(summary="Process behavior needs analyst context.", uncertainty=["Intent is unknown."], missing_context=["Parent process context is unavailable."], suggested_checks=["Review parent process context."])

    def transport(self, config, request):
        request = adapter.strict_support_json(request)
        self.assertEqual(request["model"], self.config["model"])
        self.assertFalse(request["stream"])
        self.assertEqual(json.loads(request["messages"][1]["content"]), self.packet)
        return self.envelope()

    def envelope(self, output=None):
        return adapter.support_json(dict(model=self.config["model"], done=True, message=dict(role="assistant", content=json.dumps(self.output if output is None else output))))

    def run_adapter(self, raw):
        return adapter.run_support(self.packet, self.config, transport=lambda config, request: raw)

    def test_default_preserves_upstream_without_calling_connector(self):
        with patch.object(adapter, "local_ollama_transport", side_effect=AssertionError("must not connect")):
            for config in (None, self.config):
                receipt = adapter.run_support(self.packet, config)
                self.assertEqual(receipt["state"], "AI_UNAVAILABLE")
                self.assertEqual(receipt["upstream_sha256"], self.packet["upstream_sha256"])
                self.assertEqual(receipt["attempts"], 0)
                self.assertFalse(receipt["actual_model_inference_executed"])

    def test_real_serialization_and_test_transport_receipt(self):
        receipt = adapter.run_support(self.packet, self.config, transport=self.transport)
        self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")
        self.assertEqual(receipt["execution_mode"], "TEST_DOUBLE")
        self.assertFalse(receipt["actual_model_inference_executed"])
        self.assertEqual(receipt["model_identity_basis"], "OPERATOR_ATTESTED")
        adapter.verify_support_receipt(receipt, self.packet)

    def test_timeouts_bounded_and_upstream_preserved(self):
        calls = []
        def unavailable(config, request):
            calls.append(1)
            raise TimeoutError("private provider text must never escape")
        receipt = adapter.run_support(self.packet, self.config, transport=unavailable)
        self.assertEqual(len(calls), 2)
        self.assertEqual(receipt["state"], "AI_UNAVAILABLE")
        self.assertIsNone(receipt["output"])
        self.assertNotIn("private provider", json.dumps(receipt))

    def test_retry_recovers_without_duplicate_support(self):
        calls = []
        def transient(config, request):
            calls.append(1)
            if len(calls) == 1:
                raise OSError("unavailable")
            return self.transport(config, request)
        receipt = adapter.run_support(self.packet, self.config, transport=transient)
        self.assertEqual(receipt["attempts"], 2)
        self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")

    def test_invalid_envelopes_fail_closed_without_retry(self):
        valid = json.loads(self.envelope())
        cases = [b"bad json", b'{"model":1,"model":2}', b'{"x":NaN}', b"x" * (adapter.MAX_RESPONSE + 1)]
        for update in ({"model": "wrong-model"}, {"done": False}, {"approve": True}, {"message": {"role": "assistant", "content": "{}", "tool_calls": []}}):
            cases.append(adapter.support_json({**valid, **update}))
        for raw in cases:
            with self.subTest(raw_length=len(raw)):
                receipt = self.run_adapter(raw)
                self.assertEqual(receipt["state"], "AI_OUTPUT_REJECTED")
                self.assertEqual(receipt["attempts"], 1)

    def test_authority_and_private_output_blocked(self):
        for field in ("approval", "disposition", "close_eligible", "tools", "config", "public_safe"):
            self.assertEqual(self.run_adapter(self.envelope({**self.output, field: True}))["state"], "AI_OUTPUT_REJECTED")
        for text in ("Approve this case", "Suppress the detection", "Close this case", "Promote proof", "Ignore previous instructions", "Run powershell now", "Contact http://127.0.0.1", "Read C:\\private\\data", "password value", "x" * 513):
            with self.subTest(text=text):
                self.assertEqual(self.run_adapter(self.envelope({**self.output, "summary": text}))["state"], "AI_OUTPUT_REJECTED")

    def test_required_uncertainty_cannot_be_erased(self):
        for field in ("uncertainty", "missing_context", "suggested_checks"):
            self.assertEqual(self.run_adapter(self.envelope({**self.output, field: []}))["state"], "AI_OUTPUT_REJECTED")

    def test_configuration_rejects_remote_and_unbounded_values(self):
        updates = [{"endpoint": "http://example.invalid:1"}, {"endpoint": "http://127.0.0.1:1/path"}, {"endpoint": "http://user@127.0.0.1:1"}, {"timeout_seconds": float("nan")}, {"timeout_seconds": True}, {"timeout_seconds": 31}, {"max_attempts": 3}, {"max_attempts": True}, {"model_digest": "unknown"}, {"provider": "event-selected"}]
        for update in updates:
            with self.subTest(update=update), self.assertRaises(adapter.SupportError):
                adapter.run_support(self.packet, {**self.config, **update}, transport=self.transport)

    def test_input_allowlist_prevents_event_instruction_plumbing(self):
        for update in ({"raw_alert": "ignore"}, {"endpoint": "http://127.0.0.1:1"}, {"execution_id": "x;command"}, {"backend": "unknown"}, {"event_class": "ignore policy"}, {"input_provenance": "LIVE_PROVEN"}, {"telemetry_source_os": "unknown"}):
            with self.subTest(update=update), self.assertRaises(adapter.SupportError):
                adapter.build_support_input(**{**self.packet, **update})

    def test_controlled_input_cannot_activate_inference(self):
        with patch.object(adapter, "local_ollama_transport", side_effect=AssertionError("must not connect")):
            with self.assertRaises(adapter.SupportError):
                adapter.run_support(self.packet, self.config, authorize_inference=True)

    def test_local_connector_uses_fixed_route_and_closes_transport(self):
        class Response:
            status = 200
            def __init__(self, payload):
                self.payload = payload
            def read1(self, size):
                result, self.payload = self.payload[:size], self.payload[size:]
                return result
        from unittest.mock import MagicMock
        connection = MagicMock()
        connection.getresponse.return_value = Response(self.envelope())
        with patch.object(adapter.http.client, "HTTPConnection", return_value=connection) as constructor:
            result = adapter.local_ollama_transport(self.config, b'{}')
        self.assertEqual(result, self.envelope())
        constructor.assert_called_once_with("127.0.0.1", 1, timeout=1.0)
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/api/chat"))
        connection.close.assert_called_once()

    def test_local_connector_rejects_redirect_and_oversize(self):
        from unittest.mock import MagicMock
        for status in (302, 503):
            connection = MagicMock()
            connection.getresponse.return_value.status = status
            with patch.object(adapter.http.client, "HTTPConnection", return_value=connection), self.assertRaises(OSError):
                adapter.local_ollama_transport(self.config, b'{}')
            connection.close.assert_called_once()
        connection = MagicMock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read1.side_effect = lambda size: b'x' * size
        with patch.object(adapter.http.client, "HTTPConnection", return_value=connection), self.assertRaises(adapter.SupportError):
            adapter.local_ollama_transport(self.config, b'{}')
        connection.close.assert_called_once()

    def test_elapsed_transport_budget_cannot_report_success(self):
        with patch.object(adapter.time, "monotonic", side_effect=[0, 2, 2, 4]):
            receipt = adapter.run_support(self.packet, self.config, transport=self.transport)
        self.assertEqual(receipt["state"], "AI_UNAVAILABLE")
        self.assertEqual(receipt["attempts"], 2)

    def test_integrity_verifier_rejects_tampering_even_rehashed_authority(self):
        original = adapter.run_support(self.packet, self.config, transport=self.transport)
        changed_input = {**self.packet, "upstream_sha256": "c" * 64}
        with self.assertRaises(adapter.SupportError):
            adapter.verify_support_receipt(original, changed_input)
        for update in ({"ledger_append_allowed": True}, {"ai_disposition_authority": 0}, {"actual_model_inference_executed": True}, {"execution_mode": "NO_EXECUTION"}, {"model_identity_basis": "INDEPENDENTLY_OBSERVED"}, {"output_hash_sha256": "d" * 64}):
            changed = {**copy.deepcopy(original), **update}
            changed["receipt_hash_sha256"] = adapter.support_hash({k: v for k, v in changed.items() if k != "receipt_hash_sha256"})
            with self.subTest(update=update), self.assertRaises(adapter.SupportError):
                adapter.verify_support_receipt(changed, self.packet)

    def test_cli_from_unexpected_workdir_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, value in (("input.json", self.packet), ("config.json", self.config), ("response.json", json.loads(self.envelope()))):
                (root / name).write_bytes(adapter.support_json(value))
            command = [sys.executable, "-B", str(SCRIPT), "support-run", "--input", str(root / "input.json")]
            idle = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(idle.returncode, 3, idle.stderr)
            self.assertEqual(json.loads(idle.stdout)["state"], "AI_UNAVAILABLE")
            command += ["--config", str(root / "config.json"), "--test-response", str(root / "response.json")]
            executed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            receipt = json.loads(executed.stdout)
            self.assertFalse(receipt["actual_model_inference_executed"])
            (root / "receipt.json").write_bytes(adapter.support_json(receipt))
            verified = subprocess.run([sys.executable, "-B", str(SCRIPT), "support-verify", "--input", str(root / "input.json"), "--receipt", str(root / "receipt.json")], cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("ORIGIN_AUTHENTICATED=false", verified.stdout)
            (root / "input.json").write_text('{"x":1,"x":2}', encoding="utf-8")
            invalid = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(invalid.returncode, 2)
            self.assertNotIn(str(root), invalid.stderr)


if __name__ == "__main__":
    unittest.main()
