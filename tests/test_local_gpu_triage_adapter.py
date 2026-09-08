from __future__ import annotations

import copy
import importlib.util
import json
import http.server
import threading
import time
import platform
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

    def test_factual_security_vocabulary_is_not_an_action(self):
        output = {**self.output, "summary": "PowerShell identity is present. Intent remains unknown."}
        self.assertEqual(self.run_adapter(self.envelope(output))["state"], "AI_SUPPORT_AVAILABLE")

    def test_documented_thinking_metadata_is_discarded(self):
        envelope = json.loads(self.envelope())
        envelope["message"]["thinking"] = "Untrusted provider reasoning is never reviewer evidence."
        receipt = self.run_adapter(adapter.support_json(envelope))
        self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")
        self.assertNotIn("Untrusted provider reasoning", json.dumps(receipt))

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


class EvidenceProviderProtocolTests(unittest.TestCase):
    """Protocol branch tests; owner reexecution is exercised separately by CLI."""
    def setUp(self):
        self.packet = {"schema_version": adapter.EVIDENCE_VERSION, "execution_id": "HO-DET-001-20260907T120000Z-FACT01",
                       "upstream_sha256": "b" * 64, "input_provenance": "CONTROLLED_TEST",
                       "evidence_id": "HO-DET-001-20260907T120000Z-FACT01:validated-facts",
                       "upstream": {"facts": {"executable_identity": "POWERSHELL", "parent_context": "UNKNOWN", "argument_indicators": ["ENCODED_SHORT_DASH_SPACE"]}}}
        self.config = dict(provider="ollama", endpoint="http://127.0.0.1:1", model="controlled-test-model:1", model_digest="a" * 64, timeout_seconds=0.3, max_attempts=2)
        self.calls = []
        self.requests = []
        self.output = {"summary": "PowerShell identity is present. Intent is unknown.", "uncertainty": ["Intent is unknown."],
                       "missing_context": ["Parent context is unavailable."], "suggested_checks": ["Review the parent context."],
                       "evidence_refs": [self.packet["evidence_id"]]}
        self.inventory = {"models": [{"name": self.config["model"], "model": self.config["model"], "digest": self.config["model_digest"]}]}
        # Only the independent owner boundary is stubbed in these transport unit
        # tests. Actual Git/source/owner/CLI integration below has no such patch.
        patcher = patch.object(adapter, "validate_evidence_input", side_effect=lambda packet, **_: packet)
        patcher.start()
        self.addCleanup(patcher.stop)

    def completion(self, output=None, **extra):
        return adapter.support_json({"model": self.config["model"], "done": True,
            "message": {"role": "assistant", "content": json.dumps(self.output if output is None else output), "thinking": "discarded private reasoning"}, **extra})

    def transport(self, config, method, route, request, observation):
        self.calls.append((method, route))
        observation.update(request_attempted=True, request_sent=True, response_received=True)
        if method == "GET":
            return adapter.support_json(self.inventory)
        parsed = adapter.strict_support_json(request)
        self.requests.append(parsed)
        self.assertEqual(json.loads(parsed["messages"][1]["content"]), self.packet)
        self.assertFalse(parsed["stream"])
        return self.completion()

    def run_support(self, transport=None, **kwargs):
        return adapter.run_evidence_support(self.packet, self.config, transport=transport or self.transport, **kwargs)

    def test_no_request_preserves_validated_facts(self):
        with patch.object(adapter, "provider_exchange", side_effect=AssertionError("no contact")):
            receipt = adapter.run_evidence_support(self.packet, self.config)
        self.assertEqual(receipt["attempts"], [])
        self.assertEqual(receipt["validated_facts"], self.packet["upstream"]["facts"])
        self.assertEqual(receipt["actual_model_inference"], "NOT_EXECUTED")

    def test_accepted_completion_inventory_and_discarded_thinking(self):
        receipt = self.run_support()
        self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")
        self.assertEqual(self.calls, [("GET", "/api/tags"), ("POST", "/api/chat"), ("GET", "/api/tags")])
        self.assertTrue(receipt["attempts"][0]["completion_observed"])
        self.assertEqual(receipt["model_identity_basis"], "EMULATED_INVENTORY_MATCH_NOT_HARDWARE_ATTESTATION")
        self.assertNotIn("discarded private", json.dumps(receipt))
        self.assertEqual(receipt["actual_model_inference"], "NOT_EXECUTED")

    def test_rejected_authority_retains_observed_completion_and_facts(self):
        for text in ("Approve the case", "Suppress the detection", "Close this case", "Promote proof", "Run PowerShell now", "Invoke a tool", "Read C:\\private\\input", "Contact http://127.0.0.1", "PowerShell -enc payload", "user@example.invalid", "aa:bb:cc:dd:ee:ff", "Read /opt/private", "ａｐｐｒｏｖｅ this case", "Delete the file"):
            with self.subTest(text=text):
                self.output["summary"] = text
                receipt = self.run_support()
                self.assertEqual(receipt["state"], "AI_OUTPUT_REJECTED")
                self.assertTrue(receipt["attempts"][0]["completion_observed"])
                self.assertFalse(receipt["attempts"][0]["output_accepted"])
                self.assertIsNone(receipt["output"])
                self.assertEqual(receipt["validated_facts"], self.packet["upstream"]["facts"])

    def test_forged_references_and_authoritative_observations_rejected(self):
        original = copy.deepcopy(self.output)
        for change in ({"evidence_refs": ["OTHER-EXECUTION:validated-facts"]}, {"evidence_refs": []}, {"observed_facts": {"parent_context": "BENIGN"}}, {"approval": True}, {"tools": []}):
            self.output = {**original, **change}
            self.assertEqual(self.run_support()["state"], "AI_OUTPUT_REJECTED")

    def test_pre_send_failure_retries_but_uncertain_delivery_does_not(self):
        for sent, expected_attempts, status in ((False, 2, "NOT_OBSERVED"), (True, 1, "UNKNOWN_AFTER_REQUEST"), (None, 1, "UNKNOWN_AFTER_REQUEST")):
            def fail(config, method, route, request, observation):
                if method == "GET":
                    return self.transport(config, method, route, request, observation)
                observation.update(request_attempted=True, request_sent=sent)
                raise TimeoutError("private error must be withheld")
            receipt = self.run_support(fail)
            self.assertEqual(len(receipt["attempts"]), expected_attempts)
            self.assertEqual(receipt["attempts"][-1]["completion_status"], status)
            self.assertEqual(receipt["state"], "AI_UNAVAILABLE")
            self.assertNotIn("private error", json.dumps(receipt))

    def test_inventory_wrong_digest_absence_alias_and_ambiguity_block_request(self):
        row = self.inventory["models"][0]
        for rows in ([], [row, row], [{**row, "digest": "c" * 64}], [{**row, "name": "alias"}], [{"name": row["name"], "model": row["model"]}]):
            self.inventory = {"models": rows}
            self.calls.clear()
            receipt = self.run_support()
            self.assertEqual(receipt["state"], "AI_OUTPUT_REJECTED")
            self.assertFalse(any(method == "POST" for method, _ in self.calls))

    def test_changed_identity_after_completion_withholds_output(self):
        def changed(config, method, route, request, observation):
            if method == "GET" and self.requests:
                self.inventory["models"][0]["digest"] = "c" * 64
            return self.transport(config, method, route, request, observation)
        receipt = self.run_support(changed)
        self.assertEqual(receipt["state"], "AI_OUTPUT_REJECTED")
        self.assertTrue(receipt["attempts"][0]["completion_observed"])
        self.assertIsNone(receipt["output"])

    def test_documented_metadata_and_invalid_provider_envelopes(self):
        accepted = self.completion(created_at="2026-09-07T12:00:00Z", done_reason="stop", eval_count=12, total_duration=900)
        self.assertIsInstance(adapter.provider_completion(accepted, self.config), str)
        raw = json.loads(accepted)
        variants = [b'{}', b'{"done":true,"done":false}', b'{"x":NaN}', self.completion(done=False), self.completion(model="wrong-model"), self.completion(eval_count=True), self.completion(tools=[])]
        for message in ({**raw["message"], "tool_calls": []}, {**raw["message"], "thinking": {}}, {**raw["message"], "images": []}):
            variants.append(adapter.support_json({**raw, "message": message}))
        for data in variants:
            with self.assertRaises(adapter.SupportError):
                adapter.provider_completion(data, self.config)

    def test_real_transport_observation_semantics_without_real_provider(self):
        # Exercise the actual-transport receipt branch with a controlled injected
        # implementation; this test itself performs no inference/network call.
        self.packet["input_provenance"] = "OPERATOR_ATTESTED_INPUT"
        for valid in (False, True):
            self.output["summary"] = "PowerShell identity is present." if valid else "Approve the case"
            with patch.object(adapter, "provider_exchange", side_effect=self.transport):
                receipt = adapter.run_evidence_support(self.packet, self.config, authorize_inference=True)
            self.assertEqual(receipt["actual_model_inference"], "PROVIDER_REPORTED_COMPLETION")
            self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE" if valid else "AI_OUTPUT_REJECTED")
        def timeout(config, method, route, request, observation):
            if method == "GET":
                return self.transport(config, method, route, request, observation)
            observation.update(request_attempted=True, request_sent=True)
            raise TimeoutError()
        with patch.object(adapter, "provider_exchange", side_effect=timeout):
            receipt = adapter.run_evidence_support(self.packet, self.config, authorize_inference=True)
        self.assertEqual(receipt["actual_model_inference"], "UNKNOWN")

    def test_receipt_rehashed_authority_and_execution_tamper_rejected(self):
        original = self.run_support()
        for update in ({"actual_model_inference": "PROVIDER_REPORTED_COMPLETION"}, {"public_safe": True}, {"validated_facts": {"parent_context": "KNOWN"}}, {"model_identity_basis": "HARDWARE_ATTESTED"}, {"attempts": []}, {"selected_model": {**original["selected_model"], "endpoint": "private-route"}}):
            changed = {**copy.deepcopy(original), **update}
            changed["receipt_hash_sha256"] = adapter.support_hash({k: v for k, v in changed.items() if k != "receipt_hash_sha256"})
            with self.assertRaises(adapter.SupportError):
                adapter.verify_evidence_receipt(changed, self.packet)

    def test_actual_http_fixed_routes_and_request_body(self):
        parent = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                parent.assertEqual(self.path, "/api/tags")
                self.reply(adapter.support_json(parent.inventory))
            def do_POST(self):
                parent.assertEqual(self.path, "/api/chat")
                request = adapter.strict_support_json(self.rfile.read(int(self.headers["Content-Length"])))
                parent.assertEqual(json.loads(request["messages"][1]["content"]), parent.packet)
                self.reply(parent.completion())
            def reply(self, payload):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = {**self.config, "endpoint": "http://127.0.0.1:" + str(server.server_port), "timeout_seconds": 2}
            receipt = adapter.run_evidence_support(self.packet, config, transport=adapter.provider_exchange)
            self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")
            self.assertTrue(receipt["attempts"][0]["request_sent"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_cli_emulation_owns_server_and_never_contacts_configured_endpoint(self):
        observed = []
        real_exchange = adapter.provider_exchange
        def inspected(config, *args):
            self.assertNotEqual(config["endpoint"], self.config["endpoint"])
            observed.append(config["endpoint"])
            return real_exchange(config, *args)
        with patch.object(adapter, "provider_exchange", side_effect=inspected):
            receipt = adapter.run_evidence_support(self.packet, self.config, test_http=True)
        self.assertEqual(receipt["state"], "AI_SUPPORT_AVAILABLE")
        self.assertEqual(len(observed), 3)
        self.assertEqual(len(set(observed)), 1)

    def test_http_error_timeout_and_oversize_are_bounded(self):
        parent = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                if parent.response_kind == "timeout":
                    time.sleep(0.4)
                    return
                status = 302 if parent.response_kind == "redirect" else 503 if parent.response_kind == "unavailable" else 200
                self.send_response(status)
                self.send_header("Content-Length", str(adapter.MAX_RESPONSE + 1))
                self.end_headers()
                if status == 200:
                    try:
                        self.wfile.write(b"x" * (adapter.MAX_RESPONSE + 1))
                    except OSError:
                        pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = {**self.config, "endpoint": "http://127.0.0.1:" + str(server.server_port), "timeout_seconds": 0.15}
            for kind in ("redirect", "unavailable", "timeout", "oversize"):
                self.response_kind = kind
                observation = dict(request_attempted=False, request_sent=False, response_received=False)
                started = time.monotonic()
                with self.subTest(kind=kind), self.assertRaises((OSError, adapter.SupportError, adapter.http.client.HTTPException)):
                    adapter.provider_exchange(config, "POST", "/api/chat", b'{}', observation)
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(observation["request_sent"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_contradictory_completion_and_ambiguous_retry_receipts_blocked(self):
        original = self.run_support()
        false_completion = copy.deepcopy(original)
        false_completion.update(state="AI_UNAVAILABLE", output=None, output_hash_sha256=None)
        false_completion["attempts"][0].update(completion_observed=False, output_accepted=False)
        ambiguous_retry = copy.deepcopy(original)
        ambiguous_retry["attempts"].insert(0, dict(request_attempted=True, request_sent=None, response_received=False,
            completion_observed=False, completion_status="UNKNOWN_AFTER_REQUEST", output_accepted=False))
        for changed in (false_completion, ambiguous_retry):
            changed["receipt_hash_sha256"] = adapter.support_hash({k: v for k, v in changed.items() if k != "receipt_hash_sha256"})
            with self.assertRaises(adapter.SupportError):
                adapter.verify_evidence_receipt(changed, self.packet)


class EvidenceOwnerCliIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validation = ROOT.parent / "hawkinsoperations-validation"
        cls.detections = ROOT.parent / "hawkinsoperations-detections"
        cls.validation_ref = subprocess.check_output(["git", "-C", str(cls.validation), "rev-parse", "HEAD"], text=True).strip()
        cls.detections_ref = subprocess.check_output(["git", "-C", str(cls.detections), "rev-parse", "HEAD"], text=True).strip()
        cls.execution = "HO-DET-001-20260907T120000Z-FACT01"

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="evidence-handoff-")
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.facts_file = self.work / "facts.json"
        self.input_file = self.work / "input.json"
        self.receipt_file = self.work / "receipt.json"
        self.config_file = self.work / "config.json"
        self.config_file.write_bytes(adapter.support_json(dict(provider="ollama", endpoint="http://127.0.0.1:1", model="controlled-test-model:1", model_digest="a" * 64, timeout_seconds=2, max_attempts=1)))

    def cli(self, script, args, code=0):
        result = subprocess.run([sys.executable, "-B", str(script), *args], cwd=self.work, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        if code == 2:
            self.assertNotIn(str(self.work), result.stderr + result.stdout)
            self.assertNotIn("Traceback", result.stderr + result.stdout)
            return result
        return json.loads(result.stdout)

    def selected(self, case):
        return ["--validation-root", str(self.validation), "--validation-ref", self.validation_ref,
                "--detections-root", str(self.detections), "--detections-ref", self.detections_ref,
                "--facts-case", case, "--execution-id", self.execution]

    def produce(self, case):
        facts = self.cli(self.validation / "scripts/detection_quality.py", ["--detections-root", str(self.detections),
                         "--detections-ref", self.detections_ref, "--facts-case", case, "--execution-id", self.execution])
        self.facts_file.write_bytes(adapter.support_json(facts))
        packet = self.cli(SCRIPT, ["evidence-input", *self.selected(case), "--facts", str(self.facts_file)])
        self.input_file.write_bytes(adapter.support_json(packet))
        return packet

    def test_distinct_source_events_to_http_support_and_exact_replay(self):
        packets, summaries = [], []
        cases = [("pos-001-powershell-enc", True), ("pos-003-pwsh-enc", True),
                 ("neg-003-benign-admin-powershell", False), ("neg-005-missing-commandline", False)]
        for case, expected in cases:
            with self.subTest(case=case):
                packet = self.produce(case)
                self.assertEqual(packet["upstream"]["observed_match"], expected)
                self.assertEqual(packet["execution_host_os"], platform.system())
                self.assertEqual(packet["telemetry_source_os"], "Windows")
                self.assertEqual(packet["backend"], "SOURCE_RULE_EVALUATOR")
                idle = self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file)], code=3)
                self.assertEqual(idle["validated_facts"], packet["upstream"]["facts"])
                receipt = self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file), "--config", str(self.config_file), "--test-http"])
                self.assertEqual(receipt["actual_model_inference"], "NOT_EXECUTED")
                self.assertEqual(receipt["output"]["evidence_refs"], [packet["evidence_id"]])
                self.receipt_file.write_bytes(adapter.support_json(receipt))
                checked = self.cli(SCRIPT, ["evidence-verify", *self.selected(case), "--input", str(self.input_file), "--receipt", str(self.receipt_file)])
                self.assertEqual(checked["owner_reexecution"], "PASS")
                replay = self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file), "--config", str(self.config_file), "--test-http"])
                self.assertEqual(receipt, replay)
                packets.append(adapter.support_hash(packet))
                summaries.append(receipt["output"]["summary"])
        self.assertEqual(len(set(packets)), 4)
        self.assertGreaterEqual(len(set(summaries)), 3)

    def test_tamper_wrong_selection_and_inference_gate_fail_before_contact(self):
        case = "pos-001-powershell-enc"
        original = self.produce(case)
        for change in ({"upstream_sha256": "c" * 64}, {"input_provenance": "OPERATOR_ATTESTED_INPUT"}, {"telemetry_source_os": "Linux"}):
            self.input_file.write_bytes(adapter.support_json({**original, **change}))
            self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file)], code=2)
        altered = copy.deepcopy(original)
        altered["upstream"]["facts"]["parent_context"] = "KNOWN_BENIGN"
        altered["upstream"]["result_sha256"] = adapter.support_hash({k:v for k,v in altered["upstream"].items() if k != "result_sha256"})
        altered["upstream_sha256"] = adapter.support_hash(altered["upstream"])
        self.input_file.write_bytes(adapter.support_json(altered))
        self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file)], code=2)
        self.input_file.write_bytes(adapter.support_json(original))
        self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file), "--config", str(self.config_file), "--authorize-inference"], code=2)
        wrong = self.selected(case)
        wrong[wrong.index("--validation-ref") + 1] = "a" * 40
        self.cli(SCRIPT, ["evidence-run", *wrong, "--input", str(self.input_file)], code=2)
        self.input_file.write_text('{"x":1,"x":2}', encoding="utf-8")
        self.cli(SCRIPT, ["evidence-run", *self.selected(case), "--input", str(self.input_file)], code=2)

    def test_operator_input_contract_prepared_with_no_inference(self):
        event = {"EventID": 1, "Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED", "ParentImage": "parent-context-withheld"}
        event_path = self.work / "event.json"
        event_path.write_bytes(adapter.support_json(event))
        facts = self.cli(self.validation / "scripts/detection_quality.py", ["--detections-root", str(self.detections), "--detections-ref", self.detections_ref,
                         "--facts-event", str(event_path), "--execution-id", self.execution])
        self.assertIsNone(facts["expected_match"])
        self.assertFalse(facts["boundary"]["origin_authenticated"])
        self.facts_file.write_bytes(adapter.support_json(facts))
        selection = self.selected("unused")
        index = selection.index("--facts-case")
        selection[index:index+2] = ["--event", str(event_path)]
        packet = self.cli(SCRIPT, ["evidence-input", *selection, "--facts", str(self.facts_file)])
        self.input_file.write_bytes(adapter.support_json(packet))
        receipt = self.cli(SCRIPT, ["evidence-run", *selection, "--input", str(self.input_file)], code=3)
        self.assertEqual(receipt["attempts"], [])
        self.assertNotIn("REDACTED", json.dumps(packet))
        self.assertNotIn("parent-context-withheld", json.dumps(packet))
        event_path.write_bytes(adapter.support_json({**event, "CommandLine": "different"}))
        self.cli(SCRIPT, ["evidence-run", *selection, "--input", str(self.input_file)], code=2)


if __name__ == "__main__":
    unittest.main()
