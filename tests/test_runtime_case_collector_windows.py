from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ho_factory_windows_collector", ROOT / "scripts" / "ho_factory.py")
ho_factory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ho_factory
spec.loader.exec_module(ho_factory)


class WindowsCollectorPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.route = Path(self.temp.name).resolve()
        self.platform = mock.patch.object(ho_factory.sys, "platform", "win32")
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.normalizer = mock.patch.object(ho_factory, "normalize_windows_collector_route", return_value=str(self.route))
        self.normalize = self.normalizer.start()
        self.addCleanup(self.normalizer.stop)

    def preflight(self) -> dict:
        return ho_factory.runtime_collector_windows_preflight("approved-route")

    def test_existing_writable_route_passes_without_writing(self) -> None:
        before = list(self.route.iterdir())
        result = self.preflight()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["collect_ready"])
        self.assertTrue(result["route_status"]["route_writable"])
        self.assertEqual(list(self.route.iterdir()), before)

    def test_missing_route_fails_and_is_not_created_by_collect(self) -> None:
        missing = self.route / "missing"
        self.normalize.return_value = str(missing)
        for operation in (self.preflight, lambda: ho_factory.runtime_collector_windows_run_once(False, "approved-route")):
            with self.subTest(operation=operation), self.assertRaisesRegex(ho_factory.FactoryError, "does not exist"):
                operation()
        self.assertFalse(missing.exists())

    def test_route_that_is_a_file_fails(self) -> None:
        route_file = self.route / "file"
        route_file.write_text("not a directory", encoding="utf-8")
        self.normalize.return_value = str(route_file)
        with self.assertRaisesRegex(ho_factory.FactoryError, "must be a directory"):
            self.preflight()

    def test_unwritable_route_fails_before_collection(self) -> None:
        with mock.patch.object(ho_factory.os, "access", return_value=False):
            for operation in (self.preflight, lambda: ho_factory.runtime_collector_windows_run_once(False, "approved-route")):
                with self.subTest(operation=operation), self.assertRaisesRegex(ho_factory.FactoryError, "not writable"):
                    operation()
        self.assertEqual(list(self.route.iterdir()), [])

    def test_redirected_route_fails(self) -> None:
        with mock.patch.object(ho_factory.Path, "resolve", return_value=self.route.parent):
            with self.assertRaisesRegex(ho_factory.FactoryError, "must not redirect"):
                self.preflight()

    def test_non_windows_collection_fails(self) -> None:
        with mock.patch.object(ho_factory.sys, "platform", "linux"):
            with self.assertRaisesRegex(ho_factory.FactoryError, "requires a Windows host"):
                self.preflight()
        self.assertEqual(list(self.route.iterdir()), [])

    def test_configuration_only_preflight_does_not_claim_route_readiness(self) -> None:
        result = ho_factory.runtime_collector_windows_preflight()
        self.assertFalse(result["collect_ready"])
        self.assertIsNone(result["route_status"]["route_writable"])
        self.assertEqual(result["route_probe_scope"], "historical_route_probe_receipt_only")
        self.assertEqual(result["current_route_probe_status"], "not_run_by_preflight")

    def test_dry_run_never_writes_or_requires_private_route(self) -> None:
        with mock.patch.object(ho_factory.sys, "platform", "linux"):
            result = ho_factory.runtime_collector_windows_run_once(True)
        self.assertFalse(result["generated_output_files"])
        self.assertEqual(list(self.route.iterdir()), [])

    def test_bounded_collection_verifies_and_preserves_duplicate(self) -> None:
        result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertTrue(result["generated_output_files"])
        written = ho_factory.runtime_collector_windows_verify(result["output_file"])
        self.assertEqual(written["status"], "pass")
        self.assertTrue(written["checks"]["append_to_lifetime_ledger_blocked"])
        duplicate = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertFalse(duplicate["generated_output_files"])
        self.assertTrue(duplicate["duplicate_preserved"])
        self.assertEqual(len(list(self.route.iterdir())), 1)

    def test_corrupt_existing_packet_fails_and_is_not_overwritten(self) -> None:
        result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        output = Path(result["output_file"])
        for corrupted in ("not JSON", json.dumps({"candidates": []})):
            output.write_text(corrupted, encoding="utf-8")
            with self.subTest(corrupted=corrupted), self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
            self.assertEqual(output.read_text(encoding="utf-8"), corrupted)

    def test_valid_substituted_candidate_fails_and_is_not_overwritten(self) -> None:
        result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        output = Path(result["output_file"])
        payload = ho_factory.runtime_collector_windows_default_payload()
        payload["sanitized_event_fingerprint"] = "different-valid-candidate"
        other = ho_factory.runtime_collector_windows_packet(ho_factory.build_runtime_collector_windows_candidate(payload))
        self.assertEqual(ho_factory.verify_runtime_collector_windows_packet(other)["status"], "pass")
        substituted = json.dumps(other)
        output.write_text(substituted, encoding="utf-8")
        with self.assertRaisesRegex(ho_factory.FactoryError, "differs from the expected deterministic packet"):
            ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertEqual(output.read_text(encoding="utf-8"), substituted)

    def test_duplicate_nested_authority_field_is_rejected(self) -> None:
        result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        output = Path(result["output_file"])
        ambiguous = output.read_text(encoding="utf-8").replace(
            '"ai_decided_disposition": false',
            '"ai_decided_disposition": true, "ai_decided_disposition": false',
        )
        output.write_text(ambiguous, encoding="utf-8")
        for operation in (
            lambda: ho_factory.runtime_collector_windows_verify(str(output)),
            lambda: ho_factory.runtime_collector_windows_dedupe_check(str(output)),
            lambda: ho_factory.runtime_collector_windows_run_once(False, "approved-route"),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(ho_factory.FactoryError, "duplicate object keys"):
                operation()
        self.assertEqual(output.read_text(encoding="utf-8"), ambiguous)

    def test_nonfinite_json_constants_are_rejected(self) -> None:
        result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        output = Path(result["output_file"])
        valid = output.read_text(encoding="utf-8")
        for constant in ("NaN", "Infinity", "-Infinity"):
            malformed = valid.replace('"candidate_count": 1', f'"extra": {constant}, "candidate_count": 1')
            output.write_text(malformed, encoding="utf-8")
            with self.subTest(constant=constant), self.assertRaisesRegex(ho_factory.FactoryError, "non-finite numeric constants"):
                ho_factory.runtime_collector_windows_verify(str(output))
            with self.subTest(constant=constant), self.assertRaisesRegex(ho_factory.FactoryError, "non-finite numeric constants"):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
            self.assertEqual(output.read_text(encoding="utf-8"), malformed)

    def test_concurrent_valid_candidate_is_verified_and_preserved(self) -> None:
        original_open = Path.open
        existing = json.dumps(ho_factory.runtime_collector_windows_packet())

        def create_first(path, mode="r", *args, **kwargs):
            if mode == "x":
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write(existing)
                raise FileExistsError("simulated competing candidate creation")
            return original_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, "open", create_first):
            result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertFalse(result["generated_output_files"])
        self.assertTrue(result["duplicate_preserved"])
        self.assertEqual(Path(result["output_file"]).read_text(encoding="utf-8"), existing)

    def test_concurrent_corrupt_candidate_is_not_overwritten(self) -> None:
        original_open = Path.open
        raced_path = None

        def create_first(path, mode="r", *args, **kwargs):
            nonlocal raced_path
            if mode == "x":
                raced_path = path
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write("concurrent invalid packet")
                raise FileExistsError("simulated competing candidate creation")
            return original_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, "open", create_first):
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertIsNotNone(raced_path)
        self.assertEqual(raced_path.read_text(encoding="utf-8"), "concurrent invalid packet")

    def test_concurrent_output_redirect_is_rejected_without_overwriting_target(self) -> None:
        original_open = Path.open
        original_resolve = Path.resolve
        target = self.route / "outside-target"
        target.write_text("preserve unrelated target", encoding="utf-8")
        raced = False

        def redirect_first(path, mode="r", *args, **kwargs):
            nonlocal raced
            if mode == "x":
                raced = True
                raise FileExistsError("simulated competing output symlink")
            return original_open(path, mode, *args, **kwargs)

        def resolve_redirect(path, *args, **kwargs):
            if raced and path.name.endswith(".json"):
                return target
            return original_resolve(path, *args, **kwargs)

        with mock.patch.object(Path, "open", redirect_first), mock.patch.object(Path, "resolve", resolve_redirect):
            with self.assertRaisesRegex(ho_factory.FactoryError, "must not redirect"):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertTrue(raced)
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve unrelated target")

    def test_actual_packet_schema_and_promotion_boundaries_fail_closed(self) -> None:
        original = ho_factory.runtime_collector_windows_packet()
        output = self.route / "hostile.json"
        mutations = [
            lambda packet: packet.update(collector_version="unreviewed-collector"),
            lambda packet: packet.update(generated_output_files=True),
            lambda packet: packet.update(notes_boundary="production ready"),
            lambda packet: packet.update(collector_run_id="different-run"),
            lambda packet: packet.update(candidate_count=True),
            lambda packet: packet.update(unsupported_authority=True),
            lambda packet: packet.pop("invariants"),
            lambda packet: packet["candidates"][0].update(case_status="CASE_CLOSED"),
            lambda packet: packet["candidates"][0].update(notes_boundary="public-safe proof"),
            lambda packet: packet["candidates"][0].update(unsupported_authority=True),
            lambda packet: packet["invariants"].update(unsupported_authority=True),
        ]
        for key, expected in original["invariants"].items():
            replacement = not expected if type(expected) is bool else "PROMOTED"
            mutations.append(lambda packet, key=key, replacement=replacement: packet["invariants"].update({key: replacement}))
        for key in ("ai_decided_disposition", "human_review_required"):
            mutations.append(lambda packet, key=key: packet["invariants"].update({key: int(original["invariants"][key])}))
        for index, mutate in enumerate(mutations):
            hostile = json.loads(json.dumps(original))
            mutate(hostile)
            output.write_text(json.dumps(hostile), encoding="utf-8")
            with self.subTest(mutation=index), self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_verify(str(output))
            with self.subTest(mutation=index), self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_dedupe_check(str(output))

    def test_future_unsupported_schema_assertions_fail_closed(self) -> None:
        schema = ho_factory.load_json(ho_factory.RUNTIME_COLLECTOR_WINDOWS_SCHEMA)
        schema["properties"]["candidates"]["maxItems"] = 1
        with mock.patch.object(ho_factory, "load_json", return_value=schema):
            with self.assertRaisesRegex(ho_factory.FactoryError, "unsupported assertions"):
                ho_factory.verify_runtime_collector_windows_packet(ho_factory.runtime_collector_windows_packet())
        schema = ho_factory.load_json(ho_factory.RUNTIME_COLLECTOR_WINDOWS_SCHEMA)
        schema["properties"]["absent_optional_field"] = {"anyOf": [{"type": "string"}]}
        with mock.patch.object(ho_factory, "load_json", return_value=schema):
            with self.assertRaisesRegex(ho_factory.FactoryError, "unsupported assertions"):
                ho_factory.verify_runtime_collector_windows_packet(ho_factory.runtime_collector_windows_packet())


class WindowsCollectorRouteTests(unittest.TestCase):
    def test_both_existing_workflow_routes_are_allowlisted(self) -> None:
        for route in ho_factory.RUNTIME_COLLECTOR_WINDOWS_OUTPUT_ROUTES:
            with self.subTest(route=route):
                self.assertEqual(ho_factory.normalize_windows_collector_route(route.lower().replace("\\", "/")), route)

    def test_route_escape_and_unapproved_routes_are_rejected(self) -> None:
        routes = (
            "C:/Raylee/Data/runtime-case-collector-v0/windows/../outside",
            "C:/Raylee/Repo/HawkinsOperations/hawkinsoperations-platform/out/windows",
            "D:/Raylee/Data/runtime-case-collector-v0/windows",
            "C:/Users/Raylee/AppData/Local/Temp/runtime-case-collector-v0/windows",
        )
        for route in routes:
            with self.subTest(route=route), self.assertRaises(ho_factory.FactoryError):
                ho_factory.normalize_windows_collector_route(route)


if __name__ == "__main__":
    unittest.main()
