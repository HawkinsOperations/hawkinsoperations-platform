from __future__ import annotations

import importlib.util
import json
import os
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
        self.assertTrue(all(ho_factory.verify_runtime_collector_windows_candidate(other["candidates"][0]).values()))
        substituted = json.dumps(other)
        output.write_text(substituted, encoding="utf-8")
        with self.assertRaises(ho_factory.FactoryError):
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
        protected_open = ho_factory.open_runtime_collector_windows_output
        existing = json.dumps(ho_factory.runtime_collector_windows_packet())

        def create_first(path, route_fd, mode):
            if mode == "x":
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write(existing)
                raise FileExistsError("simulated competing candidate creation")
            return protected_open(path, route_fd, mode)

        with mock.patch.object(ho_factory, "open_runtime_collector_windows_output", create_first):
            result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertFalse(result["generated_output_files"])
        self.assertTrue(result["duplicate_preserved"])
        self.assertEqual(Path(result["output_file"]).read_text(encoding="utf-8"), existing)

    def test_concurrent_corrupt_candidate_is_not_overwritten(self) -> None:
        original_open = Path.open
        protected_open = ho_factory.open_runtime_collector_windows_output
        raced_path = None

        def create_first(path, route_fd, mode):
            nonlocal raced_path
            if mode == "x":
                raced_path = path
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write("concurrent invalid packet")
                raise FileExistsError("simulated competing candidate creation")
            return protected_open(path, route_fd, mode)

        with mock.patch.object(ho_factory, "open_runtime_collector_windows_output", create_first):
            with self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertIsNotNone(raced_path)
        self.assertEqual(raced_path.read_text(encoding="utf-8"), "concurrent invalid packet")

    def test_concurrent_output_redirect_is_rejected_without_overwriting_target(self) -> None:
        protected_open = ho_factory.open_runtime_collector_windows_output
        original_resolve = Path.resolve
        target = self.route / "outside-target"
        target.write_text("preserve unrelated target", encoding="utf-8")
        raced = False

        def redirect_first(path, route_fd, mode):
            nonlocal raced
            if mode == "x":
                raced = True
                raise FileExistsError("simulated competing output symlink")
            return protected_open(path, route_fd, mode)

        def resolve_redirect(path, *args, **kwargs):
            if raced and path.name.endswith(".json"):
                return target
            return original_resolve(path, *args, **kwargs)

        with mock.patch.object(ho_factory, "open_runtime_collector_windows_output", redirect_first), mock.patch.object(Path, "resolve", resolve_redirect):
            with self.assertRaisesRegex(ho_factory.FactoryError, "must not redirect"):
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertTrue(raced)
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve unrelated target")

    def test_parent_swap_at_creation_cannot_write_into_unapproved_directory(self) -> None:
        parent = self.route / "approved-parent"
        collector_route = parent / "collector"
        collector_route.mkdir(parents=True)
        parked = self.route / "parked-parent"
        outside = self.route / "outside"
        (outside / "collector").mkdir(parents=True)
        self.normalize.return_value = str(collector_route)
        protected_open = ho_factory.open_runtime_collector_windows_output
        attempted = False
        blocked = False

        def swap_before_open(path, route_fd, mode):
            nonlocal attempted, blocked
            if mode == "x":
                attempted = True
                try:
                    parent.rename(parked)
                except OSError:
                    blocked = True
                else:
                    parent.symlink_to(outside, target_is_directory=True)
            return protected_open(path, route_fd, mode)

        with mock.patch.object(ho_factory, "open_runtime_collector_windows_output", swap_before_open):
            if os.name == "nt":
                result = ho_factory.runtime_collector_windows_run_once(False, "approved-route")
                self.assertTrue(result["generated_output_files"])
                self.assertTrue(blocked)
            else:
                with self.assertRaises(ho_factory.FactoryError):
                    ho_factory.runtime_collector_windows_run_once(False, "approved-route")
        self.assertTrue(attempted)
        self.assertEqual(list((outside / "collector").iterdir()), [])

    def test_unsupported_native_route_protection_fails_closed(self) -> None:
        with mock.patch.object(ho_factory.os, "name", "unsupported"):
            with self.assertRaisesRegex(ho_factory.FactoryError, "supported native route protection"):
                with ho_factory.locked_runtime_collector_windows_route(self.route):
                    self.fail("unsupported route protection must never yield")

    @unittest.skipUnless(os.name == "nt", "Windows native acquisition contract")
    def test_each_directory_acquisition_is_relative_to_previously_held_handle(self) -> None:
        native = ho_factory.native_runtime_collector_windows_handle
        acquisitions = []

        def record(name, parent, mode, *, directory=False):
            handle = native(name, parent, mode, directory=directory)
            acquisitions.append((name, parent, mode, directory, handle))
            return handle

        with mock.patch.object(ho_factory, "native_runtime_collector_windows_handle", record):
            with ho_factory.locked_runtime_collector_windows_route(self.route):
                self.assertIsNone(acquisitions[0][1])
                self.assertTrue(acquisitions[0][0].startswith("\\??\\"))
                for previous, current in zip(acquisitions, acquisitions[1:]):
                    name, parent, mode, directory, _ = current
                    self.assertEqual(parent, previous[4])
                    self.assertFalse(any(character in name for character in "\\/:"))
                    self.assertEqual(mode, "r")
                    self.assertTrue(directory)
        self.assertGreater(len(acquisitions), 1)

    @unittest.skipUnless(os.name == "nt", "Windows native acquisition contract")
    def test_native_handle_child_names_cannot_reintroduce_full_paths(self) -> None:
        for name in ("..", ".", "child/next", "child\\next", "C:\\outside"):
            with self.subTest(name=name), self.assertRaises(ho_factory.FactoryError):
                ho_factory.native_runtime_collector_windows_handle(name, 1, "r", directory=True)

    @unittest.skipUnless(os.name == "nt", "Windows reparse metadata attack")
    def test_reparse_metadata_change_cannot_redirect_directory_relative_creation(self) -> None:
        import ctypes
        import struct
        from ctypes import wintypes

        approved = self.route / "approved-empty-directory"
        outside = self.route / "unapproved-target"
        approved.mkdir()
        outside.mkdir()
        self.normalize.return_value = str(approved)
        protected_open = ho_factory.open_runtime_collector_windows_output
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel32.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        control = kernel32.DeviceIoControl
        control.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        control.restype = wintypes.BOOL
        close = kernel32.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        attempted = False
        changed = False

        def change_before_open(path, route_handle, mode):
            nonlocal attempted, changed
            if mode == "x":
                attempted = True
                handle = create(str(approved), 0x100, 0x7, None, 3, 0x02200000, None)
                if handle != ctypes.c_void_p(-1).value:
                    try:
                        substitute = ("\\??\\" + str(outside)).encode("utf-16-le")
                        printed = str(outside).encode("utf-16-le")
                        names = substitute + b"\x00\x00" + printed + b"\x00\x00"
                        reparse = struct.pack("<LHHHHHH", 0xA0000003, len(names) + 8, 0, 0, len(substitute), len(substitute) + 2, len(printed)) + names
                        buffer = ctypes.create_string_buffer(reparse)
                        returned = wintypes.DWORD()
                        changed = bool(control(handle, 0x900A4, buffer, len(reparse), None, 0, ctypes.byref(returned), None))
                    finally:
                        close(handle)
            return protected_open(path, route_handle, mode)

        with mock.patch.object(ho_factory, "open_runtime_collector_windows_output", change_before_open):
            if_changed_error = None
            try:
                ho_factory.runtime_collector_windows_run_once(False, "approved-route")
            except ho_factory.FactoryError as exc:
                if_changed_error = exc
        self.assertTrue(attempted)
        self.assertEqual(list(outside.iterdir()), [])
        if changed:
            self.assertIsNotNone(if_changed_error)
        else:
            self.assertIsNone(if_changed_error)

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
        for key in ("source_truth_status", "runtime_truth_status", "signal_truth_status", "detection_family", "collected_at_utc"):
            mutations.append(lambda packet, key=key: packet["candidates"][0].update({key: "UNREVIEWED_PROMOTION"}))
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

    def test_route_probe_uses_protected_access_and_emits_only_sanitized_flags(self) -> None:
        with mock.patch.object(ho_factory, "build_runtime_collector_windows_candidate") as collector:
            result = ho_factory.runtime_collector_windows_route_probe("approved-route", "123", "1")
            collector.assert_not_called()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["write_succeeded"])
        self.assertTrue(result["read_verified"])
        for field in ("collector_invoked", "lifetime_case_ledger_mutated", "governed_cases_appended", "public_safe_promotion"):
            self.assertIs(result[field], False)
        self.assertNotIn(str(self.route), json.dumps(result))
        self.assertEqual(len(list(self.route.iterdir())), 1)

    def test_route_probe_rejects_existing_target_without_overwriting(self) -> None:
        ho_factory.runtime_collector_windows_route_probe("approved-route", "123", "1")
        output = self.route / "route-probe-123-1.txt"
        original = output.read_bytes()
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.runtime_collector_windows_route_probe("approved-route", "123", "1")
        self.assertEqual(output.read_bytes(), original)

    def test_route_probe_rejects_invalid_identity_and_unavailable_guard(self) -> None:
        for run_id in ("../escape", "1' arbitrary", "0", "1" * 21):
            with self.subTest(run_id=run_id), self.assertRaises(ho_factory.FactoryError):
                ho_factory.runtime_collector_windows_route_probe("approved-route", run_id, "1")
        with mock.patch.object(ho_factory, "locked_runtime_collector_windows_route", side_effect=ho_factory.FactoryError("guard unavailable")):
            with self.assertRaisesRegex(ho_factory.FactoryError, "guard unavailable"):
                ho_factory.runtime_collector_windows_route_probe("approved-route", "123", "1")
        self.assertEqual(list(self.route.iterdir()), [])

    def test_route_probe_rejects_redirected_route(self) -> None:
        with mock.patch.object(ho_factory.Path, "resolve", return_value=self.route.parent):
            with self.assertRaisesRegex(ho_factory.FactoryError, "must not redirect"):
                ho_factory.runtime_collector_windows_route_probe("approved-route", "123", "1")
        self.assertEqual(list(self.route.iterdir()), [])


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

    def test_route_probe_rejects_unapproved_route(self) -> None:
        with self.assertRaises(ho_factory.FactoryError):
            ho_factory.runtime_collector_windows_route_probe("C:/not-approved/windows", "123", "1")


if __name__ == "__main__":
    unittest.main()
