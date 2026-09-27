"""Pure wrapper argv/lock contracts; subprocess and lock are mocked."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load_runner():
    path = ROOT / "autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py"
    spec = importlib.util.spec_from_file_location("focused_cpu_runner_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FocusedCpuRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = load_runner()

    def test_defaults_filters_and_mode_are_preserved_and_scoped(self) -> None:
        command = self.runner.command([])
        self.assertEqual([self.runner.z, "test"], command[:2])
        self.assertEqual(["--test-filter", "SHA canonical memory call", "--test-filter", "SHA provider"], command[-4:])
        self.assertEqual(1, command.count("-Minterop_postcard=src/interop/postcard.zig"))
        self.assertEqual(1, command.count("-Mstwo_proof_wire=src/interop/proof_wire/mod.zig"))
        self.assertEqual(1, command.count("-lc"))
        for i, item in enumerate(command):
            if item.startswith("-M"):
                self.assertEqual(["-OReleaseFast", "-mcpu=native"], command[i - 2:i])

    def test_all_ignores_filters_and_explicit_debug_applies_to_every_module(self) -> None:
        command = self.runner.command(["--root", "custom.zig", "--all", "--optimize", "Debug", "ignored"])
        self.assertNotIn("--test-filter", command)
        self.assertIn("-Mroot=custom.zig", command)
        for i, item in enumerate(command):
            if item.startswith("-M"):
                self.assertEqual(["-ODebug", "-mcpu=native"], command[i - 2:i])

    def test_custom_runner_uses_common_graph_and_named_filters(self) -> None:
        with mock.patch.dict(self.runner.test_command.__globals__, {"standard_runner_source": lambda zig: "selected/test_runner.zig"}):
            command = self.runner.command(["--test-runner", "policy.zig", "first", "second"])
        self.assertIn("-Mblock_v5_standard_test_runner=selected/test_runner.zig", command)
        self.assertEqual(1, command.count("--test-runner"))
        self.assertEqual(["--test-runner", "policy.zig", "--test-filter", "first", "--test-filter", "second"], command[-6:])

    def test_wrapper_calls_subprocess_under_exactly_one_lock(self) -> None:
        command = ["never-run-zig", "test"]
        with mock.patch.object(self.runner, "command", return_value=command), mock.patch.object(self.runner, "build_lock") as lock, mock.patch.object(self.runner.subprocess, "run") as run:
            self.assertEqual(0, self.runner.main(["named-filter"]))
        lock.assert_called_once_with(label="ethereum-auth-build")
        lock.return_value.__enter__.assert_called_once()
        lock.return_value.__exit__.assert_called_once()
        run.assert_called_once_with(command, check=True, cwd=self.runner.R)

    def test_canonical_cli_uses_same_builder_with_one_lock_and_no_nested_runner(self) -> None:
        from scripts import zig_protocol_test
        with mock.patch.object(zig_protocol_test, "build_lock") as lock, mock.patch.object(zig_protocol_test.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(0, zig_protocol_test.main(["focused.zig", "-ODebug", "-mcpu=native", "--test-filter", "exact"] ))
        lock.assert_called_once_with(zig_protocol_test.DEFAULT_LOCK, label="zig_protocol_test")
        argv = run.call_args.args[0]
        self.assertEqual(["zig", "test"], argv[:2])
        self.assertIn("-Minterop_postcard=src/interop/postcard.zig", argv)
        for i, item in enumerate(argv):
            if item.startswith("-M"):
                self.assertEqual(["-ODebug", "-mcpu=native"], argv[i - 2:i])
        self.assertEqual(["--test-filter", "exact"], argv[-2:])

    def test_import_and_command_construction_do_not_acquire_lock_or_spawn(self) -> None:
        with mock.patch.object(self.runner, "build_lock") as lock, mock.patch.object(self.runner.subprocess, "run") as run:
            self.runner.command(["named-filter"])
        lock.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
