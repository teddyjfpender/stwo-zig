from __future__ import annotations

import io
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.repo import ci_scope_plan, ci_scope_push, ci_scope_run, zig_serial_build
from scripts.tests.focused_ci_fixtures import catalog_fixture, product


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "1" * 40
TREE = "2" * 40

def runner_policy(commands: list[list[str]], host: str | None = None) -> dict[str, object]:
    current_host = "macos" if sys.platform == "darwin" else "linux"
    return {
        "schema": "ci-touchpoints-v1",
        "always_lanes": ["focused"],
        "lanes": {
            "focused": {
                "host": host or current_host,
                "description": "test lane",
                "commands": commands,
            }
        },
        "product_scope_lanes": {},
        "rules": [],
        "documentation_prefixes": ["docs"],
    }

class RunnerReceiptTests(unittest.TestCase):
    def test_interruption_keeps_completed_command_receipt_and_unfinished_lane(self) -> None:
        policy = runner_policy([["first"], ["interrupted"], ["must-not-run"]])
        captured: list[tuple[list[str], dict[str, object]]] = []
        fake = self.fake_run([(0, b"completed\n", b"")], captured)
        streams = SimpleNamespace(buffer=io.BytesIO())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "focused.json"

            def run(argv, **kwargs):
                if argv == ["interrupted"]:
                    completed = json.loads((output.parent / "focused-0.completed.json").read_text())
                    self.assertEqual("PASS", completed["status"])
                    self.assertEqual(COMMIT, completed["commit"])
                    self.assertEqual(TREE, completed["tree"])
                    self.assertEqual(ci_scope_run.digest(b"completed\n"), completed["command"]["stdout_sha256"])
                    progress = json.loads(output.read_text())
                    self.assertEqual("INCOMPLETE", progress["status"])
                    self.assertEqual(1, len(progress["commands"]))
                    raise KeyboardInterrupt
                return fake(argv, **kwargs)

            with (
                mock.patch.object(ci_scope_run.subprocess, "run", side_effect=run),
                mock.patch.object(ci_scope_run.sys, "stdout", streams),
                mock.patch.object(ci_scope_run.sys, "stderr", streams),
                self.assertRaises(KeyboardInterrupt),
            ):
                ci_scope_run.run_lane(root=ROOT, policy=policy, lane="focused", output=output,
                                      cache_mode="inherit", cache_root=None)
            self.assertEqual("INCOMPLETE", json.loads(output.read_text())["status"])
            self.assertFalse((output.parent / "focused-1.completed.json").exists())

    def test_local_build_preserves_limits_and_runtime_args_while_serializing(self) -> None:
        for jobs in (["-j2"], ["-j", "2"], ["-j"]):
            command = [
                "zig", "build", *jobs, "test", "-Doptimize=ReleaseFast",
                "--maxrss", "4294967296", "--", "-j8",
            ]
            original = list(command)
            local = ci_scope_run.local_build_command(command)
            with mock.patch.object(zig_serial_build, "default_maxrss", return_value=1024):
                _, rss, count, _, forwarded = zig_serial_build.parse(local[2:])
            self.assertEqual((4294967296, 1), (rss, count))
            self.assertEqual(["test", "-Doptimize=ReleaseFast", "--", "-j8"], forwarded)
            self.assertEqual(original, command)
        self.assertEqual(["tool"], ci_scope_run.local_build_command(["tool"]))

    def test_local_build_keeps_invalid_job_counts_rejected(self) -> None:
        for jobs in (["-j0"], ["-j", "0"]):
            local = ci_scope_run.local_build_command(["zig", "build", *jobs, "test"])
            with mock.patch.object(zig_serial_build, "default_maxrss", return_value=1024):
                with self.assertRaises(ValueError):
                    zig_serial_build.parse(local[2:])

    def fake_run(
        self,
        command_results: list[tuple[int, bytes, bytes]],
        captured: list[tuple[list[str], dict[str, object]]],
    ):
        remaining = list(command_results)

        def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            if argv == ["git", "rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, COMMIT + "\n", "")
            if argv == ["git", "rev-parse", "HEAD^{tree}"]:
                return subprocess.CompletedProcess(argv, 0, TREE + "\n", "")
            if argv == ["git", "diff", "--quiet", "HEAD", "--"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv == ["git", "ls-files", "--others", "--exclude-standard"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            captured.append((list(argv), kwargs))
            returncode, stdout, stderr = remaining.pop(0)
            kwargs["stdout"].write(stdout)
            kwargs["stderr"].write(stderr)
            return subprocess.CompletedProcess(argv, returncode)

        return run

    def test_pre_push_clears_git_environment_before_nested_git_commands(self) -> None:
        result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="GIT_DIR\nGIT_WORK_TREE\nGIT_INDEX_FILE\n", stderr="",
        )
        inherited = {
            "GIT_DIR": "/repository/.git",
            "GIT_WORK_TREE": "/repository",
            "GIT_INDEX_FILE": "/repository/.git/index",
        }
        with (
            mock.patch.dict(os.environ, inherited, clear=False),
            mock.patch.object(ci_scope_push.subprocess, "run", return_value=result),
        ):
            ci_scope_push.clear_git_local_environment(ROOT)
            for name in inherited:
                self.assertNotIn(name, os.environ)

    def test_pass_receipt_binds_identity_output_digests_and_durations(self) -> None:
        policy = runner_policy(
            [["test-riscv-profile-partition", "--output", "{output_dir}", "--commit", "{commit}"]]
        )
        captured: list[tuple[list[str], dict[str, object]]] = []
        stdout = SimpleNamespace(buffer=io.BytesIO())
        stderr = SimpleNamespace(buffer=io.BytesIO())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipts" / "focused.json"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"ok\n", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 500, 900],
                ),
                mock.patch.object(ci_scope_run.platform, "machine", return_value="test64"),
                mock.patch.object(ci_scope_run.sys, "stdout", stdout),
                mock.patch.object(ci_scope_run.sys, "stderr", stderr),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(b"ok\n", (output.parent / "focused-0.stdout").read_bytes())

        self.assertEqual(receipt, persisted)
        self.assertEqual("stwo-focused-ci-timing-v1", receipt["schema"])
        self.assertEqual("PASS", receipt["status"])
        self.assertEqual(COMMIT, receipt["commit"])
        self.assertEqual(TREE, receipt["tree"])
        self.assertTrue(receipt["clean"])
        self.assertEqual("test64", receipt["host_machine"])
        self.assertEqual(800, receipt["duration_ns"])
        self.assertEqual(300, receipt["commands"][0]["duration_ns"])
        self.assertEqual(ci_scope_run.digest(b"ok\n"), receipt["commands"][0]["stdout_sha256"])
        self.assertEqual(ci_scope_run.digest(b""), receipt["commands"][0]["stderr_sha256"])
        self.assertEqual(b"ok\n", stdout.buffer.getvalue())
        self.assertEqual([], [entry for entry in captured if entry[0][:2] == ["git", "rev-parse"]])
        self.assertEqual(
            [
                "test-riscv-profile-partition",
                "--output",
                str(output.parent.resolve()),
                "--commit",
                COMMIT,
            ],
            captured[0][0],
        )

    def test_failed_command_stops_lane_and_persists_failure_receipt(self) -> None:
        policy = runner_policy([["first"], ["second"], ["must-not-run"]])
        captured: list[tuple[list[str], dict[str, object]]] = []
        streams = SimpleNamespace(buffer=io.BytesIO())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "failed.json"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run(
                        [(0, b"", b""), (7, b"", b"failed\n")], captured
                    ),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400, 650, 1000],
                ),
                mock.patch.object(ci_scope_run.sys, "stdout", streams),
                mock.patch.object(
                    ci_scope_run.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )

            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(b"failed\n", (output.parent / "focused-1.stderr").read_bytes())
        self.assertEqual("FAIL", receipt["status"])
        self.assertEqual(receipt, persisted)
        self.assertEqual(["first", "second"], [item[0][0] for item in captured])
        self.assertEqual([0, 7], [record["exit_code"] for record in receipt["commands"]])
        self.assertEqual([100, 250], [record["duration_ns"] for record in receipt["commands"]])
        self.assertEqual(900, receipt["duration_ns"])

    def test_warm_cache_exports_isolated_cache_roots(self) -> None:
        policy = runner_policy([["tool"]])
        captured: list[tuple[list[str], dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "receipt.json"
            cache = root / "cache"
            with (
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400],
                ),
                mock.patch.object(
                    ci_scope_run.sys,
                    "stdout",
                    SimpleNamespace(buffer=io.BytesIO()),
                ),
                mock.patch.object(
                    ci_scope_run.sys,
                    "stderr",
                    SimpleNamespace(buffer=io.BytesIO()),
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=output,
                    cache_mode="warm",
                    cache_root=cache,
                )
        environment = captured[0][1]["env"]
        assert isinstance(environment, dict)
        self.assertEqual(str(cache.resolve() / "local"), environment["STWO_CI_CACHE_DIR"])
        self.assertEqual(
            str(cache.resolve() / "zig-local"), environment["ZIG_LOCAL_CACHE_DIR"]
        )
        self.assertEqual(str(cache.resolve() / "global"), environment["ZIG_GLOBAL_CACHE_DIR"])
        self.assertEqual(str(cache.resolve() / "cargo-target"), environment["CARGO_TARGET_DIR"])
        self.assertEqual("warm", receipt["cache_mode"])

    def test_invalid_cache_arguments_fail_before_git_or_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            ci_scope_run.subprocess, "run", side_effect=AssertionError("no Git or lane execution")
        ):
            output = Path(raw) / "not-created" / "receipt.json"
            for mode, message in (("warm", "warm cache mode requires --cache-root"),
                                  ("invalid", "invalid cache mode")):
                with self.subTest(mode=mode), self.assertRaisesRegex(ci_scope_run.PlanError, message):
                    ci_scope_run.run_lane(
                        root=Path(raw) / "no-checkout", policy=runner_policy([["tool"]]),
                        lane="focused", output=output, cache_mode=mode, cache_root=None,
                    )
            self.assertFalse(output.parent.exists())

    def test_wrong_host_and_unknown_lane_fail_before_execution(self) -> None:
        current_host = "macos" if sys.platform == "darwin" else "linux"
        other_host = "linux" if current_host == "macos" else "macos"
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipt.json"
            with self.assertRaisesRegex(ci_scope_run.PlanError, "requires"):
                ci_scope_run.run_lane(
                    root=ROOT,
                    policy=runner_policy([["tool"]], host=other_host),
                    lane="focused",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )
            with self.assertRaisesRegex(ci_scope_run.PlanError, "unknown CI lane"):
                ci_scope_run.run_lane(
                    root=ROOT,
                    policy=runner_policy([["tool"]]),
                    lane="missing",
                    output=output,
                    cache_mode="inherit",
                    cache_root=None,
                )

    def test_macos_can_run_linux_compatible_lane_only_when_explicit(self) -> None:
        policy = runner_policy([["zig", "build", "test", "-Doptimize=ReleaseFast", "-j2"]], host="linux")
        captured: list[tuple[list[str], dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as raw:
            with (
                mock.patch.object(ci_scope_run.sys, "platform", "darwin"),
                mock.patch.object(
                    ci_scope_run.subprocess,
                    "run",
                    side_effect=self.fake_run([(0, b"", b"")], captured),
                ),
                mock.patch.object(
                    ci_scope_run.time,
                    "monotonic_ns",
                    side_effect=[100, 200, 300, 400],
                ),
                mock.patch.object(
                    ci_scope_run.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())
                ),
                mock.patch.object(
                    ci_scope_run.sys, "stderr", SimpleNamespace(buffer=io.BytesIO())
                ),
            ):
                receipt = ci_scope_run.run_lane(
                    root=ROOT,
                    policy=policy,
                    lane="focused",
                    output=Path(raw) / "receipt.json",
                    cache_mode="inherit",
                    cache_root=None,
                    local_compatible=True,
                )
        self.assertEqual("macos", receipt["host"])
        self.assertEqual("linux", receipt["required_host"])
        self.assertEqual(
            [sys.executable, "scripts/repo/zig_serial_build.py", "-j1", "test", "-Doptimize=ReleaseFast"],
            captured[0][0],
        )
