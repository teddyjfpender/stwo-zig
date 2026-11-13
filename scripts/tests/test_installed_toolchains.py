"""Installed tools are evidence only when their selected versions execute."""
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts.repo import installed_toolchains as T

ROOT = Path(__file__).resolve().parents[2]


class InstalledToolchainTests(unittest.TestCase):
    def test_cpu_requires_both_actual_versions_and_records_their_outputs(self):
        with mock.patch.object(T, "host", return_value="aarch64-macos"), mock.patch.object(
            T.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, "0.15.2\n", ""),
                                             subprocess.CompletedProcess([], 0, "Python 3.13.18\n", "")],
        ):
            report = T.inspect(ROOT, "cpu")
        self.assertEqual("PASS", report["status"])
        self.assertEqual(2, len(report["tools"]))
        self.assertTrue(all(row["stdout_sha256"] for row in report["tools"]))

    def test_wrong_missing_or_timed_out_tools_fail_without_installing(self):
        for failure in (subprocess.CompletedProcess([], 0, "0.15.1\n", ""),
                        FileNotFoundError("zig"), subprocess.TimeoutExpired(["zig"], 20)):
            with self.subTest(failure=failure), mock.patch.object(T, "host", return_value="aarch64-macos"), mock.patch.object(
                T.subprocess, "run", side_effect=[failure, subprocess.CompletedProcess([], 0, "Python 3.13.18\n", "")],
            ) as run:
                report = T.inspect(ROOT, "cpu")
                self.assertEqual("FAIL", report["status"])
                self.assertNotIn("install", " ".join(run.call_args_list[0].args[0]))

    def test_unqualified_host_profile_is_rejected_before_any_command(self):
        with mock.patch.object(T, "host", return_value="aarch64-macos"), mock.patch.object(T.subprocess, "run") as run:
            report = T.inspect(ROOT, "formal")
        self.assertEqual("FAIL", report["status"])
        self.assertFalse(run.called)

    def test_oracles_select_exact_channels_and_declared_components(self):
        pins = json.loads((ROOT / "toolchain.json").read_text())
        specs = T.specifications(ROOT, pins, "oracles")
        rust = [s for s in specs if s["tool"].startswith("rust:")]
        expected = set(pins["rust"]["crates"].values()) | set(pins["rust"]["guests"].values())
        self.assertEqual(expected, {s["command"][2] for s in rust})
        for spec in rust:
            self.assertEqual(["rustup", "run"], spec["command"][:2])
            self.assertNotIn("install", spec["command"])

    def test_formal_selects_pinned_lean_and_sail_without_default_aliases(self):
        pins = json.loads((ROOT / "toolchain.json").read_text())
        specs = T.specifications(ROOT, pins, "formal")
        self.assertIn(["elan", "run", "leanprover/lean4:v4.29.0", "lean", "--version"], [s["command"] for s in specs])
        self.assertIn(["sail", "--version"], [s["command"] for s in specs])
