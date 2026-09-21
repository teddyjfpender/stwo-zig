"""Portable scheduling and argument boundaries for the serialized build loop."""
import fcntl
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import zig_serial_build as subject


class SerialBuildTests(unittest.TestCase):
    def test_host_budget_reserves_memory_and_caps_large_hosts(self):
        for gib in (8, 16, 36, 64):
            with self.subTest(gib=gib), mock.patch.object(
                os, "sysconf", side_effect=[gib * (1 << 30) // 4096, 4096]
            ):
                self.assertEqual(
                    min(24 * (1 << 30), gib * (1 << 30) * 2 // 3),
                    subject.default_maxrss(),
                )
        with mock.patch.object(os, "sysconf", side_effect=ValueError):
            self.assertEqual(8 * (1 << 30), subject.default_maxrss())

    def test_limits_stop_at_runtime_argument_separator(self):
        with mock.patch.object(subject, "default_maxrss", return_value=123):
            _, memory, jobs, _, args = subject.parse([
                "--maxrss", "456", "-j2", "run", "--", "-j8", "--maxrss", "999",
            ])
            self.assertEqual((456, 2, ["run", "--", "-j8", "--maxrss", "999"]),
                             (memory, jobs, args))
            self.assertEqual((123, 1), subject.parse(["test"])[1:3])
        for args in (["--cwd"], ["--lock"], ["--maxrss"], ["-j"],
                     ["-j0"], ["-j-1"], ["--maxrss", "0"], ["--maxrss", "oops"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                subject.parse(args)

    def test_main_passes_limits_to_root_and_delegated_builds(self):
        with mock.patch.object(subject.sys, "argv", [
            "wrapper", "--no-lock", "--maxrss", "456", "-j", "2", "run", "--", "arg",
        ]), mock.patch.object(subject.subprocess, "call", return_value=7) as run:
            self.assertEqual(7, subject.main())
        self.assertEqual(["zig", "build", "--maxrss", "456", "-j2", "run", "--", "arg"],
                         run.call_args.args[0])
        env = run.call_args.kwargs["env"]
        self.assertEqual("456", env["STWO_ZIG_BUILD_MAXRSS"])
        self.assertEqual("2", env["STWO_ZIG_BUILD_JOBS"])


class SerializedSubprocessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.lock_path = self.directory / "build.lock"
        self.marker = self.directory / "invocation.json"
        self.root = Path(__file__).resolve().parents[2]
        zig = self.directory / "zig"
        zig.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['TEST_ZIG_MARKER']).write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(7)\n"
        )
        zig.chmod(0o755)
        self.environment = dict(os.environ, PATH=f"{self.directory}{os.pathsep}{os.environ['PATH']}", TEST_ZIG_MARKER=str(self.marker))

    def command(self, wrapper, *arguments):
        return [sys.executable, str(self.root / "scripts" / wrapper), *arguments]

    def test_both_wrappers_wait_for_shared_lock_and_propagate_child_exit(self):
        for wrapper, target in (("zig_serial_build.py", "test"), ("zig_protocol_test.py", "src/stwo.zig")):
            with self.subTest(wrapper=wrapper), open(self.lock_path, "a+") as lock:
                self.marker.unlink(missing_ok=True)
                fcntl.flock(lock, fcntl.LOCK_EX)
                with subprocess.Popen(self.command(wrapper, "--lock", str(self.lock_path), target),
                                      env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stderr, selectors.EVENT_READ)
                            self.assertTrue(selector.select(timeout=10), "wrapper did not report lock contention")
                        self.assertIn("waiting", process.stderr.readline())
                        self.assertIsNone(process.poll())
                        self.assertFalse(self.marker.exists(), "Zig started while another caller held the lock")
                        fcntl.flock(lock, fcntl.LOCK_UN)
                        _, stderr = process.communicate(timeout=10)
                        self.assertEqual(7, process.returncode, stderr)
                        self.assertTrue(self.marker.exists())
                        self.assertIn("acquired", stderr)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()
                # Child failure must release ownership, not strand the lock.
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)

    def test_protocol_no_lock_is_explicit_and_preserves_all_zig_arguments(self):
        with open(self.lock_path, "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = subprocess.run(self.command("zig_protocol_test.py", "--lock", str(self.lock_path),
                                                "--no-lock", "src/stwo.zig", "--test-filter", "--no-lock",
                                                "--", "--lock", "runtime-path", "--no-lock"),
                                    env=self.environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(7, result.returncode, result.stderr)
        arguments = json.loads(self.marker.read_text())
        self.assertEqual(["--test-filter", "--no-lock", "--", "--lock", "runtime-path", "--no-lock"], arguments[-6:])
        self.assertNotIn("waiting", result.stderr)

    def test_nested_protocol_wrapper_uses_explicit_parent_lock_without_deadlock(self):
        zig = self.directory / "zig"
        wrapper = str(self.root / "scripts" / "zig_protocol_test.py")
        zig.write_text(
            f"#!{sys.executable}\n"
            "import fcntl, json, os, pathlib, subprocess, sys\n"
            "held = os.environ['STWO_ZIG_BUILD_HELD_LOCK']\n"
            "if sys.argv[1] == 'build':\n"
            f"    raise SystemExit(subprocess.call([sys.executable, {wrapper!r}, '--no-lock', 'src/stwo.zig']))\n"
            "with open(held, 'a+') as lock:\n"
            "    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "    except BlockingIOError: pass\n"
            "    else: raise SystemExit('parent did not retain lock during nested test')\n"
            "pathlib.Path(os.environ['TEST_ZIG_MARKER']).write_text(json.dumps({'held': held, 'args': sys.argv[1:]}))\n"
            "raise SystemExit(7)\n"
        )
        result = subprocess.run(self.command("zig_serial_build.py", "--lock", str(self.lock_path), "deep-gate"),
                                env=self.environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(7, result.returncode, result.stderr)
        receipt = json.loads(self.marker.read_text())
        self.assertEqual(str(self.lock_path), receipt["held"])
        self.assertEqual("test", receipt["args"][0])

    def test_serial_no_lock_clears_inherited_ownership_marker(self):
        zig = self.directory / "zig"
        zig.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib\n"
            "pathlib.Path(os.environ['TEST_ZIG_MARKER']).write_text(json.dumps(os.environ.get('STWO_ZIG_BUILD_HELD_LOCK')))\n"
            "raise SystemExit(7)\n"
        )
        environment = dict(self.environment, STWO_ZIG_BUILD_HELD_LOCK="stale-parent")
        result = subprocess.run(self.command("zig_serial_build.py", "--no-lock", "test"),
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(7, result.returncode, result.stderr)
        self.assertIsNone(json.loads(self.marker.read_text()))

    def test_protocol_missing_lock_path_rejects_before_running_zig(self):
        result = subprocess.run(self.command("zig_protocol_test.py", "--lock"), env=self.environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertIn("requires a path", result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
