from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import typed_air_zig_lane as lane


class ZigCompilerLaneTests(unittest.TestCase):
    def test_zig_build_gets_slot_cache_and_releases_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            private = repository / ".git"
            private.mkdir()
            completed = subprocess.CompletedProcess(["zig", "build"], 17)
            with (
                mock.patch.object(lane, "_git_private_directory", return_value=private),
                mock.patch.object(lane.subprocess, "run", return_value=completed) as run,
            ):
                result = lane.run("a013", ["zig", "build", "test"], repository)

            self.assertEqual(17, result)
            call = run.call_args
            expected_cache = private / lane.CACHE_DIRECTORY_NAME / "slot-0"
            self.assertEqual(
                (["zig", "build", "--cache-dir", str(expected_cache), "test"],),
                call.args,
            )
            self.assertEqual(repository, call.kwargs["cwd"])
            self.assertFalse(call.kwargs["check"])
            self.assertEqual(2, len(call.kwargs["pass_fds"]))
            self.assertEqual(
                b"", (private / f"{lane.SLOT_LOCK_PREFIX}0.lock").read_bytes()
            )

    def test_time_wrapped_build_replaces_unsafe_caller_cache(self) -> None:
        cache = Path("/private/repository/.git/typed-air-zig-cache/slot-2")
        command = [
            "/usr/bin/time",
            "-l",
            "zig",
            "build",
            "--cache-dir=/tmp/shared",
            "test",
            "--cache-dir",
            "/tmp/also-shared",
            "-Doptimize=Debug",
        ]
        self.assertEqual(
            [
                "/usr/bin/time",
                "-l",
                "zig",
                "build",
                "--cache-dir",
                str(cache),
                "test",
                "-Doptimize=Debug",
            ],
            lane._prepare_command(command, cache),
        )

    def test_non_build_command_is_unchanged(self) -> None:
        command = ["zig", "fmt", "source.zig"]
        self.assertEqual(command, lane._prepare_command(command, Path("unused")))

    def test_occupied_first_slot_admits_second_with_distinct_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            private = repository / ".git"
            private.mkdir()
            first_path = private / f"{lane.SLOT_LOCK_PREFIX}0.lock"
            first = os.open(first_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(
                    first,
                    json.dumps(
                        {
                            "schema": lane.SCHEMA,
                            "slot": 0,
                            "label": "first",
                            "pid": 120,
                            "command": ["zig", "build", "test-first"],
                        }
                    ).encode(),
                )
                completed = subprocess.CompletedProcess(["zig", "build"], 0)
                with (
                    mock.patch.object(
                        lane, "_git_private_directory", return_value=private
                    ),
                    mock.patch.object(
                        lane.subprocess, "run", return_value=completed
                    ) as run,
                ):
                    result = lane.run(
                        "second", ["zig", "build", "test-second"], repository
                    )
                self.assertEqual(0, result)
                expected_cache = private / lane.CACHE_DIRECTORY_NAME / "slot-1"
                self.assertEqual(
                    [
                        "zig",
                        "build",
                        "--cache-dir",
                        str(expected_cache),
                        "test-second",
                    ],
                    run.call_args.args[0],
                )
                self.assertEqual(
                    b"", (private / f"{lane.SLOT_LOCK_PREFIX}1.lock").read_bytes()
                )
            finally:
                fcntl.flock(first, fcntl.LOCK_UN)
                os.close(first)

    def test_all_slots_busy_fails_fast_with_every_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            private = repository / ".git"
            private.mkdir()
            descriptors: list[int] = []
            try:
                for slot in range(2):
                    path = private / f"{lane.SLOT_LOCK_PREFIX}{slot}.lock"
                    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
                    descriptors.append(descriptor)
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    owner = {
                        "schema": lane.SCHEMA,
                        "slot": slot,
                        "label": f"owner-{slot}",
                        "pid": 120 + slot,
                        "command": ["zig", "build", f"test-{slot}"],
                    }
                    os.write(descriptor, json.dumps(owner).encode())
                stderr = io.StringIO()
                with (
                    mock.patch.object(lane, "_git_private_directory", return_value=private),
                    mock.patch.object(lane.subprocess, "run") as run,
                    contextlib.redirect_stderr(stderr),
                ):
                    result = lane.run(
                        "waiting", ["zig", "build"], repository, slot_count=2
                    )
                self.assertEqual(lane.BUSY_EXIT, result)
                self.assertIn("label='owner-0'", stderr.getvalue())
                self.assertIn("label='owner-1'", stderr.getvalue())
                run.assert_not_called()
            finally:
                for descriptor in descriptors:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)

    def test_status_reports_only_live_locks_and_available_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            private = repository / ".git"
            private.mkdir()
            stale = private / f"{lane.SLOT_LOCK_PREFIX}0.lock"
            stale.write_text('{"label":"stale"}')
            live_path = private / f"{lane.SLOT_LOCK_PREFIX}1.lock"
            live = os.open(live_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(
                    live,
                    json.dumps(
                        {
                            "schema": lane.SCHEMA,
                            "slot": 1,
                            "label": "live",
                            "pid": 456,
                            "command": ["zig", "build", "test-live"],
                        }
                    ).encode(),
                )
                with mock.patch.object(
                    lane, "_git_private_directory", return_value=private
                ):
                    result = lane.status(repository, slot_count=3)
                self.assertEqual(3, result["capacity"])
                self.assertEqual(1, result["occupied_slots"])
                self.assertEqual(2, result["available_slots"])
                self.assertFalse(result["legacy_guard_active"])
                self.assertEqual(1, len(result["active"]))
                self.assertEqual("live", result["active"][0]["owner"]["label"])
            finally:
                fcntl.flock(live, fcntl.LOCK_UN)
                os.close(live)

    def test_legacy_owner_excludes_new_slots_during_migration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            private = repository / ".git"
            private.mkdir()
            path = private / lane.LEGACY_LOCK_NAME
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                owner = {
                    "schema": "stwo.typed-air.zig-compiler-lane.v1",
                    "label": "legacy",
                    "pid": 123,
                    "command": ["zig", "build", "test-recursion"],
                }
                os.write(descriptor, json.dumps(owner).encode())
                stderr = io.StringIO()
                with (
                    mock.patch.object(lane, "_git_private_directory", return_value=private),
                    mock.patch.object(lane.subprocess, "run") as run,
                    contextlib.redirect_stderr(stderr),
                ):
                    result = lane.run("new", ["zig", "build"], repository)
                self.assertEqual(lane.BUSY_EXIT, result)
                self.assertIn("label='legacy'", stderr.getvalue())
                run.assert_not_called()
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def test_invalid_inputs_fail_before_locking(self) -> None:
        repository = Path("/")
        with self.assertRaises(ValueError):
            lane.run("has spaces", ["zig"], repository)
        with self.assertRaises(ValueError):
            lane.run("a013", [], repository)
        with self.assertRaises(ValueError):
            lane.run("a013", ["zig"], repository, slot_count=0)


if __name__ == "__main__":
    unittest.main()
