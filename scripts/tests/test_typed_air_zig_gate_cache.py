from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import typed_air_zig_gate_cache as cache
from scripts import typed_air_zig_gate_execution as execution
from scripts import typed_air_zig_lane as lane


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class FakeZigRepository:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        _git(self.root, "init")
        _git(self.root, "config", "user.email", "gate@example.invalid")
        _git(self.root, "config", "user.name", "Gate Test")
        (self.root / "source.txt").write_text("initial\n")
        tool = self.root / "tool" / "zig"
        tool.parent.mkdir()
        tool.write_text(
            """#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
if len(sys.argv) > 1 and sys.argv[1] == "version":
    print("0.14.1-test")
    raise SystemExit(0)
counter = root / ".git" / "fake-zig-count"
count = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(count))
print(f"fake-zig-run={count}")
if "test-mutate" in sys.argv:
    with (root / "source.txt").open("a") as source:
        source.write("mutated\\n")
raise SystemExit(0)
"""
        )
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        self.zig = tool
        _git(self.root, "add", "source.txt", "tool/zig")
        _git(self.root, "commit", "-m", "fixture")

    def close(self) -> None:
        self.temporary.cleanup()

    @property
    def count(self) -> int:
        path = self.root / ".git" / "fake-zig-count"
        return int(path.read_text()) if path.exists() else 0

    def command(self, target: str = "test-unit") -> list[str]:
        return [str(self.zig), "build", target, "--summary", "all"]


class ReusePolicyTests(unittest.TestCase):
    def test_development_target_and_cache_paths_are_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            reusable, _ = cache.reuse_policy(
                repository,
                [
                    "zig",
                    "build",
                    "test-runner",
                    "--global-cache-dir",
                    "/tmp/zig-global-cache",
                    "--summary",
                    "all",
                ],
                evidence=False,
            )
        self.assertTrue(reusable)

    def test_only_direct_or_approved_time_wrapped_zig_grammar_is_reusable(self) -> None:
        repository = Path.cwd()
        wrapped, _ = cache.reuse_policy(
            repository,
            ["/usr/bin/time", "-l", "zig", "build", "test-unit"],
            evidence=False,
        )
        arbitrary, _ = cache.reuse_policy(
            repository,
            [sys.executable, "arbitrary.py", "zig", "test", "unit.zig"],
            evidence=False,
        )
        self.assertTrue(wrapped)
        self.assertFalse(arbitrary)

    def test_normative_targets_and_outputs_are_never_reusable(self) -> None:
        repository = Path.cwd()
        commands = (
            ["zig", "build", "test-proof"],
            ["zig", "build", "run-recursive-proof"],
            ["zig", "run", "tool.zig"],
            ["zig", "test", "proof_capture_test.zig"],
            ["zig", "build", "test-unit", "--report-out=/tmp/report.json"],
        )
        for command in commands:
            with self.subTest(command=command):
                reusable, _ = cache.reuse_policy(
                    repository, command, evidence=False
                )
                self.assertFalse(reusable)
        reusable, _ = cache.reuse_policy(
            repository, ["zig", "build", "test-unit"], evidence=True
        )
        self.assertFalse(reusable)

    def test_embedded_and_separate_external_semantic_paths_deny_reuse(self) -> None:
        repository = Path.cwd()
        for argument in (
            "-Dmetal-core-aot-bundle=/tmp/external.bundle",
            "--system=/tmp/external-sdk",
        ):
            reusable, reason = cache.reuse_policy(
                repository,
                ["zig", "build", "test-unit", argument],
                evidence=False,
            )
            self.assertFalse(reusable)
            self.assertIn("external", reason)
        reusable, _ = cache.reuse_policy(
            repository,
            ["zig", "build", "test-unit", "--system", "/tmp/external-sdk"],
            evidence=False,
        )
        self.assertFalse(reusable)

    def test_heavy_classification_serializes_only_expensive_work(self) -> None:
        self.assertFalse(
            cache.requires_heavy_lock(
                ["zig", "build", "test-runner"], evidence=False
            )
        )
        self.assertTrue(
            cache.requires_heavy_lock(["zig", "build"], evidence=False)
        )
        self.assertTrue(
            cache.requires_heavy_lock(
                ["zig", "build", "install-riscv-cpu"], evidence=False
            )
        )
        self.assertTrue(
            cache.requires_heavy_lock(
                ["zig", "build", "test-proof"], evidence=False
            )
        )


class AuthorityTests(unittest.TestCase):
    def _authority(
        self,
        command: list[str],
        *,
        environment: dict[str, str],
        stage: str = "narrow",
        cache_group: str | None = "family",
        evidence: bool = False,
    ) -> cache.GateAuthority:
        with (
            mock.patch.object(cache, "source_authority", return_value={"tree": "a"}),
            mock.patch.object(
                cache,
                "toolchain_authority",
                return_value={"zig": {"sha256": "b"}},
            ),
        ):
            return cache.build_authority(
                Path.cwd(),
                command,
                stage=stage,
                cache_group=cache_group,
                evidence=evidence,
                environment=environment,
            )

    def test_key_and_cache_affinity_bind_the_correct_authorities(self) -> None:
        first = self._authority(
            ["zig", "build", "test-a"], environment={"PATH": "one"}
        )
        other_command = self._authority(
            ["zig", "build", "test-b"], environment={"PATH": "one"}
        )
        other_stage = self._authority(
            ["zig", "build", "test-a"],
            environment={"PATH": "one"},
            stage="broad",
        )
        other_environment = self._authority(
            ["zig", "build", "test-a"], environment={"PATH": "two"}
        )
        self.assertNotEqual(first.key, other_command.key)
        self.assertNotEqual(first.key, other_stage.key)
        self.assertNotEqual(first.key, other_environment.key)
        self.assertEqual(first.cache_affinity, other_command.cache_affinity)
        self.assertNotEqual(first.cache_affinity, other_environment.cache_affinity)

    def test_host_identity_changes_key_and_cache_affinity(self) -> None:
        with mock.patch.object(
            cache,
            "host_authority",
            return_value={
                "system": "HostA",
                "machine": "arm64",
                "kernel_release": "1",
                "macos_version": "15",
            },
        ):
            first = self._authority(
                ["zig", "build", "test-a"], environment={"PATH": "one"}
            )
        with mock.patch.object(
            cache,
            "host_authority",
            return_value={
                "system": "HostB",
                "machine": "x86_64",
                "kernel_release": "2",
                "macos_version": "",
            },
        ):
            second = self._authority(
                ["zig", "build", "test-a"], environment={"PATH": "one"}
            )
        self.assertNotEqual(first.key, second.key)
        self.assertNotEqual(first.cache_affinity, second.cache_affinity)

    def test_default_timeout_is_finite_only_for_reusable_development_gates(self) -> None:
        reusable = self._authority(
            ["zig", "build", "test-unit"], environment={"PATH": "one"}
        )
        evidence = self._authority(
            ["zig", "build", "test-unit"],
            environment={"PATH": "one"},
            evidence=True,
        )
        self.assertEqual(cache.DEFAULT_REUSABLE_TIMEOUT_SECONDS, reusable.timeout_seconds)
        self.assertIsNone(evidence.timeout_seconds)

    def test_caller_global_cache_lock_affinity_is_path_bound(self) -> None:
        first = self._authority(
            [
                "zig",
                "build",
                "test-a",
                "--global-cache-dir=/tmp/shared-zig-global",
            ],
            environment={"PATH": "one"},
        )
        second = self._authority(
            [
                "zig",
                "build",
                "test-b",
                "--global-cache-dir",
                "/tmp/shared-zig-global",
            ],
            environment={"PATH": "one"},
        )
        other = self._authority(
            [
                "zig",
                "build",
                "test-b",
                "--global-cache-dir=/tmp/other-zig-global",
            ],
            environment={"PATH": "one"},
        )
        self.assertEqual(first.global_cache_affinity, second.global_cache_affinity)
        self.assertNotEqual(first.global_cache_affinity, other.global_cache_affinity)

    def test_unhashed_external_semantic_environment_disables_reuse(self) -> None:
        authority = self._authority(
            ["zig", "build", "test-unit"],
            environment={
                "PATH": "one",
                "STWO_METAL_CORE_AOT_BUNDLE": "/tmp/external.metallib",
            },
        )
        self.assertFalse(authority.reusable)
        self.assertIn("environment", authority.policy_reason)

    def test_source_authority_binds_tracked_staged_and_untracked_content(self) -> None:
        fixture = FakeZigRepository()
        try:
            baseline = cache.source_authority(fixture.root)
            (fixture.root / "source.txt").write_text("unstaged\n")
            unstaged = cache.source_authority(fixture.root)
            self.assertNotEqual(
                baseline["tracked_diff_sha256"], unstaged["tracked_diff_sha256"]
            )
            _git(fixture.root, "add", "source.txt")
            staged = cache.source_authority(fixture.root)
            self.assertNotEqual(
                baseline["tracked_diff_sha256"], staged["tracked_diff_sha256"]
            )
            (fixture.root / "new.txt").write_text("untracked\n")
            untracked = cache.source_authority(fixture.root)
            self.assertEqual(1, untracked["untracked_files"])
            self.assertNotEqual(
                staged["untracked_manifest_sha256"],
                untracked["untracked_manifest_sha256"],
            )
        finally:
            fixture.close()

    def test_untracked_symlink_marks_checkout_closure_nonreusable(self) -> None:
        fixture = FakeZigRepository()
        try:
            (fixture.root / "external-link").symlink_to("/tmp/external-source")
            source = cache.source_authority(fixture.root)
            self.assertFalse(source["closure_complete"])
            self.assertEqual(1, source["untracked_symlinks"])
        finally:
            fixture.close()


def _authority_fixture(key: str = "a" * 64) -> cache.GateAuthority:
    return cache.GateAuthority(
        key=key,
        cache_affinity="b" * 64,
        reusable=True,
        policy_reason="test",
        heavy=False,
        global_cache_affinity=None,
        timeout_seconds=1200.0,
        payload={"schema": cache.AUTHORITY_SCHEMA, "fixture": True},
    )


class StoreAndExecutionTests(unittest.TestCase):
    def _publish_green(
        self, store: cache.GateStore, authority: cache.GateAuthority
    ) -> tuple[Path, Path, Path]:
        run_id, stdout, stderr = store.create_logs(authority.cache_affinity)
        stdout.write_text("stdout\n")
        stderr.write_text("stderr\n")
        path, _ = store.publish(
            authority,
            label="unit",
            stage="narrow",
            run_id=run_id,
            started_unix_ns=1,
            elapsed_ns=2,
            exit_code=0,
            timed_out=False,
            cache_directory=store.root / "cache",
            stdout_path=stdout,
            stderr_path=stderr,
        )
        return path, stdout, stderr

    def test_green_receipt_requires_unchanged_retained_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = cache.GateStore(Path(directory))
            authority = _authority_fixture()
            _, stdout, _ = self._publish_green(store, authority)
            self.assertIsNotNone(store.read_green(authority))
            stdout.write_text("tampered\n")
            self.assertIsNone(store.read_green(authority))

    def test_symlinked_log_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = cache.GateStore(root / "private")
            authority = _authority_fixture()
            _, stdout, stderr = self._publish_green(store, authority)
            log_directory = stdout.parent
            outside = root / "outside"
            outside.mkdir()
            shutil.copy2(stdout, outside / stdout.name)
            shutil.copy2(stderr, outside / stderr.name)
            shutil.rmtree(log_directory)
            log_directory.symlink_to(outside, target_is_directory=True)
            self.assertIsNone(store.read_green(authority))

    def test_non_green_result_invalidates_earlier_green(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = cache.GateStore(Path(directory))
            authority = _authority_fixture()
            self._publish_green(store, authority)
            run_id, stdout, stderr = store.create_logs(authority.cache_affinity)
            store.publish(
                authority,
                label="forced",
                stage="narrow",
                run_id=run_id,
                started_unix_ns=3,
                elapsed_ns=4,
                exit_code=1,
                timed_out=False,
                cache_directory=store.root / "cache",
                stdout_path=stdout,
                stderr_path=stderr,
            )
            self.assertFalse(store.green_path(authority.key).exists())

    def test_nonblocking_lock_has_exact_owner_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            first = cache.try_lock(path, {"label": "first"})
            self.assertIsNotNone(first)
            self.assertIsNone(cache.try_lock(path, {"label": "second"}))
            first.release()
            second = cache.try_lock(path, {"label": "second"})
            self.assertIsNotNone(second)
            second.release()

    def test_lock_file_and_parent_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            outside = root / "outside.lock"
            outside.write_text("outside")
            (real_parent / "linked.lock").symlink_to(outside)
            with self.assertRaises(OSError):
                cache.try_lock(real_parent / "linked.lock", {"label": "unsafe"})

            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(OSError):
                cache.try_lock(linked_parent / "new.lock", {"label": "unsafe"})

    def test_process_output_is_retained_and_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            captured_out = io.StringIO()
            captured_err = io.StringIO()
            with (
                contextlib.redirect_stdout(captured_out),
                contextlib.redirect_stderr(captured_err),
            ):
                result = execution.execute_with_logs(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('out'); print('err', file=sys.stderr)",
                    ],
                    repository=root,
                    pass_fds=(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    label="output",
                    stage="narrow",
                    key="c" * 64,
                    heartbeat_seconds=1.0,
                    timeout_seconds=2.0,
                )
            self.assertEqual(0, result.exit_code)
            self.assertEqual("out\n", stdout.read_text())
            self.assertEqual("err\n", stderr.read_text())
            self.assertEqual("out\n", captured_out.getvalue())
            self.assertEqual("err\n", captured_err.getvalue())

    def test_large_output_replays_once_in_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            byte_count = execution.REPLAY_CHUNK_BYTES * 2 + 17
            captured = io.StringIO()
            with (
                contextlib.redirect_stdout(captured),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = execution.execute_with_logs(
                    [
                        sys.executable,
                        "-c",
                        f"import sys; sys.stdout.write('x' * {byte_count})",
                    ],
                    repository=root,
                    pass_fds=(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    label="large-output",
                    stage="narrow",
                    key="e" * 64,
                    heartbeat_seconds=1.0,
                    timeout_seconds=2.0,
                )
            self.assertEqual(0, result.exit_code)
            self.assertEqual(byte_count, stdout.stat().st_size)
            self.assertEqual("x" * byte_count, captured.getvalue())

    def test_timeout_terminates_process_group_and_keeps_heartbeats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            captured = io.StringIO()
            program = (
                "import signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); time.sleep(30)"
            )
            with (
                mock.patch.object(execution, "TERMINATE_GRACE_SECONDS", 0.2),
                contextlib.redirect_stderr(captured),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = execution.execute_with_logs(
                    [sys.executable, "-c", program],
                    repository=root,
                    pass_fds=(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    label="timeout",
                    stage="broad",
                    key="d" * 64,
                    heartbeat_seconds=0.03,
                    timeout_seconds=0.1,
                )
            self.assertEqual(cache.TIMEOUT_EXIT, result.exit_code)
            self.assertTrue(result.timed_out)
            self.assertIn("phase=timeout-term", captured.getvalue())
            self.assertIn("phase=terminating", captured.getvalue())
            self.assertIn("phase=timeout-kill", captured.getvalue())

    def test_timeout_kills_grandchild_after_wrapper_exits_on_term(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            sentinel = root / "descendant.lock"
            ready = root / "ready"
            program = f"""
import fcntl, os, signal, time
from pathlib import Path
child = os.fork()
if child == 0:
    descriptor = os.open({str(sentinel)!r}, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    Path({str(ready)!r}).write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
else:
    while not Path({str(ready)!r}).exists():
        time.sleep(0.01)
    time.sleep(30)
"""
            captured = io.StringIO()
            with (
                mock.patch.object(execution, "TERMINATE_GRACE_SECONDS", 0.2),
                mock.patch.object(execution, "PROCESS_GROUP_DRAIN_SECONDS", 0.2),
                contextlib.redirect_stderr(captured),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = execution.execute_with_logs(
                    [sys.executable, "-c", program],
                    repository=root,
                    pass_fds=(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    label="descendant-timeout",
                    stage="broad",
                    key="f" * 64,
                    heartbeat_seconds=0.03,
                    timeout_seconds=0.15,
                )
            self.assertEqual(cache.TIMEOUT_EXIT, result.exit_code)
            self.assertIn("phase=timeout-kill", captured.getvalue())
            descriptor = os.open(sentinel, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)


class LaneIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = FakeZigRepository()

    def tearDown(self) -> None:
        self.fixture.close()

    def _run(
        self,
        label: str,
        command: list[str],
        **options: object,
    ) -> tuple[int, str]:
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            result = lane.run(
                label,
                command,
                self.fixture.root,
                development_gate=True,
                heartbeat_seconds=0.1,
                **options,
            )
        return result, stderr.getvalue()

    def _authority(
        self, command: list[str], *, cache_group: str | None = None
    ) -> cache.GateAuthority:
        return cache.build_authority(
            self.fixture.root,
            command,
            stage="gate",
            cache_group=cache_group,
            evidence=False,
            environment=dict(os.environ),
            controller_files=(
                Path(lane.__file__),
                Path(cache.__file__),
                Path(execution.__file__),
            ),
        )

    def test_exact_green_reuses_across_labels_and_prints_receipt_key(self) -> None:
        command = self.fixture.command()
        first, _ = self._run("first", command)
        second, stderr = self._run("second", command)
        self.assertEqual(0, first)
        self.assertEqual(0, second)
        self.assertEqual(1, self.fixture.count)
        self.assertIn("cached GREEN", stderr)
        self.assertIn("receipt=", stderr)
        self.assertIn("key=", stderr)

    def test_source_mutation_during_reusable_and_evidence_run_is_drift(self) -> None:
        reusable, stderr = self._run("mutate", self.fixture.command("test-mutate"))
        self.assertEqual(cache.AUTHORITY_CHANGED_EXIT, reusable)
        self.assertIn("authority changed", stderr)
        (self.fixture.root / "source.txt").write_text("initial\n")
        evidence, stderr = self._run(
            "evidence-mutate",
            self.fixture.command("test-mutate"),
            evidence=True,
        )
        self.assertEqual(cache.AUTHORITY_CHANGED_EXIT, evidence)
        self.assertIn("authority changed", stderr)

    def test_cached_green_is_rechecked_against_current_source(self) -> None:
        command = self.fixture.command()
        first, _ = self._run("first", command)
        self.assertEqual(0, first)
        original = cache.GateStore.read_green

        def mutate_after_read(
            store: cache.GateStore, authority: cache.GateAuthority
        ) -> tuple[Path, dict[str, object]] | None:
            result = original(store, authority)
            (self.fixture.root / "source.txt").write_text("changed\n")
            return result

        with mock.patch.object(cache.GateStore, "read_green", mutate_after_read):
            result, stderr = self._run("second", command)
        self.assertEqual(cache.AUTHORITY_CHANGED_EXIT, result)
        self.assertIn("changed before cached GREEN", stderr)
        self.assertEqual(1, self.fixture.count)

    def test_source_drift_after_lock_admission_stops_before_spawn(self) -> None:
        command = self.fixture.command()
        original = lane._acquire_slot

        def mutate_after_slot(
            private_directory: Path, slot_count: int
        ) -> tuple[int, int, list[str]] | None:
            result = original(private_directory, slot_count)
            (self.fixture.root / "source.txt").write_text("changed-before-spawn\n")
            return result

        with mock.patch.object(lane, "_acquire_slot", mutate_after_slot):
            result, stderr = self._run("pre-spawn-drift", command)
        self.assertEqual(cache.AUTHORITY_CHANGED_EXIT, result)
        self.assertIn("changed before child launch", stderr)
        self.assertEqual(0, self.fixture.count)

    def test_force_busy_preserves_green_and_forced_red_invalidates_it(self) -> None:
        command = self.fixture.command()
        first, _ = self._run("first", command)
        self.assertEqual(0, first)
        authority = self._authority(command)
        store = cache.GateStore(self.fixture.root / ".git")
        held = cache.try_lock(store.group_lock_path(authority.cache_affinity), {"label": "held"})
        self.assertIsNotNone(held)
        try:
            busy, _ = self._run("forced-busy", command, force=True)
        finally:
            held.release()
        self.assertEqual(lane.BUSY_EXIT, busy)
        self.assertTrue(store.green_path(authority.key).exists())

        def fail_execution(*args: object, **kwargs: object) -> cache.ExecutionResult:
            Path(kwargs["stdout_path"]).write_text("")
            Path(kwargs["stderr_path"]).write_text("forced failure\n")
            return cache.ExecutionResult(9, 1, False)

        with mock.patch.object(cache, "execute_with_logs", side_effect=fail_execution):
            failed, _ = self._run("forced-red", command, force=True)
        self.assertEqual(9, failed)
        self.assertFalse(store.green_path(authority.key).exists())
        rerun, _ = self._run("after-red", command)
        self.assertEqual(0, rerun)
        self.assertEqual(2, self.fixture.count)

    def test_key_cache_group_and_heavy_locks_fail_fast_independently(self) -> None:
        command = self.fixture.command()
        authority = self._authority(command, cache_group="shared")
        store = cache.GateStore(self.fixture.root / ".git")
        key = cache.try_lock(store.key_lock_path(authority.key), {"label": "key"})
        self.assertIsNotNone(key)
        try:
            result, _ = self._run("key-busy", command, cache_group="shared")
        finally:
            key.release()
        self.assertEqual(lane.BUSY_EXIT, result)

        group = cache.try_lock(
            store.group_lock_path(authority.cache_affinity), {"label": "group"}
        )
        self.assertIsNotNone(group)
        try:
            result, _ = self._run(
                "group-busy", self.fixture.command("test-other"), cache_group="shared"
            )
        finally:
            group.release()
        self.assertEqual(lane.BUSY_EXIT, result)

        heavy = cache.try_lock(store.heavy_lock_path(), {"label": "heavy"})
        self.assertIsNotNone(heavy)
        try:
            heavy_result, _ = self._run("product", [str(self.fixture.zig), "build"])
            normal_result, _ = self._run("normal", command)
        finally:
            heavy.release()
        self.assertEqual(lane.BUSY_EXIT, heavy_result)
        self.assertEqual(0, normal_result)

    def test_caller_global_cache_lock_conflicts_across_distinct_commands(self) -> None:
        shared = self.fixture.root / ".git" / "caller-global"
        first_command = [
            *self.fixture.command("test-a"),
            "--global-cache-dir",
            str(shared),
        ]
        second_command = [
            *self.fixture.command("test-b"),
            "--global-cache-dir",
            str(shared),
        ]
        authority = self._authority(first_command)
        self.assertIsNotNone(authority.global_cache_affinity)
        store = cache.GateStore(self.fixture.root / ".git")
        held = cache.try_lock(
            store.global_cache_lock_path(authority.global_cache_affinity),
            {"label": "global-cache"},
        )
        self.assertIsNotNone(held)
        try:
            result, stderr = self._run("global-cache-busy", second_command)
        finally:
            held.release()
        self.assertEqual(lane.BUSY_EXIT, result)
        self.assertIn("caller global cache busy", stderr)

    def test_direct_cli_status_works_from_outside_repository(self) -> None:
        script = Path(lane.__file__).resolve()
        result = subprocess.run(
            [sys.executable, str(script), "--status"],
            cwd=Path(tempfile.gettempdir()),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "stwo.typed-air.zig-compiler-lane-status.v1",
            json.loads(result.stdout)["schema"],
        )


if __name__ == "__main__":
    unittest.main()
