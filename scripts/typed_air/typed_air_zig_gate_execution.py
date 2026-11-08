#!/usr/bin/env python3
"""Retained-output process execution for typed-AIR Zig development gates."""

from __future__ import annotations

import codecs
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import stat
import time
from dataclasses import dataclass
from typing import Mapping, Sequence


TIMEOUT_EXIT = 124
TERMINATE_GRACE_SECONDS = 5.0
PROCESS_GROUP_DRAIN_SECONDS = 1.0
REPLAY_CHUNK_BYTES = 64 * 1024
_TIME_OPTIONS_WITH_VALUES = frozenset(("--format", "--output", "-f", "-o"))
_SEMANTIC_ENVIRONMENT_TERMS = (
    "BUNDLE",
    "ELF",
    "INPUT",
    "PROFILE",
    "SDK",
    "SOURCE",
    "SYSTEM",
    "TOOLCHAIN",
)
_EXTERNAL_TOOL_ENVIRONMENT_NAMES = frozenset(
    (
        "AR",
        "CARGO_HOME",
        "CC",
        "CFLAGS",
        "CPATH",
        "CPPFLAGS",
        "CXX",
        "DEVELOPER_DIR",
        "LD",
        "LDFLAGS",
        "LIBRARY_PATH",
        "PKG_CONFIG_PATH",
        "RANLIB",
        "RUSTC",
        "RUSTUP_HOME",
        "SDKROOT",
    )
)


def zig_command_index(command: Sequence[str]) -> int | None:
    if not command:
        return None
    if Path(command[0]).name == "zig":
        return 0
    if Path(command[0]).resolve() != Path("/usr/bin/time").resolve():
        return None
    index = 1
    while index < len(command):
        argument = command[index]
        if argument == "--":
            index += 1
            break
        if argument in _TIME_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        break
    if index < len(command) and Path(command[index]).name == "zig":
        return index
    return None


def caller_global_cache_affinity(
    repository: Path,
    command: Sequence[str],
    environment: Mapping[str, str],
) -> str | None:
    selected: str | None = None
    index = 0
    while index < len(command):
        argument = command[index]
        if argument == "--global-cache-dir":
            if index + 1 >= len(command):
                raise ValueError("--global-cache-dir requires a path")
            selected = command[index + 1]
            index += 2
            continue
        if argument.startswith("--global-cache-dir="):
            selected = argument.split("=", 1)[1]
        index += 1
    if selected is None:
        selected = environment.get("ZIG_GLOBAL_CACHE_DIR")
    if selected is None:
        return None
    if not selected:
        raise ValueError("caller-provided Zig global cache path is empty")
    candidate = Path(selected)
    path = candidate if candidate.is_absolute() else repository / candidate
    identity = {
        "schema": "stwo.typed-air.caller-zig-global-cache-lock.v1",
        "resolved_path": str(path.resolve()),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def semantic_external_environment(
    repository: Path, environment: Mapping[str, str]
) -> list[str]:
    root = repository.resolve()
    found: list[str] = []
    for name, value in sorted(environment.items()):
        upper_name = name.upper()
        if "CACHE" in upper_name or not (
            upper_name.startswith("STWO_")
            or upper_name in _EXTERNAL_TOOL_ENVIRONMENT_NAMES
            or any(term in upper_name for term in _SEMANTIC_ENVIRONMENT_TERMS)
        ):
            continue
        candidates = value.split(os.pathsep)
        try:
            tokens = shlex.split(value)
        except ValueError:
            tokens = [value]
        for token in tokens:
            if token.startswith(("-I", "-L")):
                candidates.append(token[2:])
            elif token.startswith("--sysroot="):
                candidates.append(token.split("=", 1)[1])
            elif token.startswith("-Wl,"):
                candidates.extend(token.split(","))
            else:
                candidates.append(token)
        for candidate_value in candidates:
            if "/" not in candidate_value and os.sep not in candidate_value:
                continue
            candidate = Path(candidate_value)
            path = candidate if candidate.is_absolute() else repository / candidate
            resolved = path.resolve()
            if resolved != root and root not in resolved.parents:
                found.append(name)
                break
    return found


@dataclass
class HeldLock:
    descriptor: int
    path: Path

    def release(self) -> None:
        try:
            try:
                os.ftruncate(self.descriptor, 0)
                os.fsync(self.descriptor)
            except OSError:
                # Unlocked stale metadata is ignored by every reader.
                pass
        finally:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                try:
                    os.close(self.descriptor)
                except OSError:
                    pass


def try_lock(path: Path, owner: Mapping[str, object]) -> HeldLock | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_NOFOLLOW", 0)
    parent = os.open(path.parent, parent_flags)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise RuntimeError(f"gate lock is not a regular file: {path}")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    raw = json.dumps(dict(owner), sort_keys=True, separators=(",", ":")).encode()
    os.ftruncate(descriptor, 0)
    os.write(descriptor, raw + b"\n")
    os.fsync(descriptor)
    return HeldLock(descriptor, path)


def read_lock_owner(path: Path) -> str:
    try:
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            return "invalid owner metadata"
        return (
            f"label={value.get('label')!r} pid={value.get('pid')!r} "
            f"key={value.get('key')!r}"
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "unreadable owner metadata"


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    elapsed_ns: int
    timed_out: bool


def _replay(path: Path, stream: object) -> None:
    buffer = getattr(stream, "buffer", None)
    decoder = None if buffer is not None else codecs.getincrementaldecoder("utf-8")("replace")
    with path.open("rb") as source:
        while chunk := source.read(REPLAY_CHUNK_BYTES):
            if buffer is not None:
                buffer.write(chunk)
            else:
                stream.write(decoder.decode(chunk))
    if buffer is not None:
        buffer.flush()
    else:
        stream.write(decoder.decode(b"", final=True))
        stream.flush()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def execute_with_logs(
    command: Sequence[str],
    *,
    repository: Path,
    pass_fds: Sequence[int],
    stdout_path: Path,
    stderr_path: Path,
    label: str,
    stage: str,
    key: str,
    heartbeat_seconds: float,
    timeout_seconds: float | None,
    environment: Mapping[str, str] | None = None,
) -> ExecutionResult:
    started = time.monotonic_ns()
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
    next_heartbeat = time.monotonic() + heartbeat_seconds
    timed_out = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            list(command),
            cwd=repository,
            env=None if environment is None else dict(environment),
            stdout=stdout,
            stderr=stderr,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
        )

        def heartbeat(phase: str) -> None:
            elapsed = (time.monotonic_ns() - started) / 1_000_000_000
            print(
                "typed-air Zig gate heartbeat: "
                f"label={label!r} stage={stage!r} key={key} phase={phase} "
                f"elapsed={elapsed:.1f}s stdout_bytes={stdout.tell()} "
                f"stderr_bytes={stderr.tell()}",
                file=sys.stderr,
                flush=True,
            )

        while process.poll() is None:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                timed_out = True
                process_group = process.pid
                heartbeat("timeout-term")
                try:
                    os.killpg(process_group, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                termination_deadline = now + TERMINATE_GRACE_SECONDS
                while (
                    _process_group_exists(process_group)
                    and time.monotonic() < termination_deadline
                ):
                    now = time.monotonic()
                    if now >= next_heartbeat:
                        heartbeat("terminating")
                        next_heartbeat = now + heartbeat_seconds
                    wait_for = min(
                        0.25,
                        max(0.01, termination_deadline - now),
                        max(0.01, next_heartbeat - now),
                    )
                    if process.poll() is None:
                        try:
                            process.wait(timeout=wait_for)
                        except subprocess.TimeoutExpired:
                            pass
                    else:
                        time.sleep(wait_for)
                if _process_group_exists(process_group):
                    heartbeat("timeout-kill")
                    try:
                        os.killpg(process_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.wait()
                drain_deadline = time.monotonic() + PROCESS_GROUP_DRAIN_SECONDS
                while (
                    _process_group_exists(process_group)
                    and time.monotonic() < drain_deadline
                ):
                    time.sleep(0.01)
                break
            if now >= next_heartbeat:
                heartbeat("running")
                next_heartbeat = now + heartbeat_seconds
            wait_for = min(0.25, max(0.01, next_heartbeat - now))
            if deadline is not None:
                wait_for = min(wait_for, max(0.01, deadline - now))
            try:
                process.wait(timeout=wait_for)
            except subprocess.TimeoutExpired:
                pass
        exit_code = TIMEOUT_EXIT if timed_out else process.returncode
    elapsed_ns = time.monotonic_ns() - started
    _replay(stdout_path, sys.stdout)
    _replay(stderr_path, sys.stderr)
    return ExecutionResult(exit_code, elapsed_ns, timed_out)
