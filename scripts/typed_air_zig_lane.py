#!/usr/bin/env python3
"""Run high-memory Zig gates in bounded, authority-bound compiler lanes.

Typed-AIR source work is intentionally parallel. Zig build processes must not
share a local cache concurrently, however, and unconstrained compiler fan-out
makes edit loops less predictable. This controller admits at most three
commands at once and gives each command or explicit cache group a stable,
repository-private local cache protected by a nonblocking group lock:

    python3 scripts/typed_air_zig_lane.py --label a013 -- zig build ...

The slot locks, retained logs, and exact GREEN receipts live inside Git's
private directory and never dirty the worktree. Reuse is development-only and
requires an exact source, argv, toolchain, environment, stage, and controller
identity. Evidence/performance/proof commands always execute.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import stat
import sys
import time
from typing import Sequence

try:
    from scripts import typed_air_zig_gate_cache as gate_cache
except ModuleNotFoundError:  # Direct execution outside the repository root.
    import typed_air_zig_gate_cache as gate_cache


BUSY_EXIT = 75
DEFAULT_SLOT_COUNT = 3
SCHEMA = "stwo.typed-air.zig-compiler-lane.v3"
LEGACY_LOCK_NAME = "typed-air-zig-compiler.lock"
SLOT_LOCK_PREFIX = "typed-air-zig-compiler-slot-"
CACHE_DIRECTORY_NAME = "typed-air-zig-cache"
CACHE_AWARE_ZIG_OPERATIONS = frozenset(
    ("build", "build-exe", "build-lib", "build-obj", "run", "test")
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one command in a bounded repository-private Zig compiler slot."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--label", help="short owner/gate name")
    mode.add_argument(
        "--status",
        action="store_true",
        help="print active slot metadata without launching a command",
    )
    parser.add_argument(
        "--stage",
        default="gate",
        help="stable narrow/broad stage name included in gate authority",
    )
    parser.add_argument(
        "--cache-group",
        help="share one locked local cache across related staged commands",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="execute even when an exact reusable GREEN receipt exists",
    )
    parser.add_argument(
        "--evidence",
        action="store_true",
        help="classify this as normative evidence and disable GREEN reuse",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        help="terminate the command process group after this many seconds",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=30.0,
        help="progress heartbeat interval while the child is active",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def _git_private_directory(repository: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-dir"],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("cannot resolve the repository-private compiler directory")
    return Path(result.stdout.strip())


def _read_owner(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 16 * 1024)
    if not raw:
        return "unknown owner"
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unreadable owner metadata"
    label = value.get("label", "unknown")
    pid = value.get("pid", "unknown")
    command = value.get("command", [])
    slot = value.get("slot", "legacy")
    return f"slot={slot!r} label={label!r} pid={pid!r} command={command!r}"


def _open_private_lock(path: Path) -> int:
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
        raise RuntimeError(f"compiler lock is not a regular file: {path}")
    return descriptor


def _publish_owner(
    descriptor: int,
    label: str,
    command: Sequence[str],
    slot: int,
    cache_directory: Path,
    *,
    stage: str = "gate",
    key: str | None = None,
) -> None:
    value = {
        "schema": SCHEMA,
        "slot": slot,
        "label": label,
        "pid": os.getpid(),
        "started_unix_ns": time.time_ns(),
        "cwd": str(Path.cwd()),
        "cache_directory": str(cache_directory),
        "command": list(command),
        "stage": stage,
        "gate_key": key,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.write(descriptor, encoded)
    os.fsync(descriptor)


def _clear_owner(descriptor: int) -> None:
    os.ftruncate(descriptor, 0)
    os.fsync(descriptor)


def _lock_legacy_guard(private_directory: Path) -> int | None:
    """Exclude a compiler launched by the former single-lane controller.

    The shared guard is inherited by the child. During migration, an old
    controller therefore cannot enter behind a killed V2 wrapper, and V2 will
    not enter while an already-running V1 child retains the exclusive lock.
    """

    path = private_directory / LEGACY_LOCK_NAME
    descriptor = _open_private_lock(path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        print(
            f"typed-air Zig compiler legacy lane busy: {_read_owner(descriptor)}",
            file=sys.stderr,
        )
        os.close(descriptor)
        return None
    return descriptor


def _acquire_slot(
    private_directory: Path, slot_count: int
) -> tuple[int, int, list[str]] | None:
    busy: list[str] = []
    for slot in range(slot_count):
        path = private_directory / f"{SLOT_LOCK_PREFIX}{slot}.lock"
        descriptor = _open_private_lock(path)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            busy.append(_read_owner(descriptor))
            os.close(descriptor)
            continue
        return slot, descriptor, busy
    print(
        "typed-air Zig compiler lanes busy: " + "; ".join(busy),
        file=sys.stderr,
    )
    return None


def _prepare_command(command: Sequence[str], cache_directory: Path) -> list[str]:
    """Inject the locked cache into a possibly wrapped Zig compile command."""

    prepared = list(command)
    zig_index = gate_cache.zig_command_index(prepared)
    operation_index = None if zig_index is None else zig_index + 1
    if (
        operation_index is not None
        and (
            operation_index >= len(prepared)
            or prepared[operation_index] not in CACHE_AWARE_ZIG_OPERATIONS
        )
    ):
        operation_index = None
    if operation_index is None:
        return prepared

    # The controller owns local-cache isolation. Replace a caller-provided
    # cache rather than admitting two concurrent commands into the same path.
    filtered = prepared[: operation_index + 1]
    index = operation_index + 1
    while index < len(prepared):
        argument = prepared[index]
        if argument == "--cache-dir":
            if index + 1 >= len(prepared):
                raise ValueError("--cache-dir requires a path")
            index += 2
            continue
        if argument.startswith("--cache-dir="):
            index += 1
            continue
        filtered.append(argument)
        index += 1
    filtered[operation_index + 1 : operation_index + 1] = [
        "--cache-dir",
        str(cache_directory),
    ]
    return filtered


def _ensure_private_cache_directory(private_directory: Path, affinity: str) -> Path:
    current = private_directory
    for name in (CACHE_DIRECTORY_NAME, "gates", affinity):
        current /= name
        current.mkdir(exist_ok=True)
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"compiler cache path is not a private directory: {current}")
    return current


def _active_owner(path: Path) -> dict[str, object] | None:
    """Return locked-owner metadata, ignoring unlocked stale contents."""

    if not path.exists():
        return None
    descriptor = _open_private_lock(path)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, 16 * 1024)
            # V2 children retain a shared lock on the now-empty legacy file as
            # a migration guard. That is not an occupied legacy compiler lane.
            if not raw:
                return None
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {"metadata": "unreadable"}
            return value if isinstance(value, dict) else {"metadata": "invalid"}
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return None
    finally:
        os.close(descriptor)


def status(repository: Path, *, slot_count: int = DEFAULT_SLOT_COUNT) -> dict[str, object]:
    if slot_count < 1 or slot_count > 16:
        raise ValueError("slot_count must be in 1..16")
    private_directory = _git_private_directory(repository)
    active: list[dict[str, object]] = []
    legacy = _active_owner(private_directory / LEGACY_LOCK_NAME)
    if legacy is not None:
        active.append({"kind": "legacy", "owner": legacy})
    for slot in range(slot_count):
        owner = _active_owner(
            private_directory / f"{SLOT_LOCK_PREFIX}{slot}.lock"
        )
        if owner is not None:
            active.append({"kind": "slot", "slot": slot, "owner": owner})
    occupied_slots = sum(item["kind"] == "slot" for item in active)
    return {
        "schema": "stwo.typed-air.zig-compiler-lane-status.v1",
        "capacity": slot_count,
        "occupied_slots": occupied_slots,
        "available_slots": slot_count - occupied_slots,
        "legacy_guard_active": legacy is not None,
        "active": active,
    }


def _validate_gate_name(option: str, value: str) -> None:
    if (
        not value
        or len(value) > 80
        or any(not (character.isalnum() or character in "._-") for character in value)
    ):
        raise ValueError(f"{option} must use 1..80 letters, digits, '.', '_', or '-'")


def _validate_gate_options(
    *,
    stage: str,
    cache_group: str | None,
    timeout_seconds: float | None,
    heartbeat_seconds: float,
) -> None:
    _validate_gate_name("--stage", stage)
    if cache_group is not None:
        _validate_gate_name("--cache-group", cache_group)
    if timeout_seconds is not None and (
        not math.isfinite(timeout_seconds) or timeout_seconds <= 0
    ):
        raise ValueError("--timeout-seconds must be a finite positive number")
    if not math.isfinite(heartbeat_seconds) or heartbeat_seconds <= 0:
        raise ValueError("--heartbeat-seconds must be a finite positive number")


def _append_controller_error(path: Path, message: str) -> None:
    with path.open("ab") as destination:
        destination.write((message + "\n").encode("utf-8", "replace"))


def _release_descriptor(descriptor: int, *, clear_owner: bool) -> None:
    try:
        if clear_owner:
            try:
                _clear_owner(descriptor)
            except OSError:
                # Lock state, not stale metadata, is authoritative.
                pass
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _run_development_gate(
    label: str,
    command: Sequence[str],
    repository: Path,
    *,
    slot_count: int,
    stage: str,
    cache_group: str | None,
    force: bool,
    evidence: bool,
    timeout_seconds: float | None,
    heartbeat_seconds: float,
) -> int:
    private_directory = _git_private_directory(repository)
    private_directory.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    controller_files = (
        Path(__file__),
        Path(gate_cache.__file__),
        Path(gate_cache.gate_execution.__file__),
    )
    authority = gate_cache.build_authority(
        repository,
        command,
        stage=stage,
        cache_group=cache_group,
        evidence=evidence,
        timeout_seconds=timeout_seconds,
        environment=environment,
        controller_files=controller_files,
    )
    store = gate_cache.GateStore(private_directory)
    owner = {
        "schema": SCHEMA,
        "label": label,
        "pid": os.getpid(),
        "key": authority.key,
        "stage": stage,
        "command": list(command),
    }
    key_lock = gate_cache.try_lock(store.key_lock_path(authority.key), owner)
    if key_lock is None:
        detail = gate_cache.read_lock_owner(store.key_lock_path(authority.key))
        print(f"typed-air Zig gate key busy: {detail}", file=sys.stderr)
        return BUSY_EXIT

    group_lock: gate_cache.HeldLock | None = None
    global_cache_lock: gate_cache.HeldLock | None = None
    heavy_lock: gate_cache.HeldLock | None = None
    legacy_descriptor: int | None = None
    slot_descriptor: int | None = None
    try:
        if not force:
            cached = store.read_green(authority)
            if cached is not None:
                try:
                    current = gate_cache.build_authority(
                        repository,
                        command,
                        stage=stage,
                        cache_group=cache_group,
                        evidence=evidence,
                        timeout_seconds=timeout_seconds,
                        environment=environment,
                        controller_files=controller_files,
                    )
                except (OSError, RuntimeError, ValueError) as error:
                    print(
                        "typed-air Zig gate cached authority recheck failed: "
                        f"{error}",
                        file=sys.stderr,
                    )
                    return gate_cache.AUTHORITY_CHANGED_EXIT
                if current.key != authority.key:
                    print(
                        "typed-air Zig gate authority changed before cached GREEN "
                        "admission; retry against the current checkout",
                        file=sys.stderr,
                    )
                    return gate_cache.AUTHORITY_CHANGED_EXIT
                receipt_path, receipt = cached
                stdout_log = store.root / receipt["logs"]["stdout"]["path"]
                stderr_log = store.root / receipt["logs"]["stderr"]["path"]
                print(
                    "typed-air Zig gate cached GREEN: "
                    f"key={authority.key} receipt={receipt_path} "
                    f"stdout={stdout_log} stderr={stderr_log}",
                    file=sys.stderr,
                )
                return 0

        if authority.heavy:
            heavy_path = store.heavy_lock_path()
            heavy_lock = gate_cache.try_lock(heavy_path, owner)
            if heavy_lock is None:
                detail = gate_cache.read_lock_owner(heavy_path)
                print(f"typed-air Zig heavy gate busy: {detail}", file=sys.stderr)
                return BUSY_EXIT

        if authority.global_cache_affinity is not None:
            global_cache_path = store.global_cache_lock_path(
                authority.global_cache_affinity
            )
            global_cache_lock = gate_cache.try_lock(global_cache_path, owner)
            if global_cache_lock is None:
                detail = gate_cache.read_lock_owner(global_cache_path)
                print(
                    f"typed-air Zig caller global cache busy: {detail}",
                    file=sys.stderr,
                )
                return BUSY_EXIT

        group_path = store.group_lock_path(authority.cache_affinity)
        group_lock = gate_cache.try_lock(group_path, owner)
        if group_lock is None:
            detail = gate_cache.read_lock_owner(group_path)
            print(f"typed-air Zig gate cache group busy: {detail}", file=sys.stderr)
            return BUSY_EXIT

        legacy_descriptor = _lock_legacy_guard(private_directory)
        if legacy_descriptor is None:
            return BUSY_EXIT
        acquired = _acquire_slot(private_directory, slot_count)
        if acquired is None:
            return BUSY_EXIT
        slot, slot_descriptor, _ = acquired
        try:
            current = gate_cache.build_authority(
                repository,
                command,
                stage=stage,
                cache_group=cache_group,
                evidence=evidence,
                timeout_seconds=timeout_seconds,
                environment=environment,
                controller_files=controller_files,
            )
        except (OSError, RuntimeError, ValueError) as error:
            print(
                f"typed-air Zig gate pre-spawn authority recheck failed: {error}",
                file=sys.stderr,
            )
            return gate_cache.AUTHORITY_CHANGED_EXIT
        if current.key != authority.key:
            print(
                "typed-air Zig gate authority changed before child launch; retry "
                "against the current checkout",
                file=sys.stderr,
            )
            return gate_cache.AUTHORITY_CHANGED_EXIT
        cache_directory = _ensure_private_cache_directory(
            private_directory, authority.cache_affinity
        )
        prepared = _prepare_command(command, cache_directory)
        _publish_owner(
            slot_descriptor,
            label,
            prepared,
            slot,
            cache_directory,
            stage=stage,
            key=authority.key,
        )
        run_id, stdout_path, stderr_path = store.create_logs(authority.cache_affinity)
        started_unix_ns = time.time_ns()
        transaction_started = time.monotonic_ns()
        print(
            "typed-air Zig gate start: "
            f"label={label!r} stage={stage!r} key={authority.key} "
            f"reusable={authority.reusable} heavy={authority.heavy} "
            f"policy={authority.policy_reason!r} "
            f"cache={cache_directory}",
            file=sys.stderr,
            flush=True,
        )
        if force:
            # All execution locks are now held. Removing the retained GREEN
            # immediately before launch prevents a failed forced rerun from
            # leaving contradictory success evidence, without invalidating on
            # a no-wait admission failure.
            store.invalidate_green(authority.key)
        inherited_descriptors = (
            legacy_descriptor,
            slot_descriptor,
            key_lock.descriptor,
            group_lock.descriptor,
            None if global_cache_lock is None else global_cache_lock.descriptor,
            None if heavy_lock is None else heavy_lock.descriptor,
        )
        try:
            result = gate_cache.execute_with_logs(
                prepared,
                repository=repository,
                pass_fds=tuple(
                    descriptor
                    for descriptor in inherited_descriptors
                    if descriptor is not None
                ),
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                label=label,
                stage=stage,
                key=authority.key,
                heartbeat_seconds=heartbeat_seconds,
                timeout_seconds=authority.timeout_seconds,
                environment=environment,
            )
        except OSError as error:
            message = f"typed-air Zig gate launch failed: {error}"
            _append_controller_error(stderr_path, message)
            print(message, file=sys.stderr)
            result = gate_cache.ExecutionResult(
                exit_code=127,
                elapsed_ns=time.monotonic_ns() - transaction_started,
                timed_out=False,
            )

        authority_drift = False
        exit_code = result.exit_code
        if exit_code == 0:
            try:
                current = gate_cache.build_authority(
                    repository,
                    command,
                    stage=stage,
                    cache_group=cache_group,
                    evidence=evidence,
                    timeout_seconds=timeout_seconds,
                    environment=environment,
                    controller_files=controller_files,
                )
                authority_drift = current.key != authority.key
            except (OSError, RuntimeError, ValueError) as error:
                authority_drift = True
                drift_detail = f": authority recheck failed: {error}"
            else:
                drift_detail = ""
            if authority_drift:
                exit_code = gate_cache.AUTHORITY_CHANGED_EXIT
                message = (
                    "typed-air Zig gate authority changed during execution; "
                    f"GREEN publication denied{drift_detail}"
                )
                _append_controller_error(stderr_path, message)
                print(message, file=sys.stderr)

        run_path, receipt = store.publish(
            authority,
            label=label,
            stage=stage,
            run_id=run_id,
            started_unix_ns=started_unix_ns,
            elapsed_ns=time.monotonic_ns() - transaction_started,
            exit_code=exit_code,
            timed_out=result.timed_out,
            cache_directory=cache_directory,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            authority_drift=authority_drift,
        )
        print(
            "typed-air Zig gate result: "
            f"status={receipt['status']} key={authority.key} receipt={run_path} "
            f"stdout={stdout_path} stderr={stderr_path}",
            file=sys.stderr,
            flush=True,
        )
        return exit_code
    finally:
        if slot_descriptor is not None:
            _release_descriptor(slot_descriptor, clear_owner=True)
        if legacy_descriptor is not None:
            _release_descriptor(legacy_descriptor, clear_owner=False)
        if group_lock is not None:
            group_lock.release()
        if global_cache_lock is not None:
            global_cache_lock.release()
        if heavy_lock is not None:
            heavy_lock.release()
        key_lock.release()


def run(
    label: str,
    command: Sequence[str],
    repository: Path,
    *,
    slot_count: int = DEFAULT_SLOT_COUNT,
    development_gate: bool = False,
    stage: str = "gate",
    cache_group: str | None = None,
    force: bool = False,
    evidence: bool = False,
    timeout_seconds: float | None = None,
    heartbeat_seconds: float = 30.0,
) -> int:
    if not label or len(label) > 80 or any(character.isspace() for character in label):
        raise ValueError("--label must be 1..80 non-whitespace characters")
    if not command:
        raise ValueError("a command is required after --")
    if slot_count < 1 or slot_count > 16:
        raise ValueError("slot_count must be in 1..16")
    _validate_gate_options(
        stage=stage,
        cache_group=cache_group,
        timeout_seconds=timeout_seconds,
        heartbeat_seconds=heartbeat_seconds,
    )

    if development_gate:
        return _run_development_gate(
            label,
            command,
            repository,
            slot_count=slot_count,
            stage=stage,
            cache_group=cache_group,
            force=force,
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            heartbeat_seconds=heartbeat_seconds,
        )

    private_directory = _git_private_directory(repository)
    private_directory.mkdir(parents=True, exist_ok=True)
    legacy_descriptor = _lock_legacy_guard(private_directory)
    if legacy_descriptor is None:
        return BUSY_EXIT

    slot_descriptor: int | None = None
    try:
        acquired = _acquire_slot(private_directory, slot_count)
        if acquired is None:
            return BUSY_EXIT
        slot, slot_descriptor, _ = acquired
        cache_directory = private_directory / CACHE_DIRECTORY_NAME / f"slot-{slot}"
        cache_directory.mkdir(parents=True, exist_ok=True)
        prepared = _prepare_command(command, cache_directory)
        _publish_owner(slot_descriptor, label, prepared, slot, cache_directory)
        try:
            # Both descriptors are inherited. If this controller is killed,
            # wrappers such as /usr/bin/time and the compiler retain their slot
            # until the complete process lifetime ends.
            completed = subprocess.run(
                prepared,
                cwd=repository,
                check=False,
                pass_fds=(legacy_descriptor, slot_descriptor),
            )
            return completed.returncode
        finally:
            try:
                _clear_owner(slot_descriptor)
            finally:
                fcntl.flock(slot_descriptor, fcntl.LOCK_UN)
    finally:
        if slot_descriptor is not None:
            os.close(slot_descriptor)
        fcntl.flock(legacy_descriptor, fcntl.LOCK_UN)
        os.close(legacy_descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    command = list(arguments.command)
    if command and command[0] == "--":
        command.pop(0)
    repository = Path(__file__).resolve().parents[1]
    try:
        if arguments.status:
            if command:
                raise ValueError("--status does not accept a command")
            if (
                arguments.stage != "gate"
                or arguments.cache_group is not None
                or arguments.force
                or arguments.evidence
                or arguments.timeout_seconds is not None
                or arguments.heartbeat_seconds != 30.0
            ):
                raise ValueError("gate execution options do not apply to --status")
            print(json.dumps(status(repository), indent=2, sort_keys=True))
            return 0
        return run(
            arguments.label,
            command,
            repository,
            development_gate=True,
            stage=arguments.stage,
            cache_group=arguments.cache_group,
            force=arguments.force,
            evidence=arguments.evidence,
            timeout_seconds=arguments.timeout_seconds,
            heartbeat_seconds=arguments.heartbeat_seconds,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"typed-air Zig compiler lane: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
