#!/usr/bin/env python3
"""Run high-memory Zig commands in bounded, cache-isolated compiler lanes.

Typed-AIR source work is intentionally parallel. Zig build processes must not
share a local cache, however, and unconstrained compiler fan-out makes edit
loops less predictable. This controller admits at most three commands at once
and gives every occupied slot its own repository-private local cache:

    python3 scripts/typed_air_zig_lane.py --label a013 -- zig build ...

The slot locks and caches live inside Git's private directory and never dirty
the worktree. A fourth invocation exits 75 immediately with every current
owner; it does not wait while consuming an agent/tool slot. The user-global Zig
cache remains shared, so independent lanes still reuse immutable artifacts.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Sequence


BUSY_EXIT = 75
DEFAULT_SLOT_COUNT = 3
SCHEMA = "stwo.typed-air.zig-compiler-lane.v2"
LEGACY_LOCK_NAME = "typed-air-zig-compiler.lock"
SLOT_LOCK_PREFIX = "typed-air-zig-compiler-slot-"
CACHE_DIRECTORY_NAME = "typed-air-zig-cache"


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


def _publish_owner(
    descriptor: int,
    label: str,
    command: Sequence[str],
    slot: int,
    cache_directory: Path,
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
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
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
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
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
    """Inject the slot-local cache into a possibly time-wrapped Zig build."""

    prepared = list(command)
    build_index: int | None = None
    for index in range(len(prepared) - 1):
        if Path(prepared[index]).name == "zig" and prepared[index + 1] == "build":
            build_index = index + 1
            break
    if build_index is None:
        return prepared

    # The controller owns local-cache isolation. Replace a caller-provided
    # cache rather than admitting two concurrent commands into the same path.
    filtered = prepared[: build_index + 1]
    index = build_index + 1
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
    filtered[build_index + 1 : build_index + 1] = [
        "--cache-dir",
        str(cache_directory),
    ]
    return filtered


def _active_owner(path: Path) -> dict[str, object] | None:
    """Return locked-owner metadata, ignoring unlocked stale contents."""

    if not path.exists():
        return None
    descriptor = os.open(path, os.O_RDWR)
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


def run(
    label: str,
    command: Sequence[str],
    repository: Path,
    *,
    slot_count: int = DEFAULT_SLOT_COUNT,
) -> int:
    if not label or len(label) > 80 or any(character.isspace() for character in label):
        raise ValueError("--label must be 1..80 non-whitespace characters")
    if not command:
        raise ValueError("a command is required after --")
    if slot_count < 1 or slot_count > 16:
        raise ValueError("slot_count must be in 1..16")

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
            _clear_owner(slot_descriptor)
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
            print(json.dumps(status(repository), indent=2, sort_keys=True))
            return 0
        return run(arguments.label, command, repository)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"typed-air Zig compiler lane: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
