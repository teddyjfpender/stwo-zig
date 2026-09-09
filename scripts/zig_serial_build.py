#!/usr/bin/env python3
"""Serialize heavy Zig builds so they cannot thrash the machine.

One `zig build` of a product in this repository analyses a large instantiated
graph: about nine minutes and several gigabytes resident, with peaks near 15 GB
for the wider test roots.  Two of those at once on a 64 GiB laptop drive the
machine into swap, and a nine-minute build then takes two and a half hours.
That is not hypothetical: it happened on 2026-09-04 with two concurrent agents.

This wrapper takes an exclusive, machine-wide file lock for the duration of the
build, so concurrent invocations queue instead of competing, and it passes a
scheduling budget through focused sub-builds. Zig applies this budget to declared
step RSS estimates; it is not an operating-system memory limit. Builds default
to one job at each level. Explicit `-jN` opts into concurrent work.

Usage mirrors `zig build`:

    python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \\
        check-stage101-degree5-provider-sweep-v1 -Doptimize=ReleaseFast

Options consumed by the wrapper:
    --cwd DIR         run the build from DIR (default: current directory)
    --maxrss BYTES    scheduler budget (default: 2/3 of host RAM, capped at 24 GiB)
    -jN              jobs per build level (default: 1)
    --lock PATH       lock file (default: /tmp/stwo-zig-build.lock)
    --no-lock         caller already owns the lock; do not lock it again

Everything else is forwarded to `zig build` unchanged.  The exit status is the
build's own. While holding the lock, STWO_ZIG_BUILD_HELD_LOCK carries its
path to known nested build gates so they can pass --no-lock explicitly. This
marker coordinates scheduling; it is not a security authority. --no-lock
clears any inherited marker before launching Zig.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import subprocess
import sys
import time

DEFAULT_LOCK = "/tmp/stwo-zig-build.lock"
# Scheduling coordination for known nested build steps, never proof/security authority.
HELD_LOCK_ENV = "STWO_ZIG_BUILD_HELD_LOCK"
MAX_DEFAULT_RSS = 24 * 1024 * 1024 * 1024


def default_maxrss() -> int:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            return min(MAX_DEFAULT_RSS, pages * page_size * 2 // 3)
    except (OSError, ValueError):
        pass
    return 8 * 1024 * 1024 * 1024


def positive(value: str, option: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f"{option} requires a positive integer") from None
    if not 0 < number <= maximum:
        raise ValueError(f"{option} must be between 1 and {maximum}")
    return number


def parse(argv: list[str]) -> tuple[str, int, int, str | None, list[str]]:
    cwd = os.getcwd()
    maxrss = default_maxrss()
    jobs = 1
    lock: str | None = DEFAULT_LOCK
    forwarded: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            forwarded.extend(argv[index:])
            break
        if argument in ("--cwd", "--maxrss", "--lock", "-j"):
            index += 1
            if index == len(argv):
                raise ValueError(f"{argument} requires a value")
            value = argv[index]
            if argument == "--cwd":
                cwd = value
            elif argument == "--maxrss":
                maxrss = positive(value, argument, (1 << 64) - 1)
            elif argument == "-j":
                jobs = positive(value, argument, (1 << 32) - 1)
            else:
                lock = value
        elif argument.startswith("-j"):
            jobs = positive(argument[2:], "-j", (1 << 32) - 1)
        elif argument == "--no-lock":
            lock = None
        else:
            forwarded.append(argument)
        index += 1
    return cwd, maxrss, jobs, lock, forwarded


@contextmanager
def build_lock(lock_path: str | None = DEFAULT_LOCK, *, label: str = "zig_serial_build"):
    """Hold the shared build/test lock, releasing it even if launching fails."""
    if lock_path is None:
        yield
        return
    with open(lock_path, "a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"[{label}] another build holds {lock_path}; waiting", file=sys.stderr, flush=True)
            started = time.monotonic()
            fcntl.flock(handle, fcntl.LOCK_EX)
            print(f"[{label}] acquired after {time.monotonic() - started:.0f}s", file=sys.stderr, flush=True)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def main() -> int:
    try:
        cwd, maxrss, jobs, lock_path, forwarded = parse(sys.argv[1:])
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if not forwarded:
        print(__doc__, file=sys.stderr)
        return 2
    command = ["zig", "build", "--maxrss", str(maxrss), f"-j{jobs}", *forwarded]
    environment = dict(os.environ)
    environment["STWO_ZIG_BUILD_MAXRSS"] = str(maxrss)
    environment["STWO_ZIG_BUILD_JOBS"] = str(jobs)

    # A --no-lock invocation must not advertise ownership inherited from an
    # unrelated launcher. Known nested gates opt out explicitly only when
    # this invocation has actually acquired its lock.
    environment.pop(HELD_LOCK_ENV, None)
    with build_lock(lock_path):
        if lock_path is not None:
            environment[HELD_LOCK_ENV] = lock_path
        return subprocess.call(command, cwd=cwd, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())
