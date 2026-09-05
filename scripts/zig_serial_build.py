#!/usr/bin/env python3
"""Serialize heavy Zig builds so they cannot thrash the machine.

One `zig build` of a product in this repository analyses a large instantiated
graph: about nine minutes and several gigabytes resident, with peaks near 15 GB
for the wider test roots.  Two of those at once on a 64 GiB laptop drive the
machine into swap, and a nine-minute build then takes two and a half hours.
That is not hypothetical: it happened on 2026-09-04 with two concurrent agents.

This wrapper takes an exclusive, machine-wide file lock for the duration of the
build, so concurrent invocations queue instead of competing, and it passes a
memory ceiling to the build system.  Waiting is strictly faster than thrashing.

Usage mirrors `zig build`:

    python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \\
        check-stage101-degree5-provider-sweep-v1 -Doptimize=ReleaseFast

Options consumed by the wrapper:
    --cwd DIR         run the build from DIR (default: current directory)
    --maxrss BYTES    memory ceiling handed to `zig build` (default: 24 GiB)
    --lock PATH       lock file (default: /tmp/stwo-zig-build.lock)
    --no-lock         run immediately; use only for a build you know is small

Everything else is forwarded to `zig build` unchanged.  The exit status is the
build's own.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import time

DEFAULT_LOCK = "/tmp/stwo-zig-build.lock"
DEFAULT_MAXRSS = 24 * 1024 * 1024 * 1024


def parse(argv: list[str]) -> tuple[str, int, str | None, list[str]]:
    cwd = os.getcwd()
    maxrss = DEFAULT_MAXRSS
    lock: str | None = DEFAULT_LOCK
    forwarded: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--cwd":
            index += 1
            cwd = argv[index]
        elif argument == "--maxrss":
            index += 1
            maxrss = int(argv[index])
        elif argument == "--lock":
            index += 1
            lock = argv[index]
        elif argument == "--no-lock":
            lock = None
        else:
            forwarded.append(argument)
        index += 1
    return cwd, maxrss, lock, forwarded


def main() -> int:
    cwd, maxrss, lock_path, forwarded = parse(sys.argv[1:])
    if not forwarded:
        print(__doc__, file=sys.stderr)
        return 2
    command = ["zig", "build", *forwarded, "--maxrss", str(maxrss)]

    handle = None
    if lock_path is not None:
        handle = open(lock_path, "a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                f"[zig_serial_build] another build holds {lock_path}; waiting",
                file=sys.stderr,
                flush=True,
            )
            started = time.monotonic()
            fcntl.flock(handle, fcntl.LOCK_EX)
            waited = time.monotonic() - started
            print(
                f"[zig_serial_build] acquired after {waited:.0f}s",
                file=sys.stderr,
                flush=True,
            )
    try:
        return subprocess.call(command, cwd=cwd)
    finally:
        if handle is not None:
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
