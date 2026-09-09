#!/usr/bin/env python3
"""Run canonical protocol tests under the shared machine-wide build lock.

Usage: zig_protocol_test.py [--lock PATH | --no-lock] ROOT [zig-test-arguments...]

The default lock is /tmp/stwo-zig-build.lock, shared with zig_serial_build.py.
Use --no-lock only when an external caller already holds that lock. Wrapper
options precede ROOT; every argument after ROOT (including --) belongs to Zig.
Importing zig_protocol_lib.command.test_command never acquires a lock.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from zig_protocol_lib.command import test_command
from zig_serial_build import DEFAULT_LOCK, build_lock


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    lock_path = DEFAULT_LOCK
    while arguments and arguments[0] in ("--lock", "--no-lock"):
        option = arguments.pop(0)
        if option == "--no-lock":
            lock_path = None
        elif arguments:
            lock_path = arguments.pop(0)
        else:
            print("error: --lock requires a path", file=sys.stderr)
            return 2
    if not arguments or arguments[0] == "--":
        print(__doc__, file=sys.stderr)
        return 2
    root_source = arguments.pop(0)
    with build_lock(lock_path, label="zig_protocol_test"):
        return subprocess.run(test_command(root_source, *arguments), cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
