"""Focused CPU proof-source runner using the canonical package argument graph.

Only this CLI acquires the shared lock. Command construction never starts Zig
or takes a lock, and a custom runner uses this selected compiler's std runner.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

H = Path(__file__).resolve().parent
R = H.parents[2]
sys.path.insert(0, str(R / "scripts"))
from zig_protocol_lib.command import test_command
from zig_serial_build import build_lock

z = "/opt/homebrew/opt/zig@0.15/bin/zig"


def command(argv: list[str] | None = None) -> list[str]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="src/frontends/riscv/sha256_memory_proof_test_root.zig")
    parser.add_argument("--test-runner", help="explicit policy runner; delegates to the selected compiler standard runner")
    parser.add_argument("--all", action="store_true", help="run every test in the selected root")
    parser.add_argument("--package", action="append", default=[], help="additional canonical package and its transitive dependencies")
    parser.add_argument("--optimize", choices=["Debug", "ReleaseSafe", "ReleaseFast"], default="ReleaseFast", help="use Debug for actionable focused failure traces")
    parser.add_argument("filters", nargs="*")
    args = parser.parse_args(argv)
    filters = [] if args.all else args.filters or ["SHA canonical memory call", "SHA provider"]
    zig_args = ["-O" + args.optimize, "-lc", "-mcpu=native"]
    if args.test_runner:
        zig_args.extend(("--test-runner", args.test_runner))
    zig_args.extend(arg for filter_text in filters for arg in ("--test-filter", filter_text))
    try:
        return test_command(args.root, *zig_args, cpu_only=True, extra_packages=tuple(args.package), zig=z)
    except ValueError as error:
        parser.error(str(error))


def main(argv: list[str] | None = None) -> int:
    arguments = command(argv)
    with build_lock(label="ethereum-auth-build"):
        subprocess.run(arguments, check=True, cwd=R)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
