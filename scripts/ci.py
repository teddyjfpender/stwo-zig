#!/usr/bin/env python3
"""Run the repository CI entrypoint used locally and by hosted automation."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Advisory wall-clock budget for the fast tier. Exceeding it warns rather
# than fails (machines vary); the enforced guarantee is structural — the
# fast plan may never contain a compilation-class command (see FAST_PLAN
# tests). Investigate any step that pushes the total past this line.
FAST_BUDGET_SECONDS = 60.0

SCRIPT_TESTS = [
    sys.executable,
    "-m",
    "unittest",
    "discover",
    "-s",
    "scripts/tests",
    "-p",
    "test_*.py",
]

# The fast tier: static, interpretation-only checks that reject a broken
# tree in seconds. No `zig build` step is permitted here — compilation
# belongs to the standard and strict tiers.
FAST_PLAN: list[list[str]] = [
    ["zig", "fmt", "--check", "build.zig", "build_support", "src", "tools"],
    [sys.executable, "scripts/check_upstream_pins.py"],
    [sys.executable, "scripts/check_source_conformance.py"],
]


def command_plan(strict: bool, optimize: str) -> list[list[str]]:
    gate = "release-gate-strict" if strict else "release-gate"
    return [
        SCRIPT_TESTS,
        ["zig", "build", gate, f"-Doptimize={optimize}"],
    ]


def run_plan(plan: list[list[str]]) -> int:
    started = time.monotonic()
    for command in plan:
        step_started = time.monotonic()
        print(f"+ {shlex.join(command)}", flush=True)
        try:
            completed = subprocess.run(command, cwd=ROOT, check=False)
        except OSError as error:
            print(f"unable to run {command[0]}: {error}", file=sys.stderr)
            return 127
        print(f"  ({time.monotonic() - step_started:.1f}s)", flush=True)
        if completed.returncode != 0:
            return completed.returncode
    elapsed = time.monotonic() - started
    print(f"gate: PASS in {elapsed:.1f}s")
    if plan is FAST_PLAN and elapsed > FAST_BUDGET_SECONDS:
        print(
            f"warning: fast tier took {elapsed:.1f}s, over the "
            f"{FAST_BUDGET_SECONDS:.0f}s budget — find and demote the slow step",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    tier = parser.add_mutually_exclusive_group()
    tier.add_argument("--strict", action="store_true", help="run the strict release gate")
    tier.add_argument(
        "--fast",
        action="store_true",
        help="static checks only; no compilation (seconds, not minutes)",
    )
    parser.add_argument(
        "--optimize",
        choices=("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall"),
        default="ReleaseFast",
    )
    args = parser.parse_args(argv)

    plan = FAST_PLAN if args.fast else command_plan(args.strict, args.optimize)
    return run_plan(plan)


if __name__ == "__main__":
    raise SystemExit(main())
