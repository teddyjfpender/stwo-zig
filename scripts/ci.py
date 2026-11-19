#!/usr/bin/env python3
"""Run the repository CI entrypoint used locally and by hosted automation."""

from __future__ import annotations

import argparse
import json
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

TOOLCHAIN_PLAN = [[sys.executable, "-m", "unittest", "scripts.tests.test_toolchain_pins"]]

# The fast tier: static, interpretation-only checks that reject a broken
# tree in seconds. No `zig build` step is permitted here — compilation
# belongs to the standard and strict tiers.
FAST_PLAN: list[list[str]] = [
    *TOOLCHAIN_PLAN,
    ["zig", "fmt", "--check", "build.zig", "build_support", "src", "tools"],
    [sys.executable, "scripts/repo/check_package_workspace.py"],
    [sys.executable, "scripts/repo/check_upstream_pins.py"],
    [sys.executable, "scripts/repo/check_source_conformance.py"],
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


def partition_script_contracts(suite, deferred_ids):
    import unittest

    def cases(group):
        for member in group:
            if isinstance(member, unittest.TestSuite):
                yield from cases(member)
            else:
                yield member

    expected = set(deferred_ids)
    if len(expected) != len(deferred_ids):
        raise ValueError("formal deferral must match each named case exactly once")
    ordinary, deferred = [], []
    for case in cases(suite):
        (deferred if case.id() in expected else ordinary).append(case)
    if sorted(case.id() for case in deferred) != sorted(deferred_ids):
        raise ValueError("formal deferral must match each named case exactly once")
    return unittest.TestSuite(ordinary), unittest.TestSuite(deferred)


def script_contract_status(ordinary_ok, formal_ok, today, expiry):
    return int(not ordinary_ok or (not formal_ok and today >= expiry))


def run_focused_script_contracts():
    from datetime import date, datetime, timezone
    import unittest

    policy = json.loads((ROOT / "conformance/formal-script-deferral.json").read_text())
    if policy["schema"] != "stwo-formal-script-deferral-v1":
        raise ValueError("unsupported formal deferral policy")
    expiry = date.fromisoformat(policy["expires"])
    today = datetime.now(timezone.utc).date()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    discovered = unittest.defaultTestLoader.discover(str(ROOT / "scripts/tests"), pattern="test_*.py")
    ordinary, deferred = partition_script_contracts(discovered, policy["case_ids"])
    print(f"Ordinary script contracts: {ordinary.countTestCases()} cases", flush=True)
    ordinary_result = unittest.TextTestRunner().run(ordinary)
    authority = "ADVISORY" if today < expiry else "REQUIRED"
    print(
        f"Formal evidence: {deferred.countTestCases()} cases, {authority}, "
        f"owner {policy['owner']}, issue #{policy['issue']}, expires {expiry} UTC",
        flush=True,
    )
    formal_result = unittest.TextTestRunner().run(deferred)
    return script_contract_status(ordinary_result.wasSuccessful(), formal_result.wasSuccessful(), today, expiry)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    tier = parser.add_mutually_exclusive_group()
    tier.add_argument("--strict", action="store_true", help="run the strict release gate")
    tier.add_argument(
        "--focused-script-contracts", action="store_true",
        help="run all Python checks and report the time-bounded formal evidence separately",
    )
    tier.add_argument(
        "--fast",
        action="store_true",
        help="static checks only; no compilation (seconds, not minutes)",
    )
    tier.add_argument(
        "--check-toolchains", action="store_true",
        help="check declared toolchain versions without compiling or installing",
    )
    tier.add_argument(
        "--installed-toolchains", choices=("cpu", "oracles", "formal"),
        help="execute pinned installed tools for this host profile; never install implicitly",
    )
    parser.add_argument(
        "--optimize",
        choices=("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall"),
        default="ReleaseFast",
    )
    args = parser.parse_args(argv)

    if args.focused_script_contracts:
        return run_focused_script_contracts()

    if args.installed_toolchains:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from scripts.repo.installed_toolchains import inspect
        report = inspect(ROOT, args.installed_toolchains)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "PASS" else 1

    plan = TOOLCHAIN_PLAN if args.check_toolchains else (
        FAST_PLAN if args.fast else command_plan(args.strict, args.optimize)
    )
    return run_plan(plan)


if __name__ == "__main__":
    raise SystemExit(main())
