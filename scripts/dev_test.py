#!/usr/bin/env python3
"""Run the narrowest package-owned tests for local worktree changes."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import ci_package_graph
from scripts.ci_scope_plan import normalize_path, owns


FOCUSED_RULES = (
    ("stwo_core", "src/core/fields", "test-fields"),
    ("stwo_core", "src/core/fields_test_root.zig", "test-fields"),
    ("stwo_core", "src/core/crypto", "test-crypto"),
    ("stwo_core", "src/core/crypto_test_root.zig", "test-crypto"),
    ("stwo_core", "src/core/fri", "test-fri"),
    ("stwo_core", "src/core/fri_test_root.zig", "test-fri"),
    ("stwo_core", "src/core/pcs", "test-pcs"),
    ("stwo_core", "src/core/pcs_test_root.zig", "test-pcs"),
    ("stwo_prover_engine", "src/prover/air", "test-air"),
    ("stwo_prover_engine", "src/prover/air_test_root.zig", "test-air"),
    ("stwo_prover_engine", "src/prover/poly", "test-poly"),
    ("stwo_prover_engine", "src/prover/poly_test_root.zig", "test-poly"),
    ("stwo_prover_engine", "src/prover/pcs", "test-pcs-commitments"),
    (
        "stwo_prover_engine",
        "src/prover/pcs_commitments_test_root.zig",
        "test-pcs-commitments",
    ),
    ("stwo_riscv_frontend", "src/frontends/riscv/isa", "test-isa"),
    ("stwo_riscv_frontend", "src/frontends/riscv/isa_test_root.zig", "test-isa"),
    ("stwo_riscv_frontend", "src/frontends/riscv/runner", "test-runner"),
    ("stwo_riscv_frontend", "src/frontends/riscv/runner_test_root.zig", "test-runner"),
    (
        "stwo_riscv_frontend",
        "src/frontends/riscv/air/semantics",
        "test-air-semantics",
    ),
    (
        "stwo_riscv_frontend",
        "src/frontends/riscv/air_semantics_test_root.zig",
        "test-air-semantics",
    ),
    ("stwo_sm83_frontend", "src/frontends/sm83/isa", "test-isa"),
    ("stwo_sm83_frontend", "src/frontends/sm83/runner", "test-runner"),
    (
        "stwo_sm83_frontend",
        "src/frontends/sm83/runner_test_root.zig",
        "test-runner",
    ),
)

PROVER_QUOTIENT_STEPS = {
    "src/prover/pcs/quotient_column_geometry.zig": "test-pcs-quotient-geometry",
    "src/prover/pcs/quotient_domain_walk.zig": "test-pcs-quotient-geometry",
    "src/prover/pcs_quotient_geometry_test_root.zig": "test-pcs-quotient-geometry",
    "src/prover/pcs/quotient_compact_groups.zig": "test-pcs-quotient-planning",
    "src/prover/pcs/quotient_direct_groups.zig": "test-pcs-quotient-planning",
    "src/prover/pcs/quotient_direct_plan.zig": "test-pcs-quotient-planning",
    "src/prover/pcs/quotients/planning.zig": "test-pcs-quotient-planning",
    "src/prover/pcs_quotient_planning_test_root.zig": "test-pcs-quotient-planning",
    "src/prover/pcs/quotient_ops.zig": "test-pcs-quotient-ops",
    "src/prover/pcs_quotient_ops_test_root.zig": "test-pcs-quotient-ops",
    "src/prover/pcs/quotient_row_executor.zig": "test-pcs-quotient-rows",
    "src/prover/pcs/quotient_scalar_executor.zig": "test-pcs-quotient-rows",
    "src/prover/pcs/quotients/execution.zig": "test-pcs-quotient-rows",
    "src/prover/pcs/quotients/lazy_provider.zig": "test-pcs-quotient-rows",
    "src/prover/pcs_quotient_rows_test_root.zig": "test-pcs-quotient-rows",
    "src/prover/pcs/quotient_tile_executor.zig": "test-pcs-quotient-tiles",
    "src/prover/pcs/quotient_tile_sink.zig": "test-pcs-quotient-tiles",
    "src/prover/pcs_quotient_tiles_test_root.zig": "test-pcs-quotient-tiles",
}


class DevTestError(ValueError):
    pass


def worktree_paths(root: Path) -> list[str]:
    tracked = subprocess.run(
        ["git", "diff", "--name-only", "-z", "HEAD", "--"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted({
        normalize_path(raw.decode("utf-8", errors="strict"))
        for raw in (tracked + untracked).split(b"\0")
        if raw
    })


def focus_step(package: str, path: str) -> str | None:
    if package == "stwo_prover_engine" and path in PROVER_QUOTIENT_STEPS:
        return PROVER_QUOTIENT_STEPS[path]
    if package == "stwo_prover_engine" and (
        path.startswith("src/prover/pcs/quotient")
        or path.startswith("src/prover/pcs_quotient")
    ):
        return None
    for owner, prefix, step in FOCUSED_RULES:
        if owner == package and owns(path, prefix):
            return step
    return None


def local_command(command: list[str]) -> list[str]:
    localized: list[str] = []
    saw_optimize = False
    saw_jobs = False
    for argument in command:
        if argument.startswith("-Doptimize="):
            localized.append("-Doptimize=ReleaseSafe")
            saw_optimize = True
        elif argument.startswith("-j"):
            localized.append("-j1")
            saw_jobs = True
        else:
            localized.append(argument)
    if not saw_optimize:
        localized.append("-Doptimize=ReleaseSafe")
    if not saw_jobs:
        localized.append("-j1")
    return localized


def broad_command(root: Path, package: ci_package_graph.Package) -> list[str]:
    contract_path = root / package.directory / ci_package_graph.CONTRACT_NAME
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    command = payload.get("ci", {}).get("command")
    if not isinstance(command, list) or not all(
        isinstance(argument, str) and argument for argument in command
    ):
        raise DevTestError(f"package {package.name} has no valid CI command")
    return local_command(command)


def commands_for_paths(root: Path, raw_paths: Iterable[str]) -> list[list[str]]:
    paths = sorted({normalize_path(path) for path in raw_paths})
    packages = ci_package_graph.load_packages(root)
    selected: dict[str, list[str]] = {}
    unowned: list[str] = []
    for path in paths:
        package = ci_package_graph.owning_package(path, packages)
        if package is None:
            unowned.append(path)
        else:
            selected.setdefault(package, []).append(path)
    if unowned:
        raise DevTestError(
            "no Zig package owns changed path(s): " + ", ".join(unowned)
        )

    commands: list[list[str]] = []
    for package_name, package_paths in sorted(selected.items()):
        package = packages[package_name]
        steps = {focus_step(package_name, path) for path in package_paths}
        if None in steps:
            commands.append(broad_command(root, package))
            continue
        for step in sorted(value for value in steps if value is not None):
            commands.append([
                "zig",
                "build",
                step,
                "--build-file",
                f"{package.directory}/build.zig",
                "-Doptimize=ReleaseSafe",
                "-j1",
            ])
    return commands


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="changed paths; defaults to the worktree diff")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        paths = args.paths or worktree_paths(root)
        if not paths:
            print("dev test: no worktree changes")
            return 0
        commands = commands_for_paths(root, paths)
        for command in commands:
            print(f"+ {shlex.join(command)}", flush=True)
            if args.dry_run:
                continue
            result = subprocess.run(command, cwd=root, check=False)
            if result.returncode != 0:
                return result.returncode
        verb = "PLAN" if args.dry_run else "PASS"
        print(f"dev test: {verb} ({len(commands)} focused command(s))")
        return 0
    except (
        DevTestError,
        ci_package_graph.GraphError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"dev test: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
