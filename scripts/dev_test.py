#!/usr/bin/env python3
"""Run the narrowest package-owned tests for local worktree changes."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
OPTIMIZE_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.repo import ci_package_graph
from scripts.repo.ci_scope_plan import normalize_path, owns


FOCUSED_RULES = (
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig", "test-recursion-dag"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/publication.zig", "test-recursion-publication"),
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


def focus_step(package: str, path: str, root: Path = ROOT) -> str | None:
    if package == "stwo_riscv_cuda_integration":
        directory = "src/integrations/riscv_cuda/"
        resource_root = "rv64_resources_test_root.zig"
        imports = re.findall(r'@import\("([^"\n]+)"\)', (root / directory / resource_root).read_text())
        resources = {directory + name for name in imports}
        # Include only test files actually imported by an owned module;
        # guessing sibling names could silently omit a newly added test.
        for module in tuple(resources):
            text = (root / module).read_text()
            tests = re.findall(r'@import\("([^"\n]+_test\.zig)"\)', text)
            resources.update((Path(module).parent / name).as_posix() for name in tests)
        if path == directory + resource_root or path in resources:
            return "test-rv64-resources"
        node = {"outer_job.zig", "outer_encode_job.zig", "outer_result.zig"}
        runtime = {"api.zig", "api_test.zig", "worker.zig", "worker_test.zig",
                   "channel.zig", "slab.zig", "plan.zig", "plan_test.zig", "lint.zig",
                   "fake.zig", "retained.zig", "retained_test.zig", "driver.zig",
                   "driver_request.zig", "driver_dag.zig", "driver_memory.zig", "driver_test.zig"}
        prefix = "src/integrations/riscv_cuda/rv64/jobs/"
        if path.startswith(prefix) and path[len(prefix):] in node:
            return "test-rv64-jobs-node"
        if path.startswith(prefix) and path[len(prefix):] in runtime:
            return "test-rv64-jobs-runtime"
        # The roots own their direct source coverage. Derive routing from
        # those imports instead of maintaining a second native/truth/outer
        # file inventory; unknown files still take the package fallback.
        for filename, step in (
            ("rv64_native_gkr_codegen_test_root.zig", "test-native-gkr-codegen"),
            ("rv64_jobs_recursion_test_root.zig", "test-rv64-jobs-recursion"),
            ("rv64_jobs_native_test_root.zig", "test-rv64-jobs-native"),
            ("rv64_jobs_truth_test_root.zig", "test-rv64-jobs-truth"),
            ("rv64_jobs_outer_test_root.zig", "test-rv64-jobs-outer"),
        ):
            imports = re.findall(r'@import\("([^"\n]+)"\)', (root / directory / filename).read_text())
            if path == directory + filename or path in {directory + name for name in imports}:
                return step
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


def local_command(command: list[str], optimize: str = "ReleaseSafe") -> list[str]:
    localized: list[str] = []
    saw_optimize = False
    saw_jobs = False
    for argument in command:
        if argument.startswith("-Doptimize="):
            localized.append(f"-Doptimize={optimize}")
            saw_optimize = True
        elif argument.startswith("-j"):
            localized.append("-j1")
            saw_jobs = True
        else:
            localized.append(argument)
    if not saw_optimize:
        localized.append(f"-Doptimize={optimize}")
    if not saw_jobs:
        localized.append("-j1")
    return localized


def broad_command(root: Path, package: ci_package_graph.Package, optimize: str) -> list[str]:
    contract_path = root / package.directory / ci_package_graph.CONTRACT_NAME
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    command = payload.get("ci", {}).get("command")
    if not isinstance(command, list) or not all(
        isinstance(argument, str) and argument for argument in command
    ):
        raise DevTestError(f"package {package.name} has no valid CI command")
    return local_command(command, optimize)


def commands_for_paths(
    root: Path,
    raw_paths: Iterable[str],
    *,
    check_only: bool = False,
    optimize: str | None = None,
) -> list[list[str]]:
    if optimize is not None and optimize not in OPTIMIZE_MODES:
        raise DevTestError(f"unknown optimization mode: {optimize}")
    paths = sorted({normalize_path(path) for path in raw_paths})
    python_paths = [path for path in paths if path.startswith("scripts/") and path.endswith(".py")]
    commands: list[list[str]] = []
    if python_paths:
        if check_only:
            commands.append([sys.executable, "-m", "compileall", "-q", "scripts"])
        else:
            modules: set[str] = set()
            for path in python_paths:
                source = Path(path)
                test = source if source.parent.as_posix() == "scripts/tests" and source.name.startswith("test_") else Path("scripts/tests") / ("test_" + source.stem + ".py")
                if not (root / test).is_file():
                    commands.append([sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"])
                    break
                modules.add(test.with_suffix("").as_posix().replace("/", "."))
            else:
                commands.append([sys.executable, "-m", "unittest", *sorted(modules)])
        paths = [path for path in paths if path not in python_paths]
        if not paths:
            return commands
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

    for package_name, package_paths in sorted(selected.items()):
        package = packages[package_name]
        steps = {focus_step(package_name, path, root) for path in package_paths}
        if None in steps:
            commands.append(broad_command(root, package, optimize or "ReleaseSafe"))
            continue
        selected_steps = sorted(value for value in steps if value is not None)
        if selected_steps:
            command = [
                "zig",
                "build",
                *selected_steps,
                "--build-file",
                f"{package.directory}/build.zig",
                f"-Doptimize={optimize or 'Debug'}",
                "-j1",
            ]
            if check_only:
                command.extend(("-Dcheck-only=true", "-fincremental"))
            commands.append(command)
    return commands


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="changed paths; defaults to the worktree diff")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--optimize", choices=OPTIMIZE_MODES,
                        help="reproduce an explicit build mode, such as optimized CI")
    parser.add_argument(
        "--check",
        action="store_true",
        help="type-check focused roots without code generation or test execution",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="continuously type-check one focused package using Zig incremental compilation",
    )
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        paths = args.paths or worktree_paths(root)
        if not paths:
            print("dev test: no worktree changes")
            return 0
        commands = commands_for_paths(
            root,
            paths,
            check_only=args.check or args.watch,
            optimize=args.optimize,
        )
        if args.watch:
            if len(commands) != 1 or "-Dcheck-only=true" not in commands[0]:
                raise DevTestError("--watch requires one focused package")
            commands[0].append("--watch")
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
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
