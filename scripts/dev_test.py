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

from scripts.repo import ci_package_graph, ci_scope_plan, ci_scope_push
from scripts.repo.ci_scope_plan import normalize_path, owns


FOCUSED_RULES = (
    ("stwo_riscv_frontend", "src/frontends/riscv/air/guest_precompile/tests/relation_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/segment_range_authority_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/division_product_integration_test.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/optional_division_test.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/metadata_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_worker_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/claim_relation_test_support.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/measurement_test_support.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/dispatch_test_support.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_inputs_test_support.zig", "test-services-truth-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/retained_authority_contract_test_root.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/division_contract_test_root.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/services_truth_contract_test_root.zig", "test-services-truth-contracts"),

    ("stwo_riscv_frontend", "src/frontends/riscv/test_inventory_test.zig", "test-inventory"),
    ("stwo_riscv_frontend", "src/frontends/riscv/test_inventory.zig", "test-inventory"),
    ("stwo_riscv_cuda_integration", "src/integrations/riscv_cuda/rv64/jobs/gpu_native_classes.zig", "test-rv64-class-cache"),
    ("stwo_riscv_cuda_integration", "src/integrations/riscv_cuda/rv64/jobs/gpu_native_protocol.zig", "test-rv64-class-cache"),
    ('stwo_riscv_metal_integration', 'src/integrations/riscv_metal/native_polynomial_aot_export.zig', 'test-native-polynomial-aot'),
    ('stwo_riscv_metal_integration', 'src/integrations/riscv_metal/native_polynomial_aot_test_root.zig', 'test-native-polynomial-aot'),
    ('stwo_metal_backend', 'src/backends/metal/composition_pool_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/external_allocation_admission_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/fri_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/fri_inverse_lease_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/quotient_allocation_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/quotient_result_ownership_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/resident_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/sampled_budget_test_root.zig', 'test-resource-contracts'),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig", "test-recursion-dag"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/publication.zig", "test-recursion-publication"),
    ("stwo_core", "src/waist/core/fields", "test-fields"),
    ("stwo_core", "src/waist/core/fields_test_root.zig", "test-fields"),
    ("stwo_core", "src/waist/core/crypto", "test-crypto"),
    ("stwo_core", "src/waist/core/crypto_test_root.zig", "test-crypto"),
    ("stwo_core", "src/waist/core/fri", "test-fri"),
    ("stwo_core", "src/waist/core/fri_test_root.zig", "test-fri"),
    ("stwo_core", "src/waist/core/pcs", "test-pcs"),
    ("stwo_core", "src/waist/core/pcs_test_root.zig", "test-pcs"),
    ("stwo_prover_engine", "src/engine/prover/air", "test-air"),
    ("stwo_prover_engine", "src/engine/prover/air_test_root.zig", "test-air"),
    ("stwo_prover_engine", "src/engine/prover/poly", "test-poly"),
    ("stwo_prover_engine", "src/engine/prover/poly_test_root.zig", "test-poly"),
    ("stwo_prover_engine", "src/engine/prover/pcs", "test-pcs-commitments"),
    (
        "stwo_prover_engine",
        "src/engine/prover/pcs_commitments_test_root.zig",
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
    "src/engine/prover/pcs/quotient_column_geometry.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs/quotient_domain_walk.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs_quotient_geometry_test_root.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs/quotient_compact_groups.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_direct_groups.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_direct_plan.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotients/planning.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs_quotient_planning_test_root.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_ops.zig": "test-pcs-quotient-ops",
    "src/engine/prover/pcs_quotient_ops_test_root.zig": "test-pcs-quotient-ops",
    "src/engine/prover/pcs/quotient_row_executor.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotient_scalar_executor.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotients/execution.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotients/lazy_provider.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs_quotient_rows_test_root.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotient_tile_executor.zig": "test-pcs-quotient-tiles",
    "src/engine/prover/pcs/quotient_tile_sink.zig": "test-pcs-quotient-tiles",
    "src/engine/prover/pcs_quotient_tiles_test_root.zig": "test-pcs-quotient-tiles",
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
    if package == "stwo_metal_backend":
        for owner, filename, step in FOCUSED_RULES:
            if owner == package:
                source = root / filename
                imports = re.findall(r'@import\("([^"\n]+)"\)', source.read_text())
                if path == filename or path in {(source.parent / name).relative_to(root).as_posix() for name in imports if name.endswith(".zig")}:
                    return step
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
                   "driver_request.zig", "driver_install.zig", "driver_dag.zig", "driver_memory.zig", "driver_test.zig",
                   "driver_fixture_test.zig", "driver_service_test.zig"}
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
        path.startswith("src/engine/prover/pcs/quotient")
        or path.startswith("src/engine/prover/pcs_quotient")
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


def tracked_deletions(root: Path) -> set[str]:
    return set(subprocess.check_output(["git", "diff", "--diff-filter=D", "--name-only", "HEAD", "--"], cwd=root, text=True).splitlines()) if (root / ".git").exists() else set()


def commands_for_paths(
    root: Path,
    raw_paths: Iterable[str],
    *,
    check_only: bool = False,
    optimize: str | None = None,
    deferred: list[str] | None = None,
) -> list[list[str]]:
    if optimize is not None and optimize not in OPTIMIZE_MODES:
        raise DevTestError(f"unknown optimization mode: {optimize}")
    paths = sorted({normalize_path(path) for path in raw_paths})
    python_paths = [path for path in paths if path.startswith("scripts/") and path.endswith(".py")]
    commands: list[list[str]] = []
    deleted: set[str] | None = None
    missing = {path for path in paths if not (root / path).exists()}
    if missing:
        deleted = tracked_deletions(root)
        if unknown := missing - deleted:
            raise DevTestError("path does not exist and is not a tracked deletion: " + ", ".join(sorted(unknown)))
    if python_paths:
        if check_only:
            commands.append([sys.executable, "-m", "compileall", "-q", "scripts"])
        else:
            modules: set[str] = set()
            for path in python_paths:
                source = Path(path)
                test = source if source.parent.as_posix() == "scripts/tests" and source.name.startswith("test_") else Path("scripts/tests") / ("test_" + source.stem + ".py")
                if not (root / source).is_file() or not (root / test).is_file():
                    commands.append([sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"])
                    break
                modules.add(test.with_suffix("").as_posix().replace("/", "."))
            else:
                commands.append([sys.executable, "-m", "unittest", *sorted(modules)])
        paths = [path for path in paths if path not in python_paths]
        if not paths:
            return commands
    packages = ci_package_graph.load_packages(root)
    policy = ci_scope_plan.strict_json(root / "conformance/ci-touchpoints-v1.json")
    ci_scope_plan.validate_policy(policy)
    bindings = ci_package_graph.lane_packages(policy, packages)
    selected: dict[str, list[str]] = {}
    extra_lanes: set[str] = set()
    unowned: list[str] = []
    for path in paths:
        documentation = ci_scope_plan.is_documentation(path, policy)
        lanes = ci_scope_plan.rule_lanes(path, policy, documentation_only=documentation)
        if not lanes and (documentation or ci_scope_plan.is_externally_validated(path, policy)):
            continue
        package = ci_package_graph.owning_package(path, packages)
        if package is not None:
            selected.setdefault(package, []).append(path)
            continue
        if not lanes and not (root / path).exists() and (root / ".git").exists():
            if deleted is None:
                deleted = tracked_deletions(root)
            if path in deleted:
                lanes = set(policy["always_lanes"])
        if lanes:
            extra_lanes.update(lanes)
        else:
            unowned.append(path)
    if unowned:
        raise DevTestError(
            "no Zig package owns changed path(s): " + ", ".join(unowned)
        )

    host = "macos" if sys.platform == "darwin" else "linux"
    xcode = ci_scope_push.full_xcode_available() if "metal_aot" in extra_lanes else False
    full_contracts = False
    for lane in sorted(extra_lanes):
        spec = policy["lanes"][lane]
        full_lane = check_only and lane not in bindings and lane not in ("static", "script_contracts")
        if full_lane or not ci_scope_push.locally_runnable(lane, spec["host"], spec.get("local", "run"), host, xcode):
            if deferred is None:
                reason = "full-lane validation" if full_lane else "hosted validation"
                raise DevTestError(f"CI lane {lane} requires {reason}; use dev_test to report deferrals")
            deferred.append(lane)
            continue
        if lane in bindings:
            selected.setdefault(bindings[lane], []).append("")
        elif lane == "script_contracts" and check_only:
            commands.append([sys.executable, "-m", "compileall", "-q", "scripts"])
        else:
            commands.append([sys.executable, "scripts/repo/ci_scope_run.py", "--root", str(root),
                             "--policy", str(root / "conformance/ci-touchpoints-v1.json"),
                             "--lane", lane, "--output", str(root / ".zig-cache/dev-test" / f"{lane}.json"),
                             "--local-compatible"])
            full_contracts |= lane == "script_contracts"

    for package_name, package_paths in sorted(selected.items()):
        package = packages[package_name]
        steps = {focus_step(package_name, path, root) for path in package_paths}
        if None in steps:
            if check_only:
                if deferred is None:
                    raise DevTestError(f"check-only requires a focused owner; {package_name} needs full package validation")
                deferred.append(package_name + " (full package validation)")
                continue
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
    unique = {}
    for command in commands:
        if full_contracts and command[1:3] == ["-m", "unittest"] and (command[3:] == ["discover", "-s", "scripts/tests", "-p", "test_*.py"] or all(module.startswith("scripts.tests.") for module in command[3:])):
            continue
        command = [sys.executable if index == 0 and argument == "python3" else argument for index, argument in enumerate(command)]
        unique.setdefault(tuple(command), command)
    return list(unique.values())


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
        deferred: list[str] = []
        commands = commands_for_paths(
            root,
            paths,
            check_only=args.check or args.watch,
            optimize=args.optimize,
            deferred=deferred,
        )
        for lane in deferred:
            print(f"dev test: DEFER {lane} to its CI execution policy")
        if not commands:
            print("dev test: DEFERRED" if deferred else "dev test: CI policy selects no local runtime tests for documentation/external validation")
            return 0
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
        verb = "PLAN" if args.dry_run else ("PASS_LOCAL" if deferred else "PASS")
        print(f"dev test: {verb} ({len(commands)} focused command(s))")
        return 0
    except (
        DevTestError,
        ci_scope_plan.PlanError,
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
