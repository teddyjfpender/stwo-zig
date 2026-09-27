#!/usr/bin/env python3
"""Canonical direct Zig commands derived from package contracts."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# Product composition remains explicit, while every selected package's source
# and dependency edges come from its authoritative package contract.
PROTOCOL_PACKAGES = (
    "stwo_core",
    "stwo_backend_contracts",
    "stwo_prover_api",
    "stwo_prover_engine",
    "stwo_proof_wire",
    "stwo_artifact_store",
    "stwo_metal_session",
    "stwo_cpu_backend",
    "stwo_cuda_backend",
    "stwo_metal_backend",
    "stwo_riscv_frontend",
    "stwo_cairo_frontend",
    "stwo_native_examples",
    "stwo_riscv_cpu_integration",
    "stwo_cairo_cpu_integration",
    "stwo_cairo_metal_integration",
    "stwo_native_cuda_integration",
    "stwo_cairo_cuda_integration",
)


@dataclass(frozen=True)
class PackageModule:
    name: str
    source: str
    dependencies: tuple[str, ...]
    contract: Path


@lru_cache(maxsize=1)
def protocol_package_modules() -> tuple[PackageModule, ...]:
    discovered: dict[str, PackageModule] = {}
    for contract in sorted((ROOT / "src").rglob("package.contract.json")):
        payload = json.loads(contract.read_text(encoding="utf-8"))
        package = payload.get("package")
        if package not in PROTOCOL_PACKAGES:
            continue
        public_modules = payload.get("public_modules")
        dependencies = payload.get("dependencies")
        if (
            not isinstance(public_modules, dict)
            or len(public_modules) != 1
            or not isinstance(dependencies, dict)
        ):
            raise ValueError(f"{contract}: malformed public module contract")
        module_name, relative_source = next(iter(public_modules.items()))
        if module_name != package or not isinstance(relative_source, str):
            raise ValueError(
                f"{contract}: direct protocol commands require package/module identity"
            )
        source = (contract.parent / relative_source).relative_to(ROOT).as_posix()
        discovered[package] = PackageModule(
            name=module_name,
            source=source,
            dependencies=tuple(sorted(dependencies)),
            contract=contract,
        )

    missing = set(PROTOCOL_PACKAGES) - set(discovered)
    extra = set(discovered) - set(PROTOCOL_PACKAGES)
    if missing or extra:
        raise ValueError(
            "protocol package selection differs from contracts: "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    for module in discovered.values():
        missing_dependencies = set(module.dependencies) - set(discovered)
        if missing_dependencies:
            raise ValueError(
                f"{module.contract}: unselected protocol dependencies: "
                f"{sorted(missing_dependencies)}"
            )
    return tuple(discovered[name] for name in PROTOCOL_PACKAGES)


def _dependency_args(dependencies: tuple[str, ...]) -> list[str]:
    return [
        argument
        for dependency in dependencies
        for argument in ("--dep", dependency)
    ]


# Postcard is a compatibility import shim, not a second proof-wire package.
# The proof-wire/core nodes below are the same authoritative package nodes
# used by every direct protocol command.
POSTCARD_MODULE = PackageModule(
    "interop_postcard",
    "src/interop/postcard.zig",
    ("stwo_core", "stwo_proof_wire"),
    ROOT / "src/interop/proof_wire/package.contract.json",
)
CPU_PROTOCOL_PACKAGES = (
    "stwo_core", "stwo_backend_contracts", "stwo_prover_api",
    "stwo_prover_engine", "stwo_proof_wire", "stwo_cpu_backend",
)


def _compile_options(optimize: str | None, strip: bool | None, cpu: str | None = None) -> list[str]:
    return [
        *([f"-O{optimize}"] if optimize is not None else []),
        *(["-fstrip" if strip else "-fno-strip"] if strip is not None else []),
        *([f"-mcpu={cpu}"] if cpu is not None else []),
    ]


def _modules(cpu_only: bool = False, extra_packages: tuple[str, ...] = ()) -> tuple[PackageModule, ...]:
    available = protocol_package_modules()
    by_name = {module.name: module for module in available}
    unknown = set(extra_packages) - set(by_name)
    if unknown:
        raise ValueError(f"unknown additional protocol packages: {sorted(unknown)}")
    names = set(CPU_PROTOCOL_PACKAGES if cpu_only else by_name)
    pending = list(extra_packages)
    # Focused backend roots use the same contracts and only their transitive
    # package dependencies, without pulling unrelated frontends into a gate.
    while pending:
        name = pending.pop()
        if name in names:
            continue
        names.add(name)
        pending.extend(by_name[name].dependencies)
    selected = tuple(
        module for module in available if module.name in names
    )
    names = {module.name for module in selected}
    for module in (*selected, POSTCARD_MODULE):
        if not set(module.dependencies) <= names:
            raise ValueError(f"{module.name}: missing selected dependencies")
    return (*selected, POSTCARD_MODULE)


def _package_module_args(optimize: str | None = None, strip: bool | None = None,
                         cpu: str | None = None, *, modules: tuple[PackageModule, ...] | None = None) -> list[str]:
    arguments: list[str] = []
    for module in modules if modules is not None else _modules():
        arguments.extend(_dependency_args(module.dependencies))
        arguments.extend(_compile_options(optimize, strip, cpu))
        arguments.append(f"-M{module.name}={module.source}")
    return arguments


def protocol_module_args(root_source: str, *, optimize: str | None = None,
                         strip: bool | None = None, cpu: str | None = None,
                         cpu_only: bool = False,
                         extra_packages: tuple[str, ...] = (),
                         standard_test_runner: str | None = None) -> list[str]:
    modules = _modules(cpu_only, extra_packages)
    if standard_test_runner is not None:
        modules = (*modules, PackageModule("block_v5_standard_test_runner",
                     standard_test_runner, (), Path(standard_test_runner)))
    return [
        *_dependency_args(tuple(module.name for module in modules)),
        *_compile_options(optimize, strip, cpu),
        f"-Mroot={root_source}",
        *_package_module_args(optimize, strip, cpu, modules=modules),
    ]


def standard_runner_source(zig: str) -> str:
    executable = shutil.which(zig)
    if executable is None:
        raise ValueError(f"Zig compiler not found: {zig}")
    source = Path(executable).resolve().parent.parent / "lib/zig/compiler/test_runner.zig"
    if not source.is_file():
        raise ValueError(f"standard test runner not found: {source}")
    return str(source)


def test_command(root_source: str, *arguments: str, cpu_only: bool = False,
                 extra_packages: tuple[str, ...] = (),
                 zig: str = "zig", standard_test_runner: str | None = None) -> list[str]:
    # -O/-mcpu/strip reset at every -M; repeat the selected host compilation
    # settings for root, packages, postcard shim and custom-runner module.
    # Filters and program arguments are data, even when they look like flags.
    optimize: str | None = None
    strip: bool | None = None
    cpu: str | None = None
    custom_runner = False
    trailing: list[str] = []
    remaining = iter(arguments)

    def value(option: str) -> str:
        try:
            return next(remaining)
        except StopIteration:
            raise ValueError(f"{option} requires a value") from None

    for argument in remaining:
        if argument == "--":
            trailing.extend((argument, *remaining))
            break
        if argument in ("--test-filter", "--test-name-prefix", "--test-cmd", "--test-runner"):
            trailing.extend((argument, value(argument)))
            custom_runner |= argument == "--test-runner"
        elif argument in ("-fstrip", "-fno-strip"):
            strip = argument == "-fstrip"
        elif argument == "-O":
            optimize = value(argument)
        elif argument.startswith("-O"):
            optimize = argument[2:]
        elif argument == "-mcpu":
            cpu = value(argument)
        elif argument.startswith("-mcpu="):
            cpu = argument[len("-mcpu="):]
        else:
            trailing.append(argument)
    if optimize is not None and optimize not in ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall"):
        raise ValueError(f"invalid Zig optimization mode: {optimize}")
    if cpu is not None and not cpu:
        raise ValueError("-mcpu requires a value")
    runner = (standard_test_runner or standard_runner_source(zig)) if custom_runner else None
    return [
        zig, "test",
        *protocol_module_args(
            root_source, optimize=optimize, strip=strip, cpu=cpu,
            cpu_only=cpu_only, standard_test_runner=runner,
            extra_packages=extra_packages,
        ),
        *trailing,
    ]


def aggregate_run_command(root_source: str, *arguments: str) -> list[str]:
    package_names = tuple(module.name for module in _modules())
    return [
        "zig",
        "run",
        "-lc",
        *_dependency_args(("stwo", *package_names)),
        f"-Mroot={root_source}",
        *_dependency_args(package_names),
        "-Mstwo=src/stwo.zig",
        *_package_module_args(),
        "--",
        *arguments,
    ]


def source_contract() -> tuple[Path, ...]:
    modules = protocol_package_modules()
    return (
        Path(__file__).resolve(),
        ROOT / "src/stwo.zig",
        ROOT / POSTCARD_MODULE.source,
        *(module.contract for module in modules),
        *(ROOT / module.source for module in modules),
    )
