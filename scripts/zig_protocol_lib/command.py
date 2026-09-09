#!/usr/bin/env python3
"""Canonical direct Zig commands derived from package contracts."""

from __future__ import annotations

import json
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


def _compile_options(optimize: str | None, strip: bool | None) -> list[str]:
    return [
        *([f"-O{optimize}"] if optimize is not None else []),
        *(["-fstrip" if strip else "-fno-strip"] if strip is not None else []),
    ]


def _package_module_args(optimize: str | None = None, strip: bool | None = None) -> list[str]:
    arguments: list[str] = []
    for module in protocol_package_modules():
        arguments.extend(_dependency_args(module.dependencies))
        arguments.extend(_compile_options(optimize, strip))
        arguments.append(f"-M{module.name}={module.source}")
    return arguments


def protocol_module_args(root_source: str, *, optimize: str | None = None, strip: bool | None = None) -> list[str]:
    root_dependencies = tuple(module.name for module in protocol_package_modules())
    return [
        *_dependency_args(root_dependencies),
        *_compile_options(optimize, strip),
        f"-Mroot={root_source}",
        *_package_module_args(optimize, strip),
    ]


def test_command(root_source: str, *arguments: str) -> list[str]:
    # Zig resets per-module options at every -M. A trailing -O silently
    # leaves the root (and almost all dependencies) in Debug, invalidating
    # benchmark results. Apply a requested mode to every selected module.
    optimize: str | None = None
    strip: bool | None = None
    trailing: list[str] = []
    remaining = iter(arguments)
    for argument in remaining:
        if argument == "--":
            trailing.extend((argument, *remaining))
            break
        if argument in ("--test-filter", "--test-name-prefix", "--test-cmd"):
            trailing.extend((argument, next(remaining)))
        elif argument in ("-fstrip", "-fno-strip"):
            # Like -O, strip resets at each -M. A trailing flag otherwise
            # leaves the expensive root debug-location emission enabled.
            strip = argument == "-fstrip"
        elif argument == "-O":
            optimize = next(remaining)
        elif argument.startswith("-O"):
            optimize = argument[2:]
        else:
            trailing.append(argument)
    if optimize is not None and optimize not in (
        "Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall"
    ):
        raise ValueError(f"invalid Zig optimization mode: {optimize}")
    return ["zig", "test", *protocol_module_args(root_source, optimize=optimize, strip=strip), *trailing]


def aggregate_run_command(root_source: str, *arguments: str) -> list[str]:
    package_names = tuple(module.name for module in protocol_package_modules())
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
        *(module.contract for module in modules),
        *(ROOT / module.source for module in modules),
    )
