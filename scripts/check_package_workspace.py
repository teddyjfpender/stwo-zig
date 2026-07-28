#!/usr/bin/env python3
"""Audit independently buildable Zig package ownership boundaries."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "stwo-zig-package-contract-v1"
CONTRACT_NAME = "package.contract.json"
BUILTIN_MODULES = {"builtin", "std"}
IMPORT_RE = re.compile(
    r'@import\(\s*"([^"]+)"\s*,?\s*\)',
    re.DOTALL,
)
PUBLIC_DECL_RE = re.compile(
    r"^pub\s+(?:const|fn|var)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
PATH_DEPENDENCY_RE = re.compile(
    r"\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\.\{\s*"
    r'\.path\s*=\s*"([^"]+)"\s*,?\s*\}',
)


@dataclass(frozen=True)
class Contract:
    directory: Path
    package: str
    owner: str
    public_modules: dict[str, str]
    dependencies: dict[str, str]
    injected_modules: frozenset[str]
    api_surface: tuple[str, ...]
    ci_host: str
    ci_command: tuple[str, ...]


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _string_map(value: Any, label: str) -> dict[str, str]:
    raw = _object(value, label)
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in raw.items()):
        raise ValueError(f"{label} must map strings to strings")
    return dict(raw)


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list")
    return value


def load_contract(path: Path) -> Contract:
    payload = _object(json.loads(path.read_text(encoding="utf-8")), str(path))
    expected_fields = {
        "schema",
        "package",
        "owner",
        "public_modules",
        "dependencies",
        "injected_modules",
        "api_surface",
        "ci",
    }
    if set(payload) != expected_fields:
        raise ValueError(
            f"{path}: contract fields differ: "
            f"missing={sorted(expected_fields - set(payload))}, "
            f"extra={sorted(set(payload) - expected_fields)}"
        )
    if payload["schema"] != SCHEMA:
        raise ValueError(f"{path}: unknown schema {payload['schema']!r}")
    package = payload["package"]
    owner = payload["owner"]
    if not isinstance(package, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", package):
        raise ValueError(f"{path}: invalid package name")
    if not isinstance(owner, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", owner):
        raise ValueError(f"{path}: invalid owner")
    public_modules = _string_map(payload["public_modules"], f"{path}: public_modules")
    dependencies = _string_map(payload["dependencies"], f"{path}: dependencies")
    injected = _string_list(payload["injected_modules"], f"{path}: injected_modules")
    api_surface = _string_list(payload["api_surface"], f"{path}: api_surface")
    if api_surface != sorted(set(api_surface)):
        raise ValueError(f"{path}: api_surface must be sorted and unique")
    if injected != sorted(set(injected)):
        raise ValueError(f"{path}: injected_modules must be sorted and unique")
    ci = _object(payload["ci"], f"{path}: ci")
    if set(ci) != {"host", "command"}:
        raise ValueError(f"{path}: ci must contain exactly host and command")
    command = _string_list(ci["command"], f"{path}: ci.command")
    if not isinstance(ci["host"], str) or not command:
        raise ValueError(f"{path}: invalid ci contract")
    return Contract(
        directory=path.parent.resolve(),
        package=package,
        owner=owner,
        public_modules=public_modules,
        dependencies=dependencies,
        injected_modules=frozenset(injected),
        api_surface=tuple(api_surface),
        ci_host=ci["host"],
        ci_command=tuple(command),
    )


def dependency_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    visiting: list[str] = []
    active: set[str] = set()
    complete: set[str] = set()

    def visit(node: str) -> None:
        if node in complete:
            return
        if node in active:
            start = visiting.index(node)
            cycles.append(visiting[start:] + [node])
            return
        active.add(node)
        visiting.append(node)
        for dependency in sorted(graph.get(node, set())):
            visit(dependency)
        visiting.pop()
        active.remove(node)
        complete.add(node)

    for package in sorted(graph):
        visit(package)
    return cycles


def strip_comments(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", without_blocks)


def top_level_api(text: str) -> list[str]:
    return sorted(set(PUBLIC_DECL_RE.findall(strip_comments(text))))


def path_dependencies(text: str) -> dict[str, str]:
    return dict(PATH_DEPENDENCY_RE.findall(strip_comments(text)))


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _validate_manifest(contract: Contract, failures: list[str]) -> None:
    manifest_path = contract.directory / "build.zig.zon"
    build_path = contract.directory / "build.zig"
    if not manifest_path.is_file() or not build_path.is_file():
        failures.append(f"{contract.package}: missing build.zig or build.zig.zon")
        return
    manifest = strip_comments(manifest_path.read_text(encoding="utf-8"))
    if f".name = .{contract.package}" not in manifest:
        failures.append(f"{contract.package}: manifest name does not match contract")
    actual_dependencies = path_dependencies(manifest)
    if actual_dependencies != contract.dependencies:
        failures.append(
            f"{contract.package}: manifest dependencies differ: "
            f"expected={contract.dependencies}, actual={actual_dependencies}"
        )
    build = strip_comments(build_path.read_text(encoding="utf-8"))
    for module, source in contract.public_modules.items():
        if f'b.addModule("{module}"' not in build:
            failures.append(f"{contract.package}: build does not export {module}")
        if not (contract.directory / source).is_file():
            failures.append(f"{contract.package}: public module source is missing: {source}")
    for dependency in contract.dependencies:
        if re.search(
            rf'b\.dependency\(\s*"{re.escape(dependency)}"',
            build,
        ) is None:
            failures.append(f"{contract.package}: build does not consume {dependency}")


def _validate_imports(
    contract: Contract,
    module_to_package: dict[str, str],
    failures: list[str],
) -> None:
    allowed_named = (
        BUILTIN_MODULES
        | set(contract.public_modules)
        | set(contract.dependencies)
        | set(contract.injected_modules)
    )
    sources = (
        source
        for source in contract.directory.rglob("*.zig")
        if not any(part.startswith(".") or part == "zig-out" for part in source.relative_to(contract.directory).parts)
    )
    for source in sorted(sources):
        text = strip_comments(source.read_text(encoding="utf-8"))
        for imported in IMPORT_RE.findall(text):
            if imported.endswith(".zig"):
                target = (source.parent / imported).resolve()
                if not _inside(target, contract.directory):
                    failures.append(
                        f"{contract.package}: relative import escapes owner: "
                        f"{source.relative_to(contract.directory)} -> {imported}"
                    )
                elif not target.is_file():
                    failures.append(
                        f"{contract.package}: relative import target is missing: "
                        f"{source.relative_to(contract.directory)} -> {imported}"
                    )
                continue
            if imported not in allowed_named:
                failures.append(
                    f"{contract.package}: undeclared named import {imported!r} "
                    f"in {source.relative_to(contract.directory)}"
                )
                continue
            dependency_owner = module_to_package.get(imported)
            if (
                dependency_owner is not None
                and dependency_owner != contract.package
                and imported not in contract.injected_modules
                and dependency_owner not in contract.dependencies
            ):
                failures.append(
                    f"{contract.package}: import {imported!r} is not a declared dependency"
                )


def _validate_api(contract: Contract, failures: list[str]) -> None:
    if len(contract.public_modules) != 1:
        failures.append(f"{contract.package}: API ledger requires one primary module")
        return
    root = contract.directory / next(iter(contract.public_modules.values()))
    if not root.is_file():
        return
    actual = top_level_api(root.read_text(encoding="utf-8"))
    expected = list(contract.api_surface)
    if actual != expected:
        failures.append(
            f"{contract.package}: public API differs: "
            f"missing={sorted(set(expected) - set(actual))}, "
            f"added={sorted(set(actual) - set(expected))}"
        )


def _containing_contract(path: Path, contracts: list[Contract]) -> Contract | None:
    matches = [contract for contract in contracts if _inside(path, contract.directory)]
    if not matches:
        return None
    return max(matches, key=lambda contract: len(contract.directory.parts))


def _validate_relative_ingress(
    repository: Path,
    contracts: list[Contract],
    failures: list[str],
) -> None:
    """Prevent consumers from bypassing an owner's named package module."""

    sources = (
        source
        for source in repository.rglob("*.zig")
        if not any(
            part.startswith(".") or part == "zig-out"
            for part in source.relative_to(repository).parts
        )
    )
    for source in sorted(sources):
        source_owner = _containing_contract(source.resolve(), contracts)
        text = strip_comments(source.read_text(encoding="utf-8"))
        for imported in IMPORT_RE.findall(text):
            if not imported.endswith(".zig"):
                continue
            target = (source.parent / imported).resolve()
            target_owner = _containing_contract(target, contracts)
            if target_owner is None or source_owner == target_owner:
                continue
            failures.append(
                f"{target_owner.package}: relative import enters owner: "
                f"{source.relative_to(repository)} -> {imported}; "
                f"use one of {sorted(target_owner.public_modules)}"
            )


def _validate_aggregate_manifests(
    repository: Path,
    contracts: list[Contract],
    failures: list[str],
) -> None:
    expected_root = {
        contract.package: contract.directory.relative_to(repository).as_posix()
        for contract in contracts
    }
    expected_internal = {
        contract.package: Path("..", contract.directory.relative_to(repository)).as_posix()
        for contract in contracts
    }
    manifests = (
        (repository / "build.zig.zon", expected_root, "root"),
        (repository / "build_support/build.zig.zon", expected_internal, "internal"),
    )
    for path, expected, label in manifests:
        if not path.is_file():
            failures.append(f"{label}: aggregate package manifest is missing")
            continue
        actual = path_dependencies(path.read_text(encoding="utf-8"))
        if actual != expected:
            failures.append(
                f"{label}: package dependencies differ: "
                f"expected={expected}, actual={actual}"
            )


def check_repository(repository: Path) -> list[str]:
    repository = repository.resolve()
    failures: list[str] = []
    contract_paths = sorted(repository.glob(f"src/**/{CONTRACT_NAME}"))
    if not contract_paths:
        return ["package workspace: no package contracts found"]
    contracts: list[Contract] = []
    for path in contract_paths:
        try:
            contracts.append(load_contract(path))
        except (json.JSONDecodeError, OSError, ValueError) as error:
            failures.append(str(error))
    if failures:
        return failures
    packages = {contract.package: contract for contract in contracts}
    if len(packages) != len(contracts):
        failures.append("package workspace: duplicate package names")
        return failures
    module_to_package: dict[str, str] = {}
    for contract in contracts:
        for module in contract.public_modules:
            if module in module_to_package:
                failures.append(f"package workspace: duplicate public module {module}")
            module_to_package[module] = contract.package
        unknown = sorted(set(contract.dependencies) - set(packages))
        if unknown:
            failures.append(f"{contract.package}: unknown dependencies {unknown}")
        for dependency, relative in contract.dependencies.items():
            target = (contract.directory / relative).resolve()
            expected = packages.get(dependency)
            if expected is not None and target != expected.directory:
                failures.append(
                    f"{contract.package}: dependency {dependency} resolves to "
                    f"{target}, expected {expected.directory}"
                )
    graph = {
        contract.package: set(contract.dependencies)
        for contract in contracts
    }
    for cycle in dependency_cycles(graph):
        failures.append(f"package workspace: dependency cycle {' -> '.join(cycle)}")
    for contract in contracts:
        _validate_manifest(contract, failures)
        _validate_imports(contract, module_to_package, failures)
        _validate_api(contract, failures)
    _validate_relative_ingress(repository, contracts, failures)
    _validate_aggregate_manifests(repository, contracts, failures)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    arguments = parser.parse_args()
    failures = check_repository(arguments.repo)
    if failures:
        print("\n".join(failures))
        return 1
    contracts = [
        load_contract(path)
        for path in sorted(arguments.repo.resolve().glob(f"src/**/{CONTRACT_NAME}"))
    ]
    modules = sum(len(contract.public_modules) for contract in contracts)
    edges = sum(len(contract.dependencies) for contract in contracts)
    print(
        f"package workspace: PASS "
        f"({len(contracts)} packages, {modules} public modules, {edges} dependency edges)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
