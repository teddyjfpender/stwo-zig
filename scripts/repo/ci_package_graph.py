#!/usr/bin/env python3
"""Derive focused CI package lanes from the package-contract dependency graph.

The repository declares one ``package.contract.json`` per independently
buildable Zig package. Those contracts are the single machine-readable source
of both package ownership (the contract's directory owns every path beneath it)
and the dependency graph (``dependencies`` maps a dependency module name to a
relative package path).

A change inside a package must exercise that package's own focused lane and
every lane whose package transitively depends on it — the reverse-dependency
closure. Deriving that closure here replaces a hand-maintained per-prefix lane
list, which had drifted: it under-selected transitive consumers (for example a
``src/backend`` change did not select ``riscv_cpu_integration``, which reaches
the backend contracts through ``cpu_backend``).

Lane-to-package binding is derived, not declared: a focused lane that builds a
package names that package's ``build.zig`` in its ``--build-file`` argument.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


CONTRACT_NAME = "package.contract.json"
CONTRACT_ROOT = "src"
BUILD_FILE_FLAG = "--build-file"
BUILD_FILE_NAME = "build.zig"


class GraphError(ValueError):
    """A package graph or lane binding that cannot be trusted for selection."""


@dataclass(frozen=True)
class Package:
    """One independently buildable package and its declared dependencies."""

    name: str
    directory: str
    dependencies: frozenset[str]


def _posix(path: Path, root: Path) -> str:
    return PurePosixPath(path.relative_to(root)).as_posix()


def load_packages(root: Path) -> dict[str, Package]:
    """Read every package contract under ``root`` into a name-keyed graph.

    Dependency edges are resolved from the contract's declared relative paths
    back to package names, so a renamed or moved package fails loudly here
    rather than silently dropping lanes from the closure.
    """
    directories: dict[str, str] = {}
    raw: dict[str, dict[str, str]] = {}
    for contract_path in sorted((root / CONTRACT_ROOT).rglob(CONTRACT_NAME)):
        try:
            payload = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise GraphError(f"unreadable package contract {contract_path}: {error}") from error
        if not isinstance(payload, dict):
            raise GraphError(f"package contract is not an object: {contract_path}")
        name = payload.get("package")
        dependencies = payload.get("dependencies")
        if not isinstance(name, str) or not name:
            raise GraphError(f"package contract has no package name: {contract_path}")
        if not isinstance(dependencies, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in dependencies.items()
        ):
            raise GraphError(f"package contract has malformed dependencies: {contract_path}")
        if name in directories:
            raise GraphError(f"duplicate package name in the workspace: {name}")
        directory = _posix(contract_path.parent, root)
        directories[name] = directory
        raw[name] = dict(dependencies)

    if not directories:
        raise GraphError(f"no package contracts found under {root / CONTRACT_ROOT}")

    by_directory = {directory: name for name, directory in directories.items()}
    packages: dict[str, Package] = {}
    for name, dependencies in raw.items():
        resolved: set[str] = set()
        for relative in dependencies.values():
            target = (PurePosixPath(directories[name]) / relative).as_posix()
            # PurePosixPath keeps ".." literal; normalize it so the declared
            # relative dependency path resolves to a real package directory.
            normalized = _normalize(target)
            dependency = by_directory.get(normalized)
            if dependency is None:
                raise GraphError(
                    f"package {name} depends on {relative}, which is not a package directory"
                )
            resolved.add(dependency)
        packages[name] = Package(name, directories[name], frozenset(resolved))
    return packages


def _normalize(path: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(path).parts:
        if part == ".":
            continue
        if part == "..":
            if not parts:
                raise GraphError(f"dependency path escapes the repository: {path}")
            parts.pop()
            continue
        parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else ""


def edge_count(packages: Mapping[str, Package]) -> int:
    """Total resolved dependency edges — the number the workspace validator sees."""
    return sum(len(package.dependencies) for package in packages.values())


def reverse_closure(packages: Mapping[str, Package], seeds: Iterable[str]) -> frozenset[str]:
    """Every package that transitively depends on any seed, plus the seeds.

    Iterated to a fixed point rather than recursively, so a cyclic graph (which
    the workspace validator rejects independently) terminates here regardless.
    """
    affected = {name for name in seeds if name in packages}
    while True:
        additions = {
            name
            for name, package in packages.items()
            if name not in affected and package.dependencies & affected
        }
        if not additions:
            return frozenset(affected)
        affected |= additions


def lane_packages(policy: Mapping[str, Any], packages: Mapping[str, Package]) -> dict[str, str]:
    """Map each focused lane that builds one package to that package's name.

    Derived from the lane's own ``--build-file`` argument, so adding a package
    lane to the policy needs no second declaration here. A lane pointing at a
    build file that no package owns is an error: it would silently never be
    selected by the graph.
    """
    lanes = policy.get("lanes")
    if not isinstance(lanes, dict):
        raise GraphError("CI touchpoint policy has no lanes")
    by_directory = {package.directory: name for name, package in packages.items()}
    bindings: dict[str, str] = {}
    for lane, spec in sorted(lanes.items()):
        if not isinstance(spec, dict):
            raise GraphError(f"CI lane {lane} is malformed")
        for command in spec.get("commands", []):
            if not isinstance(command, list):
                continue
            for index, argument in enumerate(command):
                if argument != BUILD_FILE_FLAG or index + 1 >= len(command):
                    continue
                build_file = PurePosixPath(str(command[index + 1]))
                if build_file.name != BUILD_FILE_NAME:
                    raise GraphError(f"CI lane {lane} builds an unexpected file: {build_file}")
                directory = build_file.parent.as_posix()
                package = by_directory.get(directory)
                if package is None:
                    raise GraphError(
                        f"CI lane {lane} builds {build_file}, which no package contract owns"
                    )
                existing = bindings.get(lane)
                if existing is not None and existing != package:
                    raise GraphError(
                        f"CI lane {lane} builds more than one package: {existing}, {package}"
                    )
                bindings[lane] = package
    return bindings


def owning_package(path: str, packages: Mapping[str, Package]) -> str | None:
    """The package owning ``path``, or ``None`` when no package claims it.

    Longest-prefix wins so a nested package directory is never shadowed by its
    parent. ``None`` is the caller's fail-open signal, not a safe default.
    """
    best: str | None = None
    best_length = -1
    for name, package in packages.items():
        directory = package.directory
        if path == directory or path.startswith(directory + "/"):
            if len(directory) > best_length:
                best, best_length = name, len(directory)
    return best


def selection(
    changed_paths: Iterable[str],
    packages: Mapping[str, Package],
    bindings: Mapping[str, str],
) -> tuple[frozenset[str], frozenset[str]]:
    """Return (selected lanes, unowned paths) for the package-owned diff slice.

    Unowned paths are returned rather than ignored: the caller decides the
    fail-open policy for them.
    """
    seeds: set[str] = set()
    unowned: set[str] = set()
    for path in changed_paths:
        package = owning_package(path, packages)
        if package is None:
            unowned.add(path)
        else:
            seeds.add(package)
    if not seeds:
        return frozenset(), frozenset(unowned)
    affected = reverse_closure(packages, seeds)
    lanes = {lane for lane, package in bindings.items() if package in affected}
    return frozenset(lanes), frozenset(unowned)
