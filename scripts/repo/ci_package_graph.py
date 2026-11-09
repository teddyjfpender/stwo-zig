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
``src/waist/backend`` change did not select ``riscv_cpu_integration``, which reaches
the backend contracts through ``cpu_backend``).

Lane-to-package binding is derived, not declared: a focused lane that builds a
package names that package's ``build.zig`` in its ``--build-file`` argument.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


CONTRACT_NAME = "package.contract.json"
CONTRACT_ROOT = "src"
BUILD_FILE_FLAG = "--build-file"
BUILD_FILE_NAME = "build.zig"


def generated_embedded_assets(repository: Path) -> dict[str, Path]:
    """Resolve literal embedded_assets records owned by existing product builders."""
    bindings: dict[str, set[Path]] = {}
    for source in (repository / "build_support").rglob("*.zig"):
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", source.read_text(encoding="utf-8"), flags=re.DOTALL)
        for body in re.findall(r"const embedded_assets = [^\n]+\n(.*?)\n\};", text, re.DOTALL):
            for name, relative in re.findall(r'\.name\s*=\s*"([^\"]+)"\s*,\s*\.path\s*=\s*"([^\"]+)"', body):
                bindings.setdefault(name, set()).add((repository / relative).resolve())
    result = {}
    for name, paths in bindings.items():
        if len(paths) == 1:
            path, = paths
            if path.is_relative_to(repository) and path.is_file():
                result[name] = path
    return result


class GraphError(ValueError):
    """A package graph or lane binding that cannot be trusted for selection."""


@dataclass(frozen=True)
class Package:
    """One independently buildable package and its declared dependencies."""

    name: str
    directory: str
    dependencies: frozenset[str]


@dataclass(frozen=True)
class ConsumerContract:
    id: str
    root: str
    route: str
    imports: tuple[str, ...]
    tests: tuple[str, ...]


@dataclass(frozen=True)
class ContractMetadata:
    """Parsed shape only, never source ownership, coverage or execution evidence."""

    consumers: tuple[ConsumerContract, ...] = ()
    budget: dict[str, int] | None = None


def parse_contract_metadata(payload: Any, label: str) -> ContractMetadata:
    """Extension shape only; base validation and workspace v3 admission stay separate."""
    required = {"schema", "package", "version", "layer", "owner", "public_modules",
                "dependencies", "injected_modules", "api_surface", "api_contract", "ci"}
    optional = {"consumer_subdirs"}
    if not isinstance(payload, dict):
        raise ValueError(f"{label}: contract must be an object")
    schema = payload.get("schema")
    if schema == "stwo-zig-package-contract-v3":
        required.add("consumers")
        optional.add("budget")
    elif schema != "stwo-zig-package-contract-v2":
        raise ValueError(f"{label}: unknown contract schema {schema!r}")
    if not required <= payload.keys() or payload.keys() - required - optional:
        raise ValueError(f"{label}: contract fields differ")
    if schema == "stwo-zig-package-contract-v2":
        return ContractMetadata()

    def strings(value: Any, field: str) -> tuple[str, ...]:
        if (not isinstance(value, list) or not value
                or any(not isinstance(v, str) or not v.strip() or v != v.strip()
                       or any(ord(c) < 32 for c in v) for v in value)
                or value != sorted(set(value))):
            raise ValueError(f"{label}: {field} must be nonempty, sorted and unique")
        return tuple(value)

    raw = payload["consumers"]
    if not isinstance(raw, list):
        raise ValueError(f"{label}: consumers must be an array")
    consumers = []
    for row in raw:
        if not isinstance(row, dict) or set(row) != {"id", "root", "route", "imports", "tests"}:
            raise ValueError(f"{label}: consumer fields differ")
        identity, root, route = row["id"], row["root"], row["route"]
        if not isinstance(identity, str) or not re.fullmatch(
            r"(?:package:[a-z][a-z0-9_]*|product:[a-z][a-z0-9_-]*)", identity,
        ):
            raise ValueError(f"{label}: invalid consumer identity")
        if (not isinstance(root, str) or not root.startswith("src/") or not root.endswith(".zig")
                or "\\" in root or any(part in {".", "..", ""} for part in root.split("/"))
                or any(ord(c) < 32 for c in root)):
            raise ValueError(f"{label}: invalid consumer root")
        if identity.startswith("product:"):
            valid_route = route == identity
        else:
            valid_route = isinstance(route, str) and re.fullmatch(
                r"(?:dependency|injected):[a-z][a-z0-9_]*", route,
            )
        if not valid_route:
            raise ValueError(f"{label}: invalid consumer route")
        imports = strings(row["imports"], "consumer imports")
        if any(name == "std" or not re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in imports):
            raise ValueError(f"{label}: invalid named consumer import")
        consumers.append(ConsumerContract(identity, root, route, imports, strings(row["tests"], "consumer tests")))
    identities = [row.id for row in consumers]
    if identities != sorted(set(identities)):
        raise ValueError(f"{label}: consumer identities must be sorted and unique")
    budget = None
    if "budget" in payload:
        budget = payload["budget"]
        keys = {"code_files", "code_lines", "generated_code_files", "generated_code_lines",
                "script_files", "api_entries", "dependencies", "rv64_registry_flags", "versioned_files"}
        if (not isinstance(budget, dict) or set(budget) != keys
                or any(type(value) is not int or value < 0 for value in budget.values())):
            raise ValueError(f"{label}: budget must contain exactly nine nonnegative integer maxima")
        budget = dict(budget)
    return ContractMetadata(tuple(consumers), budget)


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


OWNER_ENTRY_RE = re.compile(
    r'\.\{\s*\.prefix\s*=\s*"([^"]+)"\s*,\s*'
    r"\.package\s*=\s*\.[A-Za-z_][A-Za-z0-9_]*\s*,\s*"
    r'\.dependency_name\s*=\s*"([^"]+)"\s*\}',
    re.DOTALL,
)
def check_ownership_projection(expected: Mapping[str, str], source: str) -> list[str]:
    failures = []
    actual: dict[str, str] = {}
    for prefix, package in OWNER_ENTRY_RE.findall(source):
        if prefix in actual:
            failures.append(f"package workspace: duplicate ownership prefix {prefix!r}")
        actual[prefix] = package
    if actual != expected:
        failures.append("package workspace: ownership projection differs from package "
                        f"contracts: expected={expected}, actual={actual}")
    return failures


def check_owner_roles(repository: Path, expected: Mapping[str, set[str]]) -> list[str]:
    """Exact CODEOWNERS routing; this is not an RFC or branch-protection decision."""
    path = repository / ".github/CODEOWNERS"
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"package workspace: CODEOWNERS unavailable: {error}"]
    failures = []
    role = None
    routes: dict[str, dict[str, tuple[str, ...]]] = {}
    seen_paths = set()
    account = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9_.-]+)?$")
    for line_number, line in enumerate(source.splitlines(), 1):
        line = line.strip()
        if line.startswith("# owner-role:"):
            role = line.removeprefix("# owner-role:").strip()
            if role in routes:
                failures.append(f"package workspace: repeated CODEOWNERS role {role!r}")
            routes.setdefault(role, {})
        elif line and not line.startswith("#"):
            fields = line.split()
            if role is None or len(fields) < 2 or any(not account.fullmatch(v) for v in fields[1:]):
                failures.append(f"package workspace: invalid CODEOWNERS route at line {line_number}")
                continue
            if fields[0] in seen_paths:
                failures.append(f"package workspace: duplicate CODEOWNERS path {fields[0]!r}")
            seen_paths.add(fields[0])
            routes[role][fields[0]] = tuple(fields[1:])
    if set(routes) != set(expected):
        failures.append(f"package workspace: CODEOWNERS roles differ: missing={sorted(set(expected) - set(routes))}, added={sorted(set(routes) - set(expected))}")
    for role, paths in expected.items():
        actual = routes.get(role, {})
        if set(actual) != paths:
            failures.append(f"package workspace: CODEOWNERS scope differs for {role!r}")
        if len(set(actual.values())) != 1:
            failures.append(f"package workspace: CODEOWNERS accounts differ or are absent for {role!r}")
    return failures


def package_owner(contracts: Mapping[str, Any], source: Path) -> Any | None:
    """Unique longest package prefix, then consumer exclusions; no import-based ownership.

    Callers supply all validated contracts and check tracked regular-file eligibility.
    An unowned source remains a gap, not an empty package or a zero global census.
    """
    directories = {contract.directory.resolve(): contract for contract in contracts.values()}
    if len(directories) != len(contracts):
        raise GraphError("package ownership: duplicate registered directory")
    source = source.resolve()
    matches = [directory for directory in directories if source.is_relative_to(directory)]
    if not matches:
        return None
    directory = max(matches, key=lambda value: len(value.parts))
    owner = directories[directory]
    relative = source.relative_to(directory)
    if any(Path(*relative.parts[:depth]).as_posix() in owner.consumer_subdirs
           for depth in range(1, len(relative.parts))):
        return None
    return owner

def read_product_declarations(repository: Path, *, include_constructed: bool = False) -> dict[str, dict[str, str | None]]:
    from scripts.repo import check_build_configure_closure as construction
    try:
        return construction.read_product_declarations(repository, include_constructed=include_constructed)
    except construction.ProductDeclarationError as error:
        raise GraphError(str(error)) from error


def validate_package_consumer_sources(repository: Path, provider: Any, metadata: ContractMetadata,
                                      contracts: Mapping[str, Any], tracked: set[str]) -> list[str]:
    """Static root consistency only; never builder/Module identity or execution proof.

    tracked is the caller's authoritative regular-file inventory for this source.
    Unsupported product/injected routes remain errors until their full validation exists.
    """
    from scripts.repo import check_build_configure_closure as construction
    repository = repository.resolve()
    failures = []
    waist_modules = {module for contract in contracts.values()
                     if contract.layer in {"protocol", "contract", "api", "interchange"}
                     for module in contract.public_modules}
    for entry in metadata.consumers:
        try:
            if not entry.id.startswith("package:"):
                raise GraphError("product owner/closure validation is pending")
            owner = contracts.get(entry.id.removeprefix("package:"))
            if owner is None:
                raise GraphError("unknown consumer package")
            source = repository / entry.root
            if (entry.root not in tracked or source.is_symlink() or not source.is_file()
                    or source.resolve() != source or not source.is_relative_to(repository)):
                raise GraphError("consumer root is not a canonical tracked regular source")
            if package_owner(contracts, source) is not owner:
                raise GraphError("consumer source belongs to another or excluded owner")
            if source.relative_to(owner.directory.resolve()).as_posix() != f"contract_tests/{provider.package}_test.zig":
                raise GraphError("consumer root does not use its provider-owned test basename")
            route, module = entry.route.split(":", 1)
            if module not in provider.public_modules:
                raise GraphError("route does not name this public provider")
            if route == "injected":
                if module not in owner.injected_modules:
                    raise GraphError("undeclared provider injection")
                raise GraphError("injected provider builder binding validation is pending")
            relative = owner.dependencies.get(module)
            if route != "dependency" or relative is None or (owner.directory / relative).resolve() != provider.directory.resolve():
                raise GraphError("consumer does not declare this provider dependency")
            allowed = (set(owner.dependencies) | set(owner.injected_modules)) & waist_modules
            allowed |= set(owner.public_modules)  # Only the owning public module may be a type witness.
            if module not in entry.imports or not set(entry.imports) <= allowed:
                raise GraphError("consumer imports undeclared or nonpublic provider/witness modules")
            tokens = construction.source_tokens(source.read_text(encoding="utf-8"))
            imports, tests, depth = [], [], 0
            for index, token in enumerate(tokens):
                if tokens[index:index + 3] == ["@", "import", "("]:
                    value = tokens[index + 3:index + 5]
                    if len(value) != 2 or not value[0].startswith('"') or value[1] != ")":
                        raise GraphError("consumer import must be a literal public module")
                    imports.append(json.loads(value[0]))
                if depth == 0 and token == "test":
                    if index + 2 >= len(tokens) or not tokens[index + 1].startswith('"') or tokens[index + 2] != "{":
                        raise GraphError("consumer tests must be named top-level cases")
                    tests.append(json.loads(tokens[index + 1]))
                depth += (token == "{") - (token == "}")
            if set(imports) != set(entry.imports) | {"std"}:
                raise GraphError("consumer imports differ from the exact registration")
            if tuple(sorted(tests)) != entry.tests or len(tests) != len(set(tests)):
                raise GraphError("consumer test discovery differs from the exact registration")
        except (ValueError, OSError) as error:
            failures.append(f"{provider.package} CDC {entry.id}: {error}")
    return failures
