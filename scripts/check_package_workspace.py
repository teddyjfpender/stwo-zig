#!/usr/bin/env python3
"""Audit independently buildable Zig package ownership boundaries."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts import ci_package_graph
except ModuleNotFoundError:
    import ci_package_graph  # type: ignore[no-redef]


SCHEMA = "stwo-zig-package-contract-v2"
CONTRACT_NAME = "package.contract.json"
BUILTIN_MODULES = {"builtin", "std"}
LAYERS = {
    "api",
    "backend",
    "contract",
    "engine",
    "example",
    "frontend",
    "integration",
    "interchange",
    "protocol",
    "service",
}
ALLOWED_DEPENDENCY_LAYERS = {
    "protocol": set(),
    "contract": {"protocol"},
    "api": {"protocol"},
    "engine": {"api", "contract", "protocol"},
    "frontend": {"api", "contract", "engine", "protocol"},
    "backend": {"api", "contract", "engine", "protocol"},
    "interchange": {"protocol"},
    "example": {"api", "backend", "engine", "interchange", "protocol"},
    "service": {"service"},
    "integration": LAYERS,
}
IMPORT_RE = re.compile(
    r'@import\(\s*"([^"]+)"\s*,?\s*\)',
    re.DOTALL,
)
EMBED_FILE_RE = re.compile(
    r'@embedFile\(\s*"([^"]+)"\s*,?\s*\)',
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
BUILD_DEPENDENCY_RE = re.compile(r'b\.dependency\(\s*"([^"]+)"', re.DOTALL)
VERSION_RE = re.compile(r'\.version\s*=\s*"([^"]+)"')
TEST_RE = re.compile(r'^test\s+"((?:[^"\\]|\\.)*)"\s*\{', re.MULTILINE)
OWNER_ENTRY_RE = re.compile(
    r'\.\{\s*\.prefix\s*=\s*"([^"]+)"\s*,\s*'
    r"\.package\s*=\s*\.[A-Za-z_][A-Za-z0-9_]*\s*,\s*"
    r'\.dependency_name\s*=\s*"([^"]+)"\s*\}',
    re.DOTALL,
)
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^)\s]+)\)")
REQUIRED_README_HEADINGS = (
    "## Public API",
    "## Dependencies",
    "## Build, test, and run",
    "## Contract and invariants",
    "## Change checklist",
    "## Related documentation",
)


@dataclass(frozen=True)
class ApiContract:
    signature_tests: tuple[str, ...]
    invariant_tests: tuple[str, ...]


@dataclass(frozen=True)
class Contract:
    directory: Path
    package: str
    version: str
    layer: str
    owner: str
    public_modules: dict[str, str]
    dependencies: dict[str, str]
    injected_modules: frozenset[str]
    api_surface: tuple[str, ...]
    api_contract: ApiContract
    ci_lane: str
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
        "version",
        "layer",
        "owner",
        "public_modules",
        "dependencies",
        "injected_modules",
        "api_surface",
        "api_contract",
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
    version = payload["version"]
    layer = payload["layer"]
    owner = payload["owner"]
    if not isinstance(package, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", package):
        raise ValueError(f"{path}: invalid package name")
    if not isinstance(version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
        version,
    ):
        raise ValueError(f"{path}: invalid semantic version")
    if layer not in LAYERS:
        raise ValueError(f"{path}: invalid architectural layer")
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
    api_contract = _object(payload["api_contract"], f"{path}: api_contract")
    if set(api_contract) != {"signature_tests", "invariant_tests"}:
        raise ValueError(
            f"{path}: api_contract must contain exactly signature_tests and invariant_tests"
        )
    signature_tests = _string_list(
        api_contract["signature_tests"],
        f"{path}: api_contract.signature_tests",
    )
    invariant_tests = _string_list(
        api_contract["invariant_tests"],
        f"{path}: api_contract.invariant_tests",
    )
    for label, tests in (
        ("signature_tests", signature_tests),
        ("invariant_tests", invariant_tests),
    ):
        if not tests or tests != sorted(set(tests)):
            raise ValueError(
                f"{path}: api_contract.{label} must be nonempty, sorted, and unique"
            )
    overlap = set(signature_tests) & set(invariant_tests)
    if overlap:
        raise ValueError(
            f"{path}: API signature and invariant tests overlap: {sorted(overlap)}"
        )
    ci = _object(payload["ci"], f"{path}: ci")
    if set(ci) != {"lane", "host", "command"}:
        raise ValueError(f"{path}: ci must contain exactly lane, host, and command")
    command = _string_list(ci["command"], f"{path}: ci.command")
    if (
        not isinstance(ci["lane"], str)
        or not ci["lane"]
        or ci["host"] not in {"linux", "macos"}
        or not command
    ):
        raise ValueError(f"{path}: invalid ci contract")
    return Contract(
        directory=path.parent.resolve(),
        package=package,
        version=version,
        layer=layer,
        owner=owner,
        public_modules=public_modules,
        dependencies=dependencies,
        injected_modules=frozenset(injected),
        api_surface=tuple(api_surface),
        api_contract=ApiContract(
            signature_tests=tuple(signature_tests),
            invariant_tests=tuple(invariant_tests),
        ),
        ci_lane=ci["lane"],
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
    versions = VERSION_RE.findall(manifest)
    if versions != [contract.version]:
        failures.append(
            f"{contract.package}: manifest version differs: "
            f"expected={contract.version!r}, actual={versions}"
        )
    actual_dependencies = path_dependencies(manifest)
    if actual_dependencies != contract.dependencies:
        failures.append(
            f"{contract.package}: manifest dependencies differ: "
            f"expected={contract.dependencies}, actual={actual_dependencies}"
        )
    build = strip_comments(build_path.read_text(encoding="utf-8"))
    consumed_dependencies = set(BUILD_DEPENDENCY_RE.findall(build))
    if consumed_dependencies != set(contract.dependencies):
        failures.append(
            f"{contract.package}: build dependency calls differ: "
            f"expected={sorted(contract.dependencies)}, "
            f"actual={sorted(consumed_dependencies)}"
        )
    for module, source in contract.public_modules.items():
        if f'b.addModule("{module}"' not in build:
            failures.append(f"{contract.package}: build does not export {module}")
        if not (contract.directory / source).is_file():
            failures.append(f"{contract.package}: public module source is missing: {source}")


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
        for embedded in EMBED_FILE_RE.findall(text):
            target = (source.parent / embedded).resolve()
            if not _inside(target, contract.directory):
                failures.append(
                    f"{contract.package}: embedded file escapes owner: "
                    f"{source.relative_to(contract.directory)} -> {embedded}"
                )
            elif not target.is_file():
                failures.append(
                    f"{contract.package}: embedded file is missing: "
                    f"{source.relative_to(contract.directory)} -> {embedded}"
                )
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


def _validate_readme(
    repository: Path,
    contract: Contract,
    failures: list[str],
) -> None:
    path = contract.directory / "README.md"
    if not path.is_file():
        failures.append(f"{contract.package}: package README.md is missing")
        return
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != f"# `{contract.package}`":
        failures.append(
            f"{contract.package}: README must start with '# `{contract.package}`'"
        )
    expected_facts = (
        f"| Version | `{contract.version}` |",
        f"| Layer | `{contract.layer}` |",
        f"| Owner | `{contract.owner}` |",
        f"| Focused CI host | {'Linux' if contract.ci_host == 'linux' else 'macOS'} |",
    )
    for fact in expected_facts:
        if fact not in text:
            failures.append(f"{contract.package}: README is missing fact {fact!r}")
    for module in contract.public_modules:
        if f'@import("{module}")' not in text:
            failures.append(
                f"{contract.package}: README has no import example for {module}"
            )
    for dependency in contract.dependencies:
        if f"`{dependency}`" not in text:
            failures.append(
                f"{contract.package}: README omits dependency {dependency}"
            )
    for public_name in contract.api_surface:
        if f"`{public_name}`" not in text:
            failures.append(
                f"{contract.package}: README omits public API name {public_name}"
            )
    command = " ".join(contract.ci_command)
    if command not in text:
        failures.append(
            f"{contract.package}: README omits exact focused CI command {command!r}"
        )
    for heading in REQUIRED_README_HEADINGS:
        if heading not in lines:
            failures.append(
                f"{contract.package}: README is missing heading {heading!r}"
            )
    if not any(
        line.startswith("## ")
        and ("Purpose" in line or "Architecture" in line)
        for line in lines
    ):
        failures.append(
            f"{contract.package}: README needs a purpose or architecture section"
        )
    if "```mermaid" not in lines:
        failures.append(f"{contract.package}: README needs an architecture diagram")
    if sum(line.startswith("```") for line in lines) % 2 != 0:
        failures.append(f"{contract.package}: README has unbalanced code fences")
    headings = [
        len(line) - len(line.lstrip("#"))
        for line in lines
        if re.match(r"^#{1,6} ", line)
    ]
    if headings.count(1) != 1 or any(
        current > previous + 1
        for previous, current in zip(headings, headings[1:])
    ):
        failures.append(f"{contract.package}: README heading hierarchy is malformed")
    if len(re.findall(r"\b[\w'-]+\b", text)) < 350:
        failures.append(f"{contract.package}: README is too brief for an owner guide")
    for destination in MARKDOWN_LINK_RE.findall(text):
        if destination.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = destination.split("#", 1)[0]
        if target and not (path.parent / target).resolve().exists():
            relative = path.relative_to(repository)
            failures.append(
                f"{contract.package}: {relative} has broken link {destination!r}"
            )


def _relative_import_closure(root: Path, owner: Path) -> set[Path]:
    pending = [root.resolve()]
    reached: set[Path] = set()
    while pending:
        source = pending.pop()
        if source in reached or not source.is_file() or not _inside(source, owner):
            continue
        reached.add(source)
        text = strip_comments(source.read_text(encoding="utf-8"))
        for imported in IMPORT_RE.findall(text):
            if not imported.endswith(".zig"):
                continue
            target = (source.parent / imported).resolve()
            if target not in reached and _inside(target, owner):
                pending.append(target)
    return reached


def _test_reference(
    contract: Contract,
    reference: str,
    failures: list[str],
) -> tuple[Path, str] | None:
    source_name, separator, test_name = reference.partition("::")
    relative = Path(source_name)
    if (
        not separator
        or not source_name.endswith(".zig")
        or not test_name
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        failures.append(
            f"{contract.package}: invalid API contract test reference {reference!r}"
        )
        return None
    source = (contract.directory / relative).resolve()
    if not _inside(source, contract.directory) or not source.is_file():
        failures.append(
            f"{contract.package}: API contract source is missing: {source_name}"
        )
        return None
    return source, test_name


def _validate_api_contract(contract: Contract, failures: list[str]) -> None:
    root = contract.directory / next(iter(contract.public_modules.values()))
    reached = _relative_import_closure(root, contract.directory)
    for category, references in (
        ("signature", contract.api_contract.signature_tests),
        ("invariant", contract.api_contract.invariant_tests),
    ):
        for reference in references:
            parsed = _test_reference(contract, reference, failures)
            if parsed is None:
                continue
            source, test_name = parsed
            if source not in reached:
                failures.append(
                    f"{contract.package}: {category} test source is not reachable "
                    f"from its public module: {reference}"
                )
                continue
            names = TEST_RE.findall(
                strip_comments(source.read_text(encoding="utf-8"))
            )
            count = names.count(test_name)
            if count != 1:
                failures.append(
                    f"{contract.package}: {category} test must resolve exactly once: "
                    f"{reference} (found {count})"
                )


def _validate_layers(
    contracts: list[Contract],
    packages: dict[str, Contract],
    failures: list[str],
) -> None:
    for contract in contracts:
        allowed = ALLOWED_DEPENDENCY_LAYERS[contract.layer]
        for dependency in contract.dependencies:
            target = packages.get(dependency)
            if target is None:
                continue
            if target.layer not in allowed:
                failures.append(
                    f"{contract.package}: {contract.layer} layer cannot depend on "
                    f"{target.layer} package {dependency}"
                )


def _owns(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _validate_ci_contracts(
    repository: Path,
    contracts: list[Contract],
    failures: list[str],
) -> None:
    policy_path = repository / "conformance/ci-touchpoints-v1.json"
    try:
        policy = _object(
            json.loads(policy_path.read_text(encoding="utf-8")),
            str(policy_path),
        )
    except (json.JSONDecodeError, OSError, ValueError) as error:
        failures.append(f"package workspace: cannot load focused CI policy: {error}")
        return
    lanes = policy.get("lanes")
    rules = policy.get("rules")
    if not isinstance(lanes, dict) or not isinstance(rules, list):
        failures.append("package workspace: focused CI policy lacks lanes or rules")
        return
    try:
        package_graph = ci_package_graph.load_packages(repository)
        lane_bindings = ci_package_graph.lane_packages(policy, package_graph)
    except ci_package_graph.GraphError as error:
        failures.append(f"package workspace: cannot derive focused CI lanes: {error}")
        return
    claimed_lanes: dict[str, str] = {}
    for contract in contracts:
        previous = claimed_lanes.get(contract.ci_lane)
        if previous is not None:
            failures.append(
                f"package workspace: CI lane {contract.ci_lane!r} is shared by "
                f"{previous} and {contract.package}"
            )
        claimed_lanes[contract.ci_lane] = contract.package
        lane = lanes.get(contract.ci_lane)
        if not isinstance(lane, dict):
            failures.append(
                f"{contract.package}: CI lane {contract.ci_lane!r} is missing"
            )
            continue
        if lane.get("host") != contract.ci_host:
            failures.append(
                f"{contract.package}: CI host differs from lane "
                f"{contract.ci_lane}: expected={contract.ci_host!r}, "
                f"actual={lane.get('host')!r}"
            )
        commands = lane.get("commands")
        if not isinstance(commands, list) or list(contract.ci_command) not in commands:
            failures.append(
                f"{contract.package}: CI command is not owned by lane "
                f"{contract.ci_lane!r}"
            )
        changed_path = (
            contract.directory.relative_to(repository) / CONTRACT_NAME
        ).as_posix()
        selected = set(
            ci_package_graph.selection(
                [changed_path],
                package_graph,
                lane_bindings,
            )[0]
        )
        selected.update({
            selected_lane
            for rule in rules
            if isinstance(rule, dict)
            for prefix in rule.get("prefixes", [])
            if isinstance(prefix, str) and _owns(changed_path, prefix)
            for selected_lane in rule.get("lanes", [])
            if isinstance(selected_lane, str)
        })
        if contract.ci_lane not in selected:
            failures.append(
                f"{contract.package}: package changes do not select declared CI "
                f"lane {contract.ci_lane!r}"
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
        for embedded in EMBED_FILE_RE.findall(text):
            target = (source.parent / embedded).resolve()
            target_owner = _containing_contract(target, contracts)
            if target_owner is None or source_owner == target_owner:
                continue
            failures.append(
                f"{target_owner.package}: embedded file enters owner: "
                f"{source.relative_to(repository)} -> {embedded}; "
                "consume owner-exported data instead"
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


def _validate_ownership_projection(
    repository: Path,
    contracts: list[Contract],
    failures: list[str],
) -> None:
    projection = repository / "build_support/graph/package_ownership.zig"
    if not projection.is_file():
        failures.append("package workspace: ownership projection is missing")
        return
    expected = {
        contract.directory.relative_to(repository).as_posix().rstrip("/") + "/":
        contract.package
        for contract in contracts
    }
    matches = OWNER_ENTRY_RE.findall(
        strip_comments(projection.read_text(encoding="utf-8"))
    )
    actual: dict[str, str] = {}
    for prefix, package in matches:
        if prefix in actual:
            failures.append(
                f"package workspace: duplicate ownership prefix {prefix!r}"
            )
        actual[prefix] = package
    if actual != expected:
        failures.append(
            "package workspace: ownership projection differs from package "
            f"contracts: expected={expected}, actual={actual}"
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
    _validate_layers(contracts, packages, failures)
    for contract in contracts:
        _validate_manifest(contract, failures)
        _validate_imports(contract, module_to_package, failures)
        _validate_api(contract, failures)
        _validate_readme(repository, contract, failures)
        _validate_api_contract(contract, failures)
    _validate_relative_ingress(repository, contracts, failures)
    _validate_aggregate_manifests(repository, contracts, failures)
    _validate_ownership_projection(repository, contracts, failures)
    _validate_ci_contracts(repository, contracts, failures)
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
