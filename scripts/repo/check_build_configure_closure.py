#!/usr/bin/env python3
"""Validate configured build graphs against the emitted typed catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


BUILTINS = {"install", "uninstall", "configure-manifest"}
FOCUSED_OWNER_FILES = (
    "build_support/products/core.zig",
    "build_support/products/prover.zig",
    "build_support/products/native_cpu.zig",
    "build_support/products/native_metal.zig",
    "build_support/products/riscv_cpu.zig",
)


def parse_steps(help_text: str) -> set[str]:
    lines = help_text.splitlines()
    start = lines.index("Steps:") + 1
    end = next(index for index in range(start, len(lines)) if not lines[index].strip())
    return {line.strip().split()[0] for line in lines[start:end]}


def internal_help(repository: Path, scope: str) -> tuple[set[str], float, str]:
    command = [
        "zig",
        "build",
        "--help",
        "--build-file",
        str(repository / "build_support/internal_build.zig"),
        "--cache-dir",
        str(repository / ".zig-cache/products" / scope),
        f"-Drepository-root={repository}",
        f"-Dproduct-scope={scope}",
    ]
    started = time.monotonic()
    result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        raise SystemExit(f"{scope} configuration failed:\n{result.stderr}")
    return parse_steps(result.stdout), elapsed, result.stdout


def read_product_catalog(
    repository: Path,
    *,
    metal: bool = False,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str]:
    with tempfile.TemporaryDirectory(prefix="stwo-product-catalog-") as raw:
        command = ["zig", "build", "product-matrix-identity", "-p", raw]
        if metal:
            command.append("-Daggregate-metal=true")
        result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
        if result.returncode != 0:
            raise SystemExit(f"product catalog identity failed:\n{result.stderr}")
        encoded = (Path(raw) / "identity/product-matrix.json").read_bytes()
    catalog = json.loads(encoded)
    if catalog.get("schema") != "stwo-product-catalog-v2":
        raise SystemExit("product catalog has an unknown schema")
    payload = json.dumps(
        {
            "schema": catalog["schema"],
            "products": catalog["products"],
            "scopes": catalog["scopes"],
        },
        separators=(",", ":"),
    ).encode()
    if hashlib.sha256(payload).hexdigest() != catalog.get("catalog_sha256"):
        raise SystemExit("product catalog digest is invalid")
    products = {item["product_id"]: item for item in catalog["products"]}
    scopes = {item["scope"]: item for item in catalog["scopes"]}
    if len(products) != len(catalog["products"]):
        raise SystemExit("product catalog contains duplicate product identities")
    if len(scopes) != len(catalog["scopes"]):
        raise SystemExit("product catalog contains duplicate scopes")
    return products, scopes, hashlib.sha256(encoded).hexdigest()


def read_configure_manifest(
    repository: Path,
    scope: str,
    products: dict[str, dict[str, Any]],
    scopes: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    with tempfile.TemporaryDirectory(prefix="stwo-configure-manifest-") as raw:
        command = [
            "zig",
            "build",
            "configure-manifest",
            "--build-file",
            str(repository / "build_support/internal_build.zig"),
            "--cache-dir",
            str(repository / ".zig-cache/products" / scope),
            f"-Drepository-root={repository}",
            f"-Dproduct-scope={scope}",
            "-p",
            raw,
        ]
        result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
        if result.returncode != 0:
            raise SystemExit(f"{scope} configure manifest failed:\n{result.stderr}")
        encoded = (Path(raw) / f"build-graph/configure-{scope}.json").read_bytes()
    manifest = json.loads(encoded)
    if manifest.get("schema") != "stwo-configure-manifest-v3":
        raise SystemExit(f"{scope} configure manifest has an unknown schema")
    expected = scopes[scope]
    for field in (
        "scope",
        "role",
        "product_ids",
        "module_roots",
        "generated_module_roots",
        "dependency_module_roots",
        "allowed_module_files",
        "allowed_module_prefixes",
        "external_tools",
        "runtime_probes",
        "constructors",
        "constructed_products",
    ):
        manifest_field = "scope_role" if field == "role" else field
        if manifest.get(manifest_field) != expected.get(field):
            raise SystemExit(
                f"{scope} configure manifest {manifest_field} mismatch: "
                f"expected={expected.get(field)!r}, actual={manifest.get(manifest_field)!r}"
            )
    validate_actual_construction(manifest, products, scope)
    return manifest, hashlib.sha256(encoded).hexdigest()


def _canonical_products(values: object, scope: str, field: str) -> list[dict[str, str]]:
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        raise SystemExit(f"{scope} {field} is not a product identity list")
    keys = ("product_id", "frontend", "backend", "role", "protocol_manifest")
    result: list[dict[str, str]] = []
    for item in values:
        assert isinstance(item, dict)
        if set(item) != set(keys) or any(not isinstance(item[key], str) for key in keys):
            raise SystemExit(f"{scope} {field} contains an incomplete product identity")
        result.append({key: item[key] for key in keys})
    return sorted(result, key=lambda item: tuple(item[key] for key in keys))


def validate_actual_construction(
    manifest: dict[str, Any],
    products: dict[str, dict[str, Any]],
    scope: str,
) -> None:
    actual = manifest.get("actual")
    if not isinstance(actual, dict):
        raise SystemExit(f"{scope} configure manifest has no observed construction graph")
    list_fields = (
        "constructors",
        "module_roots",
        "generated_module_roots",
        "dependency_module_roots",
        "external_tools",
        "runtime_probes",
    )
    for field in list_fields:
        values = actual.get(field)
        if not isinstance(values, list) or values != sorted(set(values)):
            raise SystemExit(f"{scope} actual {field} is not a sorted unique list")

    # A scope whose products are unavailable on this host constructs nothing
    # but fail-closed step stubs: no modules, hence no generated/dependency
    # roots and no external tool invocations to observe. Constructors must
    # still match — the fail-closed registration is itself construction.
    fully_stubbed = not actual["module_roots"]
    observed_probes = actual["runtime_probes"]
    declared_probes = sorted(set(manifest["runtime_probes"]))
    # A backend-tool scope may mix portable tools with host-only tools. On a
    # host where none of the declared runtime probes exist, the portable
    # construction remains observable while the host-only dependency graph is
    # replaced by fail-closed step stubs. Accept only the non-empty declared
    # subset in that partition; a capable host must still observe the exact
    # dependency closure below.
    dependency_partitioned = (
        manifest.get("scope_role") == "backend_tools"
        and bool(declared_probes)
        and not observed_probes
        and not fully_stubbed
    )
    for field in (
        "constructors",
        "generated_module_roots",
        "dependency_module_roots",
        "external_tools",
    ):
        observed = actual[field]
        declared = manifest[field]
        if (
            fully_stubbed
            and field in ("generated_module_roots", "dependency_module_roots", "external_tools")
            and not observed
        ):
            continue
        if field == "dependency_module_roots" and dependency_partitioned:
            undeclared = sorted(set(observed) - set(declared))
            if undeclared:
                raise SystemExit(
                    f"{scope} actual dependency_module_roots diverges from catalog: "
                    f"undeclared={undeclared}"
                )
            if not observed:
                raise SystemExit(
                    f"{scope} actual dependency_module_roots diverges from catalog: "
                    "partially constructed backend-tool scope observed no dependencies"
                )
            continue
        if observed != sorted(set(declared)):
            raise SystemExit(
                f"{scope} actual {field} diverges from catalog: "
                f"declared={sorted(set(declared))}, actual={observed}"
            )

    # Runtime probes are host-realizable only where the probing graphs build
    # (Apple frameworks cannot link on Linux). Capability partition, all or
    # nothing: a fully stubbed host observes none; any construction that
    # probes at all must observe exactly the declared set, and an undeclared
    # probe is fatal everywhere.
    undeclared_probes = sorted(set(observed_probes) - set(declared_probes))
    if undeclared_probes:
        raise SystemExit(
            f"{scope} actual runtime_probes diverges from catalog: "
            f"undeclared={undeclared_probes}"
        )
    if observed_probes and observed_probes != declared_probes:
        raise SystemExit(
            f"{scope} actual runtime_probes diverges from catalog: partial "
            f"construction observed={observed_probes}, declared={declared_probes}"
        )

    expected_products = _canonical_products(
        manifest.get("constructed_products"), scope, "constructed_products"
    )
    actual_products = _canonical_products(actual.get("products"), scope, "actual products")
    if actual_products != expected_products:
        raise SystemExit(
            f"{scope} constructed product identities diverge from catalog: "
            f"declared={expected_products!r}, actual={actual_products!r}"
        )
    if manifest.get("scope_role") in {
        "compatibility_tools",
        "backend_tools",
        "gates",
        "unavailable",
    } and actual_products:
        raise SystemExit(f"{scope} non-product scope constructed a released product identity")

    allowed_files: set[str] = set(manifest["module_roots"])
    allowed_files.update(manifest["allowed_module_files"])
    allowed_prefixes = [
        prefix.rstrip("/") + "/" for prefix in manifest["allowed_module_prefixes"]
    ]
    undeclared = [
        path
        for path in actual["module_roots"]
        if path not in allowed_files
        and not any(path.startswith(prefix) for prefix in allowed_prefixes)
    ]
    if undeclared:
        raise SystemExit(f"{scope} constructed undeclared module roots: {undeclared}")


def check_scope(
    repository: Path,
    scope: str,
    catalog_scope: dict[str, Any],
    products: dict[str, dict[str, Any]],
    scopes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    actual, elapsed, output = internal_help(repository, scope)
    wanted = set(catalog_scope["steps"]) | BUILTINS
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing or extra:
        raise SystemExit(
            f"{scope} configure closure mismatch: missing={missing}, extra={extra}"
        )
    manifest, manifest_digest = read_configure_manifest(
        repository, scope, products, scopes
    )
    return {
        "scope": scope,
        "steps": sorted(actual),
        "help_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "configure_seconds": round(elapsed, 6),
        "manifest": manifest,
        "manifest_sha256": manifest_digest,
    }


def check_unknown_scope(repository: Path) -> None:
    command = [
        "zig",
        "build",
        "--help",
        "--build-file",
        str(repository / "build_support/internal_build.zig"),
        "--cache-dir",
        str(repository / ".zig-cache/products/invalid-scope"),
        f"-Drepository-root={repository}",
        "-Dproduct-scope=not_a_product",
    ]
    result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
    if result.returncode == 0 or "unknown internal product scope" not in result.stderr:
        raise SystemExit("unknown internal product scope did not fail closed")


def check_install_ownership(repository: Path) -> None:
    for relative in FOCUSED_OWNER_FILES:
        source = (repository / relative).read_text()
        if "getInstallStep" in source:
            raise SystemExit(f"focused owner mutates global install step: {relative}")
    dispatcher = (repository / "build_support/root_dispatcher.zig").read_text()
    delegation = (repository / "build_support/graph/delegation.zig").read_text()
    if "delegation.addInstallProxy" not in dispatcher or '"aggregate", "stwo-zig"' not in delegation:
        raise SystemExit("root default install is not pinned to the aggregate CLI only")
    if "if (b.pkg_hash.len != 0)" not in dispatcher:
        raise SystemExit("root public modules are not dependency-only")


def inspect_linkage(binary: Path) -> str:
    result = subprocess.run(["otool", "-L", str(binary)], text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"cannot inspect aggregate linkage:\n{result.stderr}")
    return result.stdout.lower()


def validate_application_backends(
    registry: dict[str, Any],
    *,
    metal: bool,
) -> None:
    availability = registry["backend_availability"]["metal-hybrid"]
    if availability is not metal:
        raise SystemExit(
            "aggregate registry capability does not match selected Metal product"
        )
    for application in registry["applications"]:
        advertised = "metal-hybrid" in application.get("backends", [])
        expected = metal and "adapter" not in application
        if advertised is not expected:
            raise SystemExit(
                "aggregate application registry does not match selected products"
            )


def exercise_install(repository: Path, *, metal: bool) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="stwo-install-closure-") as raw:
        prefix = Path(raw)
        command = [
            "zig",
            "build",
            "stwo-zig" if metal else "install",
            "-Doptimize=ReleaseFast",
            "-p",
            str(prefix),
        ]
        if metal:
            command.append("-Daggregate-metal=true")
        result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
        if result.returncode != 0:
            raise SystemExit(f"aggregate install exercise failed:\n{result.stderr}")
        files = sorted(
            path.relative_to(prefix).as_posix()
            for path in prefix.rglob("*")
            if path.is_file()
        )
        if files != ["bin/stwo-zig"]:
            raise SystemExit(f"aggregate install manifest mismatch: {files}")
        executable = prefix / "bin/stwo-zig"
        registry_run = subprocess.run(
            [str(executable), "applications"], text=True, capture_output=True
        )
        if registry_run.returncode != 0:
            raise SystemExit(f"aggregate registry failed:\n{registry_run.stderr}")
        registry = json.loads(registry_run.stdout)
        validate_application_backends(registry, metal=metal)
        linkage = inspect_linkage(executable) if sys.platform == "darwin" else ""
        has_metal = "metal.framework" in linkage and "foundation.framework" in linkage
        if sys.platform == "darwin" and has_metal is not metal:
            raise SystemExit("aggregate binary linkage does not match selected Metal product")
        _, selected_scopes, _ = read_product_catalog(repository, metal=metal)
        aggregate_product = selected_scopes["aggregate"]["constructed_products"]
        expected_backend = "metal" if metal else "cpu"
        if aggregate_product[0]["backend"] != expected_backend:
            raise SystemExit("aggregate catalog identity does not match selected capability")
        return {
            "metal_enabled": metal,
            "files": files,
            "registry_sha256": hashlib.sha256(registry_run.stdout.encode()).hexdigest(),
            "linkage_sha256": hashlib.sha256(linkage.encode()).hexdigest() if linkage else None,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument(
        "--configure-only",
        action="store_true",
        help="Check build graphs and install ownership without building or exercising aggregate binaries",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="Receipt path (defaults to a separate path for configure-only checks)",
    )
    arguments = parser.parse_args()
    repository = arguments.repo.resolve()
    nested_cache = repository / "build_support/.zig-cache"
    nested_cache_preexisting = nested_cache.exists()

    products, scopes, catalog_receipt_sha256 = read_product_catalog(repository)
    receipts, failures = [], []
    for scope, spec in sorted(scopes.items()):
        try:
            receipts.append(check_scope(repository, scope, spec, products, scopes))
        except SystemExit as error:
            failures.append(f"{scope}: {error}")
    if failures:
        raise SystemExit("\n".join(failures))
    check_unknown_scope(repository)
    check_install_ownership(repository)
    installs = []
    if not arguments.configure_only:
        installs.append(exercise_install(repository, metal=False))
        if sys.platform == "darwin":
            installs.append(exercise_install(repository, metal=True))
    if not nested_cache_preexisting and nested_cache.exists():
        raise SystemExit("internal build invocation leaked a build_support/.zig-cache")
    payload = {
        "schema": "stwo-build-configure-closure-v2",
        "result": "pass",
        "default_install_artifacts": ["stwo-zig"],
        "dependency_only_public_modules": ["stwo_core", "stwo_prover", "stwo"],
        "product_catalog_receipt_sha256": catalog_receipt_sha256,
        "scopes": receipts,
        "install_manifests": installs,
        "negative_checks": [
            "unknown-scope-fails",
            "exact-catalog-step-set",
            "actual-constructor-and-product-match",
            "focused-install-mutation-rejected",
            "internal-cache-placement",
        ],
    }
    if arguments.configure_only:
        payload["schema"] = "stwo-build-configure-only-closure-v1"
        payload["installs_exercised"] = False
    receipt = arguments.receipt or Path(
        "zig-out/build-graph/configure-only-closure.json"
        if arguments.configure_only
        else "zig-out/build-graph/configure-closure.json"
    )
    if not receipt.is_absolute():
        receipt = repository / receipt
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    label = "build configure-only closure" if arguments.configure_only else "build configure closure"
    suffix = "; installs not exercised" if arguments.configure_only else ""
    print(f"{label}: PASS ({len(receipts)} catalog scopes{suffix})")
    return 0


class ProductDeclarationError(ValueError):
    pass


class _ProductSource:
    """Literal product-declaration reader, deliberately not a Zig evaluator."""

    def __init__(self, repository: Path):
        self.repository, self.cache = repository.resolve(), {}

    def fail(self, path, name):
        raise ProductDeclarationError(f"{path}::{name}: unsupported or ambiguous product declaration")

    def split(self, tokens, separator=","):
        result, start, depth = [], 0, 0
        for index, token in enumerate(tokens):
            if token in {"(", "[", "{"}:
                depth += 1
            elif token in {")", "]", "}"}:
                depth -= 1
            elif depth == 0 and token == separator:
                result.append(tokens[start:index]); start = index + 1
            if depth < 0:
                raise ProductDeclarationError("unbalanced product declaration")
        if depth:
            raise ProductDeclarationError("unbalanced product declaration")
        return result + ([tokens[start:]] if start < len(tokens) else [])

    def declarations(self, path):
        path = path.resolve()
        if not path.is_relative_to(self.repository) or not path.is_file():
            self.fail(path, "source owner")
        if path in self.cache:
            return self.cache[path]
        text = path.read_text(encoding="utf-8")
        pattern = r'//[^\n]*|/\*.*?\*/|\\\\[^\n]*|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[A-Za-z_][A-Za-z0-9_]*|[^\s]'
        tokens = [m.group() for m in re.finditer(pattern, text, re.DOTALL)
                  if not m.group().startswith(("//", "/*"))]
        declarations = {}
        for statement in self.split(tokens, ";"):
            # Function bodies have no top-level semicolon, so scan their closing braces too.
            remaining = statement
            while remaining:
                offset = 1 if remaining[0] == "pub" else 0
                if len(remaining) <= offset + 1 or remaining[offset] not in {"const", "fn"}:
                    break
                kind, name = remaining[offset:offset + 2]
                if kind == "const":
                    if "=" not in remaining:
                        self.fail(path, name)
                    value, remaining = remaining[remaining.index("=") + 1:], []
                else:
                    depth, body = 0, None
                    for index in range(offset + 2, len(remaining)):
                        token = remaining[index]
                        if token == "{" and depth == 0:
                            body = index; break
                        depth += (token in {"(", "["}) - (token in {")", "]"})
                    if body is None:
                        self.fail(path, name)
                    depth, end = 1, body + 1
                    while end < len(remaining) and depth:
                        depth += (remaining[end] == "{") - (remaining[end] == "}"); end += 1
                    value, remaining = remaining[body + 1:end - 1], remaining[end:]
                if name in declarations:
                    self.fail(path, name)
                declarations[name] = (kind, value, bool(offset))
        self.cache[path] = declarations
        return declarations

    def value(self, path, name, visited=()):
        path = path.resolve()
        key = (path, name)
        if key in visited or name not in self.declarations(path):
            self.fail(path, name)
        kind, tokens, _ = self.declarations(path)[name]
        if kind == "fn":
            if not tokens or tokens[0] != "return" or tokens[-1] != ";":
                self.fail(path, name)
            tokens = tokens[1:-1]
        return self.resolve(path, tokens, (*visited, key))

    def resolve(self, path, tokens, visited=()):
        if "{" in tokens:
            prefix = tokens[:tokens.index("{")]
            if any(token in {"(", ":", "if", "switch", "blk"} for token in prefix):
                self.fail(path, "dynamic literal")
            return path, tokens
        if "(" in tokens:
            opening = tokens.index("(")
            arguments = tokens[opening + 1:-1]
            if (tokens[-1] != ")" or not arguments
                    or not (len(arguments) == 1 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", arguments[0])
                            or len(arguments) == 2 and arguments[0] == ".")):
                self.fail(path, "nonliteral descriptor call")
            reference = tokens[:opening]
        else:
            reference = tokens
        if len(reference) == 1:
            return self.value(path, reference[0], visited)
        if len(reference) == 3 and reference[1] == ".":
            _, alias, _ = self.declarations(path).get(reference[0], (None, [], False))
            if len(alias) == 5 and alias[:3] == ["@", "import", "("] and alias[-1] == ")":
                target = path.parent / json.loads(alias[3])
                return self.value(target, reference[2], visited)
        self.fail(path, " ".join(tokens[:8]))

    def arm(self, path, body, name):
        markers = [i for i in range(len(body) - 3) if body[i:i + 4] == [".", name, "=", ">"]]
        if len(markers) != 1:
            self.fail(path, name)
        branch, depth = [], 0
        for token in body[markers[0] + 4:]:
            if token == "," and depth == 0:
                break
            branch.append(token)
            depth += (token in {"(", "[", "{"}) - (token in {")", "]", "}"})
        return branch

    def fields(self, path, tokens):
        if "{" not in tokens or tokens[-1] != "}":
            self.fail(path, "literal")
        result = {}
        for field in self.split(tokens[tokens.index("{") + 1:-1]):
            if len(field) < 4 or field[0] != "." or field[2] != "=" or field[1] in result:
                self.fail(path, "field")
            result[field[1]] = field[3:]
        return result


def read_product_declarations(repository: Path, *, include_constructed: bool = False) -> dict[str, dict[str, str | None]]:
    """Resolve primary literal identities; not product closure or build evidence."""
    repository = repository.resolve()
    source = _ProductSource(repository)
    specs = repository / "build_support/products/product_specs.zig"
    path, table = source.value(specs, "products")
    records, live_scopes = {}, set()
    for row in source.split(table[table.index("{") + 1:-1]):
        fields = source.fields(path, row)
        scope, constructor = fields.get("scope", []), fields.get("constructor", [])
        if len(scope) != 2 or scope[0] != "." or len(constructor) != 2 or constructor[0] != ".":
            source.fail(path, "scope/constructor")
        if "descriptor" not in fields:
            source.fail(path, "descriptor")
        descriptor_path, descriptor = source.resolve(path, fields["descriptor"])
        descriptor_fields = source.fields(descriptor_path, descriptor)
        if "product" not in descriptor_fields:
            source.fail(descriptor_path, "product")
        product_path, product = source.resolve(descriptor_path, descriptor_fields["product"])
        name = source.fields(product_path, product).get("name", [])
        if len(name) != 1 or not name[0].startswith('"'):
            source.fail(product_path, "name")
        identity = json.loads(name[0])
        if identity in records or (constructor[1] != "unavailable" and scope[1] in live_scopes):
            source.fail(path, "duplicate identity/scope")
        if constructor[1] != "unavailable":
            live_scopes.add(scope[1])
        builder = None
        if constructor[1] != "unavailable":
            matrix = repository / "build_support/products/matrix.zig"
            body = source.declarations(matrix)["construct"][1]
            branch = source.arm(matrix, body, constructor[1])
            if constructor[1] == "aggregate":
                if branch != ["unreachable"]:
                    source.fail(matrix, "aggregate dispatch")
                branch = source.declarations(matrix)["constructAggregate"][1]
            candidates = []
            for i in range(len(branch) - 3):
                if branch[i + 1:i + 4] != [".", "addProduct", "("]:
                    continue
                alias = source.declarations(matrix).get(branch[i], (None, [], False))[1]
                if len(alias) != 5 or alias[:3] != ["@", "import", "("]:
                    source.fail(matrix, "builder import")
                builder_path = (matrix.parent / json.loads(alias[3])).resolve()
                if builder_path == descriptor_path or constructor[1] == "aggregate":
                    declaration = source.declarations(builder_path).get("addProduct")
                    if not declaration or declaration[0] != "fn" or not declaration[2]:
                        source.fail(builder_path, "public addProduct")
                    candidates.append(str(builder_path.relative_to(repository)))
            if len(candidates) != 1:
                source.fail(matrix, "builder ambiguity")
            builder = candidates[0]
        records[identity] = {"scope": scope[1], "constructor": constructor[1], "builder_source": builder,
                             "descriptor_source": str(descriptor_path.relative_to(repository)),
                             "identity_source": str(product_path.relative_to(repository))}
    if include_constructed:
        _add_constructed_products(source, repository, records)
    return records


def _add_constructed_products(source, repository, records):
    catalog, table = source.value(repository / "build_support/products/catalog.zig", "configure")
    for row in source.split(table[table.index("{") + 1:-1]):
        fields = source.fields(catalog, row)
        if fields.get("role") != [".", "package_exports"]:
            continue
        constructors = fields.get("constructors", [])
        constructors = source.split(constructors[constructors.index("{") + 1:-1]) if "{" in constructors else []
        if len(constructors) != 1 or len(constructors[0]) != 1:
            source.fail(catalog, "constructed builder")
        identity = json.loads(constructors[0][0])
        relative, function = identity.rsplit(".", 1)
        builder = (repository / "build_support" / (relative + ".zig")).resolve()
        declaration = source.declarations(builder).get(function)
        if not declaration or declaration[0] != "fn" or not declaration[2]:
            source.fail(builder, "public constructed builder")
        internal = repository / "build_support/internal_build.zig"
        scope = fields.get("scope", [])
        if len(scope) != 2 or scope[0] != ".":
            source.fail(catalog, "constructed scope")
        arm = source.arm(internal, source.declarations(internal)["build"][1], scope[1])
        call = ["@", "import", "(", json.dumps(relative + ".zig"), ")", ".", function, "("]
        if not any(arm[i:i + len(call)] == call for i in range(len(arm))):
            source.fail(internal, "constructed builder binding")
        observed = {}
        body = declaration[1]
        for i in range(1, len(body) - 2):
            if body[i:i + 3] != [".", "recordProduct", "("]:
                continue
            alias = source.declarations(builder).get(body[i - 1], (None, [], False))[1]
            observer = repository / "build_support/graph/construction_observer.zig"
            if (len(alias) != 5 or alias[:3] != ["@", "import", "("]
                    or (builder.parent / json.loads(alias[3])).resolve() != observer):
                source.fail(builder, "recording authority")
            recorded = source.declarations(observer).get("recordProduct")
            if not recorded or recorded[0] != "fn" or not recorded[2]:
                source.fail(observer, "public recordProduct")
            depth, end = 1, i + 3
            while end < len(body) and depth:
                depth += (body[end] == "(") - (body[end] == ")"); end += 1
            arguments = source.split(body[i + 3:end - 1])
            if len(arguments) != 2:
                source.fail(builder, "recorded product")
            expression = arguments[1]
            expression = expression[:-2] if expression[-2:] == ["(", ")"] else expression
            product_path, product = source.resolve(builder, expression)
            name = source.fields(product_path, product).get("name", [])
            if len(name) != 1 or not name[0].startswith('"'):
                source.fail(product_path, "constructed name")
            name = json.loads(name[0])
            if name in observed:
                source.fail(builder, "duplicate recorded identity")
            observed[name] = str(product_path.relative_to(repository))
        declared = set()
        configured = fields.get("constructed_products", [])
        if "{" not in configured:
            source.fail(catalog, "constructed products")
        for item in source.split(configured[configured.index("{") + 1:-1]):
            product = source.fields(catalog, item).get("product_id", [])
            if len(product) != 1 or not product[0].startswith('"') or json.loads(product[0]) not in observed:
                source.fail(catalog, "unrecorded constructed identity")
            name = json.loads(product[0])
            if name in declared:
                source.fail(catalog, "duplicate constructed identity")
            declared.add(name)
            if name not in records:
                records[name] = {"scope": scope[1], "constructor": identity, "builder_source": str(builder.relative_to(repository)),
                                 "descriptor_source": str(catalog.relative_to(repository)), "identity_source": observed[name]}
        if declared != set(observed):
            source.fail(catalog, "constructed/recorded identities differ")


if __name__ == "__main__":
    raise SystemExit(main())
