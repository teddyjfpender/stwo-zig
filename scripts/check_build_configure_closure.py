#!/usr/bin/env python3
"""Validate configured build graphs against the emitted typed catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
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
        "--receipt",
        type=Path,
        default=Path("zig-out/build-graph/configure-closure.json"),
    )
    arguments = parser.parse_args()
    repository = arguments.repo.resolve()
    nested_cache = repository / "build_support/.zig-cache"
    nested_cache_preexisting = nested_cache.exists()

    products, scopes, catalog_receipt_sha256 = read_product_catalog(repository)
    receipts = [
        check_scope(repository, scope, spec, products, scopes)
        for scope, spec in sorted(scopes.items())
    ]
    check_unknown_scope(repository)
    check_install_ownership(repository)
    installs = [exercise_install(repository, metal=False)]
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
    receipt = arguments.receipt
    if not receipt.is_absolute():
        receipt = repository / receipt
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"build configure closure: PASS ({len(receipts)} catalog scopes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
