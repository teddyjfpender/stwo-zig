"""Command-specific authorities for architecture evidence outputs."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from scripts.architecture_host_gate_lib import aggregate_parity, link_closure
from scripts.architecture_host_gate_lib import performance_readiness
from scripts.architecture_host_gate_lib.capture import sha256_file
from scripts.architecture_host_gate_lib.products import _canonical, _normalize
from scripts.benchmark_delta_lib.product_identity import validate_native_v6_report
from scripts.build_architecture_receipt_lib.model import ReceiptError
from scripts.e2e_interop_lib.controller import SUPPORTED_EXAMPLES
from scripts.e2e_interop_lib.evidence import ARCHIVE_PROTOCOL
from scripts.metal_core_aot_receipt_lib import artifacts as aot_artifacts
from scripts.metal_core_aot_receipt_lib import controller as aot_controller
from scripts.metal_core_aot_receipt_lib.model import BUILD_SCHEMA
from scripts.product_identity_lib import validate_canonical_identity


EXECUTABLE_COMMANDS = {
    "native-cpu-product",
    "native-metal-product",
    "metal-aot-builder",
    "riscv-product",
}
IDENTITY_COMMANDS = {"core-prover", "aggregate"}
LINK_COMMANDS = {
    "native-cpu-link-closure": ("stwo-native-cpu", "zig-out/bin/stwo-zig-native-cpu", None),
    "native-metal-link-closure": ("stwo-native-metal", "zig-out/bin/stwo-zig-native-metal", None),
    "riscv-link-closure": (
        "stwo-riscv-cpu", "zig-out/bin/stwo-zig-riscv-cpu",
        "zig-out/bin/stwo-zig-riscv-cpu-x86_64-linux-musl",
    ),
    "aggregate-link-closure": ("stwo-zig", "zig-out/bin/stwo-zig", None),
}
PROVE_COMMANDS = {
    "focused-parity-prove": "stwo-native-cpu",
    "aggregate-parity-prove": "stwo-zig",
}
AGGREGATE_AIRS = [
    "wide_fibonacci", "xor", "plonk", "state_machine", "blake", "poseidon",
]
PRODUCT_CATALOG_SCOPES = [
    "aggregate", "architecture", "compatibility_tools", "core", "deferred",
    "metal_tools", "native_cpu", "native_metal", "package", "policy", "prover",
    "release", "riscv_cpu", "riscv_cpu_compat", "verification",
]
KNOWN_OUTPUT_COMMANDS = (
    EXECUTABLE_COMMANDS
    | IDENTITY_COMMANDS
    | set(LINK_COMMANDS)
    | set(PROVE_COMMANDS)
    | {
        "product-matrix", "aggregate-parity-compare",
        "configure-closure", "native-rust-oracle", "metal-aot-receipt",
        "native-metal-correctness", "native-metal-formal-matrix",
        "formal-performance-evidence", "performance-readiness",
    }
)


def _strict_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReceiptError(f"duplicate evidence field in {path}: {key}")
            value[key] = item
        return value

    raw = path.read_bytes()
    if not raw or len(raw) > 64 * 1024 * 1024:
        raise ReceiptError(f"architecture evidence size is invalid: {path}")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ReceiptError(f"architecture evidence is not an object: {path}")
    return value


def input_digest(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size == 0:
        raise ReceiptError(f"required architecture input is not a nonempty regular file: {path}")
    return sha256_file(path)


def validate_stdout(command_id: str, path: Path, *, host_role: str) -> None:
    if command_id != "aggregate-applications":
        return
    value = _strict_json(path)
    if set(value) != {
        "schema_version", "backend_availability", "applications", "deferred_adapters",
    } or value["schema_version"] != 1:
        raise ReceiptError("aggregate applications registry schema drifted")
    availability = value["backend_availability"]
    expected_availability = {"cpu": True, "metal-hybrid": host_role == "macos"}
    if availability != expected_availability:
        raise ReceiptError("aggregate backend availability differs from host linkage policy")
    applications = value["applications"]
    if not isinstance(applications, list) or [item.get("air") for item in applications] != AGGREGATE_AIRS:
        raise ReceiptError("aggregate Native application compatibility coverage drifted")
    for item in applications:
        if (
            not isinstance(item, dict)
            or item.get("status") != "release_gated"
            or item.get("backends") != ["cpu", "metal-hybrid"]
        ):
            raise ReceiptError("aggregate Native application policy drifted")
    deferred = value["deferred_adapters"]
    if not isinstance(deferred, list) or len(deferred) > 1:
        raise ReceiptError("aggregate deferred adapter registry is malformed")


def preimage_dependencies(command_id: str, outputs: list[Path], *, root: Path) -> set[Path]:
    """Return exact secondary files consumed by an authoritative output validator."""

    directories: list[Path] = []
    if command_id in {
        "metal-aot-receipt", "native-metal-formal-matrix",
    }:
        directories.extend(path.parent for path in outputs)
    elif command_id == "native-rust-oracle":
        report = _strict_json(outputs[0])
        archive = report.get("archive")
        if not isinstance(archive, dict) or not isinstance(archive.get("directory"), str):
            raise ReceiptError("Native oracle archive dependency is malformed")
        directories.append(Path(archive["directory"]))
    dependencies: set[Path] = set()
    for directory in directories:
        resolved = directory.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_dir():
            raise ReceiptError("architecture secondary preimage directory is not repository-owned")
        dependencies.update(path for path in resolved.rglob("*") if path.is_file())
    return dependencies


def _executables(outputs: list[Path]) -> None:
    if not outputs:
        raise ReceiptError("executable-producing command declared no artifacts")
    for output in outputs:
        metadata = output.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or output.is_symlink()
            or metadata.st_size == 0
            or metadata.st_mode & 0o111 == 0
        ):
            raise ReceiptError(f"generated product is not an executable regular file: {output}")


def _identity_receipt(path: Path) -> dict[str, Any]:
    value = _strict_json(path)
    if value.get("schema") != "stwo-product-artifact-identity-v1":
        raise ReceiptError(f"product artifact identity schema drifted: {path}")
    normalized, artifact, _ = _normalize(value)
    identity = validate_canonical_identity(_canonical(normalized), context=str(path))
    if not isinstance(artifact, str) or len(artifact) != 64:
        raise ReceiptError(f"product artifact digest is missing: {path}")
    return identity


def _identities(outputs: list[Path]) -> None:
    identities = [_identity_receipt(path) for path in outputs if path.suffix == ".json"]
    if not identities:
        raise ReceiptError("identity command emitted no canonical identity receipts")
    names = [identity["name"] for identity in identities]
    if len(names) != len(set(names)):
        raise ReceiptError("identity command emitted duplicate product identities")
    for output in outputs:
        if output.suffix != ".json":
            input_digest(output)


def _product_matrix(path: Path) -> None:
    value = _strict_json(path)
    if list(value) != ["schema", "catalog_sha256", "products", "scopes"]:
        raise ReceiptError("product catalog top-level field order drifted")
    if value["schema"] != "stwo-product-catalog-v2":
        raise ReceiptError("product catalog schema drifted")
    digest = value["catalog_sha256"]
    payload = {
        "schema": value["schema"], "products": value["products"], "scopes": value["scopes"],
    }
    recomputed = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    if not isinstance(digest, str) or digest != recomputed:
        raise ReceiptError("product catalog content address differs from descriptor payload")
    products = value["products"]
    expected = [
        "stwo-zig", "stwo-core", "stwo-prover", "stwo-native-cpu",
        "stwo-riscv-cpu", "stwo-native-metal", "stwo-cairo-cpu",
        "stwo-cairo-metal", "stwo-riscv-metal", "stwo-native-cuda",
        "stwo-cairo-cuda", "stwo-riscv-cuda",
    ]
    if not isinstance(products, list) or [item.get("product_id") for item in products] != expected:
        raise ReceiptError("product catalog descriptor order or coverage is non-canonical")
    product_fields = [
        "scope", "descriptor_schema_version", "product_id", "frontend", "backend",
        "role", "protocol_manifest", "state", "target_support",
        "unsupported_target_reason", "unavailable_reason", "build_step", "test_step",
        "executable", "installed_artifacts", "compatibility_aliases", "release_gates",
        "benchmark_step", "profiler_step", "module_roots", "generated_module_roots",
        "dependency_module_roots", "external_dependencies", "source_closure",
        "required_dynamic_dependencies", "forbidden_dynamic_dependencies", "allowed_files",
        "allowed_prefixes", "configure_allowed_files", "configure_allowed_prefixes",
    ]
    constructible = {"released", "staged", "parity_gated"}
    for item in products:
        if not isinstance(item, dict) or list(item) != product_fields:
            raise ReceiptError("product catalog descriptor fields are incomplete or reordered")
        if (
            item["descriptor_schema_version"] != 1
            or item["state"] not in constructible | {"experimental", "disabled", "unavailable"}
            or item["target_support"] not in {"any", "macos"}
            or item["role"] not in {"cli", "library"}
            or not all(isinstance(item[field], str) and item[field] for field in (
                "scope", "product_id", "frontend", "backend", "protocol_manifest", "build_step",
            ))
        ):
            raise ReceiptError("product catalog descriptor scalar policy drifted")
        for field in (
            "installed_artifacts", "compatibility_aliases", "release_gates", "module_roots",
            "generated_module_roots", "dependency_module_roots", "external_dependencies",
            "required_dynamic_dependencies", "forbidden_dynamic_dependencies", "allowed_files",
            "allowed_prefixes", "configure_allowed_files", "configure_allowed_prefixes",
        ):
            entries = item[field]
            if (
                not isinstance(entries, list)
                or not all(isinstance(entry, str) and entry for entry in entries)
                or len(entries) != len(set(entries))
            ):
                raise ReceiptError(f"product catalog descriptor {field} is malformed")
        available = item["state"] in constructible
        if available and (not item["module_roots"] or item["source_closure"] is None):
            raise ReceiptError("constructible product lacks dependency/source closure")
        if not available and (
            item["unavailable_reason"] is None
            or item["executable"] is not None
            or item["installed_artifacts"]
        ):
            raise ReceiptError("unavailable product exposes an artifact or lacks its reason")
        closure = item["source_closure"]
        if closure is not None:
            closure_fields = [
                "entry_roots", "named_imports", "generated_imports", "allowed_files",
                "allowed_prefixes", "required_dynamic_dependencies",
                "forbidden_dynamic_dependencies",
            ]
            if not isinstance(closure, dict) or list(closure) != closure_fields:
                raise ReceiptError("product catalog source closure fields drifted")
            if (
                closure["allowed_files"] != item["allowed_files"]
                or closure["allowed_prefixes"] != item["allowed_prefixes"]
                or closure["required_dynamic_dependencies"]
                != item["required_dynamic_dependencies"]
                or closure["forbidden_dynamic_dependencies"]
                != item["forbidden_dynamic_dependencies"]
            ):
                raise ReceiptError("product catalog flattened source closure disagrees")
    scopes = value["scopes"]
    scope_fields = [
        "scope", "role", "steps", "product_ids", "module_roots",
        "generated_module_roots", "dependency_module_roots", "allowed_module_files",
        "allowed_module_prefixes", "external_tools", "runtime_probes", "constructors",
        "constructed_products",
    ]
    if not isinstance(scopes, list) or [item.get("scope") for item in scopes] != PRODUCT_CATALOG_SCOPES:
        raise ReceiptError("product catalog scope order or coverage drifted")
    for scope in scopes:
        if not isinstance(scope, dict) or list(scope) != scope_fields:
            raise ReceiptError("product catalog scope fields are incomplete or reordered")
        if scope["role"] not in {
            "product", "package_exports", "compatibility_tools", "backend_tools", "gates",
            "unavailable",
        }:
            raise ReceiptError("product catalog scope role is invalid")
        for field in scope_fields[2:-1]:
            entries = scope[field]
            if not isinstance(entries, list) or not all(
                isinstance(entry, str) and entry for entry in entries
            ):
                raise ReceiptError(f"product catalog scope {field} is malformed")
        if not set(scope["product_ids"]).issubset(set(expected)):
            raise ReceiptError("product catalog scope names an unknown product")
        constructed = scope["constructed_products"]
        if not isinstance(constructed, list) or any(
            not isinstance(entry, dict)
            or set(entry) != {"product_id", "frontend", "backend", "role", "protocol_manifest"}
            or entry["product_id"] not in expected
            for entry in constructed
        ):
            raise ReceiptError("product catalog constructed-product closure is malformed")


def _prove(outputs: list[Path], product: str) -> None:
    if len(outputs) != 2:
        raise ReceiptError("correctness parity command must emit proof and report")
    proof_path = next((path for path in outputs if path.name.endswith("proof.json")), None)
    report_path = next((path for path in outputs if path.name.endswith("report.json")), None)
    if proof_path is None or report_path is None:
        raise ReceiptError("correctness parity proof/report naming drifted")
    _, _, proof_digest = aggregate_parity.artifact(proof_path)
    aggregate_parity.report(report_path, product, proof_digest)


def _configure_closure(path: Path) -> None:
    value = _strict_json(path)
    if set(value) != {
        "schema", "result", "default_install_artifacts", "scopes", "negative_checks",
    }:
        raise ReceiptError("configure-closure receipt fields drifted")
    if (
        value["schema"] != "stwo-build-configure-closure-v1"
        or value["result"] != "pass"
        or value["default_install_artifacts"] != ["stwo-zig"]
        or value["negative_checks"] != [
            "unknown-scope-fails", "exact-step-set", "focused-install-mutation-rejected",
        ]
    ):
        raise ReceiptError("configure-closure receipt did not pass its exact contract")
    scopes = value["scopes"]
    if (
        not isinstance(scopes, list)
        or not all(isinstance(item, dict) for item in scopes)
        or [item.get("scope") for item in scopes] != PRODUCT_CATALOG_SCOPES
    ):
        raise ReceiptError("configure-closure receipt scope coverage drifted")
    for item in scopes:
        if set(item) != {"scope", "steps", "help_sha256", "configure_seconds"}:
            raise ReceiptError("configure-closure scope receipt fields drifted")
        if not isinstance(item["steps"], list) or not item["steps"]:
            raise ReceiptError("configure-closure scope has no configured steps")


def _native_oracle(path: Path) -> None:
    value = _strict_json(path)
    required = {
        "status", "schema_version", "exchange_mode", "upstream_commit", "rust_toolchain",
        "summary", "mutation_coverage", "cases", "steps", "artifacts", "failure",
        "generated_at_unix", "duration_seconds", "archive",
    }
    if set(value) != required or value["status"] != "ok" or value["failure"] is not None:
        raise ReceiptError("Native Rust-oracle report did not pass its exact schema")
    summary = value["summary"]
    examples = list(SUPPORTED_EXAMPLES)
    if (
        not isinstance(summary, dict)
        or summary.get("examples") != examples
        or summary.get("cases_total") != len(examples) * 2
        or summary.get("cases_passed") != len(examples) * 2
        or summary.get("cases_failed") != 0
        or summary.get("tamper_cases_failed") != 0
        or summary.get("tamper_cases_passed") != summary.get("tamper_cases_total")
    ):
        raise ReceiptError("Native Rust-oracle report lacks all-six AIR/tamper coverage")
    cases = value["cases"]
    if not isinstance(cases, list) or [item.get("example") for item in cases] != examples or any(
        item.get("status") != "ok" or len(item.get("directions", [])) != 2 for item in cases
    ):
        raise ReceiptError("Native Rust-oracle exchange directions are incomplete")
    archive = value["archive"]
    if not isinstance(archive, dict) or archive.get("protocol") != ARCHIVE_PROTOCOL:
        raise ReceiptError("Native Rust-oracle content-addressed archive is missing")
    receipt = Path(archive["directory"]) / archive["receipt_path"]
    if sha256_file(receipt) != archive.get("receipt_sha256"):
        raise ReceiptError("Native Rust-oracle archived receipt digest drifted")


def _matrix(path: Path, *, formal: bool) -> None:
    value = _strict_json(path)
    validate_native_v6_report(value, str(path))
    configuration = value.get("configuration", {})
    summary = value.get("summary", {})
    if configuration.get("formal") is not formal:
        raise ReceiptError("Native matrix formal classification drifted")
    if (
        summary.get("all_proofs_verified_and_byte_identical") is not True
        or summary.get("all_cross_backend_proofs_identical") is not True
        or summary.get("all_rust_oracles_verified") is not True
        or value.get("correctness_scope", {}).get("final_correctness_oracle")
        != "pinned Rust Stwo"
    ):
        raise ReceiptError("Native matrix lacks CPU/Metal/Rust three-way acceptance")
    if formal and (
        configuration.get("warmups_per_lane", 0) < 10
        or configuration.get("samples_per_lane", 0) < 10
        or summary.get("all_rows_meet_stability_contract") is not True
        or summary.get("all_rows_headline_eligible") is not True
    ):
        raise ReceiptError("formal Native matrix is below the epoch sampling contract")


def _native_metal_correctness(path: Path) -> None:
    value = _strict_json(path)
    if set(value) != {"schema", "status", "workload", "proof", "oracle", "backend"}:
        raise ReceiptError("Native Metal correctness receipt fields drifted")
    if (
        value["schema"] != "build-architecture-native-metal-correctness-v1"
        or value["status"] != "PASS"
        or value["workload"] != {
            "air": "wide_fibonacci", "log_n_rows": 8, "sequence_len": 8,
            "protocol": "smoke",
        }
    ):
        raise ReceiptError("Native Metal correctness statement drifted")
    proof = value["proof"]
    oracle = value["oracle"]
    backend = value["backend"]
    if (
        not isinstance(proof, dict)
        or set(proof) != {
            "cpu_artifact_sha256", "metal_artifact_sha256", "proof_sha256",
            "byte_identical",
        }
        or proof["byte_identical"] is not True
        or proof["cpu_artifact_sha256"] != proof["metal_artifact_sha256"]
        or any(
            not isinstance(proof.get(field), str) or len(proof[field]) != 64
            for field in ("cpu_artifact_sha256", "metal_artifact_sha256", "proof_sha256")
        )
        or not isinstance(oracle, dict)
        or set(oracle) != {
            "binary_sha256", "cpu_accepted", "metal_accepted", "mutation_rejected",
        }
        or any(oracle.get(field) is not True for field in (
            "cpu_accepted", "metal_accepted", "mutation_rejected",
        ))
        or not isinstance(oracle.get("binary_sha256"), str)
        or len(oracle["binary_sha256"]) != 64
        or backend != {
            "runtime_initialized": True,
            "metal_dispatches_positive": True,
            "cpu_fallbacks_zero": True,
        }
    ):
        raise ReceiptError("Native Metal CPU/Rust oracle parity is incomplete")


def _metal_aot(path: Path, candidate: str) -> None:
    receipt, _ = aot_artifacts.read_receipt(path, BUILD_SCHEMA)
    recorded = aot_controller.require_build_receipt(receipt, candidate)
    bundles = {
        name: aot_artifacts.load_bundle(path.parent / name)
        for name in ("build-a", "build-b")
    }
    for name, bundle in bundles.items():
        aot_controller.require_recorded_bundle(recorded[name], bundle, name)
    aot_artifacts.require_reproducible(bundles["build-a"], bundles["build-b"])


def validate_outputs(
    command_id: str, outputs: list[Path], inputs: list[Path], *, root: Path, candidate: str,
    host_role: str | None = None,
    reinspect_link_binaries: bool = True,
) -> dict[str, str]:
    """Validate output meaning and return exact digests; unknown authorities fail closed."""

    if command_id not in KNOWN_OUTPUT_COMMANDS:
        raise ReceiptError(f"no authoritative output validator for command: {command_id}")
    if not outputs:
        raise ReceiptError(f"evidence command declared no generated output: {command_id}")
    if command_id in EXECUTABLE_COMMANDS:
        _executables(outputs)
    elif command_id in IDENTITY_COMMANDS:
        _identities(outputs)
    elif command_id == "product-matrix":
        _product_matrix(outputs[0])
    elif command_id in LINK_COMMANDS:
        product, binary, static_binary = LINK_COMMANDS[command_id]
        link_closure.validate_receipt(
            outputs[0], product=product, binary=root / binary,
            static_binary=root / static_binary if static_binary is not None else None,
            host_role=host_role,
            logical_binary=Path(binary),
            logical_static_binary=Path(static_binary) if static_binary is not None else None,
            reinspect_binary=reinspect_link_binaries,
        )
    elif command_id in PROVE_COMMANDS:
        _prove(outputs, PROVE_COMMANDS[command_id])
    elif command_id == "aggregate-parity-compare":
        by_name = {path.name: path for path in inputs}
        recomputed = aggregate_parity.validate(
            focused_path=by_name["focused-proof.json"],
            aggregate_path=by_name["aggregate-proof.json"],
            focused_report_path=by_name["focused-report.json"],
            aggregate_report_path=by_name["aggregate-report.json"],
            focused_verify_path=next(
                path for path in inputs if "focused-parity-verify" in path.name
            ),
            aggregate_verify_path=next(
                path for path in inputs if "aggregate-parity-verify" in path.name
            ),
        )
        if aggregate_parity.validate_receipt(outputs[0]) != recomputed:
            raise ReceiptError("aggregate parity receipt differs from authoritative recomputation")
    elif command_id == "configure-closure":
        _configure_closure(outputs[0])
    elif command_id == "native-rust-oracle":
        _native_oracle(outputs[0])
    elif command_id == "native-metal-correctness":
        _native_metal_correctness(outputs[0])
    elif command_id == "native-metal-formal-matrix":
        _matrix(outputs[0], formal=True)
    elif command_id == "metal-aot-receipt":
        _metal_aot(outputs[0], candidate)
    elif command_id == "formal-performance-evidence":
        raise ReceiptError(
            "BG-14 remains NO-GO until an epoch-2 architecture performance validator and baseline exist"
        )
    elif command_id == "performance-readiness":
        performance_readiness.validate(
            outputs[0], root,
            root / "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json",
        )
    return {path.relative_to(root).as_posix(): input_digest(path) for path in outputs}
