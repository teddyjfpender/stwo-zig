#!/usr/bin/env python3
"""Validate that copied CUDA artifacts have an explicit product disposition."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA_ROOT = ROOT / "src/backends/cuda"
SOURCE = CUDA_ROOT / "vendor/upstream"
SOURCE_MANIFEST = CUDA_ROOT / "source_manifest.json"
PRODUCT_MANIFEST = CUDA_ROOT / "product_manifest.json"
NATIVE = CUDA_ROOT / "native"
NATIVE_AOT = CUDA_ROOT / "aot/native"
ABI = CUDA_ROOT / "abi"
HOST_AUTHORITY = CUDA_ROOT / "vendor/host_authority"
ORDINARY_ROLES = (
    "resident_candidates",
    "quarantined_migration",
    "deferred_cairo",
    "deferred_features",
    "diagnostic_only",
)


class ProductClosureError(RuntimeError):
    pass


ZIG_EXTERN_RE = re.compile(r'pub\s+extern\s+"c"\s+fn\s+(stwo_[A-Za-z0-9_]+)\s*\(')
C_EXTERN_RE = re.compile(
    r'extern\s+"C"(?:(?!extern\s+"C").){0,320}?'
    r"\b(stwo_[A-Za-z0-9_]+)\s*\(",
    re.DOTALL,
)
RUST_EXTERN_RE = re.compile(r"\bpub\s+fn\s+(stwo_[A-Za-z0-9_]+)\s*\(")


def symbols(paths: list[Path], pattern: re.Pattern[str]) -> set[str]:
    found: set[str] = set()
    for path in paths:
        found.update(pattern.findall(path.read_text(encoding="utf-8", errors="strict")))
    return found


def validate_abi(
    product: dict[str, object],
    ordinary: dict[str, object],
) -> dict[str, int]:
    policy = product.get("abi")
    if not isinstance(policy, dict):
        raise ProductClosureError("CUDA ABI policy is absent")
    raw_relative = policy.get("rust_authority")
    if not isinstance(raw_relative, str):
        raise ProductClosureError("CUDA ABI Rust authority is absent")
    raw_path = HOST_AUTHORITY / raw_relative
    if not raw_path.is_file():
        raise ProductClosureError(f"CUDA ABI Rust authority is absent: {raw_path}")

    abi_files = sorted(ABI.rglob("*.zig"))
    active = symbols(abi_files, ZIG_EXTERN_RE)
    if not active:
        raise ProductClosureError("resident CUDA ABI is empty")

    forbidden = policy.get("forbidden_symbol_fragments")
    if not isinstance(forbidden, list) or not forbidden:
        raise ProductClosureError("forbidden CUDA ABI symbol policy is absent")
    bad = sorted(
        symbol
        for symbol in active
        if any(str(fragment) in symbol for fragment in forbidden)
    )
    if bad:
        raise ProductClosureError(f"resident CUDA ABI exposes legacy policy: {bad}")

    selected_names = ordinary.get("resident_candidates")
    if not isinstance(selected_names, list):
        raise ProductClosureError("CUDA resident source selection is absent")
    selected = [SOURCE / str(name) for name in selected_names]
    native = sorted(NATIVE.rglob("*.cpp"))
    defined = symbols(selected + native, C_EXTERN_RE)

    generated = policy.get("generated_symbols")
    zig_owned = policy.get("zig_owned_symbols")
    if (
        not isinstance(generated, list)
        or generated != sorted(generated)
        or not isinstance(zig_owned, list)
        or zig_owned != sorted(zig_owned)
    ):
        raise ProductClosureError("generated and Zig-owned ABI symbols must be sorted arrays")
    generated_symbols = {str(name) for name in generated}
    zig_owned_symbols = {str(name) for name in zig_owned}
    defined.update(generated_symbols)

    missing_definitions = sorted(active - defined)
    if missing_definitions:
        raise ProductClosureError(
            f"resident CUDA ABI has no selected implementation: {missing_definitions}"
        )

    rust_symbols = symbols([raw_path], RUST_EXTERN_RE)
    missing_authority = sorted(active - rust_symbols - zig_owned_symbols - generated_symbols)
    if missing_authority:
        raise ProductClosureError(
            f"resident CUDA ABI is absent from pinned Rust declarations: {missing_authority}"
        )
    unexpected_owned = sorted(zig_owned_symbols - defined)
    if unexpected_owned:
        raise ProductClosureError(
            f"Zig-owned CUDA ABI has no native definition: {unexpected_owned}"
        )
    return {
        "active_symbols": len(active),
        "rust_authority_symbols": len(active & rust_symbols),
        "zig_owned_symbols": len(active & zig_owned_symbols),
        "generated_symbols": len(active & generated_symbols),
    }


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProductClosureError(f"cannot decode {path}: {error}") from error


def validate() -> dict[str, object]:
    authority = read_json(SOURCE_MANIFEST)
    product = read_json(PRODUCT_MANIFEST)
    if not isinstance(authority, dict) or not isinstance(product, dict):
        raise ProductClosureError("CUDA manifests must be JSON objects")
    if product.get("schema") != "stwo-zig-cuda-product-closure-v1":
        raise ProductClosureError("unsupported CUDA product-closure schema")
    if product.get("source_authority_sha256") != authority.get("closure_sha256"):
        raise ProductClosureError("product closure is not pinned to the source authority")

    expected = {
        str(entry["path"])
        for entry in authority.get("files", [])
        if str(entry["path"]).endswith((".cu", ".cpp"))
        and "generated/" not in str(entry["path"])
    }
    ordinary = product.get("ordinary")
    if not isinstance(ordinary, dict):
        raise ProductClosureError("ordinary CUDA disposition is absent")
    classified: dict[str, str] = {}
    for role in ORDINARY_ROLES:
        paths = ordinary.get(role)
        if not isinstance(paths, list) or paths != sorted(paths):
            raise ProductClosureError(f"CUDA role {role} must be a sorted array")
        for raw in paths:
            path = str(raw)
            if path in classified:
                raise ProductClosureError(
                    f"CUDA source {path} has both {classified[path]} and {role} roles"
                )
            classified[path] = role
    actual = set(classified)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProductClosureError(
            f"CUDA source classification mismatch: missing={missing}, extra={extra}"
        )

    generated = product.get("generated_aot")
    if not isinstance(generated, dict):
        raise ProductClosureError("generated AOT disposition is absent")
    copied_aot = read_json(SOURCE / "generated/aot_manifest.json")
    if not isinstance(copied_aot, list) or len(copied_aot) != generated.get(
        "copied_entry_count"
    ):
        raise ProductClosureError("copied AOT disposition count is stale")
    if generated.get("copied_disposition") != "cairo_reference_only":
        raise ProductClosureError("copied Cairo AOT sources cannot enter the Native product")
    native_aot = read_json(NATIVE_AOT / "aot_manifest.json")
    if not isinstance(native_aot, list) or len(native_aot) != generated.get(
        "native_entry_count"
    ):
        raise ProductClosureError("Native AOT disposition count is stale")
    native_labels = {str(entry.get("label", "")) for entry in native_aot}
    if not native_labels or any("cairo" in label for label in native_labels):
        raise ProductClosureError("Native AOT manifest contains a foreign frontend")

    native_files = sorted(path for path in NATIVE.rglob("*") if path.is_file())
    native_payload = "\n".join(
        path.read_text(encoding="utf-8", errors="strict") for path in native_files
    )
    forbidden = product.get("forbidden_product_tokens")
    if not isinstance(forbidden, list) or not forbidden:
        raise ProductClosureError("forbidden CUDA product tokens are absent")
    hits = [str(token) for token in forbidden if str(token) in native_payload]
    if hits:
        raise ProductClosureError(f"Zig-owned CUDA runtime contains forbidden policy: {hits}")

    abi = validate_abi(product, ordinary)

    digest = hashlib.sha256()
    for path in native_files:
        relative = path.relative_to(NATIVE).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "little"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
    return {
        "classified_ordinary_sources": len(classified),
        "resident_candidates": len(ordinary["resident_candidates"]),
        "quarantined_or_deferred": len(classified)
        - len(ordinary["resident_candidates"]),
        "copied_aot_reference_entries": len(copied_aot),
        "native_aot_entries": len(native_aot),
        "native_runtime_sha256": digest.hexdigest(),
        **abi,
    }


def main() -> int:
    result = validate()
    print(
        "CUDA product closure verified: "
        f"{result['classified_ordinary_sources']} ordinary sources classified, "
        f"{result['resident_candidates']} resident candidates, "
        f"{result['quarantined_or_deferred']} quarantined/deferred, "
        f"{result['copied_aot_reference_entries']} copied AOT entries excluded, "
        f"{result['native_aot_entries']} Native AOT entry admitted, "
        f"{result['active_symbols']} resident ABI symbols verified"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProductClosureError as error:
        raise SystemExit(f"CUDA product closure rejected: {error}") from error
