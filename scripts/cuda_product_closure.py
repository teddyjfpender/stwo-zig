#!/usr/bin/env python3
"""Validate that copied CUDA artifacts have an explicit product disposition."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUDA_ROOT = ROOT / "src/backends/cuda"
SOURCE = CUDA_ROOT / "vendor/upstream"
SOURCE_MANIFEST = CUDA_ROOT / "source_manifest.json"
PRODUCT_MANIFEST = CUDA_ROOT / "product_manifest.json"
NATIVE = CUDA_ROOT / "native"
NATIVE_AOT = CUDA_ROOT / "aot/native"
ORDINARY_ROLES = (
    "resident_candidates",
    "quarantined_migration",
    "deferred_cairo",
    "deferred_features",
    "diagnostic_only",
)


class ProductClosureError(RuntimeError):
    pass


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
    }


def main() -> int:
    result = validate()
    print(
        "CUDA product closure verified: "
        f"{result['classified_ordinary_sources']} ordinary sources classified, "
        f"{result['resident_candidates']} resident candidates, "
        f"{result['quarantined_or_deferred']} quarantined/deferred, "
        f"{result['copied_aot_reference_entries']} copied AOT entries excluded, "
        f"{result['native_aot_entries']} Native AOT entry admitted"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProductClosureError as error:
        raise SystemExit(f"CUDA product closure rejected: {error}") from error
