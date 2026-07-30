#!/usr/bin/env python3
"""Derive the authenticated Native recorded-witness AOT source product."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "src/backends/cuda/vendor/upstream/generated"
PRODUCT = ROOT / "src/backends/cuda/aot/native"
SCHEMA = "recorded_witness_v1"
EXPECTED_ISOLATED_SOURCES = 7
INLINE_MUL = (
    b"static __device__ __forceinline__ void stwo_wit_deduce_felt_mul(\n"
)
ISOLATED_MUL = (
    b"static __device__ __noinline__ void stwo_wit_deduce_felt_mul(\n"
)


class ProductError(RuntimeError):
    pass


def derive_source(authority: bytes) -> bytes:
    occurrences = authority.count(INLINE_MUL)
    if occurrences > 1 or ISOLATED_MUL in authority:
        raise ProductError("recorded witness authority lost the FeltMul boundary")
    return (
        authority.replace(INLINE_MUL, ISOLATED_MUL)
        if occurrences == 1
        else authority
    )


def load_manifest(path: Path) -> list[dict[str, object]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProductError(f"cannot read AOT manifest {path}: {error}") from error
    if not isinstance(value, list):
        raise ProductError(f"AOT manifest is not an array: {path}")
    return value


def recorded_entries(
    manifest: list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for entry in manifest:
        if entry.get("abi_schema") != SCHEMA:
            continue
        file_name = str(entry.get("file", ""))
        if not file_name or file_name in result:
            raise ProductError("recorded witness manifest has invalid files")
        result[file_name] = entry
    return result


def expected_product() -> list[tuple[Path, bytes, dict[str, object]]]:
    authority_entries = recorded_entries(
        load_manifest(AUTHORITY / "aot_manifest.json")
    )
    product_manifest = load_manifest(PRODUCT / "aot_manifest.json")
    product_entries = recorded_entries(product_manifest)
    if not product_entries or set(product_entries) - set(authority_entries):
        raise ProductError("Native recorded witness product lost its authority")
    result: list[tuple[Path, bytes, dict[str, object]]] = []
    isolated_sources = 0
    identity_fields = (
        "abi_schema",
        "cache_key",
        "file",
        "kernel_name",
        "kind",
        "label",
        "program_identity",
        "semantic_hash",
    )
    for file_name in sorted(product_entries):
        authority_entry = authority_entries[file_name]
        product_entry = product_entries[file_name]
        if any(
            authority_entry.get(field) != product_entry.get(field)
            for field in identity_fields
        ):
            raise ProductError(
                f"Native recorded witness identity drift: {file_name}"
            )
        authority_source = (AUTHORITY / file_name).read_bytes()
        isolated_sources += int(INLINE_MUL in authority_source)
        source = derive_source(authority_source)
        result.append((PRODUCT / file_name, source, product_entry))
    if isolated_sources != EXPECTED_ISOLATED_SOURCES:
        raise ProductError(
            "recorded witness product has an unexpected FeltMul surface"
        )
    return result


def verify() -> int:
    entries = expected_product()
    for path, expected, entry in entries:
        if not path.is_file() or path.read_bytes() != expected:
            raise ProductError(f"stale Native recorded witness source: {path.name}")
        digest = hashlib.sha256(expected).hexdigest()
        if entry.get("source_sha256") != digest:
            raise ProductError(f"stale Native recorded witness digest: {path.name}")
    return len(entries)


def atomic_write(path: Path, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        stream.write(payload)
        staging = Path(stream.name)
    os.replace(staging, path)


def write() -> int:
    manifest_path = PRODUCT / "aot_manifest.json"
    manifest = load_manifest(manifest_path)
    manifest_entries = recorded_entries(manifest)
    entries = expected_product()
    for path, source, _ in entries:
        atomic_write(path, source)
        manifest_entries[path.name]["source_sha256"] = hashlib.sha256(
            source
        ).hexdigest()
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    atomic_write(manifest_path, encoded)
    return verify()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the Native product with its deterministic derivation",
    )
    args = parser.parse_args()
    count = write() if args.write else verify()
    print(f"Native recorded witness AOT product verified: {count} sources")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProductError as error:
        raise SystemExit(f"recorded witness AOT product rejected: {error}") from error
