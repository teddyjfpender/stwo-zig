"""Stage a SHA-pinned secure source export for the existing CUDA AOT builder.

No compilation, subprocess, device or alternative lookup carrier. The returned
set can be selected by an independently pinned product_sets.json declaration;
this does not mark the tracked RISC-V backend proof-capable.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import BuildError
from .secure_identity import (
    IDENTITY_SCHEME, MANIFEST_NAME, MAX_MANIFEST_BYTES, MAX_SOURCE_BYTES,
    bounded_file, catalog_records, digest, digest_bytes, parse_catalog,
    validate_signatures,
)


@dataclass(frozen=True)
class Limits:
    max_entries: int = 23
    max_source_bytes: int = MAX_SOURCE_BYTES
    max_aggregate_bytes: int = 512 * 1024 * 1024


def stage_secure_product(
    export_dir: Path,
    expected_manifest_sha256: str,
    field_header: Path,
    expected_field_sha256: str,
    destination: Path,
    limits: Limits = Limits(),
) -> Path:
    """Publish only a fully validated, bounded source set; success is not NVCC evidence."""
    if (any(type(value) is not int for value in (limits.max_entries, limits.max_source_bytes, limits.max_aggregate_bytes))
            or limits.max_entries <= 0 or limits.max_entries > 23
            or limits.max_source_bytes <= 0 or limits.max_source_bytes > MAX_SOURCE_BYTES
            or limits.max_aggregate_bytes <= 0 or destination.exists() or destination.is_symlink()):
        raise BuildError("invalid secure CUDA staging limits/destination")
    catalog_bytes = bounded_file(export_dir / "source_manifest.json", MAX_MANIFEST_BYTES)
    if digest_bytes(catalog_bytes) != digest(expected_manifest_sha256):
        raise BuildError("secure CUDA source catalog SHA mismatch")
    catalog = parse_catalog(catalog_bytes)
    source = bounded_file(export_dir / "kernels.cu", limits.max_source_bytes)
    if digest_bytes(source) != catalog["source_sha256"]:
        raise BuildError("secure CUDA source SHA mismatch")
    header = bounded_file(field_header, 128 * 1024)
    if digest_bytes(header) != digest(expected_field_sha256):
        raise BuildError("secure CUDA field header SHA mismatch")
    records = catalog_records(catalog)
    if len(records) > limits.max_entries:
        raise BuildError("secure CUDA source entry cap exceeded")
    validate_signatures(source, records)
    manifest = []
    for record in records:
        kind = "witness" if record["abi_schema"] in {"secure_word_witness_v4", "secure_range_witness_v4"} else "constraint"
        label = "secure_" + str(record["kernel_name"])
        manifest.append({
            **record, "kind": kind, "label": label, "module_globals": "none",
            "file": f"{kind}_{label}_{record['cache_key']}.cu",
            "semantic_hash": record["cache_key"], "identity_scheme": IDENTITY_SCHEME,
            "source_manifest_sha256": expected_manifest_sha256,
            "source_sha256": catalog["source_sha256"], "field_sha256": expected_field_sha256,
        })
    manifest.sort(key=lambda entry: (entry["kind"], entry["label"], int(entry["cache_key"], 16)))
    encoded = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    total_bytes = len(records) * len(source) + len(encoded) + len(catalog_bytes) + len(header)
    if total_bytes > limits.max_aggregate_bytes:
        raise BuildError("secure CUDA aggregate source byte cap exceeded")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".secure-aot-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "set"
        (staged / "oods").mkdir(parents=True)
        (staged / "oods/field.cuh").write_bytes(header)
        (staged / MANIFEST_NAME).write_bytes(catalog_bytes)
        for record in manifest:
            (staged / record["file"]).write_bytes(source)
        (staged / "aot_manifest.json").write_bytes(encoded)
        # Use the same strict selection validator that the production builder
        # uses. No per-family unchecked alternate acceptance path.
        from .product_selection import validate_aot_manifest
        validate_aot_manifest(staged, manifest)
        os.rename(staged, destination)
    return destination / "aot_manifest.json"
