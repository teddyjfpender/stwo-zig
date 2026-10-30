"""Authenticate offline framework kernels without granting proof authority.

Runtime independently exports the current admitted components and derives each
executable identity. This catalog pins source bytes, field helpers and the exact
launch ABI; it neither enables the resident RISC-V product nor accepts proofs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from .aot_pack import ABI_SCHEMAS
from .errors import BuildError
from .secure_identity import bounded_file, digest, digest_bytes, key_for, validate_signatures

SCHEMA = "framework_polynomial_composition_v1"
FRACTIONS_SCHEMA = "framework_interaction_fractions_v1"
SCAN_SCHEMA = "framework_interaction_scan_v1"
SCHEMAS = {SCHEMA, FRACTIONS_SCHEMA, SCAN_SCHEMA}
SCAN_HELPERS = (
    "stwo_cuda_framework_scan_blocks_v1_",
    "stwo_cuda_framework_scan_totals_v1_",
    "stwo_cuda_framework_scan_finalize_v1_",
)
IDENTITY_SCHEME = "sha256-framework-polynomial-source-catalog-v1"
MANIFEST_NAME = "framework_source_manifest.json"
MAX_ENTRIES = 128
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_AGGREGATE_BYTES = 512 * 1024 * 1024


def parse_catalog(payload: bytes) -> tuple[dict, list[dict]]:
    if not payload or len(payload) > MAX_MANIFEST_BYTES:
        raise BuildError("framework CUDA catalog byte cap exceeded")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BuildError("framework CUDA catalog has duplicate JSON fields")
            result[key] = value
        return result

    try:
        catalog = json.loads(payload, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeDecodeError) as error:
        raise BuildError("framework CUDA catalog is not JSON") from error
    fields = {"version", "target", "scope", "source_file", "source_sha256", "programs",
              "dynamic_claims_and_challenges", "proof_acceptance_authority", "device_compiled", "device_executed"}
    if not isinstance(catalog, dict) or set(catalog) != fields or \
            type(catalog["version"]) is not int or catalog["version"] not in (1, 2) or \
            catalog["target"] != "cuda" or catalog["scope"] != {
                1: "riscv-recursive-parent-composition",
                2: "riscv-recursive-parent-composition-and-interaction",
            }[catalog["version"]] or \
            catalog["source_file"] != "kernels.cu" or catalog["dynamic_claims_and_challenges"] is not True or \
            any(catalog[field] is not False for field in ("proof_acceptance_authority", "device_compiled", "device_executed")):
        raise BuildError("framework CUDA catalog is not canonical")
    digest(catalog["source_sha256"])
    programs = catalog["programs"]
    if not isinstance(programs, list) or not 1 <= len(programs) <= (64 if catalog["version"] == 1 else MAX_ENTRIES):
        raise BuildError("framework CUDA kernel roster exceeds bounds")
    records = []
    helpers = set()
    for program in programs:
        if not isinstance(program, dict) or set(program) != {
            "executable_identity", "kernel", "abi_schema", "argument_count", "cache_key"
        }:
            raise BuildError("framework CUDA program is malformed")
        identity = digest(program["executable_identity"])
        schema = SCHEMA
        prefix = "stwo_cuda_framework_v1_"
        argc = 11
        if catalog["version"] == 2 and program["abi_schema"] == ABI_SCHEMAS[FRACTIONS_SCHEMA]:
            schema, prefix, argc = FRACTIONS_SCHEMA, "stwo_cuda_framework_interaction_v1_", 8
        elif catalog["version"] == 2 and program["abi_schema"] == ABI_SCHEMAS[SCAN_SCHEMA]:
            schema, argc = SCAN_SCHEMA, 6
            prefixes = [candidate for candidate in SCAN_HELPERS if program["kernel"] == candidate + identity]
            if len(prefixes) != 1 or prefixes[0] in helpers:
                raise BuildError("framework CUDA scan helper roster mismatch")
            prefix = prefixes[0]
            helpers.add(prefix)
        if program["kernel"] != prefix + identity or \
                type(program["abi_schema"]) is not int or program["abi_schema"] != ABI_SCHEMAS[schema] or \
                type(program["argument_count"]) is not int or program["argument_count"] != argc or \
                type(program["cache_key"]) is not int or program["cache_key"] != key_for(identity):
            raise BuildError("framework CUDA executable identity/ABI mismatch")
        records.append({"kernel_name": program["kernel"], "program_identity": identity,
                        "abi_schema": schema, "argument_count": argc, "cache_key": f"{key_for(identity):016x}"})
    if len({r["cache_key"] for r in records}) != len(records):
        raise BuildError("framework CUDA executable cache keys collide")
    if catalog["version"] == 2 and (helpers != set(SCAN_HELPERS) or \
            {r["abi_schema"] for r in records} != SCHEMAS):
        raise BuildError("framework CUDA interaction catalog is incomplete")
    return catalog, records


def stage_framework_product(export_dir: Path, expected_manifest_sha256: str,
                            field_header: Path, expected_field_sha256: str, destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise BuildError("framework CUDA destination already exists")
    payload = bounded_file(export_dir / "source_manifest.json", MAX_MANIFEST_BYTES)
    if digest_bytes(payload) != digest(expected_manifest_sha256):
        raise BuildError("framework CUDA source catalog SHA mismatch")
    catalog, records = parse_catalog(payload)
    source = bounded_file(export_dir / "kernels.cu", MAX_SOURCE_BYTES)
    if digest_bytes(source) != catalog["source_sha256"]:
        raise BuildError("framework CUDA source SHA mismatch")
    header = bounded_file(field_header, 128 * 1024)
    if digest_bytes(header) != digest(expected_field_sha256):
        raise BuildError("framework CUDA field header SHA mismatch")
    validate_signatures(source, records)
    manifest = [{**record, "kind": "constraint", "module_globals": "none",
                 "label": "framework_" + record["kernel_name"],
                 "file": f"constraint_framework_{record['kernel_name']}_{record['cache_key']}.cu",
                 "semantic_hash": record["cache_key"], "identity_scheme": IDENTITY_SCHEME,
                 "source_manifest_sha256": expected_manifest_sha256, "source_sha256": catalog["source_sha256"],
                 "field_sha256": expected_field_sha256} for record in records]
    manifest.sort(key=lambda r: (r["kind"], r["label"], int(r["cache_key"], 16)))
    encoded = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    if len(records) * len(source) + len(payload) + len(header) + len(encoded) > MAX_AGGREGATE_BYTES:
        raise BuildError("framework CUDA aggregate source byte cap exceeded")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".framework-aot-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "set"
        (staged / "oods").mkdir(parents=True)
        (staged / "oods/field.cuh").write_bytes(header)
        (staged / MANIFEST_NAME).write_bytes(payload)
        for record in manifest:
            (staged / record["file"]).write_bytes(source)
        (staged / "aot_manifest.json").write_bytes(encoded)
        from .product_selection import validate_aot_manifest
        validate_aot_manifest(staged, manifest)
        os.rename(staged, destination)
    return destination / "aot_manifest.json"


def validate_framework_identity(generated_dir: Path, entry: dict, base_fields: set[str], index: int) -> None:
    required = base_fields | {"identity_scheme", "source_manifest_sha256", "source_sha256", "field_sha256", "argument_count"}
    if set(entry) != required or entry.get("identity_scheme") != IDENTITY_SCHEME or entry.get("module_globals") != "none":
        raise BuildError(f"AOT manifest entry {index} has a non-canonical framework identity")
    payload = bounded_file(generated_dir / MANIFEST_NAME, MAX_MANIFEST_BYTES)
    if digest_bytes(payload) != digest(entry["source_manifest_sha256"]):
        raise BuildError("framework CUDA source catalog SHA mismatch")
    catalog, records = parse_catalog(payload)
    source = bounded_file(generated_dir / str(entry["file"]), MAX_SOURCE_BYTES)
    if digest_bytes(source) != digest(entry["source_sha256"]) or entry["source_sha256"] != catalog["source_sha256"]:
        raise BuildError("framework CUDA source SHA mismatch")
    header = bounded_file(generated_dir / "oods/field.cuh", 128 * 1024)
    if digest_bytes(header) != digest(entry["field_sha256"]):
        raise BuildError("framework CUDA field header SHA mismatch")
    matches = [r for r in records if r["program_identity"] == entry["program_identity"]]
    if len(matches) != 1 or any(entry[key] != matches[0][key] for key in matches[0]) or \
            entry["semantic_hash"] != entry["cache_key"] or entry["kind"] != "constraint" or \
            entry["label"] != "framework_" + str(entry["kernel_name"]):
        raise BuildError("framework CUDA catalog entry identity mismatch")
    validate_signatures(source, records)
