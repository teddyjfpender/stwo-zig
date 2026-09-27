"""Strict identities shared by secure source staging and the existing AOT pack.

This admits a caller-pinned offline source catalog, never a proof or device
receipt. Runtime independently derives typed source identities and pins cubins.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .aot_pack import ABI_SCHEMAS
from .errors import BuildError

IDENTITY_SCHEME = "sha256-typed-secure-source-catalog-v1"
SECURE_SCHEMAS = {name for name, value in ABI_SCHEMAS.items() if 23 <= value <= 29}
MANIFEST_NAME = "secure_source_manifest.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}")
KERNEL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
HELPERS = {
    "stwo_cuda_range16_inverse_table_v1": ("secure_range_inverse_v1", 2),
    "stwo_cuda_secure_scan_block_v1": ("secure_scan_v1", 5),
    "stwo_cuda_secure_scan_carry_v1": ("secure_scan_v1", 5),
    "stwo_cuda_secure_totals_v1": ("secure_mean_v1", 4),
    "stwo_cuda_secure_mean_v1": ("secure_mean_v1", 4),
    "stwo_cuda_word_memory_witness_v4": ("secure_word_witness_v4", 5),
    "stwo_cuda_range16_witness_v4": ("secure_range_witness_v4", 3),
}
KINDS = {
    "word_equations_v4": ("secure_polynomial_equations_v1", 63),
    "word_fractions_v4": ("secure_polynomial_fractions_v1", 17),
    "range16_equations_v4": ("secure_polynomial_equations_v1", 2),
    "range16_fractions_v4": ("secure_polynomial_fractions_v1", 2),
    "ram_lanes_equations_v1": ("secure_polynomial_equations_v1", 117),
    "ram_lanes_fractions_v1": ("secure_polynomial_fractions_v1", 23),
}
LEGACY_KINDS = tuple(kind for kind in KINDS if not kind.startswith("ram_lanes_"))


def roster_authority(programs: list[dict[str, object]]) -> str:
    """Catalog custody only: runtime still derives each typed program independently."""
    hashed = hashlib.sha256(b"stwo/typed-secure-source-catalog/v2\x00")
    for entry in programs:
        hashed.update(str(entry["kind"]).encode("ascii") + b"\x00")
        hashed.update(bytes.fromhex(digest(entry["typed_authority"])))
    return hashed.hexdigest()


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def digest(value: object) -> str:
    if not isinstance(value, str) or HEX.fullmatch(value) is None or value == "0" * 64:
        raise BuildError("secure CUDA catalog has invalid digest")
    return value


def bounded_file(path: Path, cap: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BuildError("secure CUDA catalog requires a regular file")
    with path.open("rb") as stream:
        payload = stream.read(cap + 1)
    if not payload or len(payload) > cap:
        raise BuildError("secure CUDA source/catalog byte cap exceeded")
    return payload


def parse_catalog(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > MAX_MANIFEST_BYTES:
        raise BuildError("secure CUDA catalog byte cap exceeded")
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BuildError("secure CUDA catalog has duplicate JSON fields")
            result[key] = value
        return result
    try:
        catalog = json.loads(payload, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeDecodeError) as error:
        raise BuildError("secure CUDA catalog is not JSON") from error
    required = {
        "version", "target", "word_protocol_version", "word_protocol_abi",
        "typed_authority", "source_file", "source_sha256", "programs", "cuda_helpers",
        "dynamic_claims_and_challenges", "proof_acceptance_authority",
        "device_compiled", "device_executed",
    }
    if not isinstance(catalog, dict):
        raise BuildError("secure CUDA source catalog is not canonical")
    version = catalog.get("version")
    if type(version) is int and version == 2:
        required |= {"ram_lanes_protocol_version", "ram_lanes_protocol_abi"}
    if (set(catalog) != required
            or type(version) is not int or version not in (1, 2)
            or catalog["target"] != "cuda" or type(catalog["word_protocol_version"]) is not int or catalog["word_protocol_version"] != 4
            or catalog["dynamic_claims_and_challenges"] is not True
            or any(catalog[field] is not False for field in (
                "proof_acceptance_authority", "device_compiled", "device_executed"))
            or catalog["source_file"] != "kernels.cu"):
        raise BuildError("secure CUDA source catalog is not canonical")
    for field in ("word_protocol_abi", "typed_authority", "source_sha256"):
        digest(catalog[field])
    if version == 2:
        if type(catalog["ram_lanes_protocol_version"]) is not int or catalog["ram_lanes_protocol_version"] != 1:
            raise BuildError("secure CUDA RAM protocol version mismatch")
        digest(catalog["ram_lanes_protocol_abi"])
    catalog_records(catalog)
    return catalog


def key_for(identity: str) -> int:
    # Exact Zig codegen cacheKey: read first eight digest bytes LITTLE endian.
    return int.from_bytes(bytes.fromhex(digest(identity))[:8], "little") or 1


def catalog_records(catalog: dict[str, object]) -> list[dict[str, object]]:
    programs, helpers = catalog.get("programs"), catalog.get("cuda_helpers")
    if (not isinstance(programs, list) or not 1 <= len(programs) <= 16
            or not isinstance(helpers, list) or len(helpers) != len(HELPERS)):
        raise BuildError("secure CUDA source catalog entry cap/coverage mismatch")
    records: list[dict[str, object]] = []
    version = catalog.get("version")
    expected_kinds = tuple(KINDS) if version == 2 else LEGACY_KINDS
    if tuple(entry.get("kind") for entry in programs if isinstance(entry, dict)) != expected_kinds:
        raise BuildError("secure CUDA typed program roster mismatch")
    for entry in programs:
        required = {"kind", "program_identity", "executable_identity", "kernel", "inputs",
                    "parameters", "equations_or_buses", "abi_schema", "argument_count", "cache_key"}
        if version == 2:
            required.add("typed_authority")
        if not isinstance(entry, dict) or set(entry) != required or not isinstance(entry["kind"], str) or entry["kind"] not in KINDS:
            raise BuildError("secure CUDA program catalog is malformed")
        abi_name, roots = KINDS[entry["kind"]]
        digest(entry["program_identity"])
        if version == 2:
            digest(entry["typed_authority"])
        if (type(entry["inputs"]) is not int or not 1 <= entry["inputs"] <= 512
                or type(entry["parameters"]) is not int or not 0 <= entry["parameters"] <= 16384
                or type(entry["equations_or_buses"]) is not int or entry["equations_or_buses"] != roots):
            raise BuildError("secure CUDA program schema bounds mismatch")
        if entry["kernel"] != "stwo_cuda_secure_v1_" + digest(entry["executable_identity"]):
            raise BuildError("secure CUDA program name/identity mismatch")
        records.append(_record(entry, abi_name, 12))
    if version == 2:
        if roster_authority(programs) != catalog["typed_authority"]:
            raise BuildError("secure CUDA typed authority roster mismatch")
        # Both programs from each AIR must name one independently derived source.
        if (len({entry["typed_authority"] for entry in programs[:4]}) != 1
                or len({entry["typed_authority"] for entry in programs[4:]}) != 1
                or programs[0]["typed_authority"] == programs[4]["typed_authority"]):
            raise BuildError("secure CUDA typed authority family mismatch")
    seen_helpers: set[str] = set()
    for entry in helpers:
        required = {"kernel", "executable_identity", "cache_key", "abi_schema", "argument_count"}
        if not isinstance(entry, dict) or set(entry) != required or not isinstance(entry["kernel"], str) or entry["kernel"] not in HELPERS:
            raise BuildError("secure CUDA helper catalog is malformed")
        if entry["kernel"] in seen_helpers:
            raise BuildError("secure CUDA helper catalog is duplicated")
        seen_helpers.add(entry["kernel"])
        abi_name, argc = HELPERS[entry["kernel"]]
        records.append(_record(entry, abi_name, argc))
    if len({r["cache_key"] for r in records}) != len(records):
        raise BuildError("secure CUDA executable cache keys collide")
    return records


def _record(entry: dict[str, object], abi_name: str, argc: int) -> dict[str, object]:
    identity = digest(entry["executable_identity"])
    if (not isinstance(entry["kernel"], str) or KERNEL.fullmatch(entry["kernel"]) is None
            or type(entry["abi_schema"]) is not int or entry["abi_schema"] != ABI_SCHEMAS[abi_name]
            or type(entry["argument_count"]) is not int or entry["argument_count"] != argc
            or type(entry["cache_key"]) is not int or entry["cache_key"] != key_for(identity)):
        raise BuildError("secure CUDA source ABI/cache key mismatch")
    return {"kernel_name": entry["kernel"], "program_identity": identity,
            "abi_schema": abi_name, "argument_count": argc, "cache_key": f"{key_for(identity):016x}"}


def validate_signatures(source: bytes, records: list[dict[str, object]]) -> None:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError("secure CUDA source is not UTF-8") from error
    declarations = re.findall(r'extern\s+"C"\s+__global__\s+void\s+(\w+)\s*\(([^)]*)\)\s*\{', text)
    observed: dict[str, int] = {}
    for name, arguments in declarations:
        if name in observed:
            raise BuildError("secure CUDA source has duplicate kernels")
        observed[name] = len(arguments.split(",")) if arguments.strip() else 0
    expected = {r["kernel_name"]: r["argument_count"] for r in records}
    if observed != expected:
        raise BuildError("secure CUDA source function signatures mismatch")


def validate_secure_identity(generated_dir: Path, entry: dict[str, object], base_fields: set[str], index: int) -> None:
    required = base_fields | {"identity_scheme", "source_manifest_sha256", "source_sha256", "field_sha256", "argument_count"}
    if set(entry) != required or entry.get("identity_scheme") != IDENTITY_SCHEME or entry.get("module_globals") != "none":
        raise BuildError(f"AOT manifest entry {index} has a non-canonical secure identity")
    catalog_bytes = bounded_file(generated_dir / MANIFEST_NAME, MAX_MANIFEST_BYTES)
    if digest_bytes(catalog_bytes) != digest(entry["source_manifest_sha256"]):
        raise BuildError("secure CUDA source catalog SHA mismatch")
    catalog = parse_catalog(catalog_bytes)
    source = bounded_file(generated_dir / str(entry["file"]), MAX_SOURCE_BYTES)
    if digest_bytes(source) != digest(entry["source_sha256"]) or entry["source_sha256"] != catalog["source_sha256"]:
        raise BuildError("secure CUDA source SHA mismatch")
    header = bounded_file(generated_dir / "oods/field.cuh", 128 * 1024)
    if digest_bytes(header) != digest(entry["field_sha256"]):
        raise BuildError("secure CUDA field header SHA mismatch")
    records = catalog_records(catalog)
    matched = [r for r in records if r["program_identity"] == entry["program_identity"]]
    if len(matched) != 1 or any(entry[key] != matched[0][key] for key in matched[0]):
        raise BuildError("secure CUDA executable identity/ABI mismatch")
    if entry["semantic_hash"] != entry["cache_key"]:
        raise BuildError("secure CUDA semantic identity mismatch")
    expected_kind = "witness" if entry["abi_schema"] in {"secure_word_witness_v4", "secure_range_witness_v4"} else "constraint"
    if entry["kind"] != expected_kind or entry["label"] != "secure_" + str(entry["kernel_name"]):
        raise BuildError("secure CUDA product placement mismatch")
    validate_signatures(source, records)
