"""Canonical identities for Zig-owned Native CUDA AOT programs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .errors import BuildError


NATIVE_AUTHENTICATED_SCHEMAS = {
    "native_blake_constraint_v1",
    "native_constraint_slab_v1",
    "native_constant_qm31_v1",
    "native_circle_affine_state_trace_v1",
    "native_state_machine_statement_v1",
    "native_state_machine_constraint_v1",
    "native_plonk_logup_constraint_v1",
    "native_xor_logup_constraint_v1",
    "native_xor_logup_trace_v1",
    "native_blake_exact_trace_v1",
    "native_blake_exact_trace_v2",
    "native_blake_exact_interaction_v1",
    "native_indexed_recurrence_trace_v1",
    "native_m31_permutation_trace_v1",
    "native_m31_permutation_trace_v2",
    "native_m31_permutation_trace_v3",
    "native_poseidon_constraint_v1",
    "native_seeded_xorshift_trace_v1",
}
NATIVE_IDENTITY_SCHEME = "sha256-source-and-contract-v1"
NATIVE_CLOSURE_IDENTITY_SCHEME = (
    "sha256-source-closure-and-contract-v2"
)
RECORDED_WITNESS_IDENTITY_SCHEME = "sha256-source-and-blake3-program-v1"
RECORDED_WITNESS_SCHEMA = "recorded_witness_v1"
WITNESS_CODEGEN_VERSION = 12
CAIRO_EVAL_SCHEMA = "cairo_eval_part_v1"
CAIRO_EVAL_IDENTITY_SCHEME = (
    "sha256-canonical-cairo-eval-program-source-catalog-v1"
)
CAIRO_EVAL_CODEGEN_VERSION = 1
CAIRO_EVAL_PRODUCT_DOMAIN = b"stwo-zig/cairo-cuda-eval-product/v1\x00"
CAIRO_EVAL_PROGRAM_SET_DOMAIN = b"stwo-zig/cairo-eval-program-set/v1\x00"
LOCAL_INCLUDE_RE = re.compile(r'^\s*#include\s+"([^"]+)"', re.MULTILINE)


def validate_native_aot_identity(
    generated_dir: Path,
    entry: dict[str, object],
    base_fields: set[str],
    index: int,
) -> None:
    if entry["abi_schema"] == CAIRO_EVAL_SCHEMA:
        validate_cairo_eval_identity(
            generated_dir,
            entry,
            base_fields,
            index,
        )
        return
    if entry["abi_schema"] == RECORDED_WITNESS_SCHEMA:
        if (
            "identity_scheme" not in entry
            and "source_sha256" not in entry
        ):
            # The copied authority remains usable as a reference inventory, but
            # it is not eligible for the Native product pack.
            return
        validate_recorded_witness_identity(
            generated_dir,
            entry,
            base_fields,
            index,
        )
        return
    if entry["abi_schema"] not in NATIVE_AUTHENTICATED_SCHEMAS:
        return
    required = base_fields | {"identity_scheme", "semantic_contract"}
    if set(entry) != required:
        raise BuildError(
            f"AOT manifest entry {index} has a non-canonical Native identity"
        )
    scheme = entry["identity_scheme"]
    if scheme not in {
        NATIVE_IDENTITY_SCHEME,
        NATIVE_CLOSURE_IDENTITY_SCHEME,
    }:
        raise BuildError(
            f"AOT manifest entry {index} has an unknown Native identity scheme"
        )
    semantic_contract = entry["semantic_contract"]
    if not isinstance(semantic_contract, str) or not semantic_contract:
        raise BuildError(
            f"AOT manifest entry {index} has an empty semantic contract"
        )

    expected_semantic = hashlib.sha256(
        semantic_contract.encode("utf-8")
    ).hexdigest()[:16]
    source = generated_dir / str(entry["file"])
    source_identity = (
        hashlib.sha256(source.read_bytes()).hexdigest()
        if scheme == NATIVE_IDENTITY_SCHEME
        else source_closure_identity(generated_dir, source)
    )
    cache_payload = {
        "abi_schema": entry["abi_schema"],
        "kernel_name": entry["kernel_name"],
        "program_identity": source_identity,
        "semantic_hash": expected_semantic,
    }
    canonical = json.dumps(
        cache_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_cache_key = hashlib.sha256(canonical).hexdigest()[:16]
    if (
        entry["semantic_hash"] != expected_semantic
        or entry["program_identity"] != source_identity
        or entry["cache_key"] != expected_cache_key
    ):
        raise BuildError(
            f"AOT manifest entry {index} has stale Native identities"
        )


def validate_recorded_witness_identity(
    generated_dir: Path,
    entry: dict[str, object],
    base_fields: set[str],
    index: int,
) -> None:
    required = base_fields | {"identity_scheme", "source_sha256"}
    if set(entry) != required:
        raise BuildError(
            f"AOT manifest entry {index} has a non-canonical recorded-witness identity"
        )
    if entry["identity_scheme"] != RECORDED_WITNESS_IDENTITY_SCHEME:
        raise BuildError(
            f"AOT manifest entry {index} has an unknown recorded-witness identity scheme"
        )

    semantic_hash = int(str(entry["semantic_hash"]), 16)
    expected_kernel = f"stwo_jit_witness_{semantic_hash:016x}"
    expected_cache_key = witness_cache_key(semantic_hash)
    source = generated_dir / str(entry["file"])
    expected_source = hashlib.sha256(source.read_bytes()).hexdigest()
    if (
        entry["kernel_name"] != expected_kernel
        or entry["cache_key"] != f"{expected_cache_key:016x}"
        or entry["source_sha256"] != expected_source
    ):
        raise BuildError(
            f"AOT manifest entry {index} has stale recorded-witness identities"
        )


def validate_cairo_eval_identity(
    generated_dir: Path,
    entry: dict[str, object],
    base_fields: set[str],
    index: int,
) -> None:
    required = base_fields | {
        "catalog_identity",
        "codegen_version",
        "identity_scheme",
        "occurrences",
        "source_sha256",
    }
    if set(entry) != required:
        raise BuildError(
            f"AOT manifest entry {index} has a non-canonical Cairo eval identity"
        )
    if (
        entry["identity_scheme"] != CAIRO_EVAL_IDENTITY_SCHEME
        or entry["codegen_version"] != CAIRO_EVAL_CODEGEN_VERSION
        or entry["kind"] != "constraint"
    ):
        raise BuildError(
            f"AOT manifest entry {index} has an unknown Cairo eval identity scheme"
        )
    occurrences = entry["occurrences"]
    if not isinstance(occurrences, list) or not occurrences:
        raise BuildError(
            f"AOT manifest entry {index} has no Cairo eval placements"
        )
    occurrence_fields = {
        "component_index",
        "component_label",
        "component_source_identity",
        "domain_log_size",
        "evaluation_log_size",
        "global_rc_base",
        "instance",
        "part_index",
        "program_identity",
        "rc_base",
        "rc_count",
        "trace_log_size",
    }
    exact_programs: list[bytes] = []
    for occurrence in occurrences:
        if not isinstance(occurrence, dict) or set(occurrence) != occurrence_fields:
            raise BuildError(
                f"AOT manifest entry {index} has a malformed Cairo eval placement"
            )
        label = occurrence["component_label"]
        source_identity = str(occurrence["component_source_identity"])
        exact_program = str(occurrence["program_identity"])
        integers = [
            occurrence[field]
            for field in occurrence_fields
            if field not in {
                "component_label",
                "component_source_identity",
                "program_identity",
            }
        ]
        if (
            not isinstance(label, str)
            or re.fullmatch(r"[A-Za-z0-9_]+", label) is None
            or re.fullmatch(r"[0-9a-f]{64}", source_identity) is None
            or re.fullmatch(r"[0-9a-f]{64}", exact_program) is None
            or any(not isinstance(value, int) or value < 0 for value in integers)
            or occurrence["rc_count"] == 0
            or occurrence["domain_log_size"] != occurrence["trace_log_size"]
            or occurrence["trace_log_size"] > occurrence["evaluation_log_size"]
        ):
            raise BuildError(
                f"AOT manifest entry {index} has invalid Cairo eval placement semantics"
            )
        exact_programs.append(bytes.fromhex(exact_program))

    canonical_occurrences = json.dumps(
        occurrences,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_catalog = hashlib.sha256(canonical_occurrences).hexdigest()
    program_set = hashlib.sha256()
    program_set.update(CAIRO_EVAL_PROGRAM_SET_DOMAIN)
    program_set.update(len(exact_programs).to_bytes(8, "little"))
    for identity in exact_programs:
        program_set.update(identity)
    expected_program = program_set.hexdigest()
    source = generated_dir / str(entry["file"])
    expected_source = hashlib.sha256(source.read_bytes()).hexdigest()
    semantic_hash = int(str(entry["semantic_hash"]), 16)
    expected_kernel = (
        f"stwo_cairo_cuda_eval_v1_{cairo_eval_body_key(semantic_hash):016x}"
    )
    cache = hashlib.sha256()
    cache.update(CAIRO_EVAL_PRODUCT_DOMAIN)
    cache.update(bytes.fromhex(expected_program))
    cache.update(bytes.fromhex(expected_source))
    cache.update(bytes.fromhex(expected_catalog))
    cache.update(CAIRO_EVAL_CODEGEN_VERSION.to_bytes(8, "little"))
    expected_cache_key = cache.hexdigest()[:16]
    if (
        entry["catalog_identity"] != expected_catalog
        or entry["program_identity"] != expected_program
        or entry["source_sha256"] != expected_source
        or entry["kernel_name"] != expected_kernel
        or entry["cache_key"] != expected_cache_key
        or entry["label"] != f"cairo_eval_{semantic_hash:016x}"
    ):
        raise BuildError(
            f"AOT manifest entry {index} has stale Cairo eval identities"
        )


def cairo_eval_body_key(semantic_hash: int) -> int:
    value = 0xCBF29CE484222325
    payload = semantic_hash.to_bytes(
        8,
        "little",
    ) + CAIRO_EVAL_CODEGEN_VERSION.to_bytes(8, "little")
    for byte in payload:
        value ^= byte
        value = (value * 0x100000001B3) & ((1 << 64) - 1)
    return value


def witness_cache_key(semantic_hash: int) -> int:
    value = 0xCBF29CE484222325
    payload = semantic_hash.to_bytes(8, "little") + WITNESS_CODEGEN_VERSION.to_bytes(
        8,
        "little",
    )
    for byte in payload:
        value ^= byte
        value = (value * 0x100000001B3) & ((1 << 64) - 1)
    return value


def source_closure_identity(generated_dir: Path, source: Path) -> str:
    root = generated_dir.parents[1].resolve()
    entry = source.resolve()
    pending = [entry]
    discovered: set[Path] = set()
    while pending:
        current = pending.pop()
        if current in discovered:
            continue
        if not current.is_file() or not current.is_relative_to(root):
            raise BuildError("Native AOT include escapes the CUDA source root")
        discovered.add(current)
        text = current.read_text(encoding="utf-8", errors="strict")
        for relative in LOCAL_INCLUDE_RE.findall(text):
            included = (current.parent / relative).resolve()
            if included.is_file():
                pending.append(included)

    digest = hashlib.sha256()
    for path in sorted(discovered):
        relative = (
            b"<entry>"
            if path == entry
            else path.relative_to(root).as_posix().encode("utf-8")
        )
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "little"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "little"))
        digest.update(payload)
    return digest.hexdigest()
