"""Canonical identities for Zig-owned Native CUDA AOT programs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .errors import BuildError


NATIVE_AUTHENTICATED_SCHEMAS = {
    "native_constraint_slab_v1",
    "native_constant_qm31_v1",
    "native_circle_affine_state_trace_v1",
    "native_state_machine_statement_v1",
    "native_state_machine_constraint_v1",
    "native_indexed_recurrence_trace_v1",
    "native_m31_permutation_trace_v1",
    "native_seeded_xorshift_trace_v1",
}
NATIVE_IDENTITY_SCHEME = "sha256-source-and-contract-v1"
NATIVE_CLOSURE_IDENTITY_SCHEME = (
    "sha256-source-closure-and-contract-v2"
)
LOCAL_INCLUDE_RE = re.compile(r'^\s*#include\s+"([^"]+)"', re.MULTILINE)


def validate_native_aot_identity(
    generated_dir: Path,
    entry: dict[str, object],
    base_fields: set[str],
    index: int,
) -> None:
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
