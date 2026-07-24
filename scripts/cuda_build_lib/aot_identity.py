"""Canonical identities for Zig-owned Native CUDA AOT programs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .errors import BuildError


NATIVE_CONSTRAINT_SCHEMA = "native_constraint_slab_v1"
NATIVE_IDENTITY_SCHEME = "sha256-source-and-contract-v1"


def validate_native_aot_identity(
    generated_dir: Path,
    entry: dict[str, object],
    base_fields: set[str],
    index: int,
) -> None:
    if entry["abi_schema"] != NATIVE_CONSTRAINT_SCHEMA:
        return
    required = base_fields | {"identity_scheme", "semantic_contract"}
    if set(entry) != required:
        raise BuildError(
            f"AOT manifest entry {index} has a non-canonical Native identity"
        )
    if entry["identity_scheme"] != NATIVE_IDENTITY_SCHEME:
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
    source_identity = hashlib.sha256(
        (generated_dir / str(entry["file"])).read_bytes()
    ).hexdigest()
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
