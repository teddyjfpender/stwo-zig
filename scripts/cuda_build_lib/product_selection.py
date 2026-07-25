"""Authenticated CUDA product and AOT-manifest selection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .aot_identity import (
    RECORDED_WITNESS_IDENTITY_SCHEME,
    RECORDED_WITNESS_SCHEMA,
    validate_native_aot_identity,
)
from .aot_pack import ABI_SCHEMAS
from .errors import BuildError


IDENTITY_64_RE = re.compile(r"^[0-9a-f]{16}$")
IDENTITY_256_RE = re.compile(r"^[0-9a-f]{64}$")
KERNEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LABEL_RE = re.compile(r"^[a-z0-9_]+$")


@dataclass(frozen=True)
class ProductSelection:
    manifest_sha256: str
    ordinary_sources: tuple[Path, ...]
    aot_sources: tuple[Path, ...]
    aot_manifest: tuple[dict[str, object], ...]
    aot_closure_sha256: str


class ProductConfig(Protocol):
    product_manifest: Path
    native_aot_root: Path


class SourceAuthority(Protocol):
    root: Path
    closure_sha256: str


def load_product_selection(
    config: ProductConfig,
    authority: SourceAuthority,
) -> ProductSelection:
    try:
        payload = config.product_manifest.read_bytes()
        product = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read CUDA product manifest: {error}") from error
    if product.get("schema") != "stwo-zig-cuda-product-closure-v1":
        raise BuildError("unsupported CUDA product-closure manifest")
    if product.get("source_authority_sha256") != authority.closure_sha256:
        raise BuildError("CUDA product selection is stale against its source authority")
    ordinary = product.get("ordinary")
    if not isinstance(ordinary, dict):
        raise BuildError("CUDA product ordinary source selection is absent")
    selected = ordinary.get("product_sources")
    candidates = ordinary.get("resident_candidates")
    if (
        not isinstance(selected, list)
        or selected != sorted(set(selected))
        or not isinstance(candidates, list)
        or candidates != sorted(set(candidates))
        or not set(selected).issubset(candidates)
    ):
        raise BuildError("CUDA product sources must be a sorted candidate subset")
    ordinary_sources = tuple(authority.root / str(path) for path in selected)
    if any(not path.is_file() for path in ordinary_sources):
        raise BuildError("CUDA resident source selection names an absent authority file")

    aot_root = config.native_aot_root.resolve()
    aot_manifest_path = aot_root / "aot_manifest.json"
    try:
        aot_manifest = json.loads(aot_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read Native AOT manifest: {error}") from error
    validate_aot_manifest(aot_root, aot_manifest, allow_empty=True)
    for index, entry in enumerate(aot_manifest):
        if (
            entry["abi_schema"] == RECORDED_WITNESS_SCHEMA
            and entry.get("identity_scheme")
            != RECORDED_WITNESS_IDENTITY_SCHEME
        ):
            raise BuildError(
                f"Native AOT manifest entry {index} is an unauthenticated recorded witness"
            )
    aot_sources = tuple(aot_root / str(entry["file"]) for entry in aot_manifest)
    aot_closure = hashlib.sha256()
    manifest_payload = _canonical_json_bytes(aot_manifest)
    aot_closure.update(len(manifest_payload).to_bytes(8, "little"))
    aot_closure.update(manifest_payload)
    for source in aot_sources:
        relative = source.relative_to(aot_root).as_posix().encode("utf-8")
        source_payload = source.read_bytes()
        aot_closure.update(len(relative).to_bytes(8, "little"))
        aot_closure.update(relative)
        aot_closure.update(len(source_payload).to_bytes(8, "little"))
        aot_closure.update(source_payload)
    return ProductSelection(
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        ordinary_sources=ordinary_sources,
        aot_sources=aot_sources,
        aot_manifest=tuple(aot_manifest),
        aot_closure_sha256=aot_closure.hexdigest(),
    )


def validate_aot_manifest(
    generated_dir: Path,
    manifest: object,
    allow_empty: bool = False,
) -> None:
    if not isinstance(manifest, list) or (not manifest and not allow_empty):
        raise BuildError("AOT manifest must be an array with the required entries")
    seen_files: set[str] = set()
    seen_keys: set[int] = set()
    previous: tuple[str, str, int] | None = None
    required = {
        "kind",
        "label",
        "abi_schema",
        "kernel_name",
        "cache_key",
        "semantic_hash",
        "program_identity",
        "file",
    }
    for index, raw in enumerate(manifest):
        if not isinstance(raw, dict) or not required.issubset(raw):
            raise BuildError(f"AOT manifest entry {index} is incomplete")
        kind = str(raw["kind"])
        label = str(raw["label"])
        abi_schema = str(raw["abi_schema"])
        kernel_name = str(raw["kernel_name"])
        cache_key_hex = str(raw["cache_key"])
        semantic_hash = str(raw["semantic_hash"])
        program_identity = str(raw["program_identity"])
        file_name = str(raw["file"])
        if kind not in {"constraint", "witness"}:
            raise BuildError(f"AOT manifest entry {index} has invalid kind")
        if abi_schema not in ABI_SCHEMAS:
            raise BuildError(f"AOT manifest entry {index} has invalid ABI schema")
        if (
            LABEL_RE.fullmatch(label) is None
            or KERNEL_RE.fullmatch(kernel_name) is None
            or IDENTITY_64_RE.fullmatch(cache_key_hex) is None
            or IDENTITY_64_RE.fullmatch(semantic_hash) is None
            or IDENTITY_256_RE.fullmatch(program_identity) is None
        ):
            raise BuildError(f"AOT manifest entry {index} has invalid identity syntax")
        try:
            cache_key = int(cache_key_hex, 16)
            semantic_key = int(semantic_hash, 16)
        except ValueError as error:
            raise BuildError(f"AOT manifest entry {index} has invalid hex identity") from error
        if cache_key == 0 or semantic_key == 0:
            raise BuildError(f"AOT manifest entry {index} has a zero identity")
        expected_name = f"{kind}_{label}_{cache_key:016x}.cu"
        if (
            file_name != expected_name
            or Path(file_name).name != file_name
            or file_name in seen_files
            or cache_key in seen_keys
        ):
            raise BuildError(f"AOT manifest entry {index} is non-canonical")
        order = (kind, label, cache_key)
        if previous is not None and previous >= order:
            raise BuildError("AOT manifest order is not canonical")
        if not (generated_dir / file_name).is_file():
            raise BuildError(f"copied AOT source is absent: {file_name}")
        validate_native_aot_identity(generated_dir, raw, required, index)
        previous = order
        seen_files.add(file_name)
        seen_keys.add(cache_key)
    copied = {path.name for path in generated_dir.glob("*.cu")}
    if copied != seen_files:
        raise BuildError("copied generated CUDA sources do not match the AOT manifest")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
