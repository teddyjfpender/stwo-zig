"""Validate the authenticated official Cairo AIR program artifact."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from pathlib import Path


AIR_COMPILER = "tools/stwo-cairo-air-compiler"
# The evaluation-program ABI sources the compiler includes with `#[path]` (and the circuit oracle
# includes too); they are part of what determines the compiler's output.
EVAL_PROGRAM_ABI = "tools/stwo-eval-program-abi"


def generator_closure_sha256(root: Path, closure_sha256: Callable[[Path], str]) -> str:
    """The AIR compiler's closure: its own tree, then the shared ABI tree it compiles in.

    SHA-256 over `path NUL closure_sha256(path) LF` for the two trees, in that order.
    """
    lines = "".join(
        f"{path}\0{closure_sha256(root / path)}\n" for path in (AIR_COMPILER, EVAL_PROGRAM_ABI)
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def check(
    root: Path,
    relative_path: str,
    artifact: dict[str, object],
    *,
    closure_sha256: Callable[[Path], str],
) -> list[str]:
    path = artifact.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: AIR program path is invalid"]
    try:
        encoded = (root / path).read_bytes()
    except OSError as error:
        return [f"{relative_path}: unable to read AIR programs: {error}"]

    errors: list[str] = []
    if artifact.get("format") != BUNDLE_FORMAT:
        errors.append(f"{relative_path}: AIR program format drifted")
    if artifact.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: AIR program byte count drifted")
    if artifact.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: AIR program digest drifted")
    header = parse_bundle_header(encoded)
    if header is None:
        return errors + [f"{relative_path}: invalid AIR program header"]
    errors.extend(check_bundle_geometry(encoded, header, artifact, relative_path))

    generator = artifact.get("generator")
    if generator != AIR_COMPILER:
        errors.append(f"{relative_path}: AIR compiler identity drifted")
    elif artifact.get("generator_closure_sha256") != generator_closure_sha256(root, closure_sha256):
        errors.append(f"{relative_path}: AIR compiler closure drifted")
    return errors


BUNDLE_MAGIC = b"STWZEVA\0"
BUNDLE_FORMAT = "STWZEVA/1"
_PLAN_HASH_RANGE = (32, 40)


def parse_bundle_header(encoded: bytes) -> dict[str, int] | None:
    """The fixed 40-byte `STWZEVA` header (`bundle.rs`), or `None` when it is absent."""
    if len(encoded) < 40 or encoded[:8] != BUNDLE_MAGIC:
        return None
    version, max_instructions = struct.unpack_from("<II", encoded, 8)
    constraints = struct.unpack_from("<Q", encoded, 16)[0]
    max_log, components = struct.unpack_from("<II", encoded, 24)
    plan_hash = struct.unpack_from("<Q", encoded, 32)[0]
    return {
        "version": version,
        "max_instructions": max_instructions,
        "constraint_count": constraints,
        "max_evaluation_log": max_log,
        "component_count": components,
        "plan_hash": plan_hash,
    }


def bundle_summary(encoded: bytes) -> dict[str, object]:
    """The provenance fields a bundle artifact records, derived from its header."""
    header = parse_bundle_header(encoded)
    if header is None:
        raise ValueError("invalid AIR program header")
    return {
        "format": BUNDLE_FORMAT,
        "component_count": header["component_count"],
        "constraint_count": header["constraint_count"],
        "max_evaluation_log": header["max_evaluation_log"],
        "plan_hash": f"{header['plan_hash']:016x}",
    }


def check_bundle_geometry(
    encoded: bytes,
    header: dict[str, int],
    artifact: dict[str, object],
    relative_path: str,
) -> list[str]:
    """Header geometry against the recorded artifact fields, and the FNV-1a plan hash."""
    errors: list[str] = []
    expected = (
        artifact.get("component_count"),
        artifact.get("constraint_count"),
        artifact.get("max_evaluation_log"),
        artifact.get("plan_hash"),
    )
    actual = (
        header["component_count"],
        header["constraint_count"],
        header["max_evaluation_log"],
        f"{header['plan_hash']:016x}",
    )
    if (
        header["version"] != 1
        or header["max_instructions"] != 1_000_000
        or header["component_count"] == 0
        or header["constraint_count"] == 0
        or expected != actual
    ):
        errors.append(f"{relative_path}: AIR program geometry drifted")
    if header["plan_hash"] != _fnv1a_with_zeroed_range(encoded, *_PLAN_HASH_RANGE):
        errors.append(f"{relative_path}: AIR program plan hash drifted")
    return errors


def _fnv1a_with_zeroed_range(encoded: bytes, start: int, end: int) -> int:
    value = 0xCBF29CE484222325
    for index, byte in enumerate(encoded):
        value ^= 0 if start <= index < end else byte
        value = (value * 0x100000001B3) & ((1 << 64) - 1)
    return value
