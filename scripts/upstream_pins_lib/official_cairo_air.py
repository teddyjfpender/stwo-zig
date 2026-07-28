"""Validate the authenticated official Cairo AIR program artifact."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from pathlib import Path


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
    if artifact.get("format") != "STWZEVA/1":
        errors.append(f"{relative_path}: AIR program format drifted")
    if artifact.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: AIR program byte count drifted")
    if artifact.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: AIR program digest drifted")
    if len(encoded) < 40 or encoded[:8] != b"STWZEVA\0":
        return errors + [f"{relative_path}: invalid AIR program header"]

    version, max_instructions = struct.unpack_from("<II", encoded, 8)
    constraints = struct.unpack_from("<Q", encoded, 16)[0]
    max_log, components = struct.unpack_from("<II", encoded, 24)
    plan_hash = struct.unpack_from("<Q", encoded, 32)[0]
    expected = (
        artifact.get("component_count"),
        artifact.get("constraint_count"),
        artifact.get("max_evaluation_log"),
        artifact.get("plan_hash"),
    )
    actual = (components, constraints, max_log, f"{plan_hash:016x}")
    if (
        version != 1
        or max_instructions != 1_000_000
        or components == 0
        or constraints == 0
        or expected != actual
    ):
        errors.append(f"{relative_path}: AIR program geometry drifted")
    if plan_hash != _fnv1a_with_zeroed_range(encoded, 32, 40):
        errors.append(f"{relative_path}: AIR program plan hash drifted")

    generator = artifact.get("generator")
    if generator != "tools/stwo-cairo-air-compiler":
        errors.append(f"{relative_path}: AIR compiler identity drifted")
    elif artifact.get("generator_closure_sha256") != closure_sha256(root / generator):
        errors.append(f"{relative_path}: AIR compiler closure drifted")
    return errors


def _fnv1a_with_zeroed_range(encoded: bytes, start: int, end: int) -> int:
    value = 0xCBF29CE484222325
    for index, byte in enumerate(encoded):
        value ^= 0 if start <= index < end else byte
        value = (value * 0x100000001B3) & ((1 << 64) - 1)
    return value
