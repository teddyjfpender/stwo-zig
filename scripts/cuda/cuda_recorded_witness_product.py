#!/usr/bin/env python3
"""Verify that recorded-witness CUDA is cache-generated, never checked in."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "src/backends/cuda/aot/native"
BUNDLE = ROOT / "vectors/cairo/sn_pie_2_witness_programs.bin"
SCHEMA = "recorded_witness_v1"
EXPECTED_SOURCES = 33
EXPECTED_BUNDLE_MAGIC = b"STWZWIT\x00"
IDENTITY_RE = re.compile(r"^[0-9a-f]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{16}$")


class ProductError(RuntimeError):
    pass


def load_manifest(path: Path) -> list[dict[str, object]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProductError(f"cannot read AOT manifest {path}: {error}") from error
    if not isinstance(value, list):
        raise ProductError(f"AOT manifest is not an array: {path}")
    return value


def recorded_entries() -> list[dict[str, object]]:
    entries = [
        entry
        for entry in load_manifest(PRODUCT / "aot_manifest.json")
        if entry.get("abi_schema") == SCHEMA
    ]
    files = [str(entry.get("file", "")) for entry in entries]
    if len(entries) != EXPECTED_SOURCES or files != sorted(set(files)):
        raise ProductError("recorded-witness manifest population drifted")
    for entry in entries:
        if (
            entry.get("identity_scheme")
            != "sha256-source-and-blake3-program-v1"
            or IDENTITY_RE.fullmatch(str(entry.get("program_identity", "")))
            is None
            or IDENTITY_RE.fullmatch(str(entry.get("source_sha256", ""))) is None
            or HASH_RE.fullmatch(str(entry.get("semantic_hash", ""))) is None
            or HASH_RE.fullmatch(str(entry.get("cache_key", ""))) is None
        ):
            raise ProductError("recorded-witness identity pin is malformed")
    return entries


def verify() -> int:
    entries = recorded_entries()
    checked_in = [
        str(entry["file"])
        for entry in entries
        if (PRODUCT / str(entry["file"])).exists()
    ]
    if checked_in:
        raise ProductError(
            f"recorded-witness generated sources are checked in: {checked_in}"
        )
    try:
        prefix = BUNDLE.read_bytes()[: len(EXPECTED_BUNDLE_MAGIC)]
    except OSError as error:
        raise ProductError(f"cannot read witness bundle: {error}") from error
    if prefix != EXPECTED_BUNDLE_MAGIC:
        raise ProductError("recorded-witness IR bundle is not authenticated V1")
    return len(entries)


def main() -> int:
    count = verify()
    print(f"Native recorded-witness cache product verified: {count} programs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProductError as error:
        raise SystemExit(f"recorded witness AOT product rejected: {error}") from error
