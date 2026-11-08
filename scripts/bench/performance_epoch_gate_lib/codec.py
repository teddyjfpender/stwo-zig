"""Duplicate-safe canonical JSON and content-addressed artifact helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .model import EvidenceError


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"value is not canonical JSON: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise EvidenceError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def content_digest(value: dict[str, Any]) -> str:
    content = {key: item for key, item in value.items() if key != "content_sha256"}
    return sha256_bytes(canonical_bytes(content))


def strict_json(path: Path, max_bytes: int, *, canonical: bool = True) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error
    if len(raw) > max_bytes:
        raise EvidenceError(f"{path} exceeds {max_bytes} bytes")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"{path}: duplicate JSON field {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise EvidenceError(f"{path}: non-finite JSON number {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: root must be an object")
    if canonical and raw != canonical_bytes(value):
        raise EvidenceError(f"{path}: JSON is not canonical")
    return value


def atomic_write(path: Path, value: dict[str, Any], *, replace: bool = False) -> str:
    raw = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise EvidenceError(f"refusing to replace {path}") from error
    finally:
        temporary.unlink(missing_ok=True)
    return sha256_bytes(raw)
