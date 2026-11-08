"""Duplicate-safe bounded JSON and canonical receipt persistence."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .model import ReceiptError


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ReceiptError(f"value is not canonical JSON: {error}") from error
    return encoded + b"\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def content_digest(value: dict[str, Any]) -> str:
    content = {key: item for key, item in value.items() if key != "content_sha256"}
    return sha256_bytes(canonical_bytes(content))


def with_content_digest(value: dict[str, Any]) -> dict[str, Any]:
    if "content_sha256" in value:
        raise ReceiptError("content_sha256 is controller-owned")
    return {**value, "content_sha256": content_digest(value)}


def strict_json(path: Path, max_bytes: int, *, require_canonical: bool = True) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReceiptError(f"cannot stat {path}: {error}") from error
    if size > max_bytes:
        raise ReceiptError(f"{path}: exceeds {max_bytes} bytes")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptError(f"{path}: duplicate JSON field {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ReceiptError(f"{path}: non-finite JSON number {value}")

    try:
        raw = path.read_bytes()
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"cannot read {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ReceiptError(f"{path}: root must be an object")
    if require_canonical and raw != canonical_bytes(payload):
        raise ReceiptError(f"{path}: JSON is not in canonical wire form")
    return payload


def bounded_child(root: Path, *components: str) -> Path:
    resolved_root = root.resolve()
    candidate = resolved_root.joinpath(*components).resolve()
    if candidate == resolved_root or not candidate.is_relative_to(resolved_root):
        raise ReceiptError("receipt path escapes the output root")
    return candidate


def atomic_write(path: Path, value: dict[str, Any], max_bytes: int) -> str:
    raw = canonical_bytes(value)
    if len(raw) > max_bytes:
        raise ReceiptError(f"receipt exceeds {max_bytes} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ReceiptError(
                f"refusing to replay or replace existing receipt: {path}"
            ) from error
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return sha256_bytes(raw)
