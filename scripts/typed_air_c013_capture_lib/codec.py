"""Canonical JSON, digest, and create-only persistence helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .model import CaptureError


MAX_JSON_BYTES = 4 * 1024 * 1024


def _reject_constant(value: str) -> None:
    raise CaptureError(f"non-standard JSON number is forbidden: {value}")


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_strict(raw: bytes, *, maximum: int = MAX_JSON_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise CaptureError("JSON evidence is empty or exceeds its byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as error:
        raise CaptureError("JSON evidence is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise CaptureError(f"invalid JSON evidence: {error.msg}") from error


def load_strict(path: Path, *, maximum: int = MAX_JSON_BYTES) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError(f"cannot read JSON evidence: {path}") from error
    return decode_strict(raw, maximum=maximum)


def canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise CaptureError("evidence is not canonical-JSON encodable") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as error:
        raise CaptureError(f"cannot hash artifact: {path}") from error
    return size, digest.hexdigest()


def content_digest(document: dict[str, Any]) -> str:
    unsigned = dict(document)
    unsigned.pop("content_sha256", None)
    return sha256_bytes(canonical_bytes(unsigned))


def write_new(path: Path, payload: bytes) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise CaptureError(f"refusing to replace existing evidence: {destination}") from error
    finally:
        temporary.unlink(missing_ok=True)


def exact_object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CaptureError(f"{name} must be an object")
    actual = set(value)
    if actual != fields:
        raise CaptureError(
            f"{name} fields drifted; missing={sorted(fields - actual)}, "
            f"unknown={sorted(actual - fields)}"
        )
    return value
