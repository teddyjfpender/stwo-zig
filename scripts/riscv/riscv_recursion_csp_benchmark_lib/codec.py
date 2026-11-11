"""Strict JSON, canonical hashing, and append-only report publication."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from decimal import Decimal
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 64 * 1024 * 1024


class EvidenceError(ValueError):
    """Benchmark evidence is ambiguous, contradictory, or incomplete."""


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-standard JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_json(raw: bytes, *, label: str) -> dict[str, Any]:
    """Decode a bounded UTF-8 JSON object without duplicate or non-finite values."""

    if len(raw) > MAX_JSON_BYTES:
        raise EvidenceError(f"{label} exceeds the {MAX_JSON_BYTES}-byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=Decimal,
            parse_constant=_reject_constant,
        )
    except EvidenceError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        detail = error.msg if isinstance(error, json.JSONDecodeError) else str(error)
        raise EvidenceError(f"{label} is not valid JSON: {detail}") from error
    if type(value) is not dict:
        raise EvidenceError(f"{label} root must be an object")
    return value


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error
    return decode_json(raw, label=str(path)), raw


def canonical_bytes(value: Any) -> bytes:
    """Encode the integer-only benchmark contracts in one canonical JSON line."""

    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"document is not canonical-JSON encodable: {error}") from error
    return (text + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def content_digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def seal_document(value: dict[str, Any]) -> dict[str, Any]:
    if "canonical_digest" in value:
        raise EvidenceError("cannot seal a document that already has canonical_digest")
    sealed = dict(value)
    sealed["canonical_digest"] = content_digest(value)
    return sealed


def verify_document_seal(value: dict[str, Any], *, label: str) -> None:
    digest = value.get("canonical_digest")
    if type(digest) is not str or len(digest) != 64:
        raise EvidenceError(f"{label}.canonical_digest is invalid")
    unsigned = dict(value)
    del unsigned["canonical_digest"]
    expected = content_digest(unsigned)
    if digest != expected:
        raise EvidenceError(f"{label}.canonical_digest does not match its content")


def atomic_write_new(path: Path, payload: bytes) -> None:
    """Publish complete bytes atomically and never replace an existing path."""

    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
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
            raise EvidenceError(f"refusing to overwrite evidence: {destination}") from error
    finally:
        temporary.unlink(missing_ok=True)
