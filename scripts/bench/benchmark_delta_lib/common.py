"""Shared validation, hashing, and atomic-write primitives."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


DELTA_PROTOCOL = "benchmark_delta_v1"
SEQUENTIAL_DELTA_NOTE = (
    "sequential-runs (diagnostic only; not paired ABBA - never a timing claim)"
)


class DeltaError(RuntimeError):
    """A report pair is invalid or cannot be compared safely."""


class IncompatibleReports(DeltaError):
    """Individually valid reports do not describe the same benchmark."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def encoded_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeltaError(f"{context} must be an object")
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise DeltaError(f"{context} must be an array")
    return value
