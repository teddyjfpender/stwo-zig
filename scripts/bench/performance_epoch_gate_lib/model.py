"""Stable schemas, bounds, and validation primitives for performance epoch 2."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROTOCOL = ROOT / "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json"
PLAN_SCHEMA = "build-monorepo-performance-capture-plan-v1"
RECEIPT_SCHEMA = "build-monorepo-performance-baseline-v2"
RAW_BUNDLE_SCHEMA = "build-monorepo-performance-raw-bundle-v1"
VALIDATION_SCHEMA = "build-monorepo-performance-validation-v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")


class EvidenceError(ValueError):
    """Evidence cannot support the frozen epoch-2 decision."""


@dataclass(frozen=True)
class ValidatedReceipt:
    path: Path
    file_sha256: str
    content_sha256: str
    protocol_sha256: str
    candidate_commit: str
    verdict: str

    def architecture_binding(self) -> dict[str, Any]:
        return {
            "schema": VALIDATION_SCHEMA,
            "receipt_path": str(self.path),
            "receipt_sha256": self.file_sha256,
            "content_sha256": self.content_sha256,
            "protocol_sha256": self.protocol_sha256,
            "candidate_commit": self.candidate_commit,
            "verdict": self.verdict,
        }


def exact_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError(f"{label} fields drifted")
    return value


def require_string(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise EvidenceError(f"{label} must be a nonempty string")
    if len(value.encode("utf-8")) > 4096:
        raise EvidenceError(f"{label} is too long")
    return value


def require_hex(value: object, size: int, label: str) -> str:
    pattern = HEX40 if size == 40 else HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be lowercase {size}-character hex")
    return value


def require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be boolean")
    return value


def require_int(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def require_number(value: object, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise EvidenceError(f"{label} must be finite and >= {minimum}")
    return result


def require_relative_path(value: object, label: str) -> str:
    text = require_string(value, label)
    path = Path(text)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or SAFE_PATH.fullmatch(text) is None
    ):
        raise EvidenceError(f"{label} is not a bounded relative path")
    return text
