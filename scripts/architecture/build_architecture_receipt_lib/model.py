"""Stable schemas, bounds, and small validation primitives for BG-15."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
HOST_SCHEMA = "build-monorepo-host-receipt-v1"
AGGREGATE_SCHEMA = "build-monorepo-receipt-v1"
EVIDENCE_SCHEMA = "build-architecture-host-evidence-v1"
PROTOCOL_SCHEMA = "build-architecture-receipt-protocol-v1"
DEFAULT_PROTOCOL = ROOT / "conformance/build-architecture-receipt-protocol-v1.json"
DEFAULT_PRODUCT_SCHEMA = ROOT / "build_support/graph/product.zig"
DEFAULT_WORKFLOW = ROOT / ".github/workflows/ci.yml"
DEFAULT_OUTPUT_ROOT = ROOT / "zig-out/release-evidence/build-architecture"

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CHECKPOINT_RE = re.compile(r"^BG-(0[0-9]|1[0-5])$")
STATUS_PASS = "PASS"
STATUS_NO_GO = "NO-GO"
STATUS_NOT_ALLOCATED = "NOT-ALLOCATED"
EVIDENCE_NAMES = (
    "compatibility",
    "oracle",
    "benchmark",
    "source_conformance",
    "import_closure",
    "link_closure",
    "build_performance_memory",
    "source_debt",
)


class ReceiptError(ValueError):
    """Evidence is malformed or cannot support an architecture verdict."""


def exact_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiptError(f"{label} fields drifted")
    return value


def require_string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ReceiptError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > 4096:
        raise ReceiptError(f"{label} exceeds 4096 bytes")
    return value


def require_hex40(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX40_RE.fullmatch(value) is None:
        raise ReceiptError(f"{label} must be lowercase 40-character hex")
    return value


def require_hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise ReceiptError(f"{label} must be lowercase SHA-256")
    return value


def require_decimal(value: object, label: str) -> str:
    if not isinstance(value, str) or DECIMAL_RE.fullmatch(value) is None:
        raise ReceiptError(f"{label} must be a canonical decimal string")
    return value


def require_safe_component(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_COMPONENT_RE.fullmatch(value) is None:
        raise ReceiptError(f"{label} is not a bounded path component")
    if value in {".", ".."}:
        raise ReceiptError(f"{label} is not a bounded path component")
    return value


def require_non_negative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReceiptError(f"{label} must be a non-negative integer")
    return value


def require_timestamp(value: object, label: str) -> int:
    result = require_non_negative_int(value, label)
    if result < 1_500_000_000 or result > 5_000_000_000:
        raise ReceiptError(f"{label} is outside the supported epoch range")
    return result
