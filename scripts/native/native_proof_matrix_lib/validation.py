"""Fail-closed JSON validation primitives for Native benchmark evidence."""

from __future__ import annotations

import math
import statistics
from typing import Any

from .model import MatrixError


ORDERED_PROVE_DRIFT_MIN_SAMPLES = 5


def ordered_prove_time_drift(samples: list[dict[str, Any]]) -> float | None:
    """Compare early and late prove-time medians without discarding order."""
    if len(samples) < ORDERED_PROVE_DRIFT_MIN_SAMPLES:
        return None
    prove_seconds = [float(sample["prove_seconds"]) for sample in samples]
    window = max(2, len(prove_seconds) // 3)
    first = statistics.median(prove_seconds[:window])
    last = statistics.median(prove_seconds[-window:])
    return abs(first - last) / min(first, last)


def require_exact_keys(
    value: dict[str, Any], expected: set[str], context: str,
    optional: set[str] | None = None,
) -> None:
    """Exact key-set schema check; `optional` keys may be absent (fields the
    Zig report schema added after archived reports were committed — new
    reports carry them, history stays loadable)."""
    actual = set(value)
    opt = optional or set()
    missing = (expected - opt) - actual
    extra = actual - expected
    if missing or extra:
        raise MatrixError(
            f"{context} has the wrong schema; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )


def require_object(
    parent: dict[str, Any], key: str, context: str
) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise MatrixError(f"{context}.{key} must be an object")
    return value


def require_list(parent: dict[str, Any], key: str, context: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise MatrixError(f"{context}.{key} must be an array")
    return value


def require_number(value: Any, context: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MatrixError(f"{context} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        raise MatrixError(
            f"{context} must be {'positive and ' if positive else ''}finite"
        )
    return result


def require_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise MatrixError(f"{context} must be boolean")
    return value


def require_int(value: Any, context: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MatrixError(f"{context} must be an integer")
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "nonnegative"
        raise MatrixError(f"{context} must be {qualifier}")
    return value


def require_string(value: Any, context: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise MatrixError(
            f"{context} must be {'nonempty ' if nonempty else ''}text"
        )
    return value


def require_digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise MatrixError(f"{context} must be a lowercase SHA-256 digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise MatrixError(f"{context} must be a lowercase SHA-256 digest")
    return value
