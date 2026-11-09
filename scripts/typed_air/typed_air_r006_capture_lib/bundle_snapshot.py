"""Internal immutable projection from validated R-006 lane evidence."""

from __future__ import annotations

from typing import Any


def attach_validation_snapshot(
    result: dict[str, Any],
    *,
    include: bool,
    plan: dict[str, Any],
    bundle: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    if not include:
        return result
    return {
        **result,
        "_snapshot": {"plan": plan, "bundle": bundle, "records": records},
    }
