"""Plan-bound P-003 whole-prover closure for R-006 capture."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.typed_air_work_profile_contract_lib import (
    FAMILY_IDS,
    INVENTORY_PATH,
    INVENTORY_SCHEMA_VERSION,
    MATRIX_PATH,
    MATRIX_SCHEMA,
    SITE_IDS,
    MatrixContractError,
    validate_matrix,
)

from .codec import exact_object
from .model import DIGEST_RE, CaptureError


GLOBAL_EXACT_WORK_CLOSURE_SCHEMA = (
    "stwo.typed-air.p003-global-exact-work-closure.v1"
)
GLOBAL_EXACT_WORK_CLOSURE_FIELDS = {
    "schema",
    "schema_version",
    "matrix",
    "inventory",
    "coverage",
}
GLOBAL_EXACT_WORK_MATRIX_FIELDS = {"path", "schema", "sha256"}
GLOBAL_EXACT_WORK_INVENTORY_FIELDS = {
    "path",
    "schema_version",
    "site_count",
    "source_bytes",
    "source_sha256",
}
GLOBAL_EXACT_WORK_COVERAGE_FIELDS = {
    "cpu",
    "metal",
    "joint",
    "family_count",
    "whole_prover_exact",
}
GLOBAL_EXACT_WORK_STATUS_FIELDS = {"complete", "partial", "absent"}


def _status_counts(value: Any, label: str) -> dict[str, int]:
    counts = exact_object(value, GLOBAL_EXACT_WORK_STATUS_FIELDS, label)
    for name in GLOBAL_EXACT_WORK_STATUS_FIELDS:
        if type(counts[name]) is not int or counts[name] < 0:
            raise CaptureError(f"{label}.{name} must be a non-negative integer")
    if sum(counts.values()) != len(FAMILY_IDS):
        raise CaptureError(f"{label} does not cover all P-003 families")
    return counts


def validate_global_exact_work_closure(value: Any) -> dict[str, object]:
    """Validate the terminal P-003 authority carried by every R-006 plan."""

    closure = exact_object(
        value,
        GLOBAL_EXACT_WORK_CLOSURE_FIELDS,
        "P-003 global exact-work closure",
    )
    if (
        closure["schema"] != GLOBAL_EXACT_WORK_CLOSURE_SCHEMA
        or closure["schema_version"] != 1
    ):
        raise CaptureError("P-003 global exact-work closure schema changed")
    matrix = exact_object(
        closure["matrix"],
        GLOBAL_EXACT_WORK_MATRIX_FIELDS,
        "P-003 closure matrix authority",
    )
    if (
        matrix["path"] != MATRIX_PATH
        or matrix["schema"] != MATRIX_SCHEMA
        or type(matrix["sha256"]) is not str
        or DIGEST_RE.fullmatch(matrix["sha256"]) is None
    ):
        raise CaptureError("P-003 closure matrix identity changed")
    inventory = exact_object(
        closure["inventory"],
        GLOBAL_EXACT_WORK_INVENTORY_FIELDS,
        "P-003 typed-site inventory authority",
    )
    if (
        inventory["path"] != INVENTORY_PATH
        or inventory["schema_version"] != INVENTORY_SCHEMA_VERSION
        or inventory["site_count"] != len(SITE_IDS)
        or type(inventory["source_bytes"]) is not int
        or inventory["source_bytes"] <= 0
        or type(inventory["source_sha256"]) is not str
        or DIGEST_RE.fullmatch(inventory["source_sha256"]) is None
    ):
        raise CaptureError("P-003 typed-site inventory identity changed")
    coverage = exact_object(
        closure["coverage"],
        GLOBAL_EXACT_WORK_COVERAGE_FIELDS,
        "P-003 whole-prover coverage",
    )
    if (
        coverage["family_count"] != len(FAMILY_IDS)
        or coverage["whole_prover_exact"] is not True
    ):
        raise CaptureError(
            "R-006 planning requires terminal P-003 whole-prover exactness at 16/16"
        )
    expected = {"complete": len(FAMILY_IDS), "partial": 0, "absent": 0}
    for lane in ("cpu", "metal", "joint"):
        if _status_counts(coverage[lane], f"P-003 {lane} coverage") != expected:
            raise CaptureError(
                "R-006 planning requires terminal P-003 whole-prover exactness at 16/16"
            )
    return closure


def global_exact_work_closure(repository: Path) -> dict[str, object]:
    """Recompute the reviewed matrix and typed inventory from this checkout."""

    root = repository.resolve()
    try:
        report = validate_matrix(root, root / MATRIX_PATH)
    except MatrixContractError as error:
        raise CaptureError(f"P-003 closure validation failed: {error}") from error
    coverage = report["coverage"]
    result: dict[str, object] = {
        "schema": GLOBAL_EXACT_WORK_CLOSURE_SCHEMA,
        "schema_version": 1,
        "matrix": {
            "path": MATRIX_PATH,
            "schema": MATRIX_SCHEMA,
            "sha256": report["matrix_sha256"],
        },
        "inventory": report["inventory"],
        "coverage": {
            "cpu": coverage["cpu"],
            "metal": coverage["metal"],
            "joint": coverage["joint"],
            "family_count": coverage["family_count"],
            "whole_prover_exact": coverage["whole_prover_exact"],
        },
    }
    return validate_global_exact_work_closure(result)
