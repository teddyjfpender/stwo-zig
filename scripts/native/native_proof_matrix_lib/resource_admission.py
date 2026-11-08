"""Bind the Python matrix to the Zig Native resource-admission authority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


ZIG_RESOURCE_AUTHORITY = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "prover"
    / "native"
    / "resource_admission.zig"
)

_LITERAL_U64 = re.compile(
    r"^pub const ([A-Z][A-Z0-9_]+): u64 = ([0-9][0-9_]*);$",
    re.MULTILINE,
)
_REQUIRED_CONSTANTS = {
    "ACCOUNTED_BYTES_PER_COMMITTED_CELL",
    "STANDARD_MAX_COMMITTED_CELLS",
    "STANDARD_MAX_ACCOUNTED_BYTES",
    "LARGE_MAX_COMMITTED_CELLS",
    "LARGE_MAX_ACCOUNTED_BYTES",
}


@dataclass(frozen=True)
class ResourceLimits:
    max_committed_cells: int
    max_accounted_bytes: int


def load_zig_resource_constants(path: Path = ZIG_RESOURCE_AUTHORITY) -> Mapping[str, int]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"cannot read Zig resource authority: {path}") from error
    constants = {
        name: int(encoded.replace("_", ""))
        for name, encoded in _LITERAL_U64.findall(source)
    }
    missing = sorted(_REQUIRED_CONSTANTS - constants.keys())
    if missing:
        raise RuntimeError(
            "Zig resource authority is missing literal u64 constants: "
            + ", ".join(missing)
        )
    return MappingProxyType(constants)


ZIG_RESOURCE_CONSTANTS = load_zig_resource_constants()
ACCOUNTED_BYTES_PER_COMMITTED_CELL = ZIG_RESOURCE_CONSTANTS[
    "ACCOUNTED_BYTES_PER_COMMITTED_CELL"
]
RESOURCE_PROFILES: Mapping[str, ResourceLimits] = MappingProxyType(
    {
        "standard": ResourceLimits(
            ZIG_RESOURCE_CONSTANTS["STANDARD_MAX_COMMITTED_CELLS"],
            ZIG_RESOURCE_CONSTANTS["STANDARD_MAX_ACCOUNTED_BYTES"],
        ),
        "large": ResourceLimits(
            ZIG_RESOURCE_CONSTANTS["LARGE_MAX_COMMITTED_CELLS"],
            ZIG_RESOURCE_CONSTANTS["LARGE_MAX_ACCOUNTED_BYTES"],
        ),
    }
)


def resource_limits(profile: str) -> ResourceLimits:
    try:
        return RESOURCE_PROFILES[profile]
    except KeyError as error:
        raise ValueError(f"unsupported resource profile: {profile}") from error


def expected_report_admission(workload: object, profile: str) -> dict[str, object]:
    limits = resource_limits(profile)
    committed_cells = getattr(workload, "committed_trace_cells")
    accounted_bytes = getattr(workload, "accounted_bytes")
    return {
        "profile": profile,
        "accounted_bytes_per_committed_cell": ACCOUNTED_BYTES_PER_COMMITTED_CELL,
        "committed_cells": committed_cells,
        "accounted_bytes": accounted_bytes,
        "max_committed_cells": limits.max_committed_cells,
        "max_accounted_bytes": limits.max_accounted_bytes,
    }


def validate_report_admission(
    value: object,
    workload: object,
    profile: str,
) -> None:
    expected = expected_report_admission(workload, profile)
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("resource admission has an invalid schema")
    if value != expected:
        raise ValueError("resource admission does not match the reviewed profile")


def validate_source_contract() -> None:
    constants = load_zig_resource_constants()
    bytes_per_cell = constants["ACCOUNTED_BYTES_PER_COMMITTED_CELL"]
    for profile in ("STANDARD", "LARGE"):
        cells = constants[f"{profile}_MAX_COMMITTED_CELLS"]
        accounted = constants[f"{profile}_MAX_ACCOUNTED_BYTES"]
        if cells * bytes_per_cell != accounted:
            raise RuntimeError(
                f"{profile.lower()} Zig cell and accounted-byte limits disagree"
            )
    if (
        constants["STANDARD_MAX_COMMITTED_CELLS"]
        >= constants["LARGE_MAX_COMMITTED_CELLS"]
    ):
        raise RuntimeError("large Zig resource profile must exceed standard")


validate_source_contract()
