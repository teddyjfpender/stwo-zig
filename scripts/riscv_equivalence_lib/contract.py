"""Canonical RISC-V retirement-trace schema and comparison contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

TRACE_SCHEMA = "stwo-riscv-retirement-trace-v1"
PROFILE = "rv32im-zkvm-v1"
MAX_DIFFERENCES = 64
RETIREMENT_FIELDS = ("pc", "instruction", "rd", "rd_value", "next_pc")
MEMORY_FIELDS = ("address", "read_mask", "read_value", "write_mask", "write_value")


class EquivalenceError(ValueError):
    """A trace or external formal-model boundary is malformed."""


class SailDisagreement(EquivalenceError):
    """The pinned Sail model answered and contradicted the candidate."""


def load_trace(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate one canonical retirement trace."""
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    validate_trace(value, str(path))
    return value


def validate_trace(trace: Any, label: str = "trace") -> None:
    if not isinstance(trace, dict):
        raise EquivalenceError(f"{label}: root must be an object")
    if trace.get("schema") != TRACE_SCHEMA:
        raise EquivalenceError(
            f"{label}: schema is {trace.get('schema')!r}, expected {TRACE_SCHEMA!r}"
        )
    if trace.get("profile") != PROFILE:
        raise EquivalenceError(
            f"{label}: profile is {trace.get('profile')!r}, expected {PROFILE!r}"
        )
    rows = trace.get("retirements")
    if not isinstance(rows, list):
        raise EquivalenceError(f"{label}: retirements must be an array")
    if trace.get("total_steps") != len(rows):
        raise EquivalenceError(f"{label}: total_steps does not match retirements")
    for order, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("order") != order:
            raise EquivalenceError(f"{label}: non-canonical retirement order at {order}")
        for field in RETIREMENT_FIELDS:
            u32(row.get(field), f"{label}: retirement {order}.{field}")
        memory = row.get("memory")
        if not isinstance(memory, dict) or set(memory) != set(MEMORY_FIELDS):
            raise EquivalenceError(
                f"{label}: retirement {order}.memory has a non-canonical shape"
            )
        for field in MEMORY_FIELDS:
            value = u32(
                memory.get(field),
                f"{label}: retirement {order}.memory.{field}",
            )
            if field.endswith("_mask") and value > 0xF:
                raise EquivalenceError(
                    f"{label}: retirement {order}.memory.{field} exceeds RV32 width"
                )
    if "final_pc" in trace:
        u32(trace["final_pc"], f"{label}: final_pc")
    if "final_regs" in trace:
        regs = trace["final_regs"]
        if not isinstance(regs, list) or len(regs) != 32:
            raise EquivalenceError(f"{label}: final_regs must contain 32 words")
        for index, value in enumerate(regs):
            u32(value, f"{label}: final_regs[{index}]")
        if regs[0] != 0:
            raise EquivalenceError(f"{label}: final_regs[0] is not hard-wired zero")


def compare_traces(
    authoritative: dict[str, Any],
    candidate: dict[str, Any],
    authoritative_name: str = "Sail",
    candidate_name: str = "Zig",
) -> list[str]:
    """Return precise retirement differences between two canonical traces."""
    validate_trace(authoritative, authoritative_name)
    validate_trace(candidate, candidate_name)
    errors: list[str] = []
    authority_rows = authoritative["retirements"]
    candidate_rows = candidate["retirements"]
    if len(authority_rows) != len(candidate_rows):
        errors.append(
            f"retirement count: {authoritative_name}={len(authority_rows)} "
            f"{candidate_name}={len(candidate_rows)}"
        )

    for order, (expected, actual) in enumerate(zip(authority_rows, candidate_rows)):
        for field in RETIREMENT_FIELDS:
            if expected[field] != actual[field]:
                errors.append(
                    f"retirement {order}.{field}: "
                    f"{authoritative_name}=0x{expected[field]:08x} "
                    f"{candidate_name}=0x{actual[field]:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors
        for field in MEMORY_FIELDS:
            expected_value = expected["memory"][field]
            actual_value = actual["memory"][field]
            if expected_value != actual_value:
                errors.append(
                    f"retirement {order}.memory.{field}: "
                    f"{authoritative_name}=0x{expected_value:08x} "
                    f"{candidate_name}=0x{actual_value:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors

    if "final_pc" in authoritative and "final_pc" in candidate:
        if authoritative["final_pc"] != candidate["final_pc"]:
            errors.append(
                f"final_pc: {authoritative_name}=0x{authoritative['final_pc']:08x} "
                f"{candidate_name}=0x{candidate['final_pc']:08x}"
            )
    if "final_regs" in authoritative and "final_regs" in candidate:
        for index, (expected, actual) in enumerate(
            zip(authoritative["final_regs"], candidate["final_regs"])
        ):
            if expected != actual:
                errors.append(
                    f"final_regs[{index}]: {authoritative_name}=0x{expected:08x} "
                    f"{candidate_name}=0x{actual:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors
    return errors


def u32(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 0xFFFF_FFFF
    ):
        raise EquivalenceError(f"{label} must be a u32, found {value!r}")
    return value
