"""Closed proof-admission policy for the complete RV32IM trace corpus."""

from __future__ import annotations

SUPPORTED = "supported"


def for_programs(program_names: object) -> dict[str, dict[str, str]]:
    """Every valid RV32IM family is proof-admitted; no exception list exists."""
    return {name: {"status": SUPPORTED} for name in set(program_names)}


def errors(
    vectors: object,
    expected: dict[str, dict[str, str]],
) -> list[str]:
    """Validate every vector against the complete, closed admission policy."""
    if not isinstance(vectors, list):
        return ["trace-vector manifest vectors must be an array"]
    result: list[str] = []
    observed: dict[str, dict[str, str]] = {}
    for vector in vectors:
        if not isinstance(vector, dict):
            result.append("trace-vector manifest contains a non-object vector")
            continue
        name = vector.get("name")
        admission = vector.get("proof_admission")
        if not isinstance(name, str) or not isinstance(admission, dict):
            result.append(f"{name}: proof admission must be an object")
            continue
        status = admission.get("status")
        if status != SUPPORTED:
            result.append(f"{name}: unknown proof-admission status {status!r}")
        observed[name] = admission
        if admission != expected.get(name):
            result.append(
                f"{name}: proof admission {admission!r} != expected {expected.get(name)!r}"
            )
    if observed != expected:
        result.append("trace-vector proof-admission manifest is incomplete or non-canonical")
    return result
