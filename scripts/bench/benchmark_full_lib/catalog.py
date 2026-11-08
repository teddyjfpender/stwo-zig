"""Stable mapping from upstream benchmark families to proof workloads."""

from __future__ import annotations

from typing import Any

UPSTREAM_FAMILIES = (
    "bit_rev",
    "eval_at_point",
    "barycentric_eval_at_point",
    "eval_at_point_by_folding",
    "fft",
    "field",
    "fri",
    "lookups",
    "merkle",
    "prefix_sum",
    "pcs",
)

_COMMON_ARGS = [
    "--pow-bits", "0",
    "--fri-log-blowup", "1",
    "--fri-log-last-layer", "0",
    "--fri-n-queries", "3",
]


def _workload(
    example: str,
    args: list[str],
    *,
    prove_mode: str = "prove",
) -> dict[str, Any]:
    return {
        "example": example,
        "args": [*_COMMON_ARGS, *args],
        "prove_mode": prove_mode,
        "include_all_preprocessed_columns": "0",
    }


# Families retain their upstream names while using stable examples that exercise
# different prover surfaces and yield useful hotspot contrast.
WORKLOADS: dict[str, dict[str, Any]] = {
    "bit_rev": _workload(
        "xor", ["--xor-log-size", "14", "--xor-log-step", "3", "--xor-offset", "5"]
    ),
    "eval_at_point": _workload(
        "wide_fibonacci", ["--wf-log-n-rows", "10", "--wf-sequence-len", "500"]
    ),
    "barycentric_eval_at_point": _workload("plonk", ["--plonk-log-n-rows", "12"]),
    "eval_at_point_by_folding": _workload(
        "wide_fibonacci", ["--wf-log-n-rows", "11", "--wf-sequence-len", "1000"]
    ),
    "fft": _workload(
        "wide_fibonacci",
        ["--wf-log-n-rows", "11", "--wf-sequence-len", "1000"],
        prove_mode="prove_ex",
    ),
    "field": _workload(
        "xor", ["--xor-log-size", "15", "--xor-log-step", "3", "--xor-offset", "5"]
    ),
    "fri": _workload(
        "state_machine",
        ["--sm-log-n-rows", "12", "--sm-initial-0", "9", "--sm-initial-1", "3"],
    ),
    "lookups": _workload(
        "state_machine",
        ["--sm-log-n-rows", "13", "--sm-initial-0", "9", "--sm-initial-1", "3"],
        prove_mode="prove_ex",
    ),
    "merkle": _workload("plonk", ["--plonk-log-n-rows", "12"], prove_mode="prove_ex"),
    "prefix_sum": _workload(
        "state_machine",
        ["--sm-log-n-rows", "12", "--sm-initial-0", "9", "--sm-initial-1", "3"],
        prove_mode="prove_ex",
    ),
    "pcs": _workload("plonk", ["--plonk-log-n-rows", "12"]),
}
