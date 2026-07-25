"""Stable workload catalog and public benchmark option domains."""

from __future__ import annotations

from typing import Any

COMMON_CONFIG_ARGS = [
    "--pow-bits", "0",
    "--fri-log-blowup", "1",
    "--fri-log-last-layer", "0",
    "--fri-n-queries", "3",
]

BASE_WORKLOADS: list[dict[str, Any]] = [{
    "name": "state_machine_default",
    "example": "state_machine",
    "args": ["--sm-log-n-rows", "5", "--sm-initial-0", "1", "--sm-initial-1", "1"],
}]

MEDIUM_WORKLOADS: list[dict[str, Any]] = [{
    "name": "state_machine_medium",
    "example": "state_machine",
    "args": ["--sm-log-n-rows", "6", "--sm-initial-0", "3", "--sm-initial-1", "5"],
}]

LARGE_WORKLOADS: list[dict[str, Any]] = [
    {
        "name": "poseidon_large",
        "example": "poseidon",
        "args": ["--poseidon-log-n-instances", "10"],
    },
    {
        "name": "blake_large",
        "example": "blake",
        "args": [
            "--blake-log-n-rows", "9",
            "--blake-n-rounds", "10",
            "--pow-bits", "10",
        ],
    },
    {
        "name": "wide_fibonacci_fib100",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "9", "--wf-sequence-len", "100"],
    },
    {
        "name": "wide_fibonacci_fib500",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "10", "--wf-sequence-len", "500"],
    },
    {
        "name": "wide_fibonacci_fib1000",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "11", "--wf-sequence-len", "1000"],
    },
    {
        "name": "plonk_large",
        "example": "plonk",
        "args": ["--plonk-log-n-rows", "12"],
    },
]

LONG_WORKLOADS: list[dict[str, Any]] = [
    {
        "name": "poseidon_deep",
        "example": "poseidon",
        "args": ["--poseidon-log-n-instances", "12"],
    },
    {
        "name": "blake_deep",
        "example": "blake",
        "args": [
            "--blake-log-n-rows", "11",
            "--blake-n-rounds", "10",
            "--pow-bits", "10",
        ],
    },
    {
        "name": "wide_fibonacci_fib2000",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "12", "--wf-sequence-len", "2000"],
    },
    {
        "name": "wide_fibonacci_fib5000",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "13", "--wf-sequence-len", "5000"],
    },
]

SUPPORTED_ZIG_OPT_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")
SUPPORTED_BLAKE2_BACKENDS = ("auto", "scalar", "simd")
SUPPORTED_BENCH_PROOF_CODECS = ("json", "binary")
