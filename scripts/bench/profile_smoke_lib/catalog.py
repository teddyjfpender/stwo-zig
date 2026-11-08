"""Stable workload catalog and public profiling option domains."""

from __future__ import annotations

from typing import Any

COMMON_CONFIG_ARGS = [
    "--pow-bits", "0",
    "--fri-log-blowup", "1",
    "--fri-log-last-layer", "0",
    "--fri-n-queries", "3",
]

BASE_WORKLOADS: list[dict[str, Any]] = [
    {
        "name": "state_machine_deep",
        "example": "state_machine",
        "args": ["--sm-log-n-rows", "15", "--sm-initial-0", "9", "--sm-initial-1", "3"],
    },
    {
        "name": "xor_deep",
        "example": "xor",
        "args": ["--xor-log-size", "15", "--xor-log-step", "3", "--xor-offset", "5"],
    },
]

LARGE_WORKLOADS: list[dict[str, Any]] = [
    {
        "name": "wide_fibonacci_fib500",
        "example": "wide_fibonacci",
        "args": ["--wf-log-n-rows", "10", "--wf-sequence-len", "500"],
    },
    {
        "name": "plonk_deep",
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
