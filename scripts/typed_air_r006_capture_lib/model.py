"""Frozen identities and value-level constants for R-006 capture."""

from __future__ import annotations

import re


PLAN_SCHEMA = "stwo.typed-air.r006-capture-plan.v2"
PLAN_VERSION = 2
BUNDLE_SCHEMA = "stwo.typed-air.r006-raw-bundle.v1"
PROTOCOL_SCHEMA = "stwo-typed-air-m5-m9-performance-protocol-v1"
PROTOCOL_PATH = "design/typed-air/performance/m5-m9-protocol-v1.json"
PROTOCOL_SHA256 = (
    "7c213ae7c35ac8f60f204fba8fa96357195186a29a6a626c0a67fd47984cf985"
)
MILESTONE = "M7"
LANES = {
    "cpu-native": {
        "backend": "cpu",
        "cli_backend": "cpu",
        "executable": "stwo-zig-riscv-cpu",
        "build_step": "stwo-zig-riscv-cpu",
    },
    "metal-hybrid": {
        "backend": "metal-hybrid",
        "cli_backend": "metal",
        "executable": "stwo-zig-riscv-metal",
        "build_step": "stwo-zig-riscv-metal",
    },
}
WORKLOAD_IDS = (
    "multi_shard_addi",
    "memcpy_loop",
    "balanced_core_and_poseidon2",
    "poseidon2_dominant",
)
GENERATED_WORKLOADS = {
    "balanced_core_and_poseidon2": {
        "generator": "poseidon2-software-precompile-equivalence-v1",
        "seed": "stwo-typed-air-m7-balanced-poseidon2-v1",
        "shape": "balanced_core_and_poseidon2",
    },
    "poseidon2_dominant": {
        "generator": "poseidon2-software-precompile-equivalence-v1",
        "seed": "stwo-typed-air-m7-dominant-poseidon2-v1",
        "shape": "poseidon2_dominant",
    },
}
ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
WARMUPS_PER_ARM = 10
ROUNDS = 3
PAIRS_PER_ROUND = 10
COOLDOWN_NS = 1_000_000_000
ATTEMPTS_PER_COMPARISON = 2 * WARMUPS_PER_ARM + 2 * ROUNDS * PAIRS_PER_ROUND
COMPARISON_LABELS = ("two", "four", "max")
PLAN_ATTEMPTS = (
    ATTEMPTS_PER_COMPARISON
    + len(WORKLOAD_IDS) * len(COMPARISON_LABELS) * ATTEMPTS_PER_COMPARISON
)
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 64 * 1024 * 1024


class CaptureError(RuntimeError):
    """The requested plan, process result, or evidence bundle is inadmissible."""
