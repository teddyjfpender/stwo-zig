"""Closed sample contract for the experimental H-010 layout benchmark."""

from __future__ import annotations

import json
import re
from typing import Any

from .pins import (
    ARM_PINS,
    ARTIFACT_DIGEST,
    VECTOR_ARTIFACT_DIGESTS,
    VECTOR_CALL_DIGESTS,
    VECTOR_OUTPUT_DIGESTS,
    VECTOR_SEALS,
    VECTOR_TRACE_DIGESTS,
)


SAMPLE_SCHEMA = "stwo.typed-air.poseidon-layout-benchmark-sample-v1"
SAMPLE_SCHEMA_VERSION = 1
REPORT_SCHEMA = "stwo.typed-air.benchmark.poseidon2-layout-report-v1"
REPORT_KIND = "stwo-typed-air-poseidon-layout-benchmark"
CLASSIFICATION = "experimental_uncommitted_timing"
BENCHMARK_ID = "h010-authenticated-poseidon-layout-cpu-v1"
EVALUATOR = "stwo.typed-air.poseidon2-retained-cpu-evaluator-v1"
BACKEND = "cpu-retained-scalar-m31"
MEASUREMENT_SCOPE = "single-process-single-arm-cpu-candidate-evaluation-v1"
CALL_SCHEDULE = "sha256-counter-poseidon-calls-v1"
VECTOR_FORMAT = "STWAIRB-v1"
VECTOR_GENERATOR = "stwo.typed-air.benchmark.sha256-counter-v1"

DEFAULT_LOGS = (10, 14)
STRESS_LOG = 18
WARMUP_ROUNDS = 3
MEASURED_ROUNDS = 11

MAIN_COLUMNS = 445
MATERIALIZATIONS = 426
DIRECT_NODES = 3_460
DIRECT_ROOTS = 430
DIRECT_RETAINED_SCRATCH_BYTES = DIRECT_NODES * 4
SEMANTIC_RETAINED_SCRATCH_BYTES = 8_684

DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
RESOURCE_SOURCES = frozenset(
    {
        "getrusage-self-maxrss-native-bytes",
        "getrusage-self-maxrss-kib-normalized-bytes",
    }
)


class ContractError(ValueError):
    """A child result is not an admissible H-010 sample."""


ARMS = tuple(pin.arm for pin in ARM_PINS)
ARM_BY_ID = {pin.arm: pin for pin in ARM_PINS}

SAMPLE_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "benchmark_id",
        "evaluator",
        "backend",
        "measurement_scope",
        "optimization_mode",
        "zig_version",
        "target",
        "allocator",
        "monotonic_clock",
        "vector_storage_class",
        "vector_seal",
        "vector_artifact_sha256",
        "vector_bytes",
        "arm",
        "frontier_ordinal",
        "log_size",
        "rows",
        "setup_ns",
        "witness_ns",
        "direct_ns",
        "peak_rss_bytes",
        "peak_rss_native_value",
        "peak_rss_native_unit",
        "resource_source",
        "root_evaluations",
        "nonzero_roots",
        "direct_sink",
        "artifact_digest",
        "cut_digest",
        "proposal_digest",
        "layout_digest",
        "direct_program_digest",
        "evaluator_digest",
        "output_digest",
        "trace_digest",
        "trace_digest_class",
        "call_schedule",
        "call_digest",
        "semantic_execution_digest",
        "direct_result_digest",
        "main_columns",
        "materializations",
        "direct_nodes",
        "direct_roots",
        "semantic_retained_scratch_bytes",
        "direct_retained_scratch_bytes",
        "allocation_free_timed_row_loops",
        "valid",
        "proof_executed",
        "verification_executed",
        "hash_component_shell_executed",
        "logup_executed",
        "commitment_executed",
        "pcs_executed",
        "metal_candidate_execution_supported",
        "production_layout_changed",
        "promotion_authority",
        "status",
    }
)

DIGEST_KEYS = (
    "artifact_digest",
    "cut_digest",
    "proposal_digest",
    "layout_digest",
    "direct_program_digest",
    "evaluator_digest",
    "output_digest",
    "trace_digest",
    "call_digest",
    "semantic_execution_digest",
    "direct_result_digest",
    "vector_seal",
    "vector_artifact_sha256",
)

STABLE_SAMPLE_KEYS = DIGEST_KEYS + (
    "direct_sink",
    "root_evaluations",
        "nonzero_roots",
        "optimization_mode",
        "zig_version",
        "target",
        "allocator",
        "monotonic_clock",
        "vector_storage_class",
        "vector_bytes",
        "trace_digest_class",
        "resource_source",
        "peak_rss_native_unit",
)


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-standard JSON number is forbidden: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_one_line_json(raw: bytes) -> dict[str, Any]:
    """Decode exactly one compact JSON object, with no duplicate keys."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError("sample stdout is not UTF-8") from error
    if text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text:
        raise ContractError("sample stdout must contain exactly one JSON line")
    if text != text.strip():
        raise ContractError("sample JSON line has leading or trailing whitespace")
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ContractError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError(f"sample stdout is not valid JSON: {error.msg}") from error
    if type(decoded) is not dict:
        raise ContractError("sample JSON root must be an object")
    return decoded


def _expect_exact(sample: dict[str, Any], key: str, expected: Any) -> None:
    if type(sample[key]) is not type(expected) or sample[key] != expected:
        raise ContractError(f"{key} must equal {expected!r}")


def _expect_int(
    sample: dict[str, Any],
    key: str,
    *,
    minimum: int = 0,
    exact: int | None = None,
) -> int:
    value = sample[key]
    if type(value) is not int:
        raise ContractError(f"{key} must be an integer")
    if value < minimum:
        raise ContractError(f"{key} must be at least {minimum}")
    if exact is not None and value != exact:
        raise ContractError(f"{key} must equal {exact}")
    return value


def _expect_false(sample: dict[str, Any], key: str) -> None:
    _expect_exact(sample, key, False)


def validate_sample(
    raw: bytes,
    *,
    expected_arm: str,
    expected_log: int,
) -> dict[str, Any]:
    """Parse and fully authenticate one requested arm/log sample."""

    sample = decode_one_line_json(raw)
    actual_keys = frozenset(sample)
    if actual_keys != SAMPLE_KEYS:
        missing = sorted(SAMPLE_KEYS - actual_keys)
        unknown = sorted(actual_keys - SAMPLE_KEYS)
        raise ContractError(
            f"sample key set mismatch; missing={missing}, unknown={unknown}"
        )
    if expected_arm not in ARM_BY_ID:
        raise ContractError(f"host requested unknown arm: {expected_arm}")
    if expected_log not in (*DEFAULT_LOGS, STRESS_LOG):
        raise ContractError(f"host requested unsupported log size: {expected_log}")

    pin = ARM_BY_ID[expected_arm]
    exact_values = {
        "schema": SAMPLE_SCHEMA,
        "schema_version": SAMPLE_SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "benchmark_id": BENCHMARK_ID,
        "evaluator": EVALUATOR,
        "backend": BACKEND,
        "measurement_scope": MEASUREMENT_SCOPE,
        "optimization_mode": "ReleaseFast",
        "allocator": "libc-c-allocator",
        "monotonic_clock": "std.time.Timer",
        "vector_storage_class": (
            "generated_opt_in_uncommitted_non_receiptable"
            if expected_log == STRESS_LOG
            else "checked_repository_artifact"
        ),
        "vector_bytes": 130 + (1 << expected_log) * 140,
        "trace_digest_class": (
            "candidate_layout_regression_pin_not_correctness_oracle"
        ),
        "arm": expected_arm,
        "frontier_ordinal": pin.frontier_ordinal,
        "log_size": expected_log,
        "rows": 1 << expected_log,
        "artifact_digest": ARTIFACT_DIGEST,
        "proposal_digest": pin.proposal_digest,
        "cut_digest": pin.cut_digest,
        "call_schedule": CALL_SCHEDULE,
        "main_columns": MAIN_COLUMNS,
        "materializations": MATERIALIZATIONS,
        "direct_nodes": DIRECT_NODES,
        "direct_roots": DIRECT_ROOTS,
        "direct_retained_scratch_bytes": DIRECT_RETAINED_SCRATCH_BYTES,
        "semantic_retained_scratch_bytes": SEMANTIC_RETAINED_SCRATCH_BYTES,
        "allocation_free_timed_row_loops": True,
        "valid": True,
        "status": "pass",
    }
    for key, expected in exact_values.items():
        _expect_exact(sample, key, expected)

    for key in ("zig_version", "target"):
        value = sample[key]
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or any(character.isspace() for character in value)
        ):
            raise ContractError(f"{key} must be one non-empty token")

    for key in (
        "setup_ns",
        "witness_ns",
        "direct_ns",
        "peak_rss_bytes",
        "peak_rss_native_value",
    ):
        _expect_int(sample, key, minimum=1)
    _expect_int(
        sample,
        "root_evaluations",
        exact=(1 << expected_log) * DIRECT_ROOTS,
    )
    _expect_int(sample, "nonzero_roots", exact=0)
    _expect_int(sample, "direct_sink", exact=0)

    resource_source = sample["resource_source"]
    if type(resource_source) is not str or resource_source not in RESOURCE_SOURCES:
        raise ContractError("resource_source is not an admitted RSS adapter")
    native_unit = sample["peak_rss_native_unit"]
    expected_rss = sample["peak_rss_native_value"]
    if resource_source == "getrusage-self-maxrss-native-bytes":
        if native_unit != "bytes":
            raise ContractError("Darwin native peak RSS unit must be bytes")
    else:
        if native_unit != "KiB":
            raise ContractError("Linux native peak RSS unit must be KiB")
        expected_rss *= 1024
    if sample["peak_rss_bytes"] != expected_rss:
        raise ContractError("normalized peak_rss_bytes does not match native RSS")
    for key in DIGEST_KEYS:
        value = sample[key]
        if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
            raise ContractError(f"{key} must be one lowercase SHA-256 hex digest")
    expected_trace = VECTOR_TRACE_DIGESTS[expected_log][ARMS.index(expected_arm)]
    for key, expected in (
        ("vector_seal", VECTOR_SEALS[expected_log]),
        ("call_digest", VECTOR_CALL_DIGESTS[expected_log]),
        ("output_digest", VECTOR_OUTPUT_DIGESTS[expected_log]),
        ("trace_digest", expected_trace),
    ):
        if sample[key] != expected:
            raise ContractError(f"{key} does not match its protocol pin")
    if sample["vector_artifact_sha256"] != VECTOR_ARTIFACT_DIGESTS[expected_log]:
        raise ContractError(
            "vector_artifact_sha256 does not match the checked file pin"
        )

    for key in (
        "proof_executed",
        "verification_executed",
        "hash_component_shell_executed",
        "logup_executed",
        "commitment_executed",
        "pcs_executed",
        "metal_candidate_execution_supported",
        "production_layout_changed",
        "promotion_authority",
    ):
        _expect_false(sample, key)
    return sample
