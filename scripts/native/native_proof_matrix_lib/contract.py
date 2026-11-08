"""Fail-closed report-v7, proof-artifact, telemetry, and parity validation."""

from __future__ import annotations

import argparse
import math
import statistics
from typing import Any

try:
    from scripts.benchmark_product_contract_lib import (
        PRODUCT_SPECS,
        ProductEvidenceError,
        validate_product_identity,
    )
except ModuleNotFoundError:
    from benchmark_product_contract_lib import (  # type: ignore[no-redef]
        PRODUCT_SPECS,
        ProductEvidenceError,
        validate_product_identity,
    )

from .model import (
    ACCELERATED_CLASSIFICATIONS,
    ARCHIVE_STORE_COUNTER_KEYS,
    ARCHIVE_STORE_SECONDS_KEY,
    BACKEND_COUNTER_KEYS,
    EXPECTED_BACKENDS,
    HEADLINE_REQUIREMENT_KEYS,
    INTEROP_ARTIFACT_SCHEMA_VERSION,
    INTEROP_EXCHANGE_MODE,
    INTEROP_UPSTREAM_COMMIT,
    LIBRARY_PREPARATION_SECONDS_KEY,
    MIN_HEADLINE_WARMUPS,
    PIPELINE_CACHE_COUNTER_KEYS,
    PIPELINE_CACHE_SECONDS_KEY,
    PROTOCOL_PRESETS,
    RATE_ABSOLUTE_TOLERANCE,
    RATE_RELATIVE_TOLERANCE,
    REPORT_SCHEMA_VERSION,
    SESSION_KEYS,
    MatrixError,
    Workload,
    trace_generation_counters_valid,
    workload_descriptor_sha256,
)
from .validation import (
    require_bool,
    require_digest,
    require_exact_keys,
    require_int,
    require_list,
    require_number,
    require_object,
    require_string,
    ordered_prove_time_drift,
)
from .resource_admission import validate_report_admission
from .request_resources import validate_request_resources
from .runtime_admission import validate_runtime_admission


REPORT_KEYS = {
    "schema_version", "product_identity", "backend", "evidence_class", "profiled", "provenance",
    "protocol", "workload", "resource_admission", "resources", "session", "runtime_admission", "proof", "backend_telemetry", "timing",
    "throughput",
}
PROVENANCE_KEYS = {
    "git_commit", "git_dirty", "zig_version", "optimization", "target_os",
    "target_arch", "cpu_count", "simd_pack_width", "single_threaded",
    "blake2s_requested_backend", "blake2s_effective_backend",
    "blake2s_simd_supported",
    "thread_parallelism_enabled", "environment_overrides", "complete",
}
PROTOCOL_KEYS = {
    "name", "pow_bits", "log_blowup_factor", "log_last_layer_degree_bound",
    "n_queries", "fold_step",
}
WORKLOAD_KEYS = {
    "name", "descriptor_sha256", "parameters", "trace_log_rows", "trace_rows",
    "committed_trees", "committed_columns", "committed_trace_cells", "native_unit",
    "native_units",
}
PROOF_KEYS = {"samples", "verified_samples", "all_samples_byte_identical", "artifact"}
PROOF_SAMPLE_KEYS = {"bytes", "sha256"}
TIMING_KEYS = {
    "backend_init_seconds", "warmup_request_seconds", "samples", "stage_profiles",
    "input_seconds", "prove_seconds", "proof_encode_seconds", "verify_seconds",
    "request_seconds",
}
SAMPLE_KEYS = {
    "input_seconds", "prove_seconds", "proof_encode_seconds", "verify_seconds",
    "request_seconds", "native_mhz", "request_native_mhz", "trace_row_mhz",
    "request_trace_row_mhz", "committed_mcells_per_second",
}
SUMMARY_KEYS = {"median", "min", "max", "mad"}
THROUGHPUT_KEYS = {
    "headline_eligible", "headline_native_mhz", "diagnostic_native_mhz",
    "headline_request_native_mhz", "diagnostic_request_native_mhz",
    "headline_trace_row_mhz", "diagnostic_trace_row_mhz",
    "headline_request_trace_row_mhz", "diagnostic_request_trace_row_mhz",
    "headline_committed_mcells_per_second",
    "diagnostic_committed_mcells_per_second", "headline_requirements",
}
ARTIFACT_KEYS = {
    "schema_version", "upstream_commit", "exchange_mode", "generator", "example",
    "prove_mode", "pcs_config", "blake_statement", "plonk_statement",
    "poseidon_statement", "state_machine_statement", "wide_fibonacci_statement",
    "xor_statement", "proof_bytes_hex",
}
ARTIFACT_BINDING_KEYS = {
    "path", "sample_index", "bytes", "sha256", "artifact_schema_version",
    "upstream_commit", "exchange_mode",
}
TELEMETRY_KEYS = {
    "scope", "post_warmup_pipeline_cache", "post_warmup_archive_store",
    "warmups", "samples",
    "total_metal_dispatches", "total_cpu_fallbacks", "valid",
}
TELEMETRY_DELTA_KEYS = {
    "classification", "metal_dispatches", "cpu_fallbacks", "counters",
    "pipeline_cache", "archive_store",
}
# The outer request timer encloses four nanosecond-resolution phase timers. One
# timer tick plus a relative floating-point allowance prevents binary rounding
# from rejecting an otherwise exact decomposition.
REQUEST_PHASE_ABSOLUTE_TOLERANCE_SECONDS = 1e-9
REQUEST_PHASE_RELATIVE_TOLERANCE = 1e-12
ORDERED_PROVE_DRIFT_MAX_RELATIVE = 0.05
M31_MODULUS = (1 << 31) - 1


def _close(actual: float, expected: float) -> bool:
    return math.isclose(
        actual,
        expected,
        rel_tol=RATE_RELATIVE_TOLERANCE,
        abs_tol=RATE_ABSOLUTE_TOLERANCE,
    )


def _expected_summary(values: list[float]) -> dict[str, float]:
    median = statistics.median(values)
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "mad": statistics.median(abs(value - median) for value in values),
    }


def validate_summary(value: Any, expected: list[float], context: str) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    require_exact_keys(value, SUMMARY_KEYS, context)
    for key, expected_value in _expected_summary(expected).items():
        actual = require_number(value[key], f"{context}.{key}")
        if not _close(actual, expected_value):
            raise MatrixError(f"{context}.{key} is inconsistent with samples")


def proof_fingerprint(report: dict[str, Any], lane: str, samples: int) -> tuple[str, int]:
    proof = require_object(report, "proof", lane)
    require_exact_keys(proof, PROOF_KEYS, f"{lane}.proof")
    records = require_list(proof, "samples", f"{lane}.proof")
    verified_samples = require_int(
        proof["verified_samples"], f"{lane}.proof.verified_samples"
    )
    if verified_samples != samples or len(records) != samples:
        raise MatrixError(f"{lane} did not verify every requested proof sample")
    if require_bool(
        proof["all_samples_byte_identical"],
        f"{lane}.proof.all_samples_byte_identical",
    ) is not True:
        raise MatrixError(f"{lane} proof samples are not byte-identical")
    fingerprints: list[tuple[str, int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise MatrixError(f"{lane}.proof.samples[{index}] must be an object")
        require_exact_keys(record, PROOF_SAMPLE_KEYS, f"{lane}.proof.samples[{index}]")
        size = require_int(
            record["bytes"], f"{lane}.proof.samples[{index}].bytes", positive=True
        )
        fingerprints.append((require_digest(record["sha256"], f"{lane}.proof.samples[{index}].sha256"), size))
    if len(set(fingerprints)) != 1:
        raise MatrixError(f"{lane} proof fingerprints disagree")
    return fingerprints[0]


def validate_state_machine_statement(
    value: Any, workload: Workload, context: str
) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    require_exact_keys(value, {"public_input", "stmt0", "stmt1"}, context)
    parameters = workload.parameters
    log_n_rows = parameters["log_n_rows"]
    initial = [parameters["initial_x"], parameters["initial_y"]]
    final = [
        (initial[0] + (1 << log_n_rows)) % M31_MODULUS,
        (initial[1] + (1 << (log_n_rows - 1))) % M31_MODULUS,
    ]
    if value["public_input"] != [initial, final]:
        raise MatrixError(f"{context}.public_input does not match the request")

    stmt0 = value["stmt0"]
    if not isinstance(stmt0, dict):
        raise MatrixError(f"{context}.stmt0 must be an object")
    require_exact_keys(stmt0, {"n", "m"}, f"{context}.stmt0")
    if stmt0 != {"n": log_n_rows, "m": log_n_rows - 1}:
        raise MatrixError(f"{context}.stmt0 does not match the request")

    stmt1 = value["stmt1"]
    if not isinstance(stmt1, dict):
        raise MatrixError(f"{context}.stmt1 must be an object")
    require_exact_keys(
        stmt1,
        {"x_axis_claimed_sum", "y_axis_claimed_sum"},
        f"{context}.stmt1",
    )
    for name in ("x_axis_claimed_sum", "y_axis_claimed_sum"):
        coordinates = stmt1[name]
        if not isinstance(coordinates, list) or len(coordinates) != 4:
            raise MatrixError(f"{context}.stmt1.{name} must have four coordinates")
        for index, coordinate in enumerate(coordinates):
            canonical = require_int(
                coordinate,
                f"{context}.stmt1.{name}[{index}]",
            )
            if canonical >= M31_MODULUS:
                raise MatrixError(
                    f"{context}.stmt1.{name}[{index}] is not canonical M31"
                )


def validate_blake_statement(
    value: Any, workload: Workload, context: str
) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    require_exact_keys(value, {"stmt0", "stmt1"}, context)

    stmt0 = value["stmt0"]
    if not isinstance(stmt0, dict):
        raise MatrixError(f"{context}.stmt0 must be an object")
    require_exact_keys(stmt0, {"log_size"}, f"{context}.stmt0")
    if stmt0["log_size"] != workload.parameters["log_n_rows"]:
        raise MatrixError(f"{context}.stmt0 does not match the request")

    stmt1 = value["stmt1"]
    if not isinstance(stmt1, dict):
        raise MatrixError(f"{context}.stmt1 must be an object")
    require_exact_keys(
        stmt1,
        {"scheduler_claimed_sum", "round_claimed_sums", "xor_claimed_sums"},
        f"{context}.stmt1",
    )
    claims = (
        ("scheduler_claimed_sum", [stmt1["scheduler_claimed_sum"]], 1),
        ("round_claimed_sums", stmt1["round_claimed_sums"], 2),
        ("xor_claimed_sums", stmt1["xor_claimed_sums"], 5),
    )
    for name, values, expected_count in claims:
        if not isinstance(values, list) or len(values) != expected_count:
            raise MatrixError(
                f"{context}.stmt1.{name} must contain {expected_count} claimed sums"
            )
        for claim_index, coordinates in enumerate(values):
            if not isinstance(coordinates, list) or len(coordinates) != 4:
                raise MatrixError(
                    f"{context}.stmt1.{name}[{claim_index}] must have four coordinates"
                )
            for coordinate_index, coordinate in enumerate(coordinates):
                canonical = require_int(
                    coordinate,
                    (
                        f"{context}.stmt1.{name}[{claim_index}]"
                        f"[{coordinate_index}]"
                    ),
                )
                if canonical >= M31_MODULUS:
                    raise MatrixError(
                        f"{context}.stmt1.{name}[{claim_index}]"
                        f"[{coordinate_index}] is not canonical M31"
                    )


def validate_proof_artifact(
    report: dict[str, Any],
    lane: str,
    workload: Workload,
    args: argparse.Namespace,
    artifact: dict[str, Any],
    fingerprint: tuple[str, int],
) -> None:
    proof = require_object(report, "proof", lane)
    binding = require_object(proof, "artifact", f"{lane}.proof")
    require_exact_keys(binding, ARTIFACT_BINDING_KEYS, f"{lane}.proof.artifact")
    expected_binding = {
        "path": str(artifact["path"]),
        "sample_index": 0,
        "bytes": fingerprint[1],
        "sha256": fingerprint[0],
        "artifact_schema_version": INTEROP_ARTIFACT_SCHEMA_VERSION,
        "upstream_commit": INTEROP_UPSTREAM_COMMIT,
        "exchange_mode": INTEROP_EXCHANGE_MODE,
    }
    if binding != expected_binding:
        raise MatrixError(f"{lane} proof artifact binding does not match sample 0")

    document = artifact["document"]
    require_exact_keys(document, ARTIFACT_KEYS, f"{lane}.proof_artifact")
    for key, expected in {
        "schema_version": INTEROP_ARTIFACT_SCHEMA_VERSION,
        "upstream_commit": INTEROP_UPSTREAM_COMMIT,
        "exchange_mode": INTEROP_EXCHANGE_MODE,
        "generator": "zig",
        "example": workload.name,
        "prove_mode": "prove",
    }.items():
        if document[key] != expected:
            raise MatrixError(f"{lane} proof artifact has invalid {key}")

    protocol = PROTOCOL_PRESETS[args.protocol]
    expected_pcs = {
        "pow_bits": protocol["pow_bits"],
        "fri_config": {
            "log_blowup_factor": protocol["log_blowup_factor"],
            "log_last_layer_degree_bound": protocol["log_last_layer_degree_bound"],
            "n_queries": protocol["n_queries"],
            "fold_step": protocol["fold_step"],
        },
        "lifting_log_size": None,
    }
    if document["pcs_config"] != expected_pcs:
        raise MatrixError(f"{lane} proof artifact PCS config does not match request")
    statement_key = f"{workload.name}_statement"
    if workload.name == "blake":
        validate_blake_statement(
            document[statement_key],
            workload,
            f"{lane}.proof_artifact.{statement_key}",
        )
    elif workload.name == "state_machine":
        validate_state_machine_statement(
            document[statement_key],
            workload,
            f"{lane}.proof_artifact.{statement_key}",
        )
    elif document[statement_key] != workload.parameters:
        raise MatrixError(f"{lane} proof artifact statement does not match request")
    for key in ARTIFACT_KEYS:
        if key.endswith("_statement") and key != statement_key and document[key] is not None:
            raise MatrixError(f"{lane} proof artifact has unexpected {key}")
    if artifact["proof_bytes"] != fingerprint[1] or artifact["proof_sha256"] != fingerprint[0]:
        raise MatrixError(f"{lane} proof artifact bytes disagree with sample 0")


def validate_counter_object(value: Any, context: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    require_exact_keys(value, BACKEND_COUNTER_KEYS, context)
    for key, counter in value.items():
        if isinstance(counter, bool) or not isinstance(counter, int) or counter < 0:
            raise MatrixError(f"{context}.{key} must be a nonnegative integer")
    return value


def validate_pipeline_cache(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    seconds_keys = {PIPELINE_CACHE_SECONDS_KEY, LIBRARY_PREPARATION_SECONDS_KEY}
    require_exact_keys(value, PIPELINE_CACHE_COUNTER_KEYS | seconds_keys, context)
    for key in PIPELINE_CACHE_COUNTER_KEYS:
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise MatrixError(f"{context}.{key} must be a nonnegative integer")
    for key in seconds_keys:
        if require_number(value[key], f"{context}.{key}") < 0:
            raise MatrixError(f"{context}.{key} must be nonnegative")
    for kind in ("library", "pipeline"):
        entries = value[f"{kind}_cache_entries"]
        peak_entries = value[f"{kind}_cache_peak_entries"]
        entry_limit = value[f"{kind}_cache_entry_limit"]
        byte_count = value[f"{kind}_cache_bytes"]
        peak_bytes = value[f"{kind}_cache_peak_bytes"]
        byte_limit = value[f"{kind}_cache_byte_limit"]
        if entry_limit <= 0 or byte_limit <= 0:
            raise MatrixError(f"{context}.{kind}_cache limits must be positive")
        if entries > entry_limit or peak_entries > entry_limit or peak_entries < entries:
            raise MatrixError(f"{context}.{kind}_cache entry bounds are inconsistent")
        if byte_count > byte_limit or peak_bytes > byte_limit or peak_bytes < byte_count:
            raise MatrixError(f"{context}.{kind}_cache byte bounds are inconsistent")


def validate_archive_store(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{context} must be an object")
    require_exact_keys(
        value,
        ARCHIVE_STORE_COUNTER_KEYS | {ARCHIVE_STORE_SECONDS_KEY},
        context,
    )
    for key in ARCHIVE_STORE_COUNTER_KEYS:
        require_int(value[key], f"{context}.{key}")
    if require_number(value[ARCHIVE_STORE_SECONDS_KEY], f"{context}.{ARCHIVE_STORE_SECONDS_KEY}") < 0:
        raise MatrixError(f"{context}.{ARCHIVE_STORE_SECONDS_KEY} must be nonnegative")
    for prefix in ("archive_disk", "archive_quarantine"):
        entries = value[f"{prefix}_entries"]
        entry_limit = value[f"{prefix}_entry_limit"]
        byte_count = value[f"{prefix}_bytes"]
        byte_limit = value[f"{prefix}_byte_limit"]
        if entry_limit <= 0 or byte_limit <= 0:
            raise MatrixError(f"{context}.{prefix} limits must be positive")
        if entries > entry_limit or byte_count > byte_limit:
            raise MatrixError(f"{context}.{prefix} bounds are inconsistent")
    per_entry_limit = value["archive_per_entry_byte_limit"]
    if per_entry_limit <= 0 or per_entry_limit > value["archive_disk_byte_limit"]:
        raise MatrixError(f"{context}.archive_per_entry_byte_limit is inconsistent")


def metal_dispatch_total(counters: dict[str, int]) -> int:
    return sum(counters[key] for key in (
        "resident_merkle_commits", "metal_quotient_dispatches",
        "metal_sampled_value_dispatches", "metal_circle_transform_dispatches",
        "metal_circle_lde_dispatches", "metal_fri_circle_fold_dispatches",
        "metal_fri_line_fold_dispatches", "metal_fri_fold_commit_epochs",
        "metal_qm31_coordinate_dispatches", "metal_trace_generation_dispatches",
    ))


def cpu_fallback_total(counters: dict[str, int]) -> int:
    named_merkle = counters["cpu_small_merkle_commits"] + counters["cpu_streaming_merkle_commits"]
    return max(counters["host_merkle_commits"], named_merkle) + sum(counters[key] for key in (
        "cpu_sampled_value_evaluations", "cpu_small_circle_interpolations",
        "cpu_small_circle_evaluations", "cpu_small_circle_ldes",
    ))


def telemetry_classification(dispatches: int, fallbacks: int) -> str:
    if dispatches == 0:
        return "no_backend_work" if fallbacks == 0 else "host_only"
    return "accelerated_without_fallbacks" if fallbacks == 0 else "accelerated_with_fallbacks"


def pipeline_preparation_occurred(value: dict[str, Any]) -> bool:
    # Cache-hit lookup time is still accumulated; only counters that create or
    # load library/pipeline state distinguish a cold sample.
    return (
        value["library_cache_misses"] > 0
        or value["binary_archive_hits"] > 0
        or value["binary_archive_misses"] > 0
        or value["direct_compiles"] > 0
        or value["archive_populations"] > 0
        or value["archive_serializations"] > 0
    )


def archive_preparation_occurred(value: dict[str, Any]) -> bool:
    return any(
        value[key] > 0
        for key in ARCHIVE_STORE_COUNTER_KEYS
        if key not in {
            "archive_disk_entries",
            "archive_disk_bytes",
            "archive_disk_entry_limit",
            "archive_disk_byte_limit",
            "archive_per_entry_byte_limit",
            "archive_quarantine_entries",
            "archive_quarantine_bytes",
            "archive_quarantine_entry_limit",
            "archive_quarantine_byte_limit",
        }
    ) or value[ARCHIVE_STORE_SECONDS_KEY] > 0


def validate_metal_telemetry(report: dict[str, Any], warmups: int, samples: int) -> bool:
    telemetry = report.get("backend_telemetry")
    if not isinstance(telemetry, dict):
        raise MatrixError("metal.backend_telemetry must be present")
    require_exact_keys(telemetry, TELEMETRY_KEYS, "metal.backend_telemetry")
    if require_string(telemetry["scope"], "metal.backend_telemetry.scope") != "verified_proof_request":
        raise MatrixError("metal telemetry has the wrong scope")
    validate_pipeline_cache(telemetry["post_warmup_pipeline_cache"], "metal.backend_telemetry.post_warmup_pipeline_cache")
    validate_archive_store(telemetry["post_warmup_archive_store"], "metal.backend_telemetry.post_warmup_archive_store")
    records_by_group = {"warmups": telemetry["warmups"], "samples": telemetry["samples"]}
    if not all(isinstance(records, list) for records in records_by_group.values()):
        raise MatrixError("metal telemetry request groups must be arrays")
    if len(records_by_group["warmups"]) != warmups or len(records_by_group["samples"]) != samples:
        raise MatrixError("metal telemetry does not cover every request")
    total_dispatches = 0
    total_fallbacks = 0
    measured_pipeline_warm = True
    for group, records in records_by_group.items():
        for index, record in enumerate(records):
            context = f"metal.backend_telemetry.{group}[{index}]"
            if not isinstance(record, dict):
                raise MatrixError(f"{context} must be an object")
            require_exact_keys(record, TELEMETRY_DELTA_KEYS, context)
            counters = validate_counter_object(record["counters"], f"{context}.counters")
            if not trace_generation_counters_valid(counters):
                raise MatrixError(f"{context} trace-generation counters are inconsistent")
            validate_pipeline_cache(record["pipeline_cache"], f"{context}.pipeline_cache")
            validate_archive_store(record["archive_store"], f"{context}.archive_store")
            if group == "samples" and (
                pipeline_preparation_occurred(record["pipeline_cache"])
                or archive_preparation_occurred(record["archive_store"])
            ):
                measured_pipeline_warm = False
            dispatches = metal_dispatch_total(counters)
            fallbacks = cpu_fallback_total(counters)
            declared_dispatches = require_int(
                record["metal_dispatches"], f"{context}.metal_dispatches"
            )
            declared_fallbacks = require_int(
                record["cpu_fallbacks"], f"{context}.cpu_fallbacks"
            )
            if declared_dispatches != dispatches or declared_fallbacks != fallbacks:
                raise MatrixError(f"{context} totals disagree with counters")
            classification = require_string(
                record["classification"], f"{context}.classification"
            )
            if classification != telemetry_classification(dispatches, fallbacks):
                raise MatrixError(f"{context}.classification disagrees with counters")
            if dispatches == 0 or classification not in ACCELERATED_CLASSIFICATIONS:
                raise MatrixError(f"{context} records no accelerated work")
            total_dispatches += dispatches
            total_fallbacks += fallbacks
    declared_total_dispatches = require_int(
        telemetry["total_metal_dispatches"],
        "metal.backend_telemetry.total_metal_dispatches",
    )
    declared_total_fallbacks = require_int(
        telemetry["total_cpu_fallbacks"],
        "metal.backend_telemetry.total_cpu_fallbacks",
    )
    if declared_total_dispatches != total_dispatches or declared_total_fallbacks != total_fallbacks:
        raise MatrixError("metal telemetry aggregate totals are inconsistent")
    measured_backend_valid = measured_pipeline_warm and total_fallbacks == 0
    declared_valid = require_bool(
        telemetry["valid"], "metal.backend_telemetry.valid"
    )
    if declared_valid != measured_backend_valid:
        raise MatrixError(
            "metal.backend_telemetry.valid disagrees with pipeline warmth or CPU fallback counters"
        )
    return measured_backend_valid


def validate_sample(sample: dict[str, Any], lane: str, index: int, workload: Workload) -> None:
    context = f"{lane}.timing.samples[{index}]"
    require_exact_keys(sample, SAMPLE_KEYS, context)
    for field in SAMPLE_KEYS:
        value = require_number(sample[field], f"{context}.{field}", positive=field not in {
            "input_seconds", "proof_encode_seconds", "verify_seconds",
        })
        if value < 0:
            raise MatrixError(f"{context}.{field} must be nonnegative")
    prove = float(sample["prove_seconds"])
    request = float(sample["request_seconds"])
    if request < prove:
        raise MatrixError(f"{context}.request_seconds is shorter than prove_seconds")
    phase_seconds = sum(
        float(sample[field])
        for field in (
            "input_seconds",
            "prove_seconds",
            "proof_encode_seconds",
            "verify_seconds",
        )
    )
    phase_tolerance = max(
        REQUEST_PHASE_ABSOLUTE_TOLERANCE_SECONDS,
        request * REQUEST_PHASE_RELATIVE_TOLERANCE,
    )
    if request + phase_tolerance < phase_seconds:
        raise MatrixError(f"{context}.request_seconds is shorter than its phases")
    expected = {
        "native_mhz": workload.native_units / prove / 1_000_000.0,
        "request_native_mhz": workload.native_units / request / 1_000_000.0,
        "trace_row_mhz": workload.trace_rows / prove / 1_000_000.0,
        "request_trace_row_mhz": workload.trace_rows / request / 1_000_000.0,
        "committed_mcells_per_second": workload.committed_trace_cells / prove / 1_000_000.0,
    }
    for field, expected_value in expected.items():
        if not _close(float(sample[field]), expected_value):
            raise MatrixError(f"{context}.{field} is inconsistent")


def validate_session(report: dict[str, Any], lane: str, workload: Workload, protocol: dict[str, Any]) -> None:
    session = require_object(report, "session", lane)
    require_exact_keys(session, SESSION_KEYS, f"{lane}.session")
    for field, value in session.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MatrixError(f"{lane}.session.{field} must be a nonnegative integer")
    required_log = max(workload.trace_log_rows + 1, workload.trace_log_rows + protocol["log_blowup_factor"])
    if session["max_circle_log"] < required_log:
        raise MatrixError(f"{lane}.session.max_circle_log does not cover workload")
    if session["tower_build_count"] != 1:
        raise MatrixError(f"{lane}.session.tower_build_count must equal 1")
    if not 0 < session["retained_host_twiddle_bytes"] <= session["host_byte_budget"]:
        raise MatrixError(f"{lane}.session retained twiddles exceed budget or are empty")


def headline_blockers(report: dict[str, Any], lane: str) -> list[str]:
    blockers: list[str] = []
    provenance = report["provenance"]
    for condition, name in (
        (provenance["complete"] is True, "provenance_incomplete"),
        (provenance["git_dirty"] is False, "git_dirty"),
        (provenance["optimization"] == "ReleaseFast", "not_release_fast"),
        (provenance["thread_parallelism_enabled"] is True, "thread_parallelism_disabled"),
    ):
        if not condition:
            blockers.append(f"{lane}_{name}")
    throughput = report["throughput"]
    requirements = throughput["headline_requirements"]
    for name, satisfied in requirements.items():
        if satisfied is not True:
            blockers.append(f"{lane}_requirement_{name}")
    if report["protocol"]["name"] != "functional":
        blockers.append(f"{lane}_nonfunctional_protocol")
    if throughput["headline_eligible"] is not True:
        blockers.append(f"{lane}_report_not_headline_eligible")
    if report["evidence_class"] != "verified_unprofiled" or report["profiled"] is not False:
        blockers.append(f"{lane}_not_verified_unprofiled")
    return blockers


def validate_report(
    report: dict[str, Any], lane: str, workload: Workload, args: argparse.Namespace
) -> tuple[tuple[str, int], list[str]]:
    require_exact_keys(report, REPORT_KEYS, lane)
    if report["schema_version"] != REPORT_SCHEMA_VERSION:
        raise MatrixError(f"{lane} report schema version is unsupported")
    if report["backend"] != EXPECTED_BACKENDS[lane]:
        raise MatrixError(f"{lane} report identifies the wrong backend")
    evidence_class = require_string(report["evidence_class"], f"{lane}.evidence_class")
    if evidence_class not in {
        "verified_unprofiled",
        "profiled_diagnostic",
        "correctness_only",
    }:
        raise MatrixError(f"{lane}.evidence_class is unsupported")
    profiled = require_bool(report["profiled"], f"{lane}.profiled")

    provenance = require_object(report, "provenance", lane)
    require_exact_keys(provenance, PROVENANCE_KEYS, f"{lane}.provenance")
    git_commit = require_string(provenance["git_commit"], f"{lane}.provenance.git_commit")
    if len(git_commit) != 40 or any(character not in "0123456789abcdef" for character in git_commit):
        raise MatrixError(f"{lane}.provenance.git_commit must be a lowercase Git object id")
    require_bool(provenance["git_dirty"], f"{lane}.provenance.git_dirty")
    for field in ("zig_version", "optimization", "target_os", "target_arch"):
        require_string(provenance[field], f"{lane}.provenance.{field}", nonempty=True)
    require_int(provenance["cpu_count"], f"{lane}.provenance.cpu_count", positive=True)
    require_int(provenance["simd_pack_width"], f"{lane}.provenance.simd_pack_width", positive=True)
    requested_blake2s = require_string(
        provenance["blake2s_requested_backend"],
        f"{lane}.provenance.blake2s_requested_backend",
    )
    effective_blake2s = require_string(
        provenance["blake2s_effective_backend"],
        f"{lane}.provenance.blake2s_effective_backend",
    )
    simd_supported = require_bool(
        provenance["blake2s_simd_supported"],
        f"{lane}.provenance.blake2s_simd_supported",
    )
    if requested_blake2s not in {"auto", "scalar", "simd"}:
        raise MatrixError(f"{lane}.provenance.blake2s_requested_backend is unsupported")
    if effective_blake2s not in {"scalar", "simd"}:
        raise MatrixError(f"{lane}.provenance.blake2s_effective_backend is unsupported")
    expected_blake2s = (
        "simd"
        if simd_supported and requested_blake2s in {"auto", "simd"}
        else "scalar"
    )
    if effective_blake2s != expected_blake2s:
        raise MatrixError(f"{lane} Blake2s requested/effective dispatch is inconsistent")
    single_threaded = require_bool(
        provenance["single_threaded"], f"{lane}.provenance.single_threaded"
    )
    parallel = require_bool(
        provenance["thread_parallelism_enabled"],
        f"{lane}.provenance.thread_parallelism_enabled",
    )
    if single_threaded == parallel:
        raise MatrixError(f"{lane} provenance threading flags disagree")
    complete = require_bool(provenance["complete"], f"{lane}.provenance.complete")
    overrides = provenance["environment_overrides"]
    if not isinstance(overrides, list) or any(
        not isinstance(item, dict)
        or set(item) != {"name", "value"}
        or not isinstance(item["name"], str)
        or not item["name"]
        or not isinstance(item["value"], str)
        for item in overrides
    ):
        raise MatrixError(f"{lane}.provenance.environment_overrides has invalid schema")
    if complete != (len(overrides) == 0):
        raise MatrixError(f"{lane}.provenance.complete disagrees with overrides")
    try:
        product_identity = validate_product_identity(
            report["product_identity"], lane, provenance=provenance
        )
    except ProductEvidenceError as error:
        raise MatrixError(str(error)) from error
    if report["backend"] != PRODUCT_SPECS[lane].report_backend:
        raise MatrixError(f"{lane} report backend disagrees with its focused product")
    protocol = require_object(report, "protocol", lane)
    require_exact_keys(protocol, PROTOCOL_KEYS, f"{lane}.protocol")
    if protocol != PROTOCOL_PRESETS[args.protocol]:
        raise MatrixError(f"{lane} protocol descriptor does not match request")

    reported_workload = require_object(report, "workload", lane)
    require_exact_keys(reported_workload, WORKLOAD_KEYS, f"{lane}.workload")
    expected_workload = workload.report_dict()
    for key, expected in expected_workload.items():
        if reported_workload[key] != expected:
            raise MatrixError(f"{lane} workload field {key} does not match request")
    if require_digest(reported_workload["descriptor_sha256"], f"{lane}.workload.descriptor_sha256") != workload_descriptor_sha256(workload, args.protocol):
        raise MatrixError(f"{lane} workload descriptor digest is inconsistent")
    profile = getattr(args, "resource_profile", "standard")
    try:
        validate_report_admission(report["resource_admission"], workload, profile)
    except ValueError as error:
        raise MatrixError(f"{lane}.{error}") from error
    validate_session(report, lane, workload, protocol)
    validate_runtime_admission(report, lane, args, product_identity)

    timing = require_object(report, "timing", lane)
    require_exact_keys(timing, TIMING_KEYS, f"{lane}.timing")
    if require_number(timing["backend_init_seconds"], f"{lane}.timing.backend_init_seconds") < 0:
        raise MatrixError(f"{lane}.timing.backend_init_seconds must be nonnegative")
    warmup_values = timing["warmup_request_seconds"]
    if not isinstance(warmup_values, list) or len(warmup_values) != args.warmups:
        raise MatrixError(f"{lane} timing does not cover requested warmups")
    for index, value in enumerate(warmup_values):
        require_number(value, f"{lane}.timing.warmup_request_seconds[{index}]", positive=True)
    samples = timing["samples"]
    if not isinstance(samples, list) or len(samples) != args.samples:
        raise MatrixError(f"{lane} timing does not cover requested samples")
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise MatrixError(f"{lane}.timing.samples[{index}] must be an object")
        validate_sample(sample, lane, index, workload)
    if timing["stage_profiles"] is not None:
        raise MatrixError(f"{lane} formal matrix report unexpectedly contains profiles")
    for field in ("input_seconds", "prove_seconds", "proof_encode_seconds", "verify_seconds", "request_seconds"):
        validate_summary(timing[field], [float(sample[field]) for sample in samples], f"{lane}.timing.{field}")

    fingerprint = proof_fingerprint(report, lane, args.samples)
    resources_complete = validate_request_resources(report, lane, args, fingerprint)
    if lane == "metal":
        backend_telemetry_valid = validate_metal_telemetry(
            report, args.warmups, args.samples
        )
    else:
        if report["backend_telemetry"] is not None:
            raise MatrixError("CPU report must not claim Metal telemetry")
        backend_telemetry_valid = True

    prove_median = statistics.median(
        float(sample["prove_seconds"]) for sample in samples
    )
    minimum_samples = 5 if prove_median < 1.0 else 3
    sampling_contract = (
        args.warmups >= MIN_HEADLINE_WARMUPS
        and args.samples >= minimum_samples
    )
    expected_evidence_class = (
        "profiled_diagnostic"
        if profiled
        else "verified_unprofiled"
        if sampling_contract
        else "correctness_only"
    )
    if evidence_class != expected_evidence_class:
        raise MatrixError(f"{lane} evidence class does not match measured sampling")

    expected_requirements = {
        "verified_unprofiled": expected_evidence_class == "verified_unprofiled",
        "sampling_contract": sampling_contract,
        "functional_protocol": report["protocol"]["name"] == "functional",
        "release_fast": provenance["optimization"] == "ReleaseFast",
        "clean_complete_provenance": (
            provenance["complete"] is True
            and provenance["git_dirty"] is False
            and not overrides
        ),
        "thread_parallelism_enabled": parallel,
        "byte_identical_verified_samples": True,
        "backend_telemetry_valid": backend_telemetry_valid,
    }
    expected_headline_eligible = all(expected_requirements.values())

    throughput = require_object(report, "throughput", lane)
    require_exact_keys(throughput, THROUGHPUT_KEYS, f"{lane}.throughput")
    headline_eligible = require_bool(
        throughput["headline_eligible"], f"{lane}.throughput.headline_eligible"
    )
    if headline_eligible != expected_headline_eligible:
        raise MatrixError(f"{lane}.throughput.headline_eligible is inconsistent")
    requirements = require_object(throughput, "headline_requirements", f"{lane}.throughput")
    require_exact_keys(requirements, HEADLINE_REQUIREMENT_KEYS, f"{lane}.throughput.headline_requirements")
    for name, satisfied in requirements.items():
        require_bool(satisfied, f"{lane}.throughput.headline_requirements.{name}")
    if requirements != expected_requirements:
        raise MatrixError(f"{lane}.throughput.headline_requirements are inconsistent")
    metric_fields = {
        "native_mhz": ("headline_native_mhz", "diagnostic_native_mhz"),
        "request_native_mhz": ("headline_request_native_mhz", "diagnostic_request_native_mhz"),
        "trace_row_mhz": ("headline_trace_row_mhz", "diagnostic_trace_row_mhz"),
        "request_trace_row_mhz": ("headline_request_trace_row_mhz", "diagnostic_request_trace_row_mhz"),
        "committed_mcells_per_second": ("headline_committed_mcells_per_second", "diagnostic_committed_mcells_per_second"),
    }
    for sample_field, (headline_field, diagnostic_field) in metric_fields.items():
        values = [float(sample[sample_field]) for sample in samples]
        if headline_eligible:
            validate_summary(throughput[headline_field], values, f"{lane}.throughput.{headline_field}")
        elif throughput[headline_field] is not None:
            raise MatrixError(f"{lane}.throughput.{headline_field} must be null")
        if expected_evidence_class == "profiled_diagnostic":
            validate_summary(throughput[diagnostic_field], values, f"{lane}.throughput.{diagnostic_field}")
        elif throughput[diagnostic_field] is not None:
            raise MatrixError(f"{lane}.throughput.{diagnostic_field} must be null")

    blockers = headline_blockers(report, lane)
    if not resources_complete:
        blockers.append(f"{lane}_request_resources_incomplete")
    ordered_drift = ordered_prove_time_drift(samples)
    if (
        headline_eligible
        and ordered_drift is not None
        and ordered_drift > ORDERED_PROVE_DRIFT_MAX_RELATIVE
    ):
        blockers.append(f"{lane}_ordered_prove_time_drift")
    return fingerprint, blockers


def validate_pair(
    cpu: dict[str, Any],
    metal: dict[str, Any],
    cpu_fingerprint: tuple[str, int],
    metal_fingerprint: tuple[str, int],
) -> None:
    for field in ("schema_version", "protocol", "workload", "provenance"):
        if cpu[field] != metal[field]:
            raise MatrixError(f"CPU and Metal {field} differ")
    if cpu_fingerprint != metal_fingerprint:
        raise MatrixError("CPU and Metal canonical proof digests differ")
