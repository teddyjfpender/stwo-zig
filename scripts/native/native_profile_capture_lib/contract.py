"""Fail-closed host-stage, proof, CPU-sample, and Metal-profile contracts."""

from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from typing import Any

if __package__.startswith("scripts."):
    from scripts.metal_profile_report_lib import build_report, load_events
    from scripts.native_proof_matrix_lib import contract as matrix_contract
    from scripts.native_proof_matrix_lib.model import MatrixError, Workload
else:
    from metal_profile_report_lib import build_report, load_events
    from native_proof_matrix_lib import contract as matrix_contract
    from native_proof_matrix_lib.model import MatrixError, Workload

from .evidence import canonical_sha256
from .model import (
    COMMIT_CHILD_STAGE_IDS,
    HOST_TIMER_IDS,
    PROFILE_SAMPLES,
    STABLE_CORE_STAGE_IDS,
    STABLE_ROOT_STAGE_IDS,
    CaptureError,
)


DIAGNOSTIC_METRICS = {
    "native_mhz": "diagnostic_native_mhz",
    "request_native_mhz": "diagnostic_request_native_mhz",
    "trace_row_mhz": "diagnostic_trace_row_mhz",
    "request_trace_row_mhz": "diagnostic_request_trace_row_mhz",
    "committed_mcells_per_second": "diagnostic_committed_mcells_per_second",
}


def _finite_nonnegative(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CaptureError(f"{context} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise CaptureError(f"{context} must be finite and non-negative")
    return number


def _children(node: dict[str, Any], context: str) -> list[dict[str, Any]]:
    value = node.get("children")
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(child, dict) for child in value):
        raise CaptureError(f"{context}.children must be null or an array of objects")
    return value


def _validate_node(node: dict[str, Any], context: str) -> None:
    if set(node) != {"id", "label", "seconds", "children"}:
        raise CaptureError(f"{context} has an unsupported stage-node schema")
    if not isinstance(node["id"], str) or not node["id"]:
        raise CaptureError(f"{context}.id must be non-empty")
    if not isinstance(node["label"], str) or not node["label"]:
        raise CaptureError(f"{context}.label must be non-empty")
    _finite_nonnegative(node["seconds"], f"{context}.seconds")
    for index, child in enumerate(_children(node, context)):
        _validate_node(child, f"{context}.children[{index}]")


def validate_stage_profile(
    profile: dict[str, Any], lane: str, workload: Workload, runtime: str
) -> dict[str, Any]:
    context = f"{lane}.stage_profile"
    if set(profile) != {"schema_version", "runtime", "example", "stages"}:
        raise CaptureError(f"{context} has an unsupported schema")
    if profile["schema_version"] != 1:
        raise CaptureError(f"{context}.schema_version is unsupported")
    if profile["runtime"] != runtime or profile["example"] != workload.name:
        raise CaptureError(f"{context} does not identify the measured runtime/example")
    stages = profile["stages"]
    if not isinstance(stages, list) or any(not isinstance(stage, dict) for stage in stages):
        raise CaptureError(f"{context}.stages must be an array of objects")
    for index, stage in enumerate(stages):
        _validate_node(stage, f"{context}.stages[{index}]")
    root_ids = tuple(stage["id"] for stage in stages)
    if root_ids != STABLE_ROOT_STAGE_IDS:
        raise CaptureError(f"{context} stable root stage IDs changed: {root_ids}")

    for index in (1, 2):
        commit_children = _children(stages[index], f"{context}.stages[{index}]")
        commit_ids = [child["id"] for child in commit_children]
        if any(stage_id not in COMMIT_CHILD_STAGE_IDS for stage_id in commit_ids):
            raise CaptureError(f"{context} commit stage contains an unknown child ID")
        if commit_ids.count("merkle_commit") != 1:
            raise CaptureError(f"{context} commit stage must contain one merkle_commit")

    core_children = _children(stages[4], f"{context}.stages[4]")
    core_ids = tuple(child["id"] for child in core_children)
    if core_ids != STABLE_CORE_STAGE_IDS:
        raise CaptureError(f"{context} stable core stage IDs changed: {core_ids}")
    if any(_children(child, f"{context}.core.{child['id']}") for child in core_children):
        raise CaptureError(f"{context} core leaf stages unexpectedly gained children")
    return {
        "schema_version": 1,
        "root_stage_ids": list(root_ids),
        "core_stage_ids": list(core_ids),
        "commit_child_ids": {
            "preprocessed_commit": [child["id"] for child in _children(stages[1], context)],
            "main_trace_commit": [child["id"] for child in _children(stages[2], context)],
        },
    }


def _unprofiled_validation_shadow(report: dict[str, Any]) -> dict[str, Any]:
    shadow = copy.deepcopy(report)
    shadow["profiled"] = False
    shadow["evidence_class"] = "correctness_only"
    shadow["timing"]["stage_profiles"] = None
    for headline, diagnostic in (
        ("headline_native_mhz", "diagnostic_native_mhz"),
        ("headline_request_native_mhz", "diagnostic_request_native_mhz"),
        ("headline_trace_row_mhz", "diagnostic_trace_row_mhz"),
        ("headline_request_trace_row_mhz", "diagnostic_request_trace_row_mhz"),
        (
            "headline_committed_mcells_per_second",
            "diagnostic_committed_mcells_per_second",
        ),
    ):
        shadow["throughput"][headline] = None
        shadow["throughput"][diagnostic] = None
    return shadow


def validate_profile_report(
    report: dict[str, Any], lane: str, workload: Workload, args: Any
) -> tuple[tuple[str, int], dict[str, Any]]:
    if report.get("profiled") is not True or report.get("evidence_class") != "profiled_diagnostic":
        raise CaptureError(f"{lane} report is not explicitly profiled diagnostic evidence")
    throughput = report.get("throughput")
    if not isinstance(throughput, dict) or throughput.get("headline_eligible") is not False:
        raise CaptureError(f"{lane} profiled report must be ineligible for headline throughput")
    if any(throughput.get(name) is not None for name in (
        "headline_native_mhz",
        "headline_request_native_mhz",
        "headline_trace_row_mhz",
        "headline_request_trace_row_mhz",
        "headline_committed_mcells_per_second",
    )):
        raise CaptureError(f"{lane} profiled report must not publish headline metrics")
    samples = report.get("timing", {}).get("samples")
    if not isinstance(samples, list) or len(samples) != PROFILE_SAMPLES:
        raise CaptureError(f"{lane} profiler acceptance requires exactly one measured sample")
    for sample_field, diagnostic_field in DIAGNOSTIC_METRICS.items():
        matrix_contract.validate_summary(
            throughput.get(diagnostic_field),
            [float(sample[sample_field]) for sample in samples],
            f"{lane}.throughput.{diagnostic_field}",
        )

    profiles = report.get("timing", {}).get("stage_profiles")
    if not isinstance(profiles, list) or len(profiles) != PROFILE_SAMPLES:
        raise CaptureError(f"{lane} report must contain one prove-stage tree per sample")
    stage_coverage = validate_stage_profile(
        profiles[0], lane, workload, report["provenance"]["optimization"]
    )
    shadow = _unprofiled_validation_shadow(report)
    try:
        fingerprint, _ = matrix_contract.validate_report(shadow, lane, workload, args)
    except MatrixError as error:
        raise CaptureError(str(error)) from error

    timing = report["timing"]
    _finite_nonnegative(timing["backend_init_seconds"], f"{lane}.backend_init_seconds")
    for timer_id in HOST_TIMER_IDS[1:]:
        _finite_nonnegative(samples[0][timer_id], f"{lane}.timing.samples[0].{timer_id}")
    coverage: dict[str, Any] = {
        "host_timer_ids": list(HOST_TIMER_IDS),
        "host_timer_scope": {
            "backend_init_seconds": "backend/session initialization",
            "input_seconds": "input and trace preparation",
            "prove_seconds": "prove stage tree",
            "proof_encode_seconds": "canonical proof encoding",
            "verify_seconds": "local Zig verification",
            "request_seconds": "complete verified request",
        },
        "stage_tree": stage_coverage,
    }
    if lane == "metal":
        telemetry = report["backend_telemetry"]
        coverage["metal_backend"] = {
            "telemetry_sha256": canonical_sha256(telemetry),
            "total_metal_dispatches": telemetry["total_metal_dispatches"],
            "total_cpu_fallbacks": telemetry["total_cpu_fallbacks"],
            "sample_records": [
                {
                    "classification": record["classification"],
                    "metal_dispatches": record["metal_dispatches"],
                    "cpu_fallbacks": record["cpu_fallbacks"],
                    "counters": record["counters"],
                }
                for record in telemetry["samples"]
            ],
        }
    return fingerprint, coverage


def validate_profile_pair(
    cpu: dict[str, Any],
    metal: dict[str, Any],
    cpu_fingerprint: tuple[str, int],
    metal_fingerprint: tuple[str, int],
) -> None:
    try:
        matrix_contract.validate_pair(cpu, metal, cpu_fingerprint, metal_fingerprint)
    except MatrixError as error:
        raise CaptureError(str(error)) from error


def validate_metal_profile(
    ndjson_path: Path,
    aggregate_path: Path,
    *,
    mode: str,
    expected_pid: int,
    backend_dispatches: int,
) -> dict[str, Any]:
    events = load_events(ndjson_path)
    if [event.get("sequence") for event in events] != list(range(len(events))):
        raise CaptureError("Metal profile event sequence is incomplete or reordered")
    expected = build_report(events)
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CaptureError("Metal aggregate report is not valid JSON") from error
    if aggregate != expected:
        raise CaptureError("Metal aggregate report does not match exact NDJSON events")
    metadata = aggregate["metadata"]
    summary = aggregate["summary"]
    if metadata.get("pid") != expected_pid:
        raise CaptureError("Metal profile metadata is not bound to the measured process")
    requested = mode == "encoder-timestamps"
    if metadata.get("encoder_timestamps_requested") is not requested:
        raise CaptureError("Metal encoder-counter request does not match capture mode")
    if requested:
        if metadata.get("stage_boundary_timestamps_supported") is not True:
            raise CaptureError("targeted Metal workload lacks stage-boundary counter support")
        if metadata.get("encoder_timestamps_enabled") is not True:
            raise CaptureError("targeted Metal workload did not enable encoder timestamps")
        if summary["untimed_encoders"] != 0 or summary["encoder_gpu_ms"] <= 0:
            raise CaptureError("targeted Metal workload has incomplete encoder timing")
    elif metadata.get("encoder_timestamps_enabled") is not False:
        raise CaptureError("command-only Metal workload unexpectedly enabled encoder timestamps")
    for field in (
        "command_errors",
        "counter_overflows",
        "counter_allocation_errors",
        "counter_configuration_errors",
        "timing_inconsistent_commands",
    ):
        if summary[field] != 0:
            raise CaptureError(f"Metal profile reports nonzero {field}")
    kernel_dispatches = sum(row["total_dispatches"] for row in aggregate["kernels"])
    if summary["command_buffers"] <= 0 or summary["command_gpu_ms"] <= 0:
        raise CaptureError("Metal profile contains no timed command-buffer work")
    if summary["encoders"] <= 0 or kernel_dispatches <= 0 or backend_dispatches <= 0:
        raise CaptureError("Metal profile is not bound to real backend dispatch work")
    return {
        "mode": mode,
        "command_buffers": summary["command_buffers"],
        "encoders": summary["encoders"],
        "kernel_dispatches": kernel_dispatches,
        "command_gpu_ms": summary["command_gpu_ms"],
        "encoder_gpu_ms": summary["encoder_gpu_ms"],
        "unattributed_gpu_ms": summary["unattributed_gpu_ms"],
    }
