"""Strict validation of one production ``bench --profiled`` result."""

from __future__ import annotations

import math
import hashlib
import struct
from pathlib import Path
from typing import Any

from .codec import decode_strict, exact_object, sha256_file
from .model import DIGEST_RE, MAX_STREAM_BYTES, CaptureError


PROFILED_SCHEMA = "riscv_profiled_proof_v3"
EXACT_WORK_PROFILED_SCHEMA = "riscv_profiled_proof_v4"
ATTEMPT_SCHEMA = "riscv_verified_request_attempt_v2"
EXACT_WORK_ATTEMPT_SCHEMA = "riscv_verified_request_attempt_v3"
WORK_PROFILE_SCHEMA = "stwo.prover.logical-work-profile.v2"
WORK_PROFILE_VERSION = 2
WORK_PROFILE_DIGEST_DOMAIN = b"stwo-zig/prover/logical-work-profile/v2\0"
WORK_PROFILE_SEMANTICS = "scalar_lane_completed_algorithm_boundaries_v1"
WORK_PROFILE_ALL_SOURCES = (1 << 6) - 1
PRODUCER_LEDGER_VERSION = 2
PRODUCER_COUNT = 7
U64_MAX = (1 << 64) - 1
TIMING_PARTITION = (
    "protocol_complete:guest_execution+witness_materialization+proving+"
    "native_verification;proof_serialization_excluded"
)
REPORT_FIELDS = {
    "schema",
    "release_status",
    "mode",
    "experimental",
    "profiled",
    "recursion_enabled",
    "warmups",
    "samples",
    "verified_samples",
    "total_steps",
    "n_components",
    "throughput_numerator",
    "median_seconds",
    "throughput_mhz",
    "mean_execution_seconds",
    "mean_witness_seconds",
    "mean_proving_seconds",
    "mean_verification_seconds",
    "sample_seconds",
    "statement_sha256",
    "transcript_state_blake2s",
    "implementation_commit",
    "implementation_dirty",
    "executable_sha256",
    "artifact_sha256",
    "proof_path",
    "resources",
    "timing_authority",
    "verified_request_attempts",
}
TIMING_AUTHORITY_FIELDS = {
    "clock",
    "unit",
    "partition",
    "protocol_partition_complete",
    "witness_materialization_regions",
    "authoritative_samples",
    "legacy_outer_samples",
}
ATTEMPT_FIELDS = {
    "schema",
    "status",
    "sample_index",
    "timing_partition",
    "protocol_partition_complete",
    "witness_materialization_regions",
    "guest_execution_ns",
    "witness_materialization_ns",
    "proving_ns",
    "proving_including_witness_ns",
    "native_verification_ns",
    "verified_request_ns",
    "task_profile",
}
EXACT_WORK_ATTEMPT_FIELDS = ATTEMPT_FIELDS | {"work_profile"}
WORK_COUNTER_FIELDS = (
    "field_additions",
    "field_multiplications",
    "field_inversions",
    "fft_butterflies",
    "fri_folds",
    "merkle_compressions",
)
WORK_PROFILE_FIELDS = {
    "schema",
    "schema_version",
    "counter_semantics",
    "authority",
    "source_mask",
    "record_count",
    "producer_ledger_schema_version",
    "expected_producer_counts",
    "completed_producer_counts",
    "producer_coverage_terminal_sealed",
    *WORK_COUNTER_FIELDS,
    "profile_sha256",
}
PROFILE_FIELDS = {"schema_version", "runtime", "example", "graphs"}
GRAPH_FIELDS = {"graph_id", "events", "contributions", "component_work", "summary"}
SUMMARY_FIELDS = {
    "requested_workers",
    "admitted_workers",
    "pool_capacity",
    "worker_stack_bytes",
    "peak_active_tasks",
    "peak_active_workers",
    "planned_tasks",
    "submitted_tasks",
    "completed_tasks",
    "failed_tasks",
    "cancelled_tasks",
    "unsubmitted_cancelled_tasks",
    "started_tasks",
    "finished_tasks",
    "duplicate_starts",
    "duplicate_finishes",
    "useful_task_work_ns",
    "critical_path_ns",
    "admission_wait_ns",
    "queue_wait_ns",
    "resource_wait_ns",
    "task_run_ns",
    "worker_busy_ns",
    "worker_capacity_ns",
    "graph_elapsed_ns",
    "parallel_eligible_ns",
    "peak_reserved_bytes",
    "total_work_estimate",
    "completed_rows",
    "completed_tiles",
    "scheduler",
    "steal_count",
}
KEY_FIELDS = {"epoch", "stage_rank", "component_registry_index", "shard_or_chunk_index"}
EVENT_FIELDS = {
    "key",
    "stage_id",
    "component_kind",
    "task_class",
    "dependencies",
    "dependency_count",
    "parallel_eligible",
    "contribution_range",
    "submitted",
    "started",
    "finished",
    "submitted_ns",
    "ready_ns",
    "start_ns",
    "finish_ns",
    "configured_workers",
    "worker_slot",
    "worker_kind",
    "admission_wait_ns",
    "queue_wait_ns",
    "run_ns",
    "resource_wait_ns",
    "bytes",
    "terminal_status",
    "cleanup_complete",
    "work_estimate",
    "planned_rows",
    "planned_tiles",
    "completed_rows",
    "completed_tiles",
}
BYTE_FIELDS = {
    "final_output_bytes",
    "exclusive_scratch_bytes",
    "shared_resident_bytes",
    "device_resident_bytes",
    "worker_stack_bytes",
}
CONTRIBUTION_FIELDS = {
    "component_registry_index",
    "component_kind",
    "role",
    "work_estimate",
    "planned_rows",
    "planned_tiles",
    "completed_rows",
    "completed_tiles",
}
COMPONENT_FIELDS = CONTRIBUTION_FIELDS | {"task_count"}
RESOURCE_FIELDS = {
    "availability",
    "source",
    "scope",
    "before_warmups",
    "after_verified_samples",
    "interval_delta",
}
SNAPSHOT_FIELDS = {
    "lifetime_max_phys_footprint_bytes",
    "energy_nj",
    "instructions",
    "cycles",
}
DELTA_FIELDS = {"energy_nj", "instructions", "cycles"}
METAL_FIELDS = {
    "eligible_base_components",
    "eligible_lookup_components",
    "base_batch_dispatches",
    "lookup_batch_dispatches",
    "declines",
    "verified_samples_with_dispatch",
}


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CaptureError(f"{name} must be an integer >= {minimum}")
    return value


def _u64(value: Any, name: str, *, minimum: int = 0) -> int:
    result = _integer(value, name, minimum=minimum)
    if result > U64_MAX:
        raise CaptureError(f"{name} exceeds an unsigned 64-bit counter")
    return result


def _number(value: Any, name: str, *, positive: bool = False) -> float:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise CaptureError(f"{name} must be a finite number")
    converted = float(value)
    if converted < 0 or (positive and converted <= 0):
        raise CaptureError(f"{name} must be {'positive' if positive else 'non-negative'}")
    return converted


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise CaptureError(f"{name} must be a lowercase 32-byte digest")
    return value


def _text(value: Any, name: str) -> str:
    if type(value) is not str or not value or len(value) > 1024:
        raise CaptureError(f"{name} must be bounded non-empty text")
    return value


def _key(value: Any, name: str) -> tuple[int, int, int, int]:
    key = exact_object(value, KEY_FIELDS, name)
    return tuple(_integer(key[field], f"{name}.{field}") for field in (
        "epoch", "stage_rank", "component_registry_index", "shard_or_chunk_index"
    ))  # type: ignore[return-value]


def _validate_resources(value: Any) -> dict[str, int]:
    resources = exact_object(value, RESOURCE_FIELDS, "benchmark resources")
    if (
        resources["availability"] != "available"
        or resources["source"] != "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
        or resources["scope"] != "self_process_lifetime"
    ):
        raise CaptureError("benchmark process resource authority is unavailable or changed")
    before = exact_object(resources["before_warmups"], SNAPSHOT_FIELDS, "resource before snapshot")
    after = exact_object(resources["after_verified_samples"], SNAPSHOT_FIELDS, "resource after snapshot")
    delta = exact_object(resources["interval_delta"], DELTA_FIELDS, "resource interval delta")
    for name in SNAPSHOT_FIELDS:
        _integer(before[name], f"resources.before.{name}")
        _integer(after[name], f"resources.after.{name}")
        if after[name] < before[name]:
            raise CaptureError(f"benchmark resource counter regressed: {name}")
    if after["lifetime_max_phys_footprint_bytes"] <= 0:
        raise CaptureError("benchmark peak physical footprint is empty")
    for name in DELTA_FIELDS:
        _integer(delta[name], f"resources.delta.{name}")
        if delta[name] != after[name] - before[name]:
            raise CaptureError(f"benchmark resource delta disagrees: {name}")
    return {
        "peak_rss_bytes": after["lifetime_max_phys_footprint_bytes"],
        "energy_nj": delta["energy_nj"],
        "retired_instructions": delta["instructions"],
        "cycles": delta["cycles"],
    }


def _work_profile_digest(work: dict[str, Any]) -> str:
    encoded = bytearray(WORK_PROFILE_DIGEST_DOMAIN)
    encoded.extend(struct.pack("<H", work["schema_version"]))
    encoded.extend(struct.pack("<B", 2))  # Authority.instrumented_exact.
    encoded.extend(struct.pack("<B", work["source_mask"]))
    encoded.extend(struct.pack("<Q", work["record_count"]))
    encoded.extend(struct.pack("<H", work["producer_ledger_schema_version"]))
    encoded.extend(struct.pack("<B", int(work["producer_coverage_terminal_sealed"])))
    for count in work["expected_producer_counts"]:
        encoded.extend(struct.pack("<Q", count))
    for count in work["completed_producer_counts"]:
        encoded.extend(struct.pack("<Q", count))
    for name in WORK_COUNTER_FIELDS:
        encoded.extend(struct.pack("<Q", work[name]))
    return hashlib.sha256(encoded).hexdigest()


def _validate_work_profile(value: Any) -> dict[str, Any]:
    work = exact_object(value, WORK_PROFILE_FIELDS, "logical work profile")
    expected = {
        "schema": WORK_PROFILE_SCHEMA,
        "schema_version": WORK_PROFILE_VERSION,
        "counter_semantics": WORK_PROFILE_SEMANTICS,
        "authority": "instrumented_exact",
        "source_mask": WORK_PROFILE_ALL_SOURCES,
        "producer_ledger_schema_version": PRODUCER_LEDGER_VERSION,
        "producer_coverage_terminal_sealed": True,
    }
    for name, required in expected.items():
        if type(work[name]) is not type(required) or work[name] != required:
            raise CaptureError(f"logical work profile {name} changed or is incomplete")
    _u64(work["record_count"], "logical work profile record count", minimum=1)
    expected_counts = work["expected_producer_counts"]
    completed_counts = work["completed_producer_counts"]
    if (type(expected_counts) is not list or
            type(completed_counts) is not list or
            len(expected_counts) != PRODUCER_COUNT or
            len(completed_counts) != PRODUCER_COUNT):
        raise CaptureError("logical work profile producer ledger shape changed")
    for index, count in enumerate(expected_counts):
        _u64(count, f"logical work profile expected producer {index}")
    for index, count in enumerate(completed_counts):
        _u64(count, f"logical work profile completed producer {index}")
    if expected_counts != completed_counts:
        raise CaptureError("logical work profile producer ledger is incomplete")
    if sum(completed_counts) != work["record_count"]:
        raise CaptureError("logical work profile producer ledger record count disagrees")
    for name in WORK_COUNTER_FIELDS:
        _u64(work[name], f"logical work profile {name}")
    digest = _digest(work["profile_sha256"], "logical work profile digest")
    if digest != _work_profile_digest(work):
        raise CaptureError("logical work profile digest disagrees with its counters")
    return {
        "schema": WORK_PROFILE_SCHEMA,
        "source_mask": work["source_mask"],
        "record_count": work["record_count"],
        "producer_ledger_schema_version": work["producer_ledger_schema_version"],
        "producer_counts": list(completed_counts),
        "producer_coverage_terminal_sealed": True,
        **{name: work[name] for name in WORK_COUNTER_FIELDS},
        "profile_sha256": digest,
    }


def _validate_contributions(
    events: list[dict[str, Any]],
    contributions_value: Any,
    components_value: Any,
) -> None:
    if type(contributions_value) is not list or type(components_value) is not list:
        raise CaptureError("task contribution projections must be arrays")
    contributions: list[dict[str, Any]] = []
    cursor = 0
    derived: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    for event_index, event in enumerate(events):
        region = exact_object(event["contribution_range"], {"start", "len"}, "contribution range")
        start = _integer(region["start"], "contribution range start")
        length = _integer(region["len"], "contribution range len")
        if start != cursor or start + length > len(contributions_value):
            raise CaptureError("task contribution ranges are not one contiguous partition")
        seen_in_event: set[int] = set()
        for raw in contributions_value[start : start + length]:
            contribution = exact_object(raw, CONTRIBUTION_FIELDS, "task contribution")
            index = _integer(contribution["component_registry_index"], "contribution component index")
            if index in seen_in_event:
                raise CaptureError("one task contributes to the same component twice")
            seen_in_event.add(index)
            kind = _text(contribution["component_kind"], "contribution component kind")
            role = contribution["role"]
            if role not in {"semantic_constraints", "lookup_constraints", "exclusive"}:
                raise CaptureError("task contribution role is invalid")
            if length != 1 and role == "exclusive":
                raise CaptureError("fused task carries an exclusive contribution")
            for name in ("work_estimate", "planned_rows", "planned_tiles", "completed_rows", "completed_tiles"):
                _integer(contribution[name], f"contribution.{name}")
            if contribution["completed_rows"] > contribution["planned_rows"] or contribution["completed_tiles"] > contribution["planned_tiles"]:
                raise CaptureError("task contribution completion exceeds its plan")
            aggregate = derived.get(index)
            if aggregate is None:
                aggregate = {
                    "component_registry_index": index,
                    "component_kind": kind,
                    "role": role,
                    "task_count": 0,
                    "work_estimate": 0,
                    "planned_rows": 0,
                    "planned_tiles": 0,
                    "completed_rows": 0,
                    "completed_tiles": 0,
                }
                derived[index] = aggregate
                order.append(index)
            if aggregate["component_kind"] != kind or aggregate["role"] != role:
                raise CaptureError("component contribution identity drifted")
            aggregate["task_count"] += 1
            for name in ("work_estimate", "planned_rows", "planned_tiles", "completed_rows", "completed_tiles"):
                aggregate[name] += contribution[name]
            contributions.append(contribution)
        cursor += length
        if event_index + 1 == len(events) and cursor != len(contributions_value):
            raise CaptureError("task contribution ranges leave trailing entries")
    expected_components = [derived[index] for index in order]
    if type(components_value) is not list or len(components_value) != len(expected_components):
        raise CaptureError("component-work projection cardinality disagrees")
    for actual, expected in zip(components_value, expected_components, strict=True):
        component = exact_object(actual, COMPONENT_FIELDS, "component work")
        if component != expected:
            raise CaptureError("component-work projection is not derivable from contributions")


def _validate_graph(value: Any, requested_workers: int) -> dict[str, int]:
    graph = exact_object(value, GRAPH_FIELDS, "task graph")
    _text(graph["graph_id"], "task graph ID")
    if type(graph["events"]) is not list:
        raise CaptureError("profiled task graph events must be an array")
    events: list[dict[str, Any]] = []
    keys: list[tuple[int, int, int, int]] = []
    by_key: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    sums = {
        "admission_wait_ns": 0,
        "queue_wait_ns": 0,
        "resource_wait_ns": 0,
        "task_run_ns": 0,
        "parallel_eligible_ns": 0,
        "total_work_estimate": 0,
        "completed_rows": 0,
        "completed_tiles": 0,
    }
    for raw in graph["events"]:
        event = exact_object(raw, EVENT_FIELDS, "task event")
        key = _key(event["key"], "task key")
        if keys and key <= keys[-1]:
            raise CaptureError("task events are not in unique canonical key order")
        keys.append(key)
        by_key[key] = event
        _text(event["stage_id"], "task stage ID")
        _text(event["component_kind"], "task component kind")
        if event["task_class"] not in {"leaf", "pool_exclusive", "coordinator"}:
            raise CaptureError("task class is invalid")
        if event["parallel_eligible"] is not True and event["parallel_eligible"] is not False:
            raise CaptureError("task parallel eligibility is not boolean")
        if event["submitted"] is not True or event["started"] is not True or event["finished"] is not True:
            raise CaptureError("verified task graph contains an incomplete event")
        if event["terminal_status"] != "completed" or event["cleanup_complete"] is not True:
            raise CaptureError("verified task graph contains a non-completed event")
        dependency_count = _integer(event["dependency_count"], "task dependency count")
        dependencies = event["dependencies"]
        if type(dependencies) is not list or len(dependencies) != 8 or dependency_count > 8:
            raise CaptureError("task dependency storage shape changed")
        for dependency_index, raw_dependency in enumerate(dependencies):
            dependency = _key(raw_dependency, "task dependency")
            if dependency_index < dependency_count:
                if dependency not in by_key or dependency >= key:
                    raise CaptureError("task dependency does not name an earlier event")
            elif dependency != (0, 0, 0, 0):
                raise CaptureError("unused task dependency storage is nonzero")
        ready = _integer(event["ready_ns"], "task ready timestamp")
        submitted = _integer(event["submitted_ns"], "task submitted timestamp")
        started = _integer(event["start_ns"], "task start timestamp")
        finished = _integer(event["finish_ns"], "task finish timestamp")
        if not ready <= submitted <= started <= finished:
            raise CaptureError("task event timestamps are not monotonic")
        if event["admission_wait_ns"] != submitted - ready:
            raise CaptureError("task admission-wait disclosure disagrees")
        if event["queue_wait_ns"] != started - submitted:
            raise CaptureError("task queue-wait disclosure disagrees")
        if event["run_ns"] != finished - started:
            raise CaptureError("task run disclosure disagrees")
        configured = _integer(event["configured_workers"], "task configured workers", minimum=1)
        worker_slot = _integer(event["worker_slot"], "task worker slot")
        if configured > requested_workers or worker_slot >= configured:
            raise CaptureError("task worker assignment exceeds its configured envelope")
        expected_kind = "coordinator" if worker_slot == 0 else "helper"
        if event["worker_kind"] != expected_kind:
            raise CaptureError("task worker-kind disclosure disagrees with its slot")
        byte_classes = exact_object(event["bytes"], BYTE_FIELDS, "task byte classes")
        for name in BYTE_FIELDS:
            _integer(byte_classes[name], f"task bytes.{name}")
        for name in ("admission_wait_ns", "queue_wait_ns", "run_ns", "resource_wait_ns", "work_estimate", "planned_rows", "planned_tiles", "completed_rows", "completed_tiles"):
            _integer(event[name], f"task event.{name}")
        if event["completed_rows"] > event["planned_rows"] or event["completed_tiles"] > event["planned_tiles"]:
            raise CaptureError("task completion exceeds planned work")
        sums["admission_wait_ns"] += event["admission_wait_ns"]
        sums["queue_wait_ns"] += event["queue_wait_ns"]
        sums["resource_wait_ns"] += event["resource_wait_ns"]
        sums["task_run_ns"] += event["run_ns"]
        sums["parallel_eligible_ns"] += event["run_ns"] if event["parallel_eligible"] else 0
        sums["total_work_estimate"] += event["work_estimate"]
        sums["completed_rows"] += event["completed_rows"]
        sums["completed_tiles"] += event["completed_tiles"]
        events.append(event)

    summary = exact_object(graph["summary"], SUMMARY_FIELDS, "task graph summary")
    for name in SUMMARY_FIELDS - {"scheduler"}:
        _integer(summary[name], f"task graph summary.{name}")
    admitted = summary["admitted_workers"]
    if (
        summary["requested_workers"] != requested_workers
        or summary["pool_capacity"] != requested_workers
        or not 1 <= admitted <= requested_workers
    ):
        raise CaptureError("task graph worker envelope differs from the requested lane")
    if summary["peak_active_tasks"] > admitted or summary["peak_active_workers"] > admitted:
        raise CaptureError("task graph exceeded its admitted worker bound")
    event_count = len(events)
    for name in ("planned_tasks", "submitted_tasks", "completed_tasks", "started_tasks", "finished_tasks"):
        if summary[name] != event_count:
            raise CaptureError(f"successful task graph {name} is incomplete")
    for name in ("failed_tasks", "cancelled_tasks", "unsubmitted_cancelled_tasks", "duplicate_starts", "duplicate_finishes"):
        if summary[name] != 0:
            raise CaptureError(f"successful task graph has nonzero {name}")
    if summary["submitted_tasks"] != summary["completed_tasks"] + summary["failed_tasks"] + summary["cancelled_tasks"]:
        raise CaptureError("task terminal accounting does not close")
    if summary["planned_tasks"] != summary["submitted_tasks"] + summary["unsubmitted_cancelled_tasks"]:
        raise CaptureError("task plan accounting does not close")
    for name, expected in sums.items():
        if summary[name] != expected:
            raise CaptureError(f"task graph summary {name} is not event-derived")
    if summary["useful_task_work_ns"] != sums["task_run_ns"]:
        raise CaptureError("task useful-work disclosure is not event-derived")
    if summary["worker_busy_ns"] < summary["task_run_ns"]:
        raise CaptureError("physical worker work is smaller than outer task work")
    if summary["worker_capacity_ns"] != admitted * summary["graph_elapsed_ns"]:
        raise CaptureError("task worker-capacity disclosure disagrees")
    if summary["worker_busy_ns"] > summary["worker_capacity_ns"]:
        raise CaptureError("task worker work exceeds available capacity")
    if summary["critical_path_ns"] > summary["graph_elapsed_ns"]:
        raise CaptureError("task critical path exceeds graph elapsed time")
    if summary["scheduler"] != "central_queue_no_steal" or summary["steal_count"] != 0:
        raise CaptureError("task scheduler disclosure changed")
    _validate_contributions(events, graph["contributions"], graph["component_work"])
    return {
        "events": event_count,
        "queue_wait_ns": summary["queue_wait_ns"],
        "admission_wait_ns": summary["admission_wait_ns"],
        "resource_wait_ns": summary["resource_wait_ns"],
        "task_run_ns": summary["task_run_ns"],
        "worker_busy_ns": summary["worker_busy_ns"],
        "worker_capacity_ns": summary["worker_capacity_ns"],
        "graph_elapsed_ns": summary["graph_elapsed_ns"],
        "parallel_eligible_ns": summary["parallel_eligible_ns"],
        "critical_path_ns": summary["critical_path_ns"],
        "total_work_estimate": summary["total_work_estimate"],
        "completed_rows": summary["completed_rows"],
        "completed_tiles": summary["completed_tiles"],
        "peak_active_workers": summary["peak_active_workers"],
        "peak_reserved_bytes": summary["peak_reserved_bytes"],
    }


def _validate_profile(value: Any, requested_workers: int, proving_boundary_ns: int) -> dict[str, int]:
    profile = exact_object(value, PROFILE_FIELDS, "task profile")
    if (
        profile["schema_version"] != 2
        or profile["runtime"] != "ReleaseFast"
        or profile["example"] != "sail_rv32im_zkvm_v1"
    ):
        raise CaptureError("task profile identity changed")
    if type(profile["graphs"]) is not list or not profile["graphs"]:
        raise CaptureError("profiled request contains no task graphs")
    graph_ids: set[str] = set()
    totals = {
        "graphs": 0,
        "events": 0,
        "queue_wait_ns": 0,
        "admission_wait_ns": 0,
        "resource_wait_ns": 0,
        "task_run_ns": 0,
        "worker_busy_ns": 0,
        "worker_capacity_ns": 0,
        "graph_elapsed_ns": 0,
        "parallel_eligible_ns": 0,
        "critical_path_ns": 0,
        "total_work_estimate": 0,
        "completed_rows": 0,
        "completed_tiles": 0,
        "peak_active_workers": 0,
        "peak_reserved_bytes": 0,
    }
    for raw in profile["graphs"]:
        graph = exact_object(raw, GRAPH_FIELDS, "task graph")
        graph_id = _text(graph["graph_id"], "task graph ID")
        if graph_id in graph_ids:
            raise CaptureError("task profile repeats a graph ID")
        graph_ids.add(graph_id)
        disclosure = _validate_graph(raw, requested_workers)
        if graph["summary"]["graph_elapsed_ns"] > proving_boundary_ns:
            raise CaptureError("task graph elapsed time exceeds the proof boundary")
        totals["graphs"] += 1
        for name in totals.keys() - {
            "graphs",
            "peak_active_workers",
            "peak_reserved_bytes",
        }:
            totals[name] += disclosure[name]
        totals["peak_active_workers"] = max(
            totals["peak_active_workers"], disclosure["peak_active_workers"]
        )
        totals["peak_reserved_bytes"] = max(totals["peak_reserved_bytes"], disclosure["peak_reserved_bytes"])
    if totals["events"] == 0:
        raise CaptureError("profiled request contains no physical task events")
    if requested_workers == 1 and totals["parallel_eligible_ns"] > proving_boundary_ns:
        raise CaptureError(
            "one-worker parallel-eligible task duration exceeds the proof boundary"
        )
    return totals


def validate_report(
    raw: bytes,
    *,
    plan: dict[str, Any],
    attempt: dict[str, Any],
    proof_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(raw) > MAX_STREAM_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        raise CaptureError("profiled child stdout must be one bounded JSON line")
    report = decode_strict(raw)
    if type(report) is not dict:
        raise CaptureError("profiled benchmark report must be an object")
    report_schema = report.get("schema")
    if report_schema == PROFILED_SCHEMA:
        raise CaptureError(
            "R-006 promotion capture requires installed-binary exact-work schema v4"
        )
    elif report_schema == EXACT_WORK_PROFILED_SCHEMA:
        exact_work = True
    else:
        raise CaptureError("profiled benchmark schema changed")
    expected_fields = set(REPORT_FIELDS)
    if plan["lane"]["id"] == "metal-hybrid":
        expected_fields.add("resident_polynomial_telemetry")
    exact_object(report, expected_fields, "profiled benchmark report")
    exact_values = {
        "schema": report_schema,
        "release_status": "release_gated",
        "mode": "bench",
        "experimental": True,
        "profiled": True,
        "recursion_enabled": False,
        "warmups": 0,
        "samples": 1,
        "verified_samples": 1,
        "throughput_numerator": "vm_steps",
        "implementation_commit": plan["source"]["commit"],
        "implementation_dirty": False,
        "executable_sha256": plan["build"]["executable_sha256"],
        "proof_path": attempt["proof_path"],
    }
    for name, expected in exact_values.items():
        if type(report[name]) is not type(expected) or report[name] != expected:
            raise CaptureError(f"profiled benchmark {name} identity changed")
    _integer(report["total_steps"], "benchmark total steps", minimum=1)
    _integer(report["n_components"], "benchmark component count", minimum=1)
    for name in (
        "median_seconds",
        "throughput_mhz",
        "mean_execution_seconds",
        "mean_witness_seconds",
        "mean_proving_seconds",
        "mean_verification_seconds",
    ):
        _number(report[name], f"benchmark {name}", positive=True)
    if type(report["sample_seconds"]) is not list or len(report["sample_seconds"]) != 1:
        raise CaptureError("profiled benchmark must contain exactly one outer sample")
    sample_seconds = _number(report["sample_seconds"][0], "benchmark sample seconds", positive=True)
    if report["median_seconds"] != sample_seconds:
        raise CaptureError("single-sample benchmark median changed")
    statement = _digest(report["statement_sha256"], "benchmark statement")
    transcript = _digest(report["transcript_state_blake2s"], "benchmark transcript")
    proof_digest = _digest(report["artifact_sha256"], "benchmark proof artifact")
    proof_bytes, actual_proof_digest = sha256_file(proof_path)
    if proof_bytes <= 0 or proof_digest != actual_proof_digest:
        raise CaptureError("retained proof bytes disagree with the benchmark report")
    resources = _validate_resources(report["resources"])
    authority = exact_object(report["timing_authority"], TIMING_AUTHORITY_FIELDS, "timing authority")
    expected_authority = {
        "clock": "monotonic",
        "unit": "nanoseconds",
        "partition": "protocol_complete",
        "protocol_partition_complete": True,
        "witness_materialization_regions": 5,
        "authoritative_samples": "verified_request_attempts[*].verified_request_ns",
        "legacy_outer_samples": "sample_seconds_and_median_seconds_are_non_authoritative_compatibility_fields",
    }
    if authority != expected_authority:
        raise CaptureError("profiled benchmark timing authority changed")
    attempts = report["verified_request_attempts"]
    if type(attempts) is not list or len(attempts) != 1:
        raise CaptureError("profiled benchmark must carry exactly one verified request attempt")
    inner = exact_object(
        attempts[0],
        EXACT_WORK_ATTEMPT_FIELDS if exact_work else ATTEMPT_FIELDS,
        "verified request attempt",
    )
    expected_inner = {
        "schema": EXACT_WORK_ATTEMPT_SCHEMA if exact_work else ATTEMPT_SCHEMA,
        "status": "verified",
        "sample_index": 0,
        "timing_partition": TIMING_PARTITION,
        "protocol_partition_complete": True,
        "witness_materialization_regions": 5,
    }
    for name, expected in expected_inner.items():
        if inner[name] != expected or type(inner[name]) is not type(expected):
            raise CaptureError(f"verified request {name} changed")
    for name in (
        "guest_execution_ns",
        "witness_materialization_ns",
        "proving_ns",
        "proving_including_witness_ns",
        "native_verification_ns",
        "verified_request_ns",
    ):
        _integer(inner[name], f"verified request {name}")
    if inner["proving_including_witness_ns"] != inner["witness_materialization_ns"] + inner["proving_ns"]:
        raise CaptureError("verified request proving partition does not add")
    if inner["verified_request_ns"] != inner["guest_execution_ns"] + inner["proving_including_witness_ns"] + inner["native_verification_ns"]:
        raise CaptureError("verified request timing partition does not add")
    if inner["verified_request_ns"] <= 0:
        raise CaptureError("verified request duration is empty")
    disclosure = _validate_profile(
        inner["task_profile"],
        attempt["worker_count"],
        inner["proving_including_witness_ns"],
    )
    work_disclosure = _validate_work_profile(inner["work_profile"]) if exact_work else None
    metal_disclosure = None
    if plan["lane"]["id"] == "metal-hybrid":
        telemetry = exact_object(report["resident_polynomial_telemetry"], METAL_FIELDS, "Metal telemetry")
        for name in METAL_FIELDS:
            _integer(telemetry[name], f"Metal telemetry.{name}")
        if telemetry["declines"] != 0 or telemetry["verified_samples_with_dispatch"] != 1:
            raise CaptureError("Metal attempt fell back or lacks resident dispatch")
        if telemetry["base_batch_dispatches"] + telemetry["lookup_batch_dispatches"] == 0:
            raise CaptureError("Metal attempt contains no resident polynomial dispatch")
        metal_disclosure = {
            name: telemetry[name] for name in sorted(METAL_FIELDS)
        }
    identity = {
        "statement_sha256": statement,
        "transcript_state_blake2s": transcript,
        "proof_sha256": proof_digest,
        "proof_bytes": proof_bytes,
        "total_steps": report["total_steps"],
        "n_components": report["n_components"],
    }
    metrics = {
        "verified_request_ns": inner["verified_request_ns"],
        "guest_execution_ns": inner["guest_execution_ns"],
        "witness_ns": inner["witness_materialization_ns"],
        "proving_ns": inner["proving_ns"],
        "native_verification_ns": inner["native_verification_ns"],
        **resources,
        "task_disclosure": disclosure,
    }
    if work_disclosure is not None:
        metrics["work_disclosure"] = work_disclosure
    if metal_disclosure is not None:
        metrics["metal_disclosure"] = metal_disclosure
    return identity, metrics
