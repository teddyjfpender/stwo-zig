"""Statistical reduction over a validated complete-comparison pair prefix."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, content_digest, decode_strict
from .model import CaptureError
from .pair import PAIR_LANE_ORDER
from .pair_prefix import validate_pair_prefix
from . import exact_work_cells
from . import reduction as full


PREFIX_REDUCTION_SCHEMA = "stwo.typed-air.r006-paired-prefix-scaling-reduction.v1"
PREFIX_REDUCTION_VALIDATION_SCHEMA = (
    "stwo.typed-air.r006-paired-prefix-scaling-validation.v1"
)


def _evaluate_rows(
    repository: Path,
    plan: dict[str, Any],
    lane_records: dict[str, list[dict[str, Any]]],
    exact_work_authority: dict[str, Any],
    workloads: list[str],
) -> dict[str, Any]:
    exact_work_index = exact_work_cells.cell_index(exact_work_authority)
    protocol = full._protocol(repository)
    authority, statistical_policy = full._authority(repository, protocol)
    milestone = next(item for item in protocol["milestones"] if item.get("id") == "M7")
    calibration_policy = protocol["sampling_protocol"]["a_a_calibration"]
    lane_groups = {
        lane: full._groups(plan["lanes"][lane], lane_records[lane])
        for lane in PAIR_LANE_ORDER
    }
    calibrations: dict[str, Any] = {}
    for lane in PAIR_LANE_ORDER:
        captures = lane_groups[lane][("multi_shard_addi", "aa-calibration")]
        calibrations[lane] = full._calibration(
            authority,
            statistical_policy,
            lane,
            captures,
            ratio=calibration_policy["ratio_ci_must_contain"],
            maximum_width=calibration_policy["maximum_ci_width"],
        )

    rows: list[dict[str, Any]] = []
    qualifying_workloads: set[str] = set()
    primary_pass = False
    largest_gates_pass = True
    for lane in PAIR_LANE_ORDER:
        for workload in workloads:
            for comparison in full.SCALING_COMPARISONS:
                captures = lane_groups[lane][(workload, comparison)]
                if len(captures) != 80:
                    raise CaptureError("R-006 prefix scaling cell is not complete")
                subject_workers = {
                    attempt["worker_count"]
                    for attempt, _ in captures
                    if attempt["arm"] == "subject"
                }
                if len(subject_workers) != 1:
                    raise CaptureError("R-006 prefix subject worker count changed")
                workers = next(iter(subject_workers))
                parallel = full._parallel_fraction(captures)
                p = parallel["median_fraction"]
                amdahl = 1.0 / ((1.0 - p) + p / workers)
                qualifying = (
                    p >= milestone["parallelizable_fraction"]["qualifying_minimum"]
                    and parallel["median_parallel_eligible_ns"]
                    >= milestone["parallelizable_fraction"][
                        "qualifying_minimum_eligible_ns"
                    ]
                )
                if comparison == "max-workers-over-one" and qualifying:
                    qualifying_workloads.add(workload)
                statistics: dict[str, Any] = {}
                for metric in full.SPEED_METRICS:
                    statistics[metric] = full._round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric=metric,
                        orientation="speed",
                        subject=f"M7-prefix:{lane}:{workload}:{comparison}:{metric}",
                    )
                for metric in full.RESOURCE_METRICS:
                    statistics[metric] = full._round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric=metric,
                        orientation="resource",
                        subject=f"M7-prefix:{lane}:{workload}:{comparison}:{metric}",
                    )
                if lane == "metal-hybrid":
                    statistics["gpu_dispatches"] = full._round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric="gpu_dispatches",
                        orientation="resource",
                        subject=f"M7-prefix:{lane}:{workload}:{comparison}:gpu_dispatches",
                    )
                reference_cell, subject_cell = exact_work_cells.require_cells(
                    exact_work_index,
                    ((lane, workload, 1), (lane, workload, workers)),
                )
                executed_work = exact_work_cells.compare_cells(
                    reference_cell,
                    subject_cell,
                    relation="subject_worker_minus_lane_local_one_worker",
                    blocking=False,
                )
                gates: dict[str, Any] = {}
                if (
                    lane == "cpu-native"
                    and workload == "multi_shard_addi"
                    and comparison == "four-workers-over-one"
                ):
                    threshold = max(
                        milestone["primary_target"]["threshold_floor"], 0.70 * amdahl
                    )
                    observed = statistics["verified_request_ns"]["ci_lower"]
                    primary_pass = observed >= threshold
                    gates["primary_verified_request_speed"] = {
                        "direction": "lower_greater_than_or_equal",
                        "threshold": threshold,
                        "observed": observed,
                        "pass": primary_pass,
                    }
                if comparison == "max-workers-over-one" and qualifying:
                    speed_threshold = max(1.05, 0.70 * amdahl)
                    gates.update(
                        {
                            "qualifying_verified_request_speed": {
                                "direction": "lower_greater_than_or_equal",
                                "threshold": speed_threshold,
                                "observed": statistics["verified_request_ns"]["ci_lower"],
                                "pass": statistics["verified_request_ns"]["ci_lower"]
                                >= speed_threshold,
                            },
                            "process_cpu_work": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.15,
                                "observed": statistics["process_cpu_ns"]["ci_upper"],
                                "pass": statistics["process_cpu_ns"]["ci_upper"] <= 1.15,
                            },
                            "retired_instruction_work": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.15,
                                "observed": statistics["retired_instructions"]["ci_upper"],
                                "pass": statistics["retired_instructions"]["ci_upper"]
                                <= 1.15,
                            },
                            "peak_rss": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.25,
                                "observed": statistics["peak_rss_bytes"]["ci_upper"],
                                "pass": statistics["peak_rss_bytes"]["ci_upper"] <= 1.25,
                            },
                        }
                    )
                    if lane == "metal-hybrid":
                        gates["gpu_command_work"] = {
                            "authority": "resident Metal batch-dispatch count",
                            "direction": "upper_less_than_or_equal",
                            "threshold": 1.15,
                            "observed": statistics["gpu_dispatches"]["ci_upper"],
                            "pass": statistics["gpu_dispatches"]["ci_upper"] <= 1.15,
                        }
                    largest_gates_pass = largest_gates_pass and all(
                        gate["pass"] for gate in gates.values()
                    )
                rows.append(
                    {
                        "lane": lane,
                        "workload": workload,
                        "comparison": comparison,
                        "subject_workers": workers,
                        "parallelizable_fraction": parallel,
                        "amdahl_ideal": amdahl,
                        "qualifying": qualifying,
                        "executed_work_comparison": executed_work,
                        "statistics": statistics,
                        "gates": gates,
                    }
                )
    calibration_pass = all(row["verdict"] == "PASS" for row in calibrations.values())
    enough_qualifying = len(qualifying_workloads) >= milestone[
        "parallelizable_fraction"
    ]["minimum_qualifying_workloads"]
    cross_lane_work: list[dict[str, Any]] = []
    for workload in workloads:
        widths = sorted(
            workers
            for lane, observed_workload, workers in exact_work_index
            if lane == PAIR_LANE_ORDER[0] and observed_workload == workload
        )
        for workers in widths:
            cpu_cell, metal_cell = exact_work_cells.require_cells(
                exact_work_index,
                (
                    (PAIR_LANE_ORDER[0], workload, workers),
                    (PAIR_LANE_ORDER[1], workload, workers),
                ),
            )
            cross_lane_work.append(
                exact_work_cells.compare_cells(
                    cpu_cell,
                    metal_cell,
                    relation="metal_minus_cpu",
                    blocking=False,
                )
            )
    every_attempt = exact_work_authority["every_attempt_complete_exact_work"]
    deterministic = exact_work_authority["every_cell_deterministic"]
    if not calibration_pass or not enough_qualifying:
        verdict = "NO_VERDICT"
    elif primary_pass and largest_gates_pass and every_attempt and deterministic:
        verdict = "PASS"
    else:
        verdict = "FAIL"
    return {
        "observed_complete_block_verdict": verdict,
        "statistical_authority": dict(statistical_policy),
        "calibration": calibrations,
        "rows": rows,
        "cross_lane_executed_work_observations": cross_lane_work,
        "aggregate_gates": {
            "a_a_calibration": calibration_pass,
            "minimum_two_qualifying_workloads": enough_qualifying,
            "primary_cpu_four_worker_target": primary_pass,
            "all_qualifying_largest_worker_gates": largest_gates_pass,
            "every_statistical_attempt_complete_exact_work": every_attempt,
            "every_statistical_cell_deterministic": deterministic,
        },
        "qualifying_workloads": sorted(qualifying_workloads),
    }


def evaluate_pair_prefix_scaling(
    repository: Path,
    bundle_path: Path,
    *,
    expected_authority: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repository = repository.resolve()
    validation = validate_pair_prefix(
        repository,
        bundle_path,
        expected_authority=expected_authority,
        include_snapshot=True,
    )
    snapshot = validation.pop("_snapshot")
    prefix = validation["prefix_authority"]
    if (
        validation["failed_attempts"]
        or not validation["all_statistical_attempts_complete_exact_work"]
    ):
        raise CaptureError("R-006 prefix reduction requires verified exact-work records")
    observed = _evaluate_rows(
        repository,
        snapshot["plan"],
        snapshot["lane_records"],
        validation["statistical_exact_work_authority"],
        prefix["included_workloads"],
    )
    result: dict[str, Any] = {
        "schema": PREFIX_REDUCTION_SCHEMA,
        "schema_version": 1,
        "classification": "operator-requested-resumable-complete-block-prefix-reduction",
        "plan_sha256": prefix["plan_sha256"],
        "prefix_authority_sha256": prefix["content_sha256"],
        "retained_attempts": prefix["retained_attempts"],
        "statistical_attempts": prefix["statistical_attempts"],
        "planned_attempts": prefix["planned_attempts"],
        "prefix_validation": validation,
        **observed,
        "m7_verdict": "NO_VERDICT_PARTIAL_FROZEN_MATRIX",
        "claim_boundary": {
            "normative_full_matrix": False,
            "m7_promotion_receipt": False,
            "capture_remains_resumable": True,
            "power_source_is_not_a_prefix_reduction_gate": True,
            "omitted_workloads": prefix["omitted_workloads"],
            "retained_but_unscored_attempts": prefix[
                "retained_but_unscored_attempts"
            ],
            "not_executed_attempts": prefix["not_executed_attempts"],
            "missing_required_evidence": [
                "remaining-frozen-matrix-comparison-blocks",
                "protocol-preserving-predecessor-one-worker-paired-cohort",
                "predecessor-candidate-exact-relation-summary-and-geometry-equality",
            ],
        },
    }
    replay = validate_pair_prefix(
        repository,
        bundle_path,
        expected_authority=prefix,
        include_snapshot=False,
    )
    if replay != validation:
        raise CaptureError("R-006 prefix changed during statistical reduction")
    result["content_sha256"] = content_digest(result)
    return result


def validate_pair_prefix_reduction(
    repository: Path, bundle_path: Path, receipt_path: Path
) -> dict[str, Any]:
    try:
        raw = receipt_path.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read the R-006 prefix scaling receipt") from error
    value = decode_strict(raw)
    if type(value) is not dict or raw != canonical_bytes(value):
        raise CaptureError("R-006 prefix scaling receipt is not canonical JSON")
    validation = value.get("prefix_validation")
    authority = validation.get("prefix_authority") if type(validation) is dict else None
    if type(authority) is not dict:
        raise CaptureError("R-006 prefix scaling receipt lacks its authority")
    expected = evaluate_pair_prefix_scaling(
        repository, bundle_path, expected_authority=authority
    )
    if raw != canonical_bytes(expected):
        raise CaptureError("R-006 prefix receipt differs from raw-prefix recomputation")
    return {
        "schema": PREFIX_REDUCTION_VALIDATION_SCHEMA,
        "schema_version": 1,
        "status": "VALID",
        "plan_sha256": expected["plan_sha256"],
        "prefix_authority_sha256": expected["prefix_authority_sha256"],
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_complete_block_verdict": expected[
            "observed_complete_block_verdict"
        ],
        "m7_verdict": expected["m7_verdict"],
        "validator_recomputed": True,
    }
