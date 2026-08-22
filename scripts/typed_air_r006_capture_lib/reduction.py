"""Validator-recomputed R-006 worker-scaling reduction.

This reducer closes the same-candidate 1/2/4/max evidence surface.  It does
not manufacture the predecessor one-worker cohort required by M7, so even a
clean scaling pass remains explicitly non-promotional until that separately
planned comparison is supplied.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import statistics
from collections import defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from .codec import canonical_bytes, content_digest, sha256_file
from .model import PAIRS_PER_ROUND, PLAN_ATTEMPTS, ROUNDS, WORKLOAD_IDS, CaptureError
from .pair import (
    PAIR_ATTEMPTS,
    PAIR_LANE_ORDER,
    validate_pair_bundle,
)
from .pair_validation import assert_pair_snapshot_current
from . import exact_work_cells


REDUCTION_SCHEMA = "stwo.typed-air.r006-paired-scaling-reduction.v2"
SPEED_METRICS = ("verified_request_ns", "proving_ns")
RESOURCE_METRICS = (
    "peak_rss_bytes",
    "process_cpu_ns",
    "retired_instructions",
    "energy_nj",
    "cycles",
)
ZEROABLE_OBSERVATIONAL_METRICS = {"energy_nj", "cycles"}
CALIBRATION_METRICS = ("verified_request_ns", "proving_ns", "peak_rss_bytes")
SCALING_COMPARISONS = (
    "two-workers-over-one",
    "four-workers-over-one",
    "max-workers-over-one",
)


def _protocol(repository: Path) -> dict[str, Any]:
    path = repository.resolve() / "design/typed-air/performance/m5-m9-protocol-v1.json"
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CaptureError("cannot decode the frozen M7 protocol") from error
    if type(value) is not dict:
        raise CaptureError("frozen M7 protocol is not an object")
    return value


def _authority(repository: Path, protocol: dict[str, Any]) -> tuple[ModuleType, dict[str, Any]]:
    policy = protocol["statistical_authority"]
    path = repository.resolve() / policy["statistics_path"]
    _, digest = sha256_file(path)
    if digest != policy["statistics_sha256"]:
        raise CaptureError("frozen statistical authority digest changed")
    spec = importlib.util.spec_from_file_location("stwo_r006_epoch3_stats", path)
    if spec is None or spec.loader is None:
        raise CaptureError("cannot load the frozen R-006 statistical authority")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, policy


def _seed(subject: str) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{subject}:0".encode("utf-8")).digest()[:4],
        "big",
    )


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise CaptureError(f"R-006 reduction has invalid {name}")
    return value


def _nonnegative(value: Any, name: str) -> int:
    if type(value) is not int or value < 0:
        raise CaptureError(f"R-006 reduction has invalid {name}")
    return value


def _require_unchanged_bundle_validation(
    repository: Path,
    bundle_path: Path,
    initial: dict[str, Any],
) -> None:
    replayed = validate_pair_bundle(repository, bundle_path)
    if replayed != initial:
        raise CaptureError("R-006 raw bundle changed during scaling reduction")


def _metric(record: dict[str, Any], name: str) -> int:
    if name == "process_cpu_ns":
        return _positive(record["process_cpu_ns"], name)
    metrics = record["metrics"]
    if type(metrics) is not dict:
        raise CaptureError("R-006 verified record has no metric projection")
    if name == "gpu_dispatches":
        metal = metrics.get("metal_disclosure")
        if type(metal) is not dict:
            raise CaptureError("R-006 Metal record lacks dispatch-work authority")
        return _positive(
            metal["base_batch_dispatches"] + metal["lookup_batch_dispatches"],
            name,
        )
    if name in ZEROABLE_OBSERVATIONAL_METRICS:
        return _nonnegative(metrics[name], name)
    return _positive(metrics[name], name)


def _round_statistic(
    authority: ModuleType,
    policy: dict[str, Any],
    captures: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    metric: str,
    orientation: str,
    subject: str,
) -> dict[str, Any]:
    reference_medians: list[float] = []
    subject_medians: list[float] = []
    ratios: list[float] = []
    unavailable_reason: str | None = None
    for round_index in range(ROUNDS):
        selected = [
            (attempt, record)
            for attempt, record in captures
            if attempt["phase"] == "measured" and attempt["round"] == round_index
        ]
        reference = [
            _metric(record, metric)
            for attempt, record in selected
            if attempt["arm"] == "reference"
        ]
        candidate = [
            _metric(record, metric)
            for attempt, record in selected
            if attempt["arm"] == "subject"
        ]
        if len(reference) != PAIRS_PER_ROUND or len(candidate) != PAIRS_PER_ROUND:
            raise CaptureError(f"R-006 {metric} measured-round cardinality is incomplete")
        reference_median = float(statistics.median(reference))
        subject_median = float(statistics.median(candidate))
        reference_medians.append(reference_median)
        subject_medians.append(subject_median)
        if orientation == "speed":
            ratios.append(reference_median / subject_median)
        elif orientation == "resource":
            if reference_median == 0.0:
                if metric not in ZEROABLE_OBSERVATIONAL_METRICS:
                    raise CaptureError(f"R-006 {metric} has a zero reference median")
                unavailable_reason = "zero_reference_median"
            else:
                ratios.append(subject_median / reference_median)
        else:  # pragma: no cover - callers use a closed table.
            raise AssertionError(orientation)
    if unavailable_reason is not None:
        return {
            "subject_id": subject,
            "orientation": "subject_worker_resource_over_one_worker_resource",
            "availability": "unavailable",
            "blocking": False,
            "reason": unavailable_reason,
            "reference_round_medians": reference_medians,
            "subject_round_medians": subject_medians,
            "round_ratios": None,
            "hodges_lehmann": None,
            "ci_lower": None,
            "ci_upper": None,
        }
    estimate = authority.hodges_lehmann(ratios)
    lower, upper = authority.bootstrap_ci(
        ratios,
        level=policy["confidence_level"],
        iterations=policy["bootstrap_iterations"],
        seed=_seed(subject),
    )
    return {
        "subject_id": subject,
        "orientation": (
            "one_worker_duration_over_subject_worker_duration"
            if orientation == "speed"
            else "subject_worker_resource_over_one_worker_resource"
        ),
        "availability": "available",
        "blocking": metric not in ZEROABLE_OBSERVATIONAL_METRICS,
        "reason": None,
        "reference_round_medians": reference_medians,
        "subject_round_medians": subject_medians,
        "round_ratios": ratios,
        "hodges_lehmann": estimate,
        "ci_lower": lower,
        "ci_upper": upper,
    }


def _parallel_fraction(
    captures: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    fractions: list[float] = []
    eligible: list[int] = []
    for attempt, record in captures:
        if attempt["phase"] != "measured" or attempt["arm"] != "reference":
            continue
        metrics = record["metrics"]
        parallel_ns = _nonnegative(
            metrics["task_disclosure"]["parallel_eligible_ns"],
            "one-worker parallel-eligible duration",
        )
        request_ns = _positive(metrics["verified_request_ns"], "one-worker request")
        if parallel_ns > request_ns:
            raise CaptureError("one-worker parallel-eligible duration exceeds the request")
        eligible.append(parallel_ns)
        fractions.append(parallel_ns / request_ns)
    if len(fractions) != ROUNDS * PAIRS_PER_ROUND:
        raise CaptureError("R-006 one-worker parallel-fraction cohort is incomplete")
    return {
        "definition": (
            "per-sample dependency-ready parallel-eligible task duration divided by "
            "verified-request duration; median across measured one-worker samples"
        ),
        "measured_samples": len(fractions),
        "median_parallel_eligible_ns": float(statistics.median(eligible)),
        "median_fraction": float(statistics.median(fractions)),
        "minimum_fraction": min(fractions),
        "maximum_fraction": max(fractions),
    }


def _groups(
    plan: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]]:
    if len(records) != PLAN_ATTEMPTS:
        raise CaptureError("R-006 lane reduction requires all planned attempts")
    grouped: dict[
        tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]
    ] = defaultdict(list)
    for attempt, record in zip(plan["attempts"], records, strict=True):
        if record["status"] != "verified":
            raise CaptureError("R-006 scaling reduction requires every attempt to verify")
        grouped[(attempt["workload_id"], attempt["comparison_id"])].append(
            (attempt, record)
        )
    return grouped


def _calibration(
    authority: ModuleType,
    policy: dict[str, Any],
    lane: str,
    captures: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    ratio: float,
    maximum_width: float,
) -> dict[str, Any]:
    if len(captures) != 80:
        raise CaptureError("R-006 A/A calibration requires eighty attempts")
    metrics: dict[str, Any] = {}
    passed = True
    for metric in CALIBRATION_METRICS:
        statistic = _round_statistic(
            authority,
            policy,
            captures,
            metric=metric,
            orientation="resource" if metric == "peak_rss_bytes" else "speed",
            subject=f"M7:{lane}:multi_shard_addi:a-a-{metric}",
        )
        contains = statistic["ci_lower"] <= ratio <= statistic["ci_upper"]
        width = statistic["ci_upper"] - statistic["ci_lower"]
        row_pass = contains and width <= maximum_width
        statistic.update(
            {
                "ci_width": width,
                "contains_one": contains,
                "pass": row_pass,
            }
        )
        metrics[metric] = statistic
        passed = passed and row_pass
    return {
        "attempts": len(captures),
        "metrics": metrics,
        "verdict": "PASS" if passed else "NO_VERDICT",
    }


def evaluate_pair_scaling(repository: Path, bundle_path: Path) -> dict[str, Any]:
    repository = repository.resolve()
    bundle_validation = validate_pair_bundle(
        repository, bundle_path, include_snapshot=True
    )
    snapshot = bundle_validation.pop("_snapshot")
    if bundle_validation["failed_attempts"]:
        raise CaptureError("R-006 scaling reduction requires a failure-free paired bundle")
    exact_work_authority = bundle_validation["exact_work_authority"]
    if (
        exact_work_authority["every_attempt_complete_exact_work"] is not True
        or exact_work_authority["every_cell_deterministic"] is not True
    ):
        raise CaptureError("R-006 scaling reduction requires complete deterministic cells")
    exact_work_index = exact_work_cells.cell_index(exact_work_authority)
    plan = snapshot["plan"]
    bundle = snapshot["bundle"]
    protocol = _protocol(repository)
    authority, statistical_policy = _authority(repository, protocol)
    milestone = next(
        item for item in protocol["milestones"] if item.get("id") == "M7"
    )
    calibration_policy = protocol["sampling_protocol"]["a_a_calibration"]
    lane_groups: dict[
        str,
        dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]],
    ] = {}
    calibrations: dict[str, Any] = {}
    for lane in PAIR_LANE_ORDER:
        lane_groups[lane] = _groups(
            plan["lanes"][lane],
            snapshot["lane_records"][lane],
        )
        calibration = lane_groups[lane][("multi_shard_addi", "aa-calibration")]
        calibrations[lane] = _calibration(
            authority,
            statistical_policy,
            lane,
            calibration,
            ratio=calibration_policy["ratio_ci_must_contain"],
            maximum_width=calibration_policy["maximum_ci_width"],
        )

    rows: list[dict[str, Any]] = []
    qualifying_workloads: set[str] = set()
    primary_pass = False
    largest_gates_pass = True
    for lane in PAIR_LANE_ORDER:
        for workload in WORKLOAD_IDS:
            for comparison in SCALING_COMPARISONS:
                captures = lane_groups[lane][(workload, comparison)]
                if len(captures) != 80:
                    raise CaptureError("R-006 scaling cell does not contain eighty attempts")
                subject_workers = {
                    attempt["worker_count"]
                    for attempt, _ in captures
                    if attempt["arm"] == "subject"
                }
                if len(subject_workers) != 1:
                    raise CaptureError("R-006 scaling cell subject worker count changed")
                workers = next(iter(subject_workers))
                parallel = _parallel_fraction(captures)
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
                statistics_block: dict[str, Any] = {}
                for metric in SPEED_METRICS:
                    statistics_block[metric] = _round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric=metric,
                        orientation="speed",
                        subject=f"M7:{lane}:{workload}:{comparison}:{metric}",
                    )
                for metric in RESOURCE_METRICS:
                    statistics_block[metric] = _round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric=metric,
                        orientation="resource",
                        subject=f"M7:{lane}:{workload}:{comparison}:{metric}",
                    )
                if lane == "metal-hybrid":
                    statistics_block["gpu_dispatches"] = _round_statistic(
                        authority,
                        statistical_policy,
                        captures,
                        metric="gpu_dispatches",
                        orientation="resource",
                        subject=(
                            f"M7:{lane}:{workload}:{comparison}:gpu_dispatches"
                        ),
                    )
                reference_cell, subject_cell = exact_work_cells.require_cells(
                    exact_work_index,
                    (
                        (lane, workload, 1),
                        (lane, workload, workers),
                    ),
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
                        milestone["primary_target"]["threshold_floor"],
                        0.70 * amdahl,
                    )
                    primary_pass = statistics_block["verified_request_ns"][
                        "ci_lower"
                    ] >= threshold
                    gates["primary_verified_request_speed"] = {
                        "direction": "lower_greater_than_or_equal",
                        "threshold": threshold,
                        "observed": statistics_block["verified_request_ns"][
                            "ci_lower"
                        ],
                        "pass": primary_pass,
                    }
                if comparison == "max-workers-over-one" and qualifying:
                    speed_threshold = max(1.05, 0.70 * amdahl)
                    gates.update(
                        {
                            "qualifying_verified_request_speed": {
                                "direction": "lower_greater_than_or_equal",
                                "threshold": speed_threshold,
                                "observed": statistics_block[
                                    "verified_request_ns"
                                ]["ci_lower"],
                                "pass": statistics_block[
                                    "verified_request_ns"
                                ]["ci_lower"]
                                >= speed_threshold,
                            },
                            "process_cpu_work": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.15,
                                "observed": statistics_block["process_cpu_ns"][
                                    "ci_upper"
                                ],
                                "pass": statistics_block["process_cpu_ns"][
                                    "ci_upper"
                                ]
                                <= 1.15,
                            },
                            "retired_instruction_work": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.15,
                                "observed": statistics_block[
                                    "retired_instructions"
                                ]["ci_upper"],
                                "pass": statistics_block[
                                    "retired_instructions"
                                ]["ci_upper"]
                                <= 1.15,
                            },
                            "peak_rss": {
                                "direction": "upper_less_than_or_equal",
                                "threshold": 1.25,
                                "observed": statistics_block["peak_rss_bytes"][
                                    "ci_upper"
                                ],
                                "pass": statistics_block["peak_rss_bytes"][
                                    "ci_upper"
                                ]
                                <= 1.25,
                            },
                        }
                    )
                    if lane == "metal-hybrid":
                        gates["gpu_command_work"] = {
                            "authority": "resident Metal batch-dispatch count",
                            "direction": "upper_less_than_or_equal",
                            "threshold": 1.15,
                            "observed": statistics_block["gpu_dispatches"][
                                "ci_upper"
                            ],
                            "pass": statistics_block["gpu_dispatches"][
                                "ci_upper"
                            ]
                            <= 1.15,
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
                        "statistics": statistics_block,
                        "gates": gates,
                    }
                )
    calibration_pass = all(
        result["verdict"] == "PASS" for result in calibrations.values()
    )
    enough_qualifying = len(qualifying_workloads) >= milestone[
        "parallelizable_fraction"
    ]["minimum_qualifying_workloads"]
    cross_lane_work: list[dict[str, Any]] = []
    for workload in WORKLOAD_IDS:
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
    every_attempt_exact = exact_work_authority[
        "every_attempt_complete_exact_work"
    ]
    every_cell_deterministic = exact_work_authority["every_cell_deterministic"]
    if not calibration_pass or not enough_qualifying:
        scaling_verdict = "NO_VERDICT"
    elif (
        primary_pass
        and largest_gates_pass
        and every_attempt_exact
        and every_cell_deterministic
    ):
        scaling_verdict = "PASS"
    else:
        scaling_verdict = "FAIL"
    result: dict[str, Any] = {
        "schema": REDUCTION_SCHEMA,
        "schema_version": 2,
        "classification": (
            "authenticated-paired-scaling-reduction-not-m7-promotion-receipt"
        ),
        "scaling_verdict": scaling_verdict,
        "m7_verdict": (
            "FAIL"
            if scaling_verdict == "FAIL"
            else "NO_VERDICT_MISSING_PREDECESSOR_ONE_WORKER_COHORT"
        ),
        "plan_sha256": plan["content_sha256"],
        "bundle_sha256": bundle["content_sha256"],
        "attempts": PAIR_ATTEMPTS,
        "bundle_validation": bundle_validation,
        "statistical_authority": dict(statistical_policy),
        "calibration": calibrations,
        "rows": rows,
        "cross_lane_executed_work_observations": cross_lane_work,
        "aggregate_gates": {
            "a_a_calibration": calibration_pass,
            "minimum_two_qualifying_workloads": enough_qualifying,
            "primary_cpu_four_worker_target": primary_pass,
            "all_qualifying_largest_worker_gates": largest_gates_pass,
            "every_attempt_complete_exact_work": every_attempt_exact,
            "every_cell_deterministic": every_cell_deterministic,
        },
        "qualifying_workloads": sorted(qualifying_workloads),
        "claim_boundary": {
            "normative_scaling_capture": bundle_validation[
                "normative_scaling_capture"
            ],
            "m7_promotion_receipt": False,
            "missing_required_evidence": [
                "protocol-preserving-predecessor-one-worker-paired-cohort",
                "predecessor-candidate-exact-relation-summary-and-geometry-equality",
            ],
        },
    }
    assert_pair_snapshot_current(bundle_path, snapshot)
    _require_unchanged_bundle_validation(
        repository, bundle_path, bundle_validation
    )
    result["content_sha256"] = content_digest(result)
    return result


def validate_pair_reduction(
    repository: Path,
    bundle_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    try:
        raw = receipt_path.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read the R-006 scaling receipt") from error
    expected = evaluate_pair_scaling(repository, bundle_path)
    if raw != canonical_bytes(expected):
        raise CaptureError("R-006 scaling receipt differs from raw-bundle recomputation")
    return {
        "schema": "stwo.typed-air.r006-paired-scaling-validation.v2",
        "schema_version": 2,
        "status": "VALID",
        "plan_sha256": expected["plan_sha256"],
        "bundle_sha256": expected["bundle_sha256"],
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "scaling_verdict": expected["scaling_verdict"],
        "m7_verdict": expected["m7_verdict"],
        "validator_recomputed": True,
    }
