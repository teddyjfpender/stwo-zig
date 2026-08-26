"""Digest-pinned C-013 statistics recomputed from raw child reports.

The A/A gate admits a host session.  The CPU reduction is deliberately a
lane-local result: it can establish the native software/precompile crossover
and total-work gates, but it is not the two-lane M6 promotion receipt required
by :mod:`design/typed-air/PERFORMANCE.md`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import statistics as py_statistics
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any

from . import schedule
from .codec import content_digest, load_strict, sha256_file
from .model import CaptureError, PROTOCOL_PATH


METRICS = ("verified_request_ns", "proving_ns", "peak_rss_bytes")

CPU_REDUCTION_SCHEMA = "stwo.typed-air.c013-cpu-reduction.v1"
SPEED_METRICS = {
    "launcher_wall_ns": ("record", "launcher_elapsed_ns"),
    "verified_request_ns": ("metrics", "verified_request_ns"),
    "execution_ns": ("metrics", "execution_ns"),
    "proving_ns": ("metrics", "proving_ns"),
    "proof_encoding_ns": ("metrics", "proof_encoding_ns"),
}
RESOURCE_METRICS = {
    "native_verification_ns": ("metrics", "verification_ns"),
    "peak_rss_bytes": (
        "resources",
        "lifetime_peak_physical_footprint_bytes",
    ),
    "process_cpu_ns": ("resources", "process_cpu_ns"),
    "energy_nj": ("resources", "energy_nj"),
    "retired_instructions": ("resources", "instructions"),
    "cycles": ("resources", "cycles"),
}
EXACT_ARM_FIELDS = (
    "execution_steps",
    "proof_wire_bytes",
    "preprocessed_cells",
    "main_cells",
    "interaction_cells",
)


def calibration_gate(repository: Path) -> dict[str, object]:
    protocol = load_strict(repository.resolve() / PROTOCOL_PATH)
    authority = protocol["statistical_authority"]
    sampling = protocol["sampling_protocol"]["a_a_calibration"]
    subjects = {
        metric: f"M6:cpu-native:multi_shard_addi:a_a:{metric}"
        for metric in METRICS
    }
    return {
        "authority_path": authority["statistics_path"],
        "authority_sha256": authority["statistics_sha256"],
        "estimator": authority["estimator"],
        "confidence_level": authority["confidence_level"],
        "bootstrap_iterations": authority["bootstrap_iterations"],
        "seed_rule": authority["bootstrap_seed"],
        "subjects": subjects,
        "ratio_ci_must_contain": sampling["ratio_ci_must_contain"],
        "maximum_ci_width": sampling["maximum_ci_width"],
        "failure_outcome": sampling["failure_outcome"],
    }


def _authority(repository: Path, gate: dict[str, Any]) -> ModuleType:
    path = repository.resolve() / gate["authority_path"]
    _, digest = sha256_file(path)
    if digest != gate["authority_sha256"]:
        raise CaptureError("frozen statistical authority digest changed")
    spec = importlib.util.spec_from_file_location("stwo_c013_epoch3_stats", path)
    if spec is None or spec.loader is None:
        raise CaptureError("cannot load the frozen statistical authority")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed(subject: str) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{subject}:0".encode("utf-8")).digest()[:4],
        "big",
    )


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise CaptureError(f"M6 capture has invalid {name}")
    return value


def _ratio(
    numerator: int,
    denominator: int,
    *,
    name: str,
) -> dict[str, int | float]:
    _positive(numerator, f"{name} numerator")
    _positive(denominator, f"{name} denominator")
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator,
    }


def _gate(
    *,
    direction: str,
    threshold: float,
    observed: float,
) -> dict[str, object]:
    if direction == "lower_greater_than_or_equal":
        passed = observed >= threshold
    elif direction == "lower_strictly_greater_than":
        passed = observed > threshold
    elif direction == "upper_less_than_or_equal":
        passed = observed <= threshold
    else:  # pragma: no cover - every caller is a closed literal table.
        raise AssertionError(f"unknown gate direction: {direction}")
    return {
        "direction": direction,
        "threshold": threshold,
        "observed": observed,
        "pass": passed,
    }


def _exact_upper_ratio_gate(
    ratio: dict[str, int | float],
    threshold: float,
) -> dict[str, object]:
    numerator = ratio["numerator"]
    denominator = ratio["denominator"]
    if type(numerator) is not int or type(denominator) is not int:
        raise CaptureError("exact ratio lost its integer terms")
    bound = Fraction(str(threshold))
    left = numerator * bound.denominator
    right = denominator * bound.numerator
    return {
        "direction": "upper_less_than_or_equal",
        "threshold": threshold,
        "observed": ratio["value"],
        "exact_comparison": {
            "left": left,
            "operator": "less_than_or_equal",
            "right": right,
        },
        "pass": left <= right,
    }


def _m6_policy(repository: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_strict(repository.resolve() / PROTOCOL_PATH)
    milestones = protocol.get("milestones")
    if type(milestones) is not list:
        raise CaptureError("typed-AIR protocol milestones are unavailable")
    milestone = next(
        (
            item
            for item in milestones
            if type(item) is dict and item.get("id") == "M6"
        ),
        None,
    )
    budgets = protocol.get("universal_hard_budgets")
    if milestone is None or type(budgets) is not dict:
        raise CaptureError("typed-AIR M6 policy is unavailable")
    return milestone, budgets


def _capture_value(
    record: dict[str, Any],
    report: dict[str, Any],
    source: tuple[str, str],
    name: str,
) -> int:
    container, field = source
    if container == "record":
        value = record[field]
    else:
        value = report[container][field]
    return _positive(value, name)


def _round_summary(
    authority: ModuleType,
    gate: dict[str, Any],
    captures: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    *,
    metric: str,
    source: tuple[str, str],
    orientation: str,
    subject: str,
) -> dict[str, Any]:
    software_medians: list[float] = []
    precompile_medians: list[float] = []
    ratios: list[float] = []
    for round_index in range(schedule.MEASURED_ROUNDS):
        selected = [
            item
            for item in captures
            if item[0]["phase"] == "measured"
            and item[0]["round"] == round_index
        ]
        software = [
            _capture_value(record, report, source, metric)
            for attempt, record, report in selected
            if attempt["arm"] == "software"
        ]
        precompile = [
            _capture_value(record, report, source, metric)
            for attempt, record, report in selected
            if attempt["arm"] == "precompile"
        ]
        if len(software) != schedule.PAIRS_PER_ROUND or len(precompile) != schedule.PAIRS_PER_ROUND:
            raise CaptureError(
                f"M6 {metric} measured-round cardinality is incomplete"
            )
        software_median = float(py_statistics.median(software))
        precompile_median = float(py_statistics.median(precompile))
        software_medians.append(software_median)
        precompile_medians.append(precompile_median)
        if orientation == "speed":
            ratios.append(software_median / precompile_median)
        elif orientation == "resource":
            ratios.append(precompile_median / software_median)
        else:  # pragma: no cover - closed literal tables above.
            raise AssertionError(f"unknown M6 ratio orientation: {orientation}")
    estimate = authority.hodges_lehmann(ratios)
    lower, upper = authority.bootstrap_ci(
        ratios,
        level=gate["confidence_level"],
        iterations=gate["bootstrap_iterations"],
        seed=_seed(subject),
    )
    return {
        "subject_id": subject,
        "orientation": (
            "software_duration_over_precompile_duration"
            if orientation == "speed"
            else "precompile_resource_over_software_resource"
        ),
        "software_round_medians": software_medians,
        "precompile_round_medians": precompile_medians,
        "round_ratios": ratios,
        "hodges_lehmann": estimate,
        "ci_lower": lower,
        "ci_upper": upper,
    }


def _exact_arm(
    captures: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    arm: str,
) -> dict[str, Any]:
    reports = [report for attempt, _, report in captures if attempt["arm"] == arm]
    if len(reports) != schedule.ATTEMPTS_PER_CELL // 2:
        raise CaptureError(f"M6 {arm} cell cardinality is incomplete")
    result: dict[str, Any] = {}
    for field in EXACT_ARM_FIELDS:
        values = {report["metrics"][field] for report in reports}
        if len(values) != 1:
            raise CaptureError(f"M6 {arm} {field} changed within one cell")
        result[field] = _positive(next(iter(values)), f"{arm}.{field}")
    proof_digests = {report["proof_sha256"] for report in reports}
    if len(proof_digests) != 1:
        raise CaptureError(f"M6 {arm} proof identity changed within one cell")
    result["proof_sha256"] = next(iter(proof_digests))
    result["committed_cells"] = sum(
        result[field]
        for field in ("preprocessed_cells", "main_cells", "interaction_cells")
    )
    return result


def _validate_m6_capture_order(
    plan: dict[str, Any],
    captures: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
) -> None:
    if len(captures) != schedule.M6_ATTEMPTS:
        raise CaptureError("M6 reduction requires all 1,440 verified attempts")
    planned = plan.get("attempts")
    if type(planned) is not list or len(planned) != schedule.GLOBAL_ATTEMPTS:
        raise CaptureError("M6 reduction requires the complete frozen plan")
    expected = planned[schedule.CALIBRATION_ATTEMPTS :]
    for index, ((attempt, record, report), pinned) in enumerate(
        zip(captures, expected, strict=True)
    ):
        if attempt != pinned:
            raise CaptureError(f"M6 capture {index} differs from its plan attempt")
        frozen = schedule.m6_attempt_at(index)
        expected_identity = {
            "global_ordinal": frozen.global_ordinal,
            "sample_index": frozen.sample_index,
            "kind": frozen.kind,
            "phase": frozen.phase,
            "arm": frozen.arm,
            "round": frozen.round,
            "pair_index": frozen.pair_index,
            "position": frozen.position,
            "cell_index": frozen.cell_index,
            "shape": frozen.shape,
            "calls": frozen.calls,
        }
        for key, value in expected_identity.items():
            if type(attempt.get(key)) is not type(value) or attempt.get(key) != value:
                raise CaptureError(f"M6 capture {index} {key} differs from schedule")
        if (
            record.get("global_ordinal") != frozen.global_ordinal
            or record.get("status") != "verified"
            or report.get("status") != "verified"
        ):
            raise CaptureError(f"M6 capture {index} is not a verified ordered attempt")


def evaluate_m6_cpu(
    repository: Path,
    plan: dict[str, Any],
    captures: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    """Reduce a complete authenticated CPU cohort without claiming M6 promotion."""

    _validate_m6_capture_order(plan, captures)
    milestone, budgets = _m6_policy(repository)
    gate = plan["calibration_gate"]
    authority = _authority(repository, gate)
    grouped: dict[
        tuple[str, int],
        list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    ] = defaultdict(list)
    for capture in captures:
        attempt = capture[0]
        grouped[(attempt["shape"], attempt["calls"])].append(capture)
    expected_cells = {
        (shape, calls)
        for shape in schedule.SHAPES
        for calls in schedule.CALL_COUNTS
    }
    if set(grouped) != expected_cells:
        raise CaptureError("M6 reduction cell inventory differs from schedule")

    exact_gates = milestone["exact_gates"]
    statistical_gates = milestone["statistical_gates"]
    cells: list[dict[str, Any]] = []
    for shape in schedule.SHAPES:
        for calls in schedule.CALL_COUNTS:
            cell_captures = grouped[(shape, calls)]
            if len(cell_captures) != schedule.ATTEMPTS_PER_CELL:
                raise CaptureError(f"M6 cell {shape}:{calls} is incomplete")
            software = _exact_arm(cell_captures, "software")
            precompile = _exact_arm(cell_captures, "precompile")
            outputs = {report["output_sha256"] for _, _, report in cell_captures}
            inputs = {report["input_sha256"] for _, _, report in cell_captures}
            if len(outputs) != 1 or len(inputs) != 1:
                raise CaptureError(f"M6 cell {shape}:{calls} corpus identity drifted")
            committed_ratio = _ratio(
                precompile["committed_cells"],
                software["committed_cells"],
                name="committed cells",
            )
            proof_ratio = _ratio(
                precompile["proof_wire_bytes"],
                software["proof_wire_bytes"],
                name="proof bytes",
            )
            statistics: dict[str, Any] = {}
            workload = f"{shape}:calls={calls}"
            for metric, source in SPEED_METRICS.items():
                statistics[metric] = _round_summary(
                    authority,
                    gate,
                    cell_captures,
                    metric=metric,
                    source=source,
                    orientation="speed",
                    subject=f"M6:cpu-native:{workload}:{metric}",
                )
            for metric, source in RESOURCE_METRICS.items():
                statistics[metric] = _round_summary(
                    authority,
                    gate,
                    cell_captures,
                    metric=metric,
                    source=source,
                    orientation="resource",
                    subject=f"M6:cpu-native:{workload}:{metric}",
                )
            measured = [
                item for item in cell_captures if item[0]["phase"] == "measured"
            ]
            software_rss_max = max(
                report["resources"]["lifetime_peak_physical_footprint_bytes"]
                for attempt, _, report in measured
                if attempt["arm"] == "software"
            )
            precompile_rss_max = max(
                report["resources"]["lifetime_peak_physical_footprint_bytes"]
                for attempt, _, report in measured
                if attempt["arm"] == "precompile"
            )
            rss_max_ratio = _ratio(
                precompile_rss_max,
                software_rss_max,
                name="maximum peak RSS",
            )
            row_gates: dict[str, Any] = {
                "verified_request_speed": _gate(
                    direction="lower_greater_than_or_equal",
                    threshold=(
                        statistical_gates["cpu_speed_lower_ci_at_4096_calls"]
                        if shape == "poseidon2_dominant" and calls == 4096
                        else budgets["verified_request_speed_lower_ci"]
                    ),
                    observed=statistics["verified_request_ns"]["ci_lower"],
                ),
                "proving_speed": _gate(
                    direction="lower_greater_than_or_equal",
                    threshold=budgets["proving_speed_lower_ci"],
                    observed=statistics["proving_ns"]["ci_lower"],
                ),
                "native_verification_work": _gate(
                    direction="upper_less_than_or_equal",
                    threshold=(
                        statistical_gates["native_verification_upper_ci_at_4096_calls"]
                        if calls == 4096
                        else budgets[
                            "native_verification_candidate_over_baseline_upper_ci"
                        ]
                    ),
                    observed=statistics["native_verification_ns"]["ci_upper"],
                ),
                "peak_rss": _gate(
                    direction="upper_less_than_or_equal",
                    threshold=statistical_gates["peak_rss_upper_ci_at_4096_calls"]
                    if calls == 4096
                    else budgets["peak_rss_candidate_over_baseline_upper_ci"],
                    observed=statistics["peak_rss_bytes"]["ci_upper"],
                ),
                "maximum_peak_rss": _exact_upper_ratio_gate(
                    rss_max_ratio,
                    budgets["peak_rss_candidate_max_over_baseline_max"],
                ),
                "process_cpu_work": _gate(
                    direction="upper_less_than_or_equal",
                    threshold=statistical_gates["process_cpu_upper_ci_at_4096_calls"]
                    if calls == 4096
                    else budgets["process_cpu_candidate_over_baseline_upper_ci"],
                    observed=statistics["process_cpu_ns"]["ci_upper"],
                ),
                "retired_instruction_work": _gate(
                    direction="upper_less_than_or_equal",
                    threshold=budgets[
                        "retired_instructions_candidate_over_baseline_upper_ci"
                    ],
                    observed=statistics["retired_instructions"]["ci_upper"],
                ),
                "proof_size": _exact_upper_ratio_gate(
                    proof_ratio,
                    (
                        exact_gates[
                            "proof_size_at_4096_calls_candidate_over_software"
                        ]
                        if calls == 4096
                        else budgets[
                            "protocol_changing_proof_size_candidate_over_baseline"
                        ]
                    ),
                ),
            }
            if calls in {512, 4096}:
                threshold = exact_gates[
                    f"committed_cells_at_{calls}_calls_candidate_over_software"
                ]
                row_gates["committed_cells"] = _exact_upper_ratio_gate(
                    committed_ratio,
                    threshold,
                )
            cells.append(
                {
                    "shape": shape,
                    "calls": calls,
                    "input_sha256": next(iter(inputs)),
                    "output_sha256": next(iter(outputs)),
                    "software": software,
                    "precompile": precompile,
                    "committed_cells_ratio": committed_ratio,
                    "proof_wire_bytes_ratio": proof_ratio,
                    "maximum_peak_rss_ratio": rss_max_ratio,
                    "statistics": statistics,
                    "gates": row_gates,
                    "pass": all(item["pass"] for item in row_gates.values()),
                }
            )

    crossovers: list[dict[str, Any]] = []
    for shape in schedule.SHAPES:
        shape_cells = [cell for cell in cells if cell["shape"] == shape]
        qualifying = [
            cell["calls"]
            for cell in shape_cells
            if (
                cell["committed_cells_ratio"]["numerator"]
                < cell["committed_cells_ratio"]["denominator"]
                and cell["statistics"]["verified_request_ns"]["ci_lower"]
                > 1.0
            )
        ]
        first = min(qualifying) if qualifying else None
        crossovers.append(
            {
                "shape": shape,
                "first_qualifying_calls": first,
                "maximum_calls": 512,
                "pass": first is not None and first <= 512,
            }
        )

    primary = next(
        cell
        for cell in cells
        if cell["shape"] == "poseidon2_dominant" and cell["calls"] == 4096
    )
    aggregate_gates = {
        "all_eighteen_cpu_rows": all(cell["pass"] for cell in cells),
        "crossover_by_512_for_every_shape": all(
            item["pass"] for item in crossovers
        ),
        "primary_target": primary["gates"]["verified_request_speed"]["pass"],
    }
    verdict = "PASS" if all(aggregate_gates.values()) else "FAIL"
    result = {
        "schema": CPU_REDUCTION_SCHEMA,
        "classification": "authenticated-cpu-lane-reduction-not-m6-promotion-receipt",
        "verdict": verdict,
        "lane": "cpu-native",
        "security": "secure",
        "plan_sha256": plan["content_sha256"],
        "schedule_sha256": plan["schedule"]["sha256"],
        "capture_disclosure": {
            "protocol": plan["protocol"],
            "source": plan["source"],
            "host": plan["host"],
            "environment": plan["environment"],
            "artifacts": plan["artifacts"],
            "corpus_manifest_sha256": plan["corpus_manifest"][
                "document_sha256"
            ],
        },
        "attempts": {
            "total": schedule.M6_ATTEMPTS,
            "excluded_warmups": len(schedule.SHAPES)
            * len(schedule.CALL_COUNTS)
            * 2
            * schedule.WARMUPS_PER_ARM,
            "measured": len(schedule.SHAPES)
            * len(schedule.CALL_COUNTS)
            * 2
            * schedule.MEASURED_ROUNDS
            * schedule.PAIRS_PER_ROUND,
        },
        "ratio_conventions": {
            "speed": "software_duration_over_precompile_duration",
            "resource": "precompile_resource_over_software_resource",
        },
        "statistical_authority": dict(gate),
        "cells": cells,
        "crossovers": crossovers,
        "aggregate_gates": aggregate_gates,
        "primary_target": {
            "workload": "poseidon2_dominant:calls=4096",
            "metric": "verified_request_speed",
            "threshold": statistical_gates[
                "cpu_speed_lower_ci_at_4096_calls"
            ],
            "ci_lower": primary["statistics"]["verified_request_ns"][
                "ci_lower"
            ],
            "pass": aggregate_gates["primary_target"],
        },
        "claim_boundary": {
            "m6_promotion_outcome": None,
            "promotion_receipt": False,
            "missing_required_lanes": ["metal-hybrid"],
            "missing_receipt_evidence": [
                "protocol-complete-source-build-and-environment-closure",
                "separate-native-and-independent-verifier-receipts",
                "complete-component-geometry-and-proof-artifact-retention",
            ],
        },
    }
    result["content_sha256"] = content_digest(result)
    return result


def _metric(report: dict[str, Any], name: str) -> int:
    if name == "peak_rss_bytes":
        value = report["resources"]["lifetime_peak_physical_footprint_bytes"]
    else:
        value = report["metrics"][name]
    if type(value) is not int or value <= 0:
        raise CaptureError(f"A/A report has invalid {name}")
    return value


def _round_ratios(
    captures: list[tuple[dict[str, Any], dict[str, Any]]],
    metric: str,
) -> tuple[list[float], list[float], list[float]]:
    baseline_medians: list[float] = []
    control_medians: list[float] = []
    ratios: list[float] = []
    for round_index in range(3):
        selected = [
            (attempt, report)
            for attempt, report in captures
            if attempt["round"] == round_index
        ]
        baseline = [_metric(report, metric) for attempt, report in selected if attempt["arm"] == "a"]
        control = [
            _metric(report, metric)
            for attempt, report in selected
            if attempt["arm"] == "a_control"
        ]
        if len(baseline) != 10 or len(control) != 10:
            raise CaptureError("A/A measured-round cardinality is incomplete")
        baseline_median = float(py_statistics.median(baseline))
        control_median = float(py_statistics.median(control))
        baseline_medians.append(baseline_median)
        control_medians.append(control_median)
        ratios.append(
            control_median / baseline_median
            if metric == "peak_rss_bytes"
            else baseline_median / control_median
        )
    return baseline_medians, control_medians, ratios


def evaluate_calibration(
    repository: Path,
    plan: dict[str, Any],
    captures: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    if len(captures) != 80:
        raise CaptureError("A/A admission requires all eighty attempts")
    if any(attempt["kind"] != "calibration" for attempt, _ in captures):
        raise CaptureError("A/A capture contains a non-calibration attempt")
    proof_digests = {report["proof_sha256"] for _, report in captures}
    geometry = {
        (
            report["metrics"]["execution_steps"],
            report["metrics"]["proof_wire_bytes"],
            report["metrics"]["preprocessed_cells"],
            report["metrics"]["main_cells"],
            report["metrics"]["interaction_cells"],
        )
        for _, report in captures
    }
    if len(proof_digests) != 1 or len(geometry) != 1:
        raise CaptureError("A/A proof or geometry identity changed between labels")

    gate = plan["calibration_gate"]
    authority = _authority(repository, gate)
    results: dict[str, Any] = {}
    all_pass = True
    for metric in METRICS:
        baseline, control, ratios = _round_ratios(captures, metric)
        subject = gate["subjects"][metric]
        estimate = authority.hodges_lehmann(ratios)
        lower, upper = authority.bootstrap_ci(
            ratios,
            level=gate["confidence_level"],
            iterations=gate["bootstrap_iterations"],
            seed=_seed(subject),
        )
        contains = lower <= gate["ratio_ci_must_contain"] <= upper
        width = upper - lower
        passed = contains and width <= gate["maximum_ci_width"]
        all_pass = all_pass and passed
        results[metric] = {
            "subject_id": subject,
            "baseline_round_medians": baseline,
            "control_round_medians": control,
            "round_ratios": ratios,
            "hodges_lehmann": estimate,
            "ci_lower": lower,
            "ci_upper": upper,
            "ci_width": width,
            "contains_one": contains,
            "pass": passed,
        }
    return {
        "schema": "stwo.typed-air.c013-aa-admission.v1",
        "attempts": 80,
        "proof_sha256": next(iter(proof_digests)),
        "geometry": list(next(iter(geometry))),
        "metrics": results,
        "verdict": "PASS" if all_pass else "NO_VERDICT",
    }
