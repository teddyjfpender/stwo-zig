"""Recompute paired proof-throughput and peak-memory verdicts from raw samples."""

from __future__ import annotations

import math
import statistics as py_statistics
from pathlib import Path
from typing import Any

from .artifacts import require_artifact
from .codec import strict_json
from .model import EvidenceError, exact_object, require_bool, require_hex, require_int, require_number
from .session import require_successful_attempt
from .statistics import evaluate_workload, first_order


ROW_FIELDS = {
    "host_role", "backend", "runtime_mode", "workload", "numerator",
    "baseline_executable_artifact", "candidate_executable_artifact", "warmups",
    "rounds", "summary", "verdict",
}
ROUND_FIELDS = {"index", "order", "cooldown_seconds", "baseline", "candidate"}
SAMPLE_FIELDS = {
    "attempt_sequence", "prove_seconds", "request_seconds", "peak_rss_bytes",
    "numerator_units", "locally_verified", "pinned_rust_stwo_verified",
    "canonical_proof_sha256", "metal_device_dispatches", "metal_fallback_count",
}
SUMMARY_FIELDS = {
    "paired_throughput_ratios", "hodges_lehmann", "ci_lower", "ci_upper",
    "baseline_peak_rss_bytes", "candidate_peak_rss_bytes", "peak_rss_ratio",
}


def performance_budget_pass(protocol: dict[str, Any], ci_lower: float, rss_ratio: float) -> bool:
    return (
        ci_lower >= protocol["budgets"]["minimum_throughput_ci_lower"]
        and rss_ratio <= protocol["budgets"]["maximum_peak_rss_ratio"]
    )


def _close(actual: object, expected: float, label: str) -> None:
    value = require_number(actual, label)
    if not math.isclose(value, expected, rel_tol=1e-12, abs_tol=1e-12):
        raise EvidenceError(f"{label} differs from the frozen calculation")


def _sample(
    value: object,
    *,
    row: dict[str, Any],
    arm: str,
    stage: str,
    round_index: int | None,
    order_position: int | None,
    attempts: dict[tuple[str, int], dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    raw_root: Path,
    max_bytes: int,
) -> dict[str, Any]:
    sample = exact_object(value, SAMPLE_FIELDS, "proof sample")
    workload_id = row["workload"]["id"]
    command_id = f"prove:{row['backend']}:{workload_id}:{arm}"
    attempt = require_successful_attempt(
        attempts, sample["attempt_sequence"], role=row["host_role"], arm=arm,
        command_id=command_id, stage=stage,
    )
    if attempt["workload_id"] != workload_id or attempt["round_index"] != round_index:
        raise EvidenceError("proof attempt workload/round mismatch")
    if attempt["order_position"] != order_position:
        raise EvidenceError("proof attempt order position mismatch")
    raw_evidence: dict[str, dict[str, Any]] = {}
    for key in ("proof", "verifier", "timing", "resource"):
        artifact = require_artifact(artifacts, attempt["artifacts"][key], key, f"proof sample {key}")
        if key != "proof":
            raw_evidence[key] = strict_json(raw_root / artifact["path"], max_bytes)
    require_number(sample["prove_seconds"], "sample prove seconds", 1e-15)
    require_number(sample["request_seconds"], "sample request seconds", 1e-15)
    require_int(sample["peak_rss_bytes"], "sample peak RSS", 1)
    if sample["numerator_units"] != row["numerator"]["units"]:
        raise EvidenceError("sample numerator differs from workload")
    if sample["locally_verified"] is not True or sample["pinned_rust_stwo_verified"] is not True:
        raise EvidenceError("accepted proof lacks local or pinned Rust Stwo verification")
    require_hex(sample["canonical_proof_sha256"], 64, "canonical proof digest")
    verifier = exact_object(
        raw_evidence["verifier"],
        {"schema", "local_verified", "rust_oracle_verified", "canonical_proof_sha256", "metal_device_dispatches", "metal_fallback_count"},
        "proof verifier",
    )
    if verifier != {
        "schema": "proof-verifier-v1",
        "local_verified": True,
        "rust_oracle_verified": True,
        "canonical_proof_sha256": sample["canonical_proof_sha256"],
        "metal_device_dispatches": sample["metal_device_dispatches"],
        "metal_fallback_count": sample["metal_fallback_count"],
    }:
        raise EvidenceError("proof verifier artifact does not support the sample")
    timing = exact_object(
        raw_evidence["timing"], {"schema", "prove_seconds", "request_seconds"}, "proof timing",
    )
    if timing["schema"] != "proof-timing-v1":
        raise EvidenceError("proof timing schema is unsupported")
    _close(timing["prove_seconds"], float(sample["prove_seconds"]), "raw prove seconds")
    _close(timing["request_seconds"], float(sample["request_seconds"]), "raw request seconds")
    resource = exact_object(raw_evidence["resource"], {"schema", "peak_rss_bytes"}, "proof resource")
    if resource != {"schema": "process-resource-v1", "peak_rss_bytes": sample["peak_rss_bytes"]}:
        raise EvidenceError("proof resource artifact differs from sample")
    dispatches = require_int(sample["metal_device_dispatches"], "Metal dispatches")
    fallbacks = require_int(sample["metal_fallback_count"], "Metal fallback count")
    if row["backend"] == "metal-hybrid" and arm == "candidate":
        if dispatches == 0 or fallbacks != 0:
            raise EvidenceError("candidate Metal sample did not use device-only dispatch")
    return sample


def _samples(
    values: object,
    *,
    minimum: int,
    row: dict[str, Any],
    arm: str,
    stage: str,
    round_index: int | None,
    order_position: int | None,
    attempts: dict[tuple[str, int], dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    raw_root: Path,
    max_bytes: int,
) -> list[dict[str, Any]]:
    if not isinstance(values, list) or len(values) < minimum:
        raise EvidenceError(f"{stage} requires at least {minimum} verified samples")
    return [
        _sample(
            item, row=row, arm=arm, stage=stage, round_index=round_index,
            order_position=order_position, attempts=attempts, artifacts=artifacts,
            raw_root=raw_root, max_bytes=max_bytes,
        )
        for item in values
    ]


def _build_artifacts(builds: list[dict[str, Any]]) -> dict[tuple[str, str], tuple[str, str]]:
    mapping: dict[tuple[str, str], tuple[str, str]] = {}
    build_lane = {
        "macos-native-cpu": ("macos", "cpu"),
        "macos-native-metal": ("macos", "metal-hybrid"),
        "linux-native-cpu": ("linux", "cpu"),
    }
    for build in builds:
        lane = build_lane.get(build["id"])
        if lane is not None and build["baseline"] is not None:
            mapping[lane] = (
                build["baseline"]["executable_artifact"],
                build["candidate"]["executable_artifact"],
            )
    return mapping


def validate_performance(
    values: object,
    *,
    root,
    protocol: dict[str, Any],
    builds: list[dict[str, Any]],
    attempts: dict[tuple[str, int], dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    raw_root: Path,
) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        raise EvidenceError("performance rows must be a list")
    workload_map = {item["id"]: item for item in protocol["workloads"]}
    expected = {
        (lane["host_role"], lane["backend"], workload["id"])
        for lane in protocol["performance_lanes"]
        for workload in protocol["workloads"]
    }
    actual = {
        (item.get("host_role"), item.get("backend"), item.get("workload", {}).get("id"))
        for item in values if isinstance(item, dict)
    }
    if actual != expected or len(values) != len(expected):
        raise EvidenceError("performance row set differs from the frozen basket")
    executable_map = _build_artifacts(builds)
    proof_groups: dict[str, set[str]] = {}
    minimum_warmups = protocol["statistics"]["minimum_excluded_verified_warmups"]
    minimum_samples = protocol["statistics"]["minimum_measured_verified_proofs_per_arm_per_round"]
    minimum_rounds = protocol["statistics"]["minimum_paired_rounds"]
    for item in values:
        row = exact_object(item, ROW_FIELDS, "performance row")
        key = (row["host_role"], row["backend"])
        if key not in executable_map:
            raise EvidenceError("performance row has no exact build executable")
        if (row["baseline_executable_artifact"], row["candidate_executable_artifact"]) != executable_map[key]:
            raise EvidenceError("performance row executable identity mismatch")
        require_artifact(artifacts, row["baseline_executable_artifact"], "executable", "baseline executable")
        require_artifact(artifacts, row["candidate_executable_artifact"], "executable", "candidate executable")
        workload = exact_object(row["workload"], {"id", "name", "parameters"}, "workload")
        authority = workload_map.get(workload["id"])
        if authority is None or workload != {key: authority[key] for key in ("id", "name", "parameters")}:
            raise EvidenceError("workload descriptor differs from protocol")
        if row["numerator"] != authority["numerator"]:
            raise EvidenceError("performance numerator differs from protocol")
        lane = next(
            lane for lane in protocol["performance_lanes"]
            if lane["host_role"] == row["host_role"] and lane["backend"] == row["backend"]
        )
        if row["runtime_mode"] != lane["runtime_mode"]:
            raise EvidenceError("runtime mode is not comparable")
        warmups = exact_object(row["warmups"], {"baseline", "candidate"}, "warmups")
        all_samples: list[dict[str, Any]] = []
        for arm in ("baseline", "candidate"):
            all_samples.extend(_samples(
                warmups[arm], minimum=minimum_warmups, row=row, arm=arm,
                stage="warmup", round_index=None, order_position=None,
                attempts=attempts, artifacts=artifacts,
                raw_root=raw_root, max_bytes=protocol["limits"]["max_json_bytes"],
            ))
        rounds = row["rounds"]
        if not isinstance(rounds, list) or len(rounds) < minimum_rounds:
            raise EvidenceError("performance row has too few paired rounds")
        if len(rounds) > protocol["limits"]["max_rounds_per_row"]:
            raise EvidenceError("performance row has too many rounds")
        ratios: list[float] = []
        baseline_rss: list[int] = []
        candidate_rss: list[int] = []
        initial_order = first_order(workload["id"])
        for index, item_round in enumerate(rounds, 1):
            paired = exact_object(item_round, ROUND_FIELDS, "paired round")
            expected_order = initial_order if index % 2 == 1 else initial_order[::-1]
            if paired["index"] != index or paired["order"] != expected_order:
                raise EvidenceError("paired round order was deleted, reordered, or arm-swapped")
            _close(paired["cooldown_seconds"], protocol["statistics"]["cooldown_seconds"], "cooldown")
            arm_samples: dict[str, list[dict[str, Any]]] = {}
            for arm in ("baseline", "candidate"):
                position = expected_order.index("A" if arm == "baseline" else "B")
                arm_samples[arm] = _samples(
                    paired[arm], minimum=minimum_samples, row=row, arm=arm,
                    stage="sample", round_index=index, order_position=position,
                    attempts=attempts, artifacts=artifacts,
                    raw_root=raw_root, max_bytes=protocol["limits"]["max_json_bytes"],
                )
                all_samples.extend(arm_samples[arm])
            first_arm = "baseline" if expected_order[0] == "A" else "candidate"
            second_arm = "candidate" if first_arm == "baseline" else "baseline"
            if max(sample["attempt_sequence"] for sample in arm_samples[first_arm]) >= min(sample["attempt_sequence"] for sample in arm_samples[second_arm]):
                raise EvidenceError("sample execution order differs from declared AB/BA order")
            a_seconds = py_statistics.median(sample["prove_seconds"] for sample in arm_samples["baseline"])
            b_seconds = py_statistics.median(sample["prove_seconds"] for sample in arm_samples["candidate"])
            ratios.append(a_seconds / b_seconds)
            baseline_rss.extend(sample["peak_rss_bytes"] for sample in arm_samples["baseline"])
            candidate_rss.extend(sample["peak_rss_bytes"] for sample in arm_samples["candidate"])
        proof_digests = {sample["canonical_proof_sha256"] for sample in all_samples}
        if len(proof_digests) != 1:
            raise EvidenceError("proof bytes are not stable across accepted samples")
        proof_groups.setdefault(workload["id"], set()).update(proof_digests)
        estimate, lower, upper = evaluate_workload(root, protocol, workload["id"], ratios)
        baseline_peak = max(baseline_rss)
        candidate_peak = max(candidate_rss)
        rss_ratio = candidate_peak / baseline_peak
        summary = exact_object(row["summary"], SUMMARY_FIELDS, "performance summary")
        if summary["paired_throughput_ratios"] != ratios:
            raise EvidenceError("paired throughput ratios differ from raw samples")
        for field, expected_value in (
            ("hodges_lehmann", estimate), ("ci_lower", lower), ("ci_upper", upper),
            ("peak_rss_ratio", rss_ratio),
        ):
            _close(summary[field], expected_value, field)
        if summary["baseline_peak_rss_bytes"] != baseline_peak or summary["candidate_peak_rss_bytes"] != candidate_peak:
            raise EvidenceError("peak RSS summary differs from samples")
        passed = performance_budget_pass(protocol, lower, rss_ratio)
        expected_verdict = "PASS" if passed else "NO-GO"
        if row["verdict"] != expected_verdict:
            raise EvidenceError("performance verdict differs from recomputed budgets")
        if not passed:
            raise EvidenceError(f"performance budget failed: {workload['id']} {row['backend']}")
    if any(len(digests) != 1 for digests in proof_groups.values()):
        raise EvidenceError("canonical proof bytes differ across CPU and Metal lanes")
    return values
