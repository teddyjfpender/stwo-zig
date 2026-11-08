#!/usr/bin/env python3
"""Compare compatible benchmark reports and preserve their exact source bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from benchmark_delta_lib.archive import ARCHIVE_SCHEMA_VERSION, update_archive  # noqa: E402
from benchmark_delta_lib.common import (  # noqa: E402
    DELTA_PROTOCOL,
    SEQUENTIAL_DELTA_NOTE,
    DeltaError,
    IncompatibleReports,
    atomic_write,
    canonical_bytes,
    digest_json,
    encoded_json,
    require_list,
    require_object,
)
from benchmark_delta_lib.native_oracle import (  # noqa: E402
    classify_transition,
    oracle_binary_pair,
)
from benchmark_delta_lib.product_identity import (  # noqa: E402
    LEGACY_V5_PRODUCT_ALIASES,
    product_identity_transition,
    product_receipt_revision,
    validate_native_v6_report,
)

DELTA_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 128 * 1024 * 1024
UPSTREAM_PROTOCOL = "upstream_family_matrix_v1"
NATIVE_PROTOCOL_V3 = "native_proof_cross_backend_matrix_v3"
NATIVE_PROTOCOL_V4 = "native_proof_cross_backend_matrix_v4"
NATIVE_PROTOCOL_V5 = "native_proof_cross_backend_matrix_v5"
NATIVE_PROTOCOL_V6 = "native_proof_cross_backend_matrix_v6"
NATIVE_PROTOCOL = NATIVE_PROTOCOL_V3
NATIVE_PROTOCOLS = {
    NATIVE_PROTOCOL_V3,
    NATIVE_PROTOCOL_V4,
    NATIVE_PROTOCOL_V5,
    NATIVE_PROTOCOL_V6,
}
SUPPORTED_PROTOCOLS = {UPSTREAM_PROTOCOL, *NATIVE_PROTOCOLS}
NATIVE_V4_RESOURCE_KEYS = {
    "measurement",
    "measurement_locale",
    "normalized_unit",
    "peak_rss_kib",
}
NATIVE_V4_STABILITY_KEYS = {
    "required_verified_proofs_per_lane",
    "cpu_verified_proofs",
    "metal_verified_proofs",
    "cpu_byte_identical",
    "metal_byte_identical",
    "satisfied",
}


def require_number(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DeltaError(f"{context} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise DeltaError(f"{context} must be finite and non-negative")
    return result


def optional_number(value: Any, context: str) -> float | None:
    if value is None:
        return None
    return require_number(value, context)


def nested(document: dict[str, Any], path: tuple[str, ...], context: str) -> Any:
    value: Any = document
    for name in path:
        value = require_object(value, context).get(name)
        if value is None:
            raise DeltaError(f"{context}.{'.'.join(path)} is missing")
    return value


def load_report(path: Path, label: str) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise DeltaError(f"{label} is not a regular file: {resolved}")
    raw = resolved.read_bytes()
    if len(raw) == 0 or len(raw) > MAX_REPORT_BYTES:
        raise DeltaError(f"{label} byte length is outside the accepted bounds")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeltaError(f"{label} is not one valid UTF-8 JSON document") from error
    document = require_object(document, label)
    protocol = document.get("protocol")
    if protocol not in SUPPORTED_PROTOCOLS:
        raise DeltaError(f"{label} has unsupported protocol: {protocol!r}")
    source = {
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "report_protocol": protocol,
    }
    return document, raw, source


def metric_delta(
    baseline: float | None, current: float | None, direction: str
) -> dict[str, Any]:
    if baseline is None or current is None:
        if baseline is not None or current is not None:
            raise IncompatibleReports("metric availability differs between reports")
        return {
            "baseline": None,
            "current": None,
            "absolute_delta": None,
            "percent_delta": None,
            "improvement_percent": None,
            "speedup": None,
        }
    absolute = current - baseline
    if baseline == 0:
        percent = 0.0 if current == 0 else None
    else:
        percent = absolute / baseline * 100.0
    improvement = (
        None
        if percent is None
        else (-percent if direction == "lower_is_better" else percent)
    )
    if direction == "lower_is_better":
        speedup = baseline / current if current != 0 else None
    else:
        speedup = current / baseline if baseline != 0 else None
    return {
        "baseline": baseline,
        "current": current,
        "absolute_delta": absolute,
        "percent_delta": percent,
        "improvement_percent": improvement,
        "speedup": speedup,
    }


def metric_record(
    name: str,
    unit: str,
    direction: str,
    baseline: float | None,
    current: float | None,
) -> dict[str, Any]:
    return {
        "metric": name,
        "unit": unit,
        "direction": direction,
        "classification": "unclassified",
        **metric_delta(baseline, current, direction),
    }


def compare_upstream(
    baseline: dict[str, Any], current: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    baseline_settings = require_object(baseline.get("settings"), "baseline.settings")
    current_settings = require_object(current.get("settings"), "current.settings")
    if baseline_settings != current_settings:
        raise IncompatibleReports("upstream benchmark settings differ")
    baseline_families = require_list(
        baseline.get("upstream_families"), "baseline.upstream_families"
    )
    current_families = require_list(
        current.get("upstream_families"), "current.upstream_families"
    )
    if baseline_families != current_families:
        raise IncompatibleReports("upstream family workload keys or order differ")

    baseline_rows = require_list(baseline.get("families"), "baseline.families")
    current_rows = require_list(current.get("families"), "current.families")
    if len(baseline_rows) != len(current_rows):
        raise IncompatibleReports("upstream family row counts differ")
    comparisons: list[dict[str, Any]] = []
    workload_keys: list[dict[str, Any]] = []
    for index, (baseline_value, current_value) in enumerate(
        zip(baseline_rows, current_rows, strict=True)
    ):
        base_row = require_object(baseline_value, f"baseline.families[{index}]")
        curr_row = require_object(current_value, f"current.families[{index}]")
        family = base_row.get("family")
        mapped = base_row.get("mapped_workload")
        if not isinstance(family, str) or not family:
            raise DeltaError(f"baseline.families[{index}].family is invalid")
        if family != curr_row.get("family") or mapped != curr_row.get("mapped_workload"):
            raise IncompatibleReports(f"upstream workload key differs at row {index}")
        workload_key = {"family": family, "mapped_workload": mapped}
        workload_keys.append(workload_key)
        for lane in ("rust", "zig"):
            base_lane = require_object(base_row.get(lane), f"baseline.{family}.{lane}")
            curr_lane = require_object(curr_row.get(lane), f"current.{family}.{lane}")
            metrics = [
                metric_record(
                    "prove_avg_seconds",
                    "seconds",
                    "lower_is_better",
                    require_number(nested(base_lane, ("prove", "avg_seconds"), lane), f"baseline.{family}.{lane}.prove.avg_seconds"),
                    require_number(nested(curr_lane, ("prove", "avg_seconds"), lane), f"current.{family}.{lane}.prove.avg_seconds"),
                ),
                metric_record(
                    "verify_avg_seconds",
                    "seconds",
                    "lower_is_better",
                    require_number(nested(base_lane, ("verify", "avg_seconds"), lane), f"baseline.{family}.{lane}.verify.avg_seconds"),
                    require_number(nested(curr_lane, ("verify", "avg_seconds"), lane), f"current.{family}.{lane}.verify.avg_seconds"),
                ),
                metric_record(
                    "peak_rss_kb",
                    "kilobytes",
                    "lower_is_better",
                    optional_number(base_lane.get("peak_rss_kb"), f"baseline.{family}.{lane}.peak_rss_kb"),
                    optional_number(curr_lane.get("peak_rss_kb"), f"current.{family}.{lane}.peak_rss_kb"),
                ),
            ]
            comparisons.append(
                {
                    "row_index": index,
                    "workload_key": workload_key,
                    "lane": lane,
                    "metrics": metrics,
                }
            )
    identity = {
        "report_protocol": UPSTREAM_PROTOCOL,
        "settings": baseline_settings,
        "ordered_workloads": workload_keys,
    }
    revisions = {
        "baseline": {"status": baseline.get("status")},
        "current": {"status": current.get("status")},
    }
    return identity, comparisons, revisions


NATIVE_STABLE_PROVENANCE = (
    "zig_version",
    "optimization",
    "target_os",
    "target_arch",
    "cpu_count",
    "simd_pack_width",
    "single_threaded",
    "thread_parallelism_enabled",
    "environment_overrides",
)
NATIVE_STABLE_CONFIGURATION = (
    "proof_protocol",
    "warmups_per_lane",
    "samples_per_lane",
    "cooldown_seconds",
    "execution",
    "formal",
    "bounds",
)


def selected_fields(value: dict[str, Any], names: tuple[str, ...], context: str) -> dict[str, Any]:
    missing = [name for name in names if name not in value]
    if missing:
        raise DeltaError(f"{context} is missing compatibility fields: {', '.join(missing)}")
    return {name: value[name] for name in names}


def native_lane_metrics(
    lane: dict[str, Any], context: str
) -> dict[str, dict[str, float]]:
    summaries = require_object(lane.get("metrics"), f"{context}.metrics")
    result: dict[str, dict[str, float]] = {}
    for name, value in summaries.items():
        summary = require_object(value, f"{context}.metrics.{name}")
        result[name] = {
            "median": require_number(
                summary.get("median"), f"{context}.metrics.{name}.median"
            ),
            "mad": require_number(
                summary.get("mad"), f"{context}.metrics.{name}.mad"
            ),
        }
    return result


def native_metric_shape(name: str) -> tuple[str, str]:
    if name.endswith("_seconds"):
        return "seconds", "lower_is_better"
    if name.endswith("_mhz"):
        return "megahertz", "higher_is_better"
    if name.endswith("_per_second"):
        return "million_cells_per_second", "higher_is_better"
    if name.endswith("_kib"):
        return "kibibytes", "lower_is_better"
    raise DeltaError(f"unsupported native metric direction: {name}")


def validate_native_v4_report(report: dict[str, Any], label: str) -> None:
    configuration = require_object(report.get("configuration"), f"{label}.configuration")
    stability_contract = require_object(
        configuration.get("stability_contract"),
        f"{label}.configuration.stability_contract",
    )
    if set(stability_contract) != {"minimum_measured_verified_proofs_per_lane"}:
        raise DeltaError(f"{label} has an invalid stability contract")
    required = stability_contract["minimum_measured_verified_proofs_per_lane"]
    if isinstance(required, bool) or not isinstance(required, int) or required < 10:
        raise DeltaError(f"{label} requires fewer than 10 measured proofs per lane")
    samples = configuration.get("samples_per_lane")
    if isinstance(samples, bool) or not isinstance(samples, int) or samples < required:
        raise DeltaError(f"{label} does not satisfy its measured-proof count")

    rows = require_list(report.get("rows"), f"{label}.rows")
    headline_rows = 0
    all_headline = bool(rows)
    all_stable = bool(rows)
    all_oracles = bool(rows)
    for index, value in enumerate(rows):
        row = require_object(value, f"{label}.rows[{index}]")
        headline = row.get("headline_eligible")
        if not isinstance(headline, bool):
            raise DeltaError(f"{label}.rows[{index}].headline_eligible must be boolean")
        headline_rows += int(headline)
        all_headline = all_headline and headline
        if row.get("proof_parity") is not True:
            raise DeltaError(f"{label}.rows[{index}] lacks canonical proof parity")

        stability = require_object(
            row.get("stability"), f"{label}.rows[{index}].stability"
        )
        if set(stability) != NATIVE_V4_STABILITY_KEYS:
            raise DeltaError(f"{label}.rows[{index}] has an invalid stability schema")
        for field in (
            "required_verified_proofs_per_lane",
            "cpu_verified_proofs",
            "metal_verified_proofs",
        ):
            value = stability[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DeltaError(
                    f"{label}.rows[{index}].stability.{field} must be nonnegative"
                )
        for field in ("cpu_byte_identical", "metal_byte_identical", "satisfied"):
            if not isinstance(stability[field], bool):
                raise DeltaError(
                    f"{label}.rows[{index}].stability.{field} must be boolean"
                )
        expected_stability = (
            stability["required_verified_proofs_per_lane"] == required
            and stability["cpu_verified_proofs"] >= required
            and stability["metal_verified_proofs"] >= required
            and stability["cpu_byte_identical"] is True
            and stability["metal_byte_identical"] is True
        )
        if stability["satisfied"] is not expected_stability:
            raise DeltaError(f"{label}.rows[{index}] has inconsistent stability evidence")
        all_stable = all_stable and expected_stability

        lanes = require_object(row.get("lanes"), f"{label}.rows[{index}].lanes")
        if set(lanes) != {"cpu", "metal"}:
            raise DeltaError(f"{label}.rows[{index}] must have CPU and Metal lanes")
        expected_backends = {"cpu": "cpu_native", "metal": "metal_hybrid"}
        for lane_name, expected_backend in expected_backends.items():
            lane = require_object(
                lanes.get(lane_name), f"{label}.rows[{index}].lanes.{lane_name}"
            )
            if lane.get("backend") != expected_backend:
                raise DeltaError(
                    f"{label}.rows[{index}].lanes.{lane_name} has the wrong backend"
                )
            resources = require_object(
                lane.get("resources"),
                f"{label}.rows[{index}].lanes.{lane_name}.resources",
            )
            if set(resources) != NATIVE_V4_RESOURCE_KEYS:
                raise DeltaError(
                    f"{label}.rows[{index}].lanes.{lane_name} has invalid resources"
                )
            peak = resources.get("peak_rss_kib")
            if (
                resources.get("measurement_locale") != "C"
                or resources.get("normalized_unit") != "KiB"
                or resources.get("measurement")
                not in {"darwin_usr_bin_time_l_v1", "gnu_usr_bin_time_v_v1"}
                or isinstance(peak, bool)
                or not isinstance(peak, int)
                or peak <= 0
            ):
                raise DeltaError(
                    f"{label}.rows[{index}].lanes.{lane_name} has invalid RSS evidence"
                )
            metrics = native_lane_metrics(
                lane, f"{label}.rows[{index}].lanes.{lane_name}"
            )
            rss = metrics.get("peak_rss_kib")
            if rss is None or rss != {"median": float(peak), "mad": 0.0}:
                raise DeltaError(
                    f"{label}.rows[{index}].lanes.{lane_name} RSS metric disagrees"
                )
        metal_telemetry = require_object(
            lanes["metal"].get("backend_telemetry"),
            f"{label}.rows[{index}].lanes.metal.backend_telemetry",
        )
        total_fallbacks = metal_telemetry.get("total_cpu_fallbacks")
        if (
            isinstance(total_fallbacks, bool)
            or not isinstance(total_fallbacks, int)
            or total_fallbacks < 0
        ):
            raise DeltaError(f"{label}.rows[{index}] lacks Metal fallback evidence")

        oracle = row.get("rust_oracle")
        oracle_verified = (
            isinstance(oracle, dict)
            and oracle.get("verified") is True
            and oracle.get("status") == "passed"
            and oracle.get("artifact_sha256")
            == require_object(
                lanes["cpu"].get("proof_artifact"),
                f"{label}.rows[{index}].lanes.cpu.proof_artifact",
            ).get("sha256")
        )
        all_oracles = all_oracles and oracle_verified

    summary = require_object(report.get("summary"), f"{label}.summary")
    expected_summary = {
        "rows": len(rows),
        "headline_rows": headline_rows,
        "all_rows_headline_eligible": all_headline,
        "all_proofs_verified_and_byte_identical": True,
        "all_cross_backend_proofs_identical": True,
        "all_rust_oracles_verified": all_oracles,
        "all_rows_meet_stability_contract": all_stable,
    }
    if summary != expected_summary:
        raise DeltaError(f"{label}.summary is inconsistent with Native v4 rows")
    correctness = require_object(
        report.get("correctness_scope"), f"{label}.correctness_scope"
    )
    if correctness.get("pinned_rust_stwo_oracle_checked") is not all_oracles:
        raise DeltaError(f"{label}.correctness_scope disagrees with Rust receipts")
    if configuration.get("formal") is True and (not all_oracles or not all_stable):
        raise DeltaError(f"{label} formal evidence is incomplete")


def native_row_evidence(
    baseline: dict[str, Any], current: dict[str, Any], index: int
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for label, row in (("baseline", baseline), ("current", current)):
        eligible = row.get("headline_eligible")
        blockers = row.get("headline_blockers")
        if not isinstance(eligible, bool):
            raise DeltaError(f"{label}.rows[{index}].headline_eligible must be boolean")
        blockers = require_list(blockers, f"{label}.rows[{index}].headline_blockers")
        if any(not isinstance(blocker, str) or not blocker for blocker in blockers):
            raise DeltaError(f"{label}.rows[{index}].headline_blockers is invalid")
        evidence[label] = {
            "headline_eligible": eligible,
            "headline_blockers": blockers,
        }
    evidence["stable_for_claim"] = (
        evidence["baseline"]["headline_eligible"]
        and evidence["current"]["headline_eligible"]
    )
    return evidence


def classify_native_metric(
    metric: dict[str, Any], baseline_mad: float, current_mad: float, stable: bool
) -> None:
    noise_band = baseline_mad + current_mad
    metric.update(
        {
            "baseline_mad": baseline_mad,
            "current_mad": current_mad,
            "noise_band": noise_band,
            "stable_for_claim": stable,
        }
    )
    if not stable:
        metric["classification"] = "diagnostic_unstable"
        metric["evidence_class"] = "diagnostic_only"
    elif abs(metric["absolute_delta"]) <= noise_band:
        metric["classification"] = "inconclusive"
        metric["evidence_class"] = "headline"
    else:
        improved = (
            metric["absolute_delta"] < 0
            if metric["direction"] == "lower_is_better"
            else metric["absolute_delta"] > 0
        )
        metric["classification"] = "improvement" if improved else "regression"
        metric["evidence_class"] = "headline"


def compare_native(
    baseline: dict[str, Any], current: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    baseline_protocol = baseline.get("protocol")
    current_protocol = current.get("protocol")
    protocols = (baseline_protocol, current_protocol)
    compatible_protocols = (
        baseline_protocol == current_protocol
        or protocols == (NATIVE_PROTOCOL_V4, NATIVE_PROTOCOL_V5)
        or protocols == (NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6)
    )
    if not compatible_protocols:
        raise IncompatibleReports("benchmark report protocols differ")
    schema_by_protocol = {
        NATIVE_PROTOCOL_V3: 3,
        NATIVE_PROTOCOL_V4: 4,
        NATIVE_PROTOCOL_V5: 5,
        NATIVE_PROTOCOL_V6: 6,
    }
    expected_schemas = tuple(schema_by_protocol.get(protocol) for protocol in protocols)
    if (
        baseline.get("schema_version") != expected_schemas[0]
        or current.get("schema_version") != expected_schemas[1]
    ):
        raise IncompatibleReports(
            f"native matrix schema_version does not match {baseline_protocol}->{current_protocol}"
        )
    for report, label, protocol in (
        (baseline, "baseline", baseline_protocol),
        (current, "current", current_protocol),
    ):
        if protocol in {NATIVE_PROTOCOL_V4, NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6}:
            validate_native_v4_report(report, label)
        if protocol == NATIVE_PROTOCOL_V6:
            validate_native_v6_report(report, label)
    base_configuration = require_object(
        baseline.get("configuration"), "baseline.configuration"
    )
    curr_configuration = require_object(
        current.get("configuration"), "current.configuration"
    )
    stable_configuration = NATIVE_STABLE_CONFIGURATION + (
        ("stability_contract",)
        if baseline_protocol in {NATIVE_PROTOCOL_V4, NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6}
        else ()
    )
    base_settings = selected_fields(
        base_configuration, stable_configuration, "baseline.configuration"
    )
    curr_settings = selected_fields(
        curr_configuration, stable_configuration, "current.configuration"
    )
    base_provenance = require_object(
        base_configuration.get("provenance"), "baseline.configuration.provenance"
    )
    curr_provenance = require_object(
        curr_configuration.get("provenance"), "current.configuration.provenance"
    )
    base_host = selected_fields(
        base_provenance, NATIVE_STABLE_PROVENANCE, "baseline.configuration.provenance"
    )
    curr_host = selected_fields(
        curr_provenance, NATIVE_STABLE_PROVENANCE, "current.configuration.provenance"
    )
    base_oracle = require_object(
        baseline.get("correctness_scope"), "baseline.correctness_scope"
    )
    curr_oracle = require_object(
        current.get("correctness_scope"), "current.correctness_scope"
    )
    if base_settings != curr_settings:
        raise IncompatibleReports("native matrix proof or sampling settings differ")
    if base_host != curr_host:
        raise IncompatibleReports("native matrix OS/architecture/SIMD/threading settings differ")
    if base_oracle != curr_oracle:
        raise IncompatibleReports("native matrix correctness-oracle classification differs")

    baseline_rows = require_list(baseline.get("rows"), "baseline.rows")
    current_rows = require_list(current.get("rows"), "current.rows")
    if len(baseline_rows) != len(current_rows):
        raise IncompatibleReports("native matrix row counts differ")
    comparisons: list[dict[str, Any]] = []
    workload_keys: list[dict[str, Any]] = []
    oracle_binary_pairs: set[tuple[str, str]] = set()
    for index, (baseline_value, current_value) in enumerate(
        zip(baseline_rows, current_rows, strict=True)
    ):
        base_row = require_object(baseline_value, f"baseline.rows[{index}]")
        curr_row = require_object(current_value, f"current.rows[{index}]")
        descriptor = base_row.get("descriptor_sha256")
        if not isinstance(descriptor, str) or len(descriptor) != 64:
            raise DeltaError(f"baseline.rows[{index}].descriptor_sha256 is invalid")
        for field in ("index", "descriptor_sha256", "workload", "lane_order"):
            if base_row.get(field) != curr_row.get(field):
                raise IncompatibleReports(f"native workload descriptor/order differs at row {index}: {field}")
        for field in ("proof_digest_sha256", "proof_bytes"):
            if base_row.get(field) != curr_row.get(field):
                raise IncompatibleReports(
                    f"native proof identity differs at row {index}: {field}; "
                    "the workload semantics are not comparable"
                )
        base_rust = require_object(
            base_row.get("rust_oracle"), f"baseline.rows[{index}].rust_oracle"
        )
        curr_rust = require_object(
            curr_row.get("rust_oracle"), f"current.rows[{index}].rust_oracle"
        )
        for oracle, context in (
            (base_rust, "baseline"),
            (curr_rust, "current"),
        ):
            if oracle.get("verified") is not True or oracle.get("status") != "passed":
                raise IncompatibleReports(
                    f"{context} Rust oracle did not verify row {index}"
                )
        oracle_binary_pairs.add(oracle_binary_pair(base_rust, curr_rust, index))
        workload_key = {
            "descriptor_sha256": descriptor,
            "workload": base_row.get("workload"),
        }
        workload_keys.append(workload_key)
        evidence = native_row_evidence(base_row, curr_row, index)
        base_lanes = require_object(base_row.get("lanes"), f"baseline.rows[{index}].lanes")
        curr_lanes = require_object(curr_row.get("lanes"), f"current.rows[{index}].lanes")
        if set(base_lanes) != {"cpu", "metal"} or set(curr_lanes) != {"cpu", "metal"}:
            raise IncompatibleReports(f"native lanes must be exactly cpu and metal at row {index}")
        for lane_name in ("cpu", "metal"):
            base_lane = require_object(base_lanes[lane_name], f"baseline.rows[{index}].lanes.{lane_name}")
            curr_lane = require_object(curr_lanes[lane_name], f"current.rows[{index}].lanes.{lane_name}")
            if base_lane.get("backend") != curr_lane.get("backend"):
                raise IncompatibleReports(f"native backend identity differs at row {index}, lane {lane_name}")
            base_metrics = native_lane_metrics(base_lane, f"baseline.rows[{index}].lanes.{lane_name}")
            curr_metrics = native_lane_metrics(curr_lane, f"current.rows[{index}].lanes.{lane_name}")
            if set(base_metrics) != set(curr_metrics):
                raise IncompatibleReports(f"native metric keys differ at row {index}, lane {lane_name}")
            metrics = []
            for metric_name in sorted(base_metrics):
                unit, direction = native_metric_shape(metric_name)
                metrics.append(
                    metric_record(
                        metric_name,
                        unit,
                        direction,
                        base_metrics[metric_name]["median"],
                        curr_metrics[metric_name]["median"],
                    )
                )
                classify_native_metric(
                    metrics[-1],
                    base_metrics[metric_name]["mad"],
                    curr_metrics[metric_name]["mad"],
                    evidence["stable_for_claim"],
                )
            comparisons.append(
                {
                    "row_index": index,
                    "workload_key": workload_key,
                    "lane": lane_name,
                    "evidence": evidence,
                    "metrics": metrics,
                }
            )

    oracle_transition = classify_transition(
        oracle_binary_pairs,
        protocols,
        NATIVE_PROTOCOL_V4,
        NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6,
    )
    product_transition = product_identity_transition(baseline, current, protocols)

    identity = {
        "report_protocol": (
            baseline_protocol
            if baseline_protocol == current_protocol
            else f"{baseline_protocol}->{current_protocol}"
        ),
        "settings": base_settings,
        "host_execution": base_host,
        "correctness_scope": base_oracle,
        "oracle_binary_transition": oracle_transition,
        "product_identity_transition": product_transition,
        "ordered_workloads": workload_keys,
    }
    revisions = {
        "baseline": {
            "git_commit": base_provenance.get("git_commit"),
            "git_dirty": base_provenance.get("git_dirty"),
            "binaries": base_configuration.get("binaries"),
            "timeout_seconds": base_configuration.get("timeout_seconds"),
            "rust_oracle_binary_sha256": sorted(
                {
                    row["rust_oracle"]["binary_sha256"]
                    for row in baseline_rows
                }
            ),
            "product_receipts": product_receipt_revision(baseline),
        },
        "current": {
            "git_commit": curr_provenance.get("git_commit"),
            "git_dirty": curr_provenance.get("git_dirty"),
            "binaries": curr_configuration.get("binaries"),
            "timeout_seconds": curr_configuration.get("timeout_seconds"),
            "rust_oracle_binary_sha256": sorted(
                {
                    row["rust_oracle"]["binary_sha256"]
                    for row in current_rows
                }
            ),
            "product_receipts": product_receipt_revision(current),
        },
    }
    return identity, comparisons, revisions


def compare_reports(
    baseline_path: Path, current_path: Path, timestamp: str
) -> tuple[dict[str, Any], bytes, bytes]:
    baseline, baseline_raw, baseline_source = load_report(baseline_path, "baseline")
    current, current_raw, current_source = load_report(current_path, "current")
    document: dict[str, Any] = {
        "schema_version": DELTA_SCHEMA_VERSION,
        "protocol": DELTA_PROTOCOL,
        "generated_at": timestamp,
        "report_kind": (
            baseline["protocol"]
            if baseline["protocol"] == current["protocol"]
            else f"{baseline['protocol']}->{current['protocol']}"
        ),
        "sources": {"baseline": baseline_source, "current": current_source},
        "normalizations": [],
        "sequencing": SEQUENTIAL_DELTA_NOTE,
    }
    try:
        protocol_pair = (baseline["protocol"], current["protocol"])
        if (
            baseline["protocol"] != current["protocol"]
            and protocol_pair
            not in {
                (NATIVE_PROTOCOL_V4, NATIVE_PROTOCOL_V5),
                (NATIVE_PROTOCOL_V5, NATIVE_PROTOCOL_V6),
            }
        ):
            raise IncompatibleReports("benchmark report protocols differ")
        if baseline["protocol"] == UPSTREAM_PROTOCOL:
            identity, comparisons, revisions = compare_upstream(baseline, current)
        else:
            identity, comparisons, revisions = compare_native(baseline, current)
    except IncompatibleReports as error:
        document.update(
            {
                "status": "incomparable",
                "incompatibilities": [str(error)],
                "comparison_identity": None,
                "revisions": None,
                "comparisons": [],
                "comparison_summary": None,
            }
        )
        return document, baseline_raw, current_raw
    document.update(
        {
            "status": "comparable",
            "incompatibilities": [],
            "comparison_identity": {**identity, "sha256": digest_json(identity)},
            "revisions": revisions,
            "comparisons": comparisons,
            "comparison_summary": comparison_summary(comparisons),
        }
    )
    return document, baseline_raw, current_raw


def comparison_summary(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    rows: dict[int, bool] = {}
    for comparison in comparisons:
        evidence = comparison.get("evidence")
        if evidence is not None:
            rows[comparison["row_index"]] = evidence["stable_for_claim"]
    if not rows:
        return {
            "rows": len({comparison["row_index"] for comparison in comparisons}),
            "performance_claim_eligible_rows": None,
            "diagnostic_only_rows": [],
        }
    return {
        "rows": len(rows),
        "performance_claim_eligible_rows": sum(rows.values()),
        "diagnostic_only_rows": [index for index, eligible in rows.items() if not eligible],
    }


def parse_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DeltaError("timestamp must be ISO-8601 with a timezone") from error
    if parsed.tzinfo is None:
        raise DeltaError("timestamp must include a timezone")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument(
        "--timestamp",
        help="ISO-8601 output/archive timestamp; intended for reproducible automation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        timestamp = parse_timestamp(args.timestamp)
        document, baseline_raw, current_raw = compare_reports(
            args.baseline, args.current, timestamp
        )
        if args.archive_dir is not None:
            document["archive"] = update_archive(
                args.archive_dir, document, baseline_raw, current_raw
            )
        atomic_write(args.output, encoded_json(document))
    except (DeltaError, OSError) as error:
        print(f"benchmark delta failed: {error}", file=sys.stderr)
        return 1
    return 0 if document["status"] == "comparable" else 2
