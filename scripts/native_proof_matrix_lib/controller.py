"""Sequential alternating-lane orchestration for Native proof matrices."""

from __future__ import annotations

import argparse
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.benchmark_product_contract_lib import (
        MIN_PROMOTION_WARMUPS,
        build_receipt,
        validate_receipt,
    )
except ModuleNotFoundError:
    from benchmark_product_contract_lib import (
        MIN_PROMOTION_WARMUPS,
        build_receipt,
        validate_receipt,
    )

from .artifacts import (
    atomic_write_json,
    host_measurement_lock,
    output_dir_lock,
    prepare_output_dir,
    preflight_rust_oracle_adapter,
    require_binary,
    require_unprofiled_environment,
    run_lane,
    run_rust_oracle,
    sha256_file,
)
from .contract import validate_pair, validate_proof_artifact, validate_report
from .evidence import (
    MIN_FORMAL_MEASURED_PROOFS,
    SUMMARY_PROTOCOL,
    SUMMARY_SCHEMA_VERSION,
    stability_evidence,
    validate_process_resources,
    validate_rust_oracle_receipt,
    validate_stability,
)
from .model import (
    LANES,
    MAX_LOG_ROWS,
    MAX_MATRIX_ROWS,
    MAX_SEQUENCE_LEN,
    MAX_SAMPLES,
    MAX_TOTAL_REQUEST_CELLS,
    MAX_WARMUPS,
    MatrixError,
    PROTOCOL_PRESETS,
    Workload,
)
from .provenance import collect_load, collect_static, validate_environment, validate_load
from .resource_admission import (
    ACCOUNTED_BYTES_PER_COMMITTED_CELL,
    resource_limits,
)


def numeric_summary(values: list[float]) -> dict[str, float]:
    median = statistics.median(values)
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "mad": statistics.median([abs(value - median) for value in values]),
    }


def lane_metrics(
    report: dict[str, Any],
    workload: Workload,
    resources: dict[str, Any],
) -> dict[str, dict[str, float]]:
    samples = report["timing"]["samples"]
    metrics = {
        field: numeric_summary([float(sample[field]) for sample in samples])
        for field in (
            "input_seconds",
            "prove_seconds",
            "proof_encode_seconds",
            "verify_seconds",
            "request_seconds",
            "native_mhz",
            "request_native_mhz",
            "trace_row_mhz",
            "request_trace_row_mhz",
            "committed_mcells_per_second",
        )
    }
    metrics["backend_init_seconds"] = numeric_summary(
        [float(report["timing"]["backend_init_seconds"])]
    )
    metrics["peak_rss_kib"] = numeric_summary([float(resources["peak_rss_kib"])])
    return metrics


def comparison_metrics(
    cpu: dict[str, dict[str, float]],
    metal: dict[str, dict[str, float]],
) -> dict[str, float]:
    return {
        "metal_prove_time_speedup": (
            cpu["prove_seconds"]["median"] / metal["prove_seconds"]["median"]
        ),
        "metal_request_time_speedup": (
            cpu["request_seconds"]["median"] / metal["request_seconds"]["median"]
        ),
        "metal_native_mhz_speedup": (
            metal["native_mhz"]["median"] / cpu["native_mhz"]["median"]
        ),
        "metal_request_native_mhz_speedup": (
            metal["request_native_mhz"]["median"] / cpu["request_native_mhz"]["median"]
        ),
        "metal_trace_row_mhz_speedup": (
            metal["trace_row_mhz"]["median"] / cpu["trace_row_mhz"]["median"]
        ),
        "metal_request_trace_row_mhz_speedup": (
            metal["request_trace_row_mhz"]["median"]
            / cpu["request_trace_row_mhz"]["median"]
        ),
        "metal_committed_mcells_speedup": (
            metal["committed_mcells_per_second"]["median"]
            / cpu["committed_mcells_per_second"]["median"]
        ),
    }


def relative_to_output(path: Path, output_dir: Path) -> str:
    return str(path.relative_to(output_dir))


def summarize_lane(
    execution: dict[str, Any],
    output_dir: Path,
    fingerprint: tuple[str, int],
    workload: Workload,
) -> dict[str, Any]:
    report = execution["report"]
    artifact = execution["proof_artifact"]
    resources = validate_process_resources(
        execution.get("resources"), f"{execution['lane']}.resources"
    )
    return {
        "display_name": "Zig CPU/SIMD" if execution["lane"] == "cpu" else "Zig Metal",
        "product_identity": report["product_identity"],
        "backend": report["backend"],
        "evidence_class": report["evidence_class"],
        "profiled": report["profiled"],
        "command": execution["command"],
        "process_wall_seconds": execution["process_wall_seconds"],
        "stdout_artifact": relative_to_output(execution["stdout_path"], output_dir),
        "stdout_sha256": sha256_file(execution["stdout_path"]),
        "stderr_artifact": relative_to_output(execution["stderr_path"], output_dir),
        "stderr_sha256": sha256_file(execution["stderr_path"]),
        "proof": {
            "sha256": fingerprint[0],
            "bytes": fingerprint[1],
            "verified_samples": report["proof"]["verified_samples"],
            "all_samples_byte_identical": report["proof"]["all_samples_byte_identical"],
        },
        "proof_artifact": {
            "path": relative_to_output(artifact["path"], output_dir),
            "bytes": artifact["bytes"],
            "sha256": artifact["sha256"],
            "proof_bytes": artifact["proof_bytes"],
            "proof_sha256": artifact["proof_sha256"],
        },
        "metrics": lane_metrics(report, workload, resources),
        "resources": resources,
        "request_resources": report["resources"],
        "session": report["session"],
        "backend_telemetry": report.get("backend_telemetry"),
    }


def product_receipts(
    *,
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    binary_hashes: dict[str, str],
    host_environment: dict[str, object],
    formal_ready: bool,
) -> dict[str, dict[str, Any]]:
    receipts: dict[str, dict[str, Any]] = {}
    for lane in LANES:
        identities = [row["lanes"][lane]["product_identity"] for row in rows]
        if not identities or any(identity != identities[0] for identity in identities[1:]):
            raise MatrixError(f"{lane} focused product identity changed between rows")
        measurements = []
        for row in rows:
            workload = row["workload"]
            lane_summary = row["lanes"][lane]
            measurements.append({
                "workload": {
                    **workload,
                    "descriptor_sha256": row["descriptor_sha256"],
                },
                "numerator": {
                    "unit": workload["native_unit"],
                    "units": workload["native_units"],
                },
                "security_profile": PROTOCOL_PRESETS[args.protocol],
                "timing_scope": {
                    "headline": "prove_seconds",
                    "total": "request_seconds",
                    "included": [
                        "input_seconds",
                        "prove_seconds",
                        "proof_encode_seconds",
                        "verify_seconds",
                    ],
                    "backend_init": "reported_separately",
                },
                "cold_warm_state": {
                    "backend_initialization": "once_before_warmups",
                    "warmups_excluded": args.warmups,
                    "measured_samples": args.samples,
                    "sample_state": "post_warmup",
                    "metal_runtime": getattr(args, "metal_runtime", "source-jit")
                    if lane == "metal"
                    else "not_applicable",
                },
                "proof_status": {
                    "local_verification": True,
                    "verified_samples": lane_summary["proof"]["verified_samples"],
                    "byte_identical_samples": lane_summary["proof"][
                        "all_samples_byte_identical"
                    ],
                    "cross_backend_canonical_equality": row["proof_parity"],
                    "pinned_rust_stwo_verified": (
                        row["rust_oracle"] is not None
                        and row["rust_oracle"]["verified"] is True
                    ),
                    "proof_sha256": row["proof_digest_sha256"],
                },
                "eligibility_status": {
                    "headline_eligible": row["headline_eligible"],
                    "stability_satisfied": row["stability"]["satisfied"],
                    "evidence_class": lane_summary["evidence_class"],
                    "profiled": lane_summary["profiled"],
                },
            })
        receipt = build_receipt(
            lane=lane,
            evidence_kind="benchmark",
            product_identity=identities[0],
            executable_sha256=binary_hashes[lane],
            measurement_policy={
                "execution": "sequential_alternating_lane_order",
                "proof_protocol": args.protocol,
                "formal": args.formal,
                "profiled": False,
                "final_correctness_oracle": "pinned Rust Stwo",
                "minimum_excluded_warmups": MIN_PROMOTION_WARMUPS,
                "minimum_verified_samples": MIN_FORMAL_MEASURED_PROOFS,
                "every_measured_proof_locally_verified": True,
                "cross_backend_canonical_proof_equality": True,
            },
            host_device=host_environment,
            measurements=measurements,
            promotion_eligible=formal_ready,
        )
        validate_receipt(
            receipt,
            lane=lane,
            evidence_kind="benchmark",
            expected_identity=identities[0],
            expected_executable_sha256=binary_hashes[lane],
            expected_host_device=host_environment,
        )
        receipts[lane] = receipt
    return receipts


def run_matrix(args: argparse.Namespace) -> dict[str, Any]:
    require_unprofiled_environment(os.environ)
    rust_oracle = (
        require_binary(args.rust_oracle_bin, "Rust oracle")
        if args.rust_oracle_bin is not None else None
    )
    if rust_oracle is not None:
        preflight_rust_oracle_adapter(rust_oracle, args.timeout_seconds)
    binaries = {
        "cpu": require_binary(args.cpu_bin, "cpu"),
        "metal": require_binary(args.metal_bin, "metal"),
    }
    binary_hashes = {lane: sha256_file(binary) for lane, binary in binaries.items()}
    metal_runtime = getattr(args, "metal_runtime", "source-jit")
    output_dir = args.output_dir.resolve()
    with host_measurement_lock(Path.cwd()):
        host_environment = collect_static(metal_runtime)
        try:
            validate_environment(host_environment, metal_runtime)
        except ValueError as error:
            raise MatrixError(str(error)) from error
        load_start = collect_load()
        try:
            validate_load(load_start)
        except ValueError as error:
            raise MatrixError(str(error)) from error
        with output_dir_lock(output_dir):
            prepare_output_dir(output_dir)
            return _run_matrix_locked(
                args,
                binaries,
                binary_hashes,
                output_dir,
                rust_oracle,
                host_environment,
                load_start,
            )


def _run_matrix_locked(
    args: argparse.Namespace,
    binaries: dict[str, Path],
    binary_hashes: dict[str, str],
    output_dir: Path,
    rust_oracle: Path | None,
    host_environment: dict[str, object],
    load_start: dict[str, object],
) -> dict[str, Any]:
    resource_profile = getattr(args, "resource_profile", "standard")
    admission_limits = resource_limits(resource_profile)
    max_total_request_cells = (
        MAX_TOTAL_REQUEST_CELLS
        if resource_profile == "standard"
        else admission_limits.max_committed_cells
        * len(LANES)
        * (MAX_WARMUPS + MAX_SAMPLES)
    )
    total_lanes = len(args.workloads) * len(LANES)
    completed_lanes = 0
    result_rows: list[dict[str, Any]] = []
    matrix_provenance: dict[str, Any] | None = None

    for row_index, workload in enumerate(args.workloads):
        lane_order = list(LANES if row_index % 2 == 0 else reversed(LANES))
        artifact_dir = output_dir / f"row-{row_index:03d}-{workload.slug}"
        executions: dict[str, dict[str, Any]] = {}
        for lane in lane_order:
            executions[lane] = run_lane(
                lane,
                binaries[lane],
                workload,
                args,
                artifact_dir,
            )
            if sha256_file(binaries[lane]) != binary_hashes[lane]:
                raise MatrixError(f"{lane} benchmark binary changed during the matrix")
            completed_lanes += 1
            if args.cooldown_seconds > 0 and completed_lanes < total_lanes:
                time.sleep(args.cooldown_seconds)

        fingerprints: dict[str, tuple[str, int]] = {}
        blockers: list[str] = []
        for lane in LANES:
            fingerprint, lane_blockers = validate_report(
                executions[lane]["report"],
                lane,
                workload,
                args,
            )
            fingerprints[lane] = fingerprint
            blockers.extend(lane_blockers)
            validate_proof_artifact(
                executions[lane]["report"],
                lane,
                workload,
                args,
                executions[lane]["proof_artifact"],
                fingerprint,
            )
        validate_pair(
            executions["cpu"]["report"],
            executions["metal"]["report"],
            fingerprints["cpu"],
            fingerprints["metal"],
        )
        if (
            executions["cpu"]["proof_artifact"]["document"]["proof_bytes_hex"]
            != executions["metal"]["proof_artifact"]["document"]["proof_bytes_hex"]
        ):
            raise MatrixError("CPU and Metal canonical proof bytes differ")
        oracle_evidence = (
            run_rust_oracle(
                rust_oracle,
                executions["cpu"]["proof_artifact"]["path"],
                args.timeout_seconds,
            )
            if rust_oracle is not None
            else None
        )
        if oracle_evidence is not None:
            validate_rust_oracle_receipt(
                oracle_evidence,
                rust_oracle,
                executions["cpu"]["proof_artifact"],
            )
        row_provenance = executions["cpu"]["report"]["provenance"]
        if matrix_provenance is None:
            matrix_provenance = row_provenance
        elif row_provenance != matrix_provenance:
            raise MatrixError("provenance tuple changed between matrix rows")

        lane_summaries = {
            lane: summarize_lane(
                executions[lane],
                output_dir,
                fingerprints[lane],
                workload,
            )
            for lane in LANES
        }
        unique_blockers = sorted(set(blockers))
        stability = stability_evidence(
            executions["cpu"]["report"], executions["metal"]["report"]
        )
        validate_stability(stability, f"row[{row_index}].stability")
        result_rows.append(
            {
                "index": row_index,
                "workload": workload.report_dict(),
                "descriptor_sha256": executions["cpu"]["report"]["workload"]["descriptor_sha256"],
                "lane_order": lane_order,
                "proof_digest_sha256": fingerprints["cpu"][0],
                "proof_bytes": fingerprints["cpu"][1],
                "proof_parity": True,
                "rust_oracle": oracle_evidence,
                "stability": stability,
                "headline_eligible": not unique_blockers,
                "headline_blockers": unique_blockers,
                "lanes": lane_summaries,
                "speedup": comparison_metrics(
                    lane_summaries["cpu"]["metrics"],
                    lane_summaries["metal"]["metrics"],
                ),
            }
        )

    all_rust_oracles_verified = bool(result_rows) and all(
        row["rust_oracle"] is not None
        and row["rust_oracle"]["verified"] is True
        and row["rust_oracle"]["status"] == "passed"
        for row in result_rows
    )
    all_rows_stable = bool(result_rows) and all(
        row["stability"]["satisfied"] for row in result_rows
    )
    if args.formal and not all_rust_oracles_verified:
        raise MatrixError("formal matrix is missing a verified Rust receipt")
    if args.formal and not all_rows_stable:
        raise MatrixError("formal matrix did not satisfy measured-proof stability")

    all_rows_headline = bool(result_rows) and all(
        row["headline_eligible"] for row in result_rows
    )

    load_end = collect_load()
    try:
        validate_load(load_end)
    except ValueError as error:
        raise MatrixError(str(error)) from error

    receipts = product_receipts(
        args=args,
        rows=result_rows,
        binary_hashes=binary_hashes,
        host_environment=host_environment,
        formal_ready=(
            args.formal
            and all_rust_oracles_verified
            and all_rows_stable
            and all_rows_headline
        ),
    )
    document = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "protocol": SUMMARY_PROTOCOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "correctness_scope": {
            "classification": (
                "pinned_rust_stwo_oracle"
                if all_rust_oracles_verified
                else "zig_cross_backend_parity"
            ),
            "cpu_metal_canonical_proof_equality": True,
            "pinned_rust_stwo_oracle_checked": all_rust_oracles_verified,
            "final_correctness_oracle": "pinned Rust Stwo",
        },
        "configuration": {
            "proof_protocol": args.protocol,
            "resource_profile": resource_profile,
            "blake2_backend": getattr(args, "blake2_backend", "auto"),
            "metal_runtime": getattr(args, "metal_runtime", "source-jit"),
            "metal_aot_manifest_sha256": getattr(
                args, "metal_aot_manifest_sha256", None
            ),
            "warmups_per_lane": args.warmups,
            "samples_per_lane": args.samples,
            "cooldown_seconds": args.cooldown_seconds,
            "timeout_seconds": args.timeout_seconds,
            "execution": "sequential_alternating_lane_order",
            "formal": args.formal,
            "stability_contract": {
                "minimum_measured_verified_proofs_per_lane": MIN_FORMAL_MEASURED_PROOFS,
            },
            "bounds": {
                "max_matrix_rows": MAX_MATRIX_ROWS,
                "max_log_rows": MAX_LOG_ROWS,
                "max_sequence_len": MAX_SEQUENCE_LEN,
                "accounted_bytes_per_committed_cell": ACCOUNTED_BYTES_PER_COMMITTED_CELL,
                "max_committed_trace_cells_per_row": admission_limits.max_committed_cells,
                "max_accounted_bytes_per_row": admission_limits.max_accounted_bytes,
                "max_total_request_cells": max_total_request_cells,
            },
            "binaries": {
                lane: {"path": str(binary), "sha256": binary_hashes[lane]}
                for lane, binary in binaries.items()
            },
            "provenance": matrix_provenance,
            "host_environment": host_environment,
            "host_load": {
                "start": load_start,
                "end": load_end,
            },
        },
        "summary": {
            "rows": len(result_rows),
            "headline_rows": sum(row["headline_eligible"] for row in result_rows),
            "all_rows_headline_eligible": all(
                row["headline_eligible"] for row in result_rows
            ),
            "all_proofs_verified_and_byte_identical": True,
            "all_cross_backend_proofs_identical": True,
            "all_rust_oracles_verified": all_rust_oracles_verified,
            "all_rows_meet_stability_contract": all_rows_stable,
        },
        "product_receipts": receipts,
        "rows": result_rows,
    }
    atomic_write_json(output_dir / "summary.json", document)
    return document
