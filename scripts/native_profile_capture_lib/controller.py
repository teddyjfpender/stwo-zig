"""Sequential six-example Native profiler capture controller."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.benchmark_product_contract_lib import build_receipt, validate_receipt
except ModuleNotFoundError:
    from benchmark_product_contract_lib import build_receipt, validate_receipt

if __package__.startswith("scripts."):
    from scripts.native_proof_matrix_lib.artifacts import (
        output_dir_lock,
        prepare_output_dir,
        require_binary,
        sha256_file,
    )
    from scripts.native_proof_matrix_lib.contract import validate_proof_artifact
    from scripts.native_proof_matrix_lib.model import (
        MatrixError,
        PROTOCOL_PRESETS,
        workload_descriptor_sha256,
    )
    from scripts.native_proof_matrix_lib.provenance import (
        collect_load,
        collect_static,
        validate_environment,
        validate_load,
    )
else:
    from native_proof_matrix_lib.artifacts import (
        output_dir_lock,
        prepare_output_dir,
        require_binary,
        sha256_file,
    )
    from native_proof_matrix_lib.contract import validate_proof_artifact
    from native_proof_matrix_lib.model import (
        MatrixError,
        PROTOCOL_PRESETS,
        workload_descriptor_sha256,
    )
    from native_proof_matrix_lib.provenance import (
        collect_load,
        collect_static,
        validate_environment,
        validate_load,
    )

from .contract import (
    validate_metal_profile,
    validate_profile_pair,
    validate_profile_report,
)
from .evidence import publish_manifest
from .model import PROFILE_WORKLOADS, CaptureError, CaptureSettings
from .runner import run_cpu, run_metal


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _lane_paths(execution: dict[str, Any], root: Path) -> dict[str, str]:
    names = {
        "stdout": "stdout_path",
        "stderr": "stderr_path",
        "proof_artifact": "proof_path",
    }
    if execution["lane"] == "cpu":
        names.update({
            "sample": "sample_path",
            "sample_stdout": "sample_stdout_path",
            "sample_stderr": "sample_stderr_path",
            "sample_summary": "sample_summary_path",
        })
    else:
        names.update({
            "metal_ndjson": "metal_profile_path",
            "metal_aggregate": "metal_aggregate_path",
            "aggregate_stdout": "aggregate_stdout_path",
            "aggregate_stderr": "aggregate_stderr_path",
        })
    return {name: _relative(execution[key], root) for name, key in names.items()}


def _lane_manifest(
    execution: dict[str, Any], root: Path, coverage: dict[str, Any]
) -> dict[str, Any]:
    document = {
        "product_identity": execution["report"]["product_identity"],
        "command": execution["command"],
        "environment": execution["environment"],
        "pid": execution["pid"],
        "process_wall_seconds": execution["process_wall_seconds"],
        "artifacts": _lane_paths(execution, root),
        "coverage": coverage,
        "proof": {
            "artifact_sha256": execution["proof_artifact"]["sha256"],
            "proof_sha256": execution["proof_artifact"]["proof_sha256"],
            "proof_bytes": execution["proof_artifact"]["proof_bytes"],
        },
    }
    if execution["lane"] == "cpu":
        document["sample_command"] = execution["sample_command"]
        document["sample_summary"] = execution["sample_summary"]
    else:
        document["counter_mode"] = execution["counter_mode"]
        document["aggregate_command"] = execution["aggregate_command"]
        document["metal_profile"] = execution["metal_profile_summary"]
    return document


def _product_receipts(
    *,
    settings: CaptureSettings,
    rows: list[dict[str, Any]],
    binary_hashes: dict[str, str],
    host_environment: dict[str, object],
) -> dict[str, dict[str, Any]]:
    receipts: dict[str, dict[str, Any]] = {}
    for lane in ("cpu", "metal"):
        identities = [row["lanes"][lane]["product_identity"] for row in rows]
        if not identities or any(identity != identities[0] for identity in identities[1:]):
            raise CaptureError(f"{lane} focused product identity changed during profiling")
        measurements = []
        for row in rows:
            workload = row["workload"]
            proof = row["lanes"][lane]["proof"]
            measurements.append({
                "workload": {
                    **workload,
                    "descriptor_sha256": row["descriptor_sha256"],
                },
                "numerator": {
                    "unit": workload["native_unit"],
                    "units": workload["native_units"],
                },
                "security_profile": PROTOCOL_PRESETS[settings.protocol],
                "timing_scope": {
                    "headline": None,
                    "diagnostic": "instrumented_verified_request",
                    "host_timers": row["lanes"][lane]["coverage"]["host_timer_scope"],
                    "gpu_timers": (
                        row["lanes"][lane].get("metal_profile")
                        if lane == "metal"
                        else None
                    ),
                },
                "cold_warm_state": {
                    "backend_initialization": "once_before_warmups",
                    "warmups_excluded": settings.warmups,
                    "measured_samples": settings.samples,
                    "sample_state": "profiled_post_warmup_diagnostic",
                    "metal_runtime": settings.metal_runtime
                    if lane == "metal"
                    else "not_applicable",
                },
                "proof_status": {
                    "local_verification": True,
                    "verified_samples": settings.samples,
                    "byte_identical_samples": True,
                    "cross_backend_canonical_equality": True,
                    "pinned_rust_stwo_verified": False,
                    "proof_sha256": proof["proof_sha256"],
                },
                "eligibility_status": {
                    "headline_eligible": False,
                    "stability_satisfied": False,
                    "evidence_class": "profiled_diagnostic",
                    "profiled": True,
                },
            })
        receipt = build_receipt(
            lane=lane,
            evidence_kind="profile",
            product_identity=identities[0],
            executable_sha256=binary_hashes[lane],
            measurement_policy={
                "execution": "bounded_sequential_cpu_then_metal",
                "proof_protocol": settings.protocol,
                "profiled_diagnostic": True,
                "headline_eligible": False,
                "every_measured_proof_locally_verified": True,
                "cross_backend_canonical_proof_equality": True,
                "final_correctness_oracle_checked": False,
            },
            host_device=host_environment,
            measurements=measurements,
            promotion_eligible=False,
        )
        validate_receipt(
            receipt,
            lane=lane,
            evidence_kind="profile",
            expected_identity=identities[0],
            expected_executable_sha256=binary_hashes[lane],
            expected_host_device=host_environment,
        )
        receipts[lane] = receipt
    return receipts


def _validate_settings(settings: CaptureSettings) -> tuple[Path, Path]:
    if settings.workloads != PROFILE_WORKLOADS:
        raise CaptureError("profiler acceptance requires the fixed six-example workload suite")
    names = tuple(workload.name for workload in settings.workloads)
    if len(names) != 6 or len(set(names)) != 6:
        raise CaptureError("profiler acceptance requires six distinct Native examples")
    if settings.encoder_counter_workload not in names:
        raise CaptureError("encoder-counter workload is not in the profiler suite")
    if settings.samples != 1:
        raise CaptureError("profiler acceptance requires exactly one diagnostic sample")
    return (
        require_binary(settings.cpu_bin, "CPU profiler"),
        require_binary(settings.metal_bin, "Metal profiler"),
    )


def _capture_locked(
    settings: CaptureSettings, cpu_binary: Path, metal_binary: Path, root: Path
) -> dict[str, Any]:
    host_environment = collect_static(settings.metal_runtime)
    load_start = collect_load()
    try:
        validate_environment(host_environment, settings.metal_runtime)
        validate_load(load_start)
    except ValueError as error:
        raise CaptureError(str(error)) from error
    binary_hashes = {
        "cpu": sha256_file(cpu_binary),
        "metal": sha256_file(metal_binary),
    }
    rows: list[dict[str, Any]] = []
    profile_provenance: dict[str, Any] | None = None
    total_lanes = len(settings.workloads) * 2
    completed_lanes = 0
    targeted_counter_rows = 0

    for index, workload in enumerate(settings.workloads):
        row_dir = root / f"row-{index:02d}-{workload.slug}"
        cpu = run_cpu(cpu_binary, workload, settings, row_dir / "cpu")
        completed_lanes += 1
        if settings.cooldown_seconds and completed_lanes < total_lanes:
            time.sleep(settings.cooldown_seconds)
        counter_mode = (
            "encoder-timestamps"
            if workload.name == settings.encoder_counter_workload
            else "command-only"
        )
        targeted_counter_rows += int(counter_mode == "encoder-timestamps")
        metal = run_metal(
            metal_binary,
            workload,
            settings,
            row_dir / "metal",
            counter_mode=counter_mode,
        )
        completed_lanes += 1
        if settings.cooldown_seconds and completed_lanes < total_lanes:
            time.sleep(settings.cooldown_seconds)
        if sha256_file(cpu_binary) != binary_hashes["cpu"] or sha256_file(metal_binary) != binary_hashes["metal"]:
            raise CaptureError("profile binary changed during the capture")

        try:
            cpu_fingerprint, cpu_coverage = validate_profile_report(
                cpu["report"], "cpu", workload, settings
            )
            metal_fingerprint, metal_coverage = validate_profile_report(
                metal["report"], "metal", workload, settings
            )
            validate_proof_artifact(
                cpu["report"], "cpu", workload, settings, cpu["proof_artifact"], cpu_fingerprint
            )
            validate_proof_artifact(
                metal["report"], "metal", workload, settings, metal["proof_artifact"], metal_fingerprint
            )
            validate_profile_pair(
                cpu["report"], metal["report"], cpu_fingerprint, metal_fingerprint
            )
        except MatrixError as error:
            raise CaptureError(str(error)) from error
        if cpu["proof_artifact"]["document"]["proof_bytes_hex"] != metal["proof_artifact"]["document"]["proof_bytes_hex"]:
            raise CaptureError("CPU and Metal canonical proof bytes differ")

        backend_dispatches = metal_coverage["metal_backend"]["total_metal_dispatches"]
        metal["metal_profile_summary"] = validate_metal_profile(
            metal["metal_profile_path"],
            metal["metal_aggregate_path"],
            mode=counter_mode,
            expected_pid=metal["pid"],
            backend_dispatches=backend_dispatches,
        )
        provenance = cpu["report"]["provenance"]
        if profile_provenance is None:
            profile_provenance = provenance
        elif provenance != profile_provenance or metal["report"]["provenance"] != provenance:
            raise CaptureError("profile provenance changed between lanes")
        rows.append({
            "workload": workload.report_dict(),
            "descriptor_sha256": workload_descriptor_sha256(workload, settings.protocol),
            "lanes": {
                "cpu": _lane_manifest(cpu, root, cpu_coverage),
                "metal": _lane_manifest(metal, root, metal_coverage),
            },
        })

    if targeted_counter_rows != 1:
        raise CaptureError("profiler suite must contain exactly one targeted encoder-counter row")
    assert profile_provenance is not None
    load_end = collect_load()
    try:
        validate_load(load_end)
    except ValueError as error:
        raise CaptureError(str(error)) from error
    receipts = _product_receipts(
        settings=settings,
        rows=rows,
        binary_hashes=binary_hashes,
        host_environment=host_environment,
    )
    manifest = {
        "schema_version": 2,
        "protocol": "native_profiler_baseline_v2",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "evidence_policy": {
            "evidence_class": "profiled_diagnostic",
            "headline_eligible": False,
            "timing_scope": "instrumented diagnostic; never substitute for unprofiled benchmark MHz",
            "execution": "bounded sequential CPU then Metal per workload",
            "proof_acceptance": "local verification plus CPU/Metal canonical-byte parity",
        },
        "reproduction": {
            "controller_command": settings.controller_command,
            "working_directory": str(Path.cwd().resolve()),
            "protocol": settings.protocol,
            "resource_profile": settings.resource_profile,
            "warmups": settings.warmups,
            "samples": settings.samples,
            "sample_duration_seconds": settings.sample_duration_seconds,
            "cooldown_seconds": settings.cooldown_seconds,
            "timeout_seconds": settings.timeout_seconds,
            "encoder_counter_workload": settings.encoder_counter_workload,
            "metal_max_encoders": settings.metal_max_encoders,
            "blake2_backend": settings.blake2_backend,
            "metal_runtime": settings.metal_runtime,
        },
        "host_environment": host_environment,
        "host_load": {
            "start": load_start,
            "end": load_end,
        },
        "binaries": {
            "cpu": {"path": str(cpu_binary), "sha256": binary_hashes["cpu"]},
            "metal": {"path": str(metal_binary), "sha256": binary_hashes["metal"]},
        },
        "source_provenance": profile_provenance,
        "product_receipts": receipts,
        "workload_order": [workload.report_dict() for workload in settings.workloads],
        "rows": rows,
    }
    return publish_manifest(root, manifest)


def run_capture(settings: CaptureSettings) -> dict[str, Any]:
    cpu_binary, metal_binary = _validate_settings(settings)
    root = settings.output_dir.resolve()
    with output_dir_lock(root):
        prepare_output_dir(root)
        return _capture_locked(settings, cpu_binary, metal_binary, root)
