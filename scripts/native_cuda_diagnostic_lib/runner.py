"""Sequential cold-process runner for the isolated Native CUDA product."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.process_resources_lib import (
        ResourceMeasurementError,
        measurement_command,
        measurement_environment,
        parse_process_resources,
    )
except ModuleNotFoundError:
    from process_resources_lib import (  # type: ignore[no-redef]
        ResourceMeasurementError,
        measurement_command,
        measurement_environment,
        parse_process_resources,
    )

from .contract import require_finite_positive, validate_artifact, validate_report
from .model import (
    EVIDENCE_CLASS,
    MAX_REPORT_BYTES,
    MAX_STDERR_BYTES,
    PROTOCOL,
    SCHEMA,
    DiagnosticError,
    Settings,
    Shape,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_binary(path: Path) -> Path:
    binary = path.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise DiagnosticError(f"CUDA product is not executable: {binary}")
    return binary


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise DiagnosticError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _summary(values: list[float]) -> dict[str, float]:
    median = statistics.median(values)
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "mad": statistics.median(abs(value - median) for value in values),
    }


def _write_exclusive(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise DiagnosticError(f"refusing to overwrite diagnostic output: {path}") from error


def _decode_stdout(stdout: bytes) -> dict[str, Any]:
    if len(stdout) > MAX_REPORT_BYTES:
        raise DiagnosticError("CUDA product stdout exceeds the report bound")
    try:
        report = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError(
            "CUDA product stdout is not one valid JSON document"
        ) from error
    if not isinstance(report, dict):
        raise DiagnosticError("CUDA product stdout root must be an object")
    return report


def _command(binary: Path, shape: Shape, proof: Path, report: Path) -> list[str]:
    return [
        str(binary),
        "prove",
        "--air",
        "wide_fibonacci",
        "--backend",
        "cuda",
        "--protocol",
        PROTOCOL,
        "--log-n-rows",
        str(shape.log_n_rows),
        "--sequence-len",
        str(shape.sequence_len),
        "--output",
        str(proof),
        "--report-out",
        str(report),
        "--repeat",
        "1",
    ]


def _run_sample(
    settings: Settings,
    binary: Path,
    shape: Shape,
    sample_index: int,
) -> dict[str, Any]:
    sample_dir = settings.artifact_root / shape.slug / f"sample-{sample_index:03d}"
    sample_dir.mkdir(parents=True)
    proof_path = sample_dir / "proof-artifact.json"
    report_path = sample_dir / "product-report.json"
    stderr_path = sample_dir / "process.stderr.txt"
    command = _command(binary, shape, proof_path, report_path)
    measured, resource_measurement = measurement_command(command, required=True)
    environment = measurement_environment(
        {"CUDA_VISIBLE_DEVICES": settings.device_ordinal}
    )
    started_ns = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            measured,
            cwd=settings.repo_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=settings.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DiagnosticError(
            f"{shape.slug} sample {sample_index} timed out after "
            f"{settings.timeout_seconds} seconds"
        ) from error
    external_wall_ns = time.perf_counter_ns() - started_ns
    if len(completed.stderr) > MAX_STDERR_BYTES:
        raise DiagnosticError("CUDA product stderr exceeds the capture bound")
    _write_exclusive(stderr_path, completed.stderr)
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise DiagnosticError(
            f"{shape.slug} sample {sample_index} exited "
            f"{completed.returncode}; stderr tail:\n{tail}"
        )

    report = _decode_stdout(completed.stdout)
    try:
        with report_path.open("rb") as source:
            report_file = source.read(MAX_REPORT_BYTES + 1)
    except FileNotFoundError as error:
        raise DiagnosticError("CUDA product did not persist its report") from error
    if len(report_file) > MAX_REPORT_BYTES:
        raise DiagnosticError("CUDA persisted report exceeds the report bound")
    if report_file.strip() != completed.stdout.strip():
        raise DiagnosticError("CUDA persisted report differs from stdout")
    artifact = validate_artifact(proof_path, shape)
    validated = validate_report(report, shape, proof_path, artifact)
    try:
        resources = parse_process_resources(
            completed.stderr,
            resource_measurement,
            require_peak_rss=True,
        )
    except ResourceMeasurementError as error:
        raise DiagnosticError(str(error)) from error

    wall_seconds = require_finite_positive(
        external_wall_ns / 1_000_000_000.0,
        "CUDA external wall time",
    )
    return {
        "sample_index": sample_index,
        "command": command,
        "external_wall_ns": external_wall_ns,
        "process_resources": resources,
        "proof": {
            **artifact,
            "canonical_bytes": validated["proof"]["canonical_bytes"],
            "canonical_sha256": validated["proof"]["canonical_sha256"],
        },
        "plan": validated["plan"],
        "timing_ns": validated["timing_ns"],
        "process_repetition": validated["process_repetition"],
        "throughput": {
            "resident_trace_row_mhz": validated["resident_trace_row_mhz"],
            "resident_committed_mcells_per_second": validated[
                "resident_committed_mcells_per_second"
            ],
            "cold_external_trace_row_mhz": shape.trace_rows
            / wall_seconds
            / 1_000_000.0,
            "cold_external_committed_mcells_per_second": shape.trace_cells
            / wall_seconds
            / 1_000_000.0,
        },
        "residency": validated["residency"],
        "device_stage_timing_ns": validated["device_stage_timing_ns"],
        "aot": validated["aot"],
        "device": validated["device"],
        "raw_report_sha256": hashlib.sha256(report_file).hexdigest(),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def _shape_result(shape: Shape, samples: list[dict[str, Any]]) -> dict[str, Any]:
    proof_identities = {
        (sample["proof"]["canonical_sha256"], sample["proof"]["canonical_bytes"])
        for sample in samples
    }
    if len(proof_identities) != 1:
        raise DiagnosticError(f"{shape.slug} proof identity changed between samples")
    identity = next(iter(proof_identities))
    metric_paths = {
        "external_wall_ms": [
            sample["external_wall_ns"] / 1_000_000.0 for sample in samples
        ],
        "resident_prove_ms": [
            sample["timing_ns"]["resident_prove"] / 1_000_000.0
            for sample in samples
        ],
        "runtime_init_ms": [
            sample["timing_ns"]["runtime_init"] / 1_000_000.0
            for sample in samples
        ],
        "shape_prepare_ms": [
            sample["timing_ns"]["shape_prepare"] / 1_000_000.0
            for sample in samples
        ],
        "verified_request_ms": [
            sample["timing_ns"]["verified_request"] / 1_000_000.0
            for sample in samples
        ],
        "independent_verification_ms": [
            sample["timing_ns"]["independent_verification"] / 1_000_000.0
            for sample in samples
        ],
        "runtime_teardown_ms": [
            sample["timing_ns"]["runtime_teardown"] / 1_000_000.0
            for sample in samples
        ],
        "total_before_publication_ms": [
            sample["timing_ns"]["total_before_publication"] / 1_000_000.0
            for sample in samples
        ],
        "resident_trace_row_mhz": [
            sample["throughput"]["resident_trace_row_mhz"] for sample in samples
        ],
        "resident_committed_mcells_per_second": [
            sample["throughput"]["resident_committed_mcells_per_second"]
            for sample in samples
        ],
        "cold_external_trace_row_mhz": [
            sample["throughput"]["cold_external_trace_row_mhz"]
            for sample in samples
        ],
        "cold_external_committed_mcells_per_second": [
            sample["throughput"]["cold_external_committed_mcells_per_second"]
            for sample in samples
        ],
        "peak_rss_kib": [
            float(sample["process_resources"]["peak_rss_kib"])
            for sample in samples
        ],
        "device_peak_live_bytes": [
            float(sample["residency"]["peak_live_bytes"]) for sample in samples
        ],
        "device_pool_reserved_bytes": [
            float(sample["residency"]["pool_reserved_bytes"]) for sample in samples
        ],
        "h2d_bytes": [
            float(sample["residency"]["h2d_bytes"]) for sample in samples
        ],
        "d2d_bytes": [
            float(sample["residency"]["d2d_bytes"]) for sample in samples
        ],
        "terminal_d2h_bytes": [
            float(sample["residency"]["terminal_d2h_bytes"])
            for sample in samples
        ],
        "kernel_launches": [
            float(sample["residency"]["kernel_launches"]) for sample in samples
        ],
        "graph_launches": [
            float(sample["residency"]["graph_launches"]) for sample in samples
        ],
        "sync_calls": [
            float(sample["residency"]["sync_calls"]) for sample in samples
        ],
    }
    for stage in (
        "ingress",
        "trace_generation",
        "trace_commit",
        "constraint_evaluation",
        "oods",
        "quotient",
        "fri_commit",
        "pow",
        "decommit",
        "proof_assembly",
        "total",
    ):
        metric_paths[f"device_stage_{stage}_ms"] = [
            sample["device_stage_timing_ns"][stage] / 1_000_000.0
            for sample in samples
        ]
    return {
        "shape_id": shape.slug,
        "statement": shape.statement(),
        "cold_samples": len(samples),
        "proof_identity": {
            "canonical_sha256": identity[0],
            "canonical_bytes": identity[1],
            "all_samples_identical": True,
        },
        "metrics": {
            name: _summary(values) for name, values in metric_paths.items()
        },
        "samples": samples,
    }


def _require_stable_platform(workloads: list[dict[str, Any]]) -> tuple[dict, str]:
    devices: set[str] = set()
    build_identities: set[str] = set()
    for workload in workloads:
        for sample in workload["samples"]:
            devices.add(json.dumps(sample["device"], sort_keys=True))
            build_identities.add(sample["aot"]["build_identity_sha256"])
    if len(devices) != 1:
        raise DiagnosticError("CUDA device identity changed during the diagnostic")
    if len(build_identities) != 1:
        raise DiagnosticError("CUDA AOT build identity changed during the diagnostic")
    return json.loads(next(iter(devices))), next(iter(build_identities))


def run_diagnostic(settings: Settings) -> tuple[dict[str, Any], bytes]:
    settings.validate()
    binary = _require_binary(settings.product_bin)
    binary_sha256 = sha256_file(binary)
    if settings.output_path.exists():
        raise DiagnosticError(
            f"refusing to overwrite diagnostic output: {settings.output_path}"
        )
    if settings.artifact_root.exists():
        raise DiagnosticError(
            f"refusing to overwrite diagnostic artifacts: {settings.artifact_root}"
        )
    settings.artifact_root.mkdir(parents=True)

    commit = _git(settings.repo_root, "rev-parse", "HEAD")
    dirty = bool(
        _git(settings.repo_root, "status", "--porcelain", "--untracked-files=no")
    )
    workloads: list[dict[str, Any]] = []
    total_samples = len(settings.shapes) * settings.cold_samples
    completed_samples = 0
    for shape in settings.shapes:
        samples: list[dict[str, Any]] = []
        for sample_index in range(settings.cold_samples):
            samples.append(_run_sample(settings, binary, shape, sample_index))
            completed_samples += 1
            if (
                settings.cooldown_seconds > 0
                and completed_samples < total_samples
            ):
                time.sleep(settings.cooldown_seconds)
        workloads.append(_shape_result(shape, samples))

    if sha256_file(binary) != binary_sha256:
        raise DiagnosticError("CUDA product executable changed during the diagnostic")
    device, build_identity = _require_stable_platform(workloads)
    document = {
        "schema": SCHEMA,
        "evidence_class": EVIDENCE_CLASS,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "headline_eligible": False,
        "measurement_contract": {
            "execution": "sequential_fixed_order",
            "cold_process_per_sample": True,
            "warm_request_measured": False,
            "shape_plan_measured": True,
            "warmups": 0,
            "samples_per_shape": settings.cold_samples,
            "cooldown_seconds": settings.cooldown_seconds,
            "timeout_seconds": settings.timeout_seconds,
            "protocol": PROTOCOL,
            "throughput_denominators": {
                "trace_row_mhz": "trace_rows / elapsed_seconds / 1e6",
                "committed_mcells_per_second": (
                    "trace_rows * sequence_len / elapsed_seconds / 1e6"
                ),
                "resident_elapsed": "product timing_ns.resident_prove",
                "cold_external_elapsed": (
                    "controller wall around the resource-measured product process"
                ),
            },
            "limitations": [
                "diagnostic evidence only; never headline or promotion evidence",
                "every sample is a fresh process; no warm-request timing is claimed",
                "no CPU or Metal speedup is inferred by this CUDA-only runner",
            ],
        },
        "provenance": {
            "git_commit": commit,
            "git_dirty": dirty,
            "product_binary": str(binary),
            "product_binary_sha256": binary_sha256,
            "repo_root": str(settings.repo_root.resolve()),
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "logical_cpu_count": os.cpu_count(),
            },
            "cuda_visible_devices": settings.device_ordinal,
            "aot_build_identity_sha256": build_identity,
            "device": device,
        },
        "summary": {
            "workload_shapes": len(workloads),
            "cold_processes": total_samples,
            "all_proofs_zig_verified": True,
            "all_shape_proofs_stable": True,
            "all_samples_resident": True,
            "all_samples_strict_aot": True,
            "all_samples_complete_once": True,
            "all_samples_zero_fallback": True,
            "all_samples_single_terminal_d2h": True,
            "device_identity_stable": True,
            "aot_build_identity_stable": True,
        },
        "workloads": workloads,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(settings.output_path, encoded)
    return document, encoded
