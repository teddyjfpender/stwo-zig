"""Process scheduling for the persistent mixed-family CUDA benchmark."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from scripts.native_cuda_diagnostic_lib.model import (
    MAX_REPORT_BYTES,
    MAX_STDERR_BYTES,
)
from scripts.process_resources_lib import (
    ResourceMeasurementError,
    measurement_command,
    measurement_environment,
    parse_process_resources,
)

from . import sustained
from .model import BenchmarkError, Settings, SustainedShape, Workload
from .oracle import rust_oracle_receipt


def _write_exclusive(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise BenchmarkError(
            f"refusing to overwrite sustained CUDA result: {path}"
        ) from error


def _invoke(
    settings: Settings,
    binary: Path,
    workload: Workload,
    arm: str,
    phase: str,
    ordinal: int,
) -> dict[str, Any]:
    shape = workload.shape
    assert isinstance(shape, SustainedShape)
    cycles = 1 if phase == "cold" else shape.cycles
    sample_dir = (
        settings.artifact_root
        / workload.workload_id
        / phase
        / f"{ordinal:03d}-{arm}"
    )
    sample_dir.mkdir(parents=True)
    artifact_dir = sample_dir / "proof-artifacts"
    report_path = sample_dir / "product-report.json"
    stderr_path = sample_dir / "process.stderr.txt"
    command = sustained.command(binary, artifact_dir, report_path, cycles)
    measured, measurement = measurement_command(command, required=True)
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
        raise BenchmarkError(
            f"{workload.workload_id} {phase} {ordinal} timed out"
        ) from error
    external_wall_ns = time.perf_counter_ns() - started_ns
    if len(completed.stderr) > MAX_STDERR_BYTES:
        raise BenchmarkError("sustained CUDA stderr exceeds the capture bound")
    _write_exclusive(stderr_path, completed.stderr)
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise BenchmarkError(
            f"{workload.workload_id} {arm} exited {completed.returncode}; "
            f"stderr tail:\n{tail}"
        )
    if len(completed.stdout) > MAX_REPORT_BYTES:
        raise BenchmarkError("sustained CUDA stdout exceeds the report bound")
    try:
        report = json.loads(completed.stdout)
        report_file = report_path.read_bytes()
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(
            "sustained CUDA product did not persist one JSON report"
        ) from error
    if (
        len(report_file) > MAX_REPORT_BYTES
        or report_file.strip() != completed.stdout.strip()
    ):
        raise BenchmarkError(
            "sustained CUDA persisted report differs from bounded stdout"
        )
    validated = sustained.validate_report(
        report,
        artifact_dir,
        SustainedShape(cycles),
    )
    try:
        resources = parse_process_resources(
            completed.stderr,
            measurement,
            require_peak_rss=True,
        )
    except ResourceMeasurementError as error:
        raise BenchmarkError(str(error)) from error
    return {
        "arm": arm,
        "phase": phase,
        "ordinal": ordinal,
        "command": command,
        "external_wall_ns": external_wall_ns,
        "resources": resources,
        "report_schema_version": validated["schema_version"],
        "product_identity": validated["product_identity"],
        "timing_ns": validated["timing_ns"],
        "service": validated["service"],
        "aggregate": validated["aggregate"],
        "requests": validated["requests"],
        "artifacts": validated["artifacts"],
        "proof_paths": [str(path) for path in validated["proof_paths"]],
        "proof_catalog": validated["proof_catalog"],
        "device": validated["device"],
        "report_sha256": hashlib.sha256(report_file).hexdigest(),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def _cold_metrics(
    samples: list[dict[str, Any]],
    summary: Callable[[list[float]], dict[str, float]],
) -> dict[str, Any]:
    def timing(key: str) -> list[float]:
        return [
            sample["timing_ns"][key] / 1_000_000.0
            for sample in samples
        ]

    return {
        "boundary": "whole_mixed_service_cold_process",
        "request_count_per_process": len(samples[0]["requests"]),
        "external_wall_ms": summary(
            [sample["external_wall_ns"] / 1_000_000.0 for sample in samples]
        ),
        "runtime_init_ms": summary(timing("runtime_init")),
        "shape_preparation_ms": summary(timing("shape_preparation")),
        "service_wall_ms": summary(timing("service_wall")),
        "runtime_teardown_ms": summary(timing("runtime_teardown")),
        "total_before_report_publication_ms": summary(
            timing("total_before_report_publication")
        ),
        "peak_rss_kib": summary(
            [float(sample["resources"]["peak_rss_kib"]) for sample in samples]
        ),
    }


def measure_sustained(
    settings: Settings,
    workload: Workload,
    binaries: dict[str, Path],
    *,
    cold_comparison: Callable[..., dict[str, Any] | None],
    comparison: Callable[..., dict[str, Any] | None],
    cooldown: Callable[[Settings], None],
    seed: Callable[[str], int],
) -> dict[str, Any]:
    from .runner import _summary

    cold: dict[str, list[dict[str, Any]]] = {arm: [] for arm in binaries}
    cold_ordinal = 0
    for sample_index in range(settings.cold_samples):
        order = list(binaries)
        if sample_index % 2:
            order.reverse()
        for arm in order:
            cold[arm].append(
                _invoke(
                    settings,
                    binaries[arm],
                    workload,
                    arm,
                    "cold",
                    cold_ordinal,
                )
            )
            cold_ordinal += 1
            cooldown(settings)

    sessions: list[dict[str, Any]] = []
    session_ordinal = 0
    for round_index in range(settings.rounds):
        if "baseline" in binaries:
            order = (
                ["baseline", "candidate", "candidate", "baseline"]
                if round_index % 2 == 0
                else ["candidate", "baseline", "baseline", "candidate"]
            )
        else:
            order = ["candidate"]
        for arm in order:
            raw = _invoke(
                settings,
                binaries[arm],
                workload,
                arm,
                "steady",
                session_ordinal,
            )
            sessions.append(
                {
                    "arm": arm,
                    "round": round_index,
                    "order_index": session_ordinal,
                    "metrics": {
                        **sustained.steady_metrics(raw),
                        "resources": raw["resources"],
                    },
                    "raw": raw,
                }
            )
            session_ordinal += 1
            cooldown(settings)

    gate = sustained.proof_identity(cold, sessions)
    oracle_receipts = [
        rust_oracle_receipt(settings, workload, Path(path))
        for path in cold["candidate"][0]["proof_paths"]
    ]
    oracle = {
        "accepted": all(receipt["accepted"] for receipt in oracle_receipts),
        "artifact_count": len(oracle_receipts),
        "receipts": oracle_receipts,
    }
    return {
        "workload_id": workload.workload_id,
        "structural_class": workload.structural_class,
        "headline_scored": False,
        "statement": workload.shape.statement() if workload.shape else None,
        "proof_gate": gate,
        "cold": {
            arm: _cold_metrics(samples, _summary)
            for arm, samples in cold.items()
        },
        "cold_comparison": cold_comparison(
            cold,
            settings.bootstrap_resamples,
            seed(f"cold:{workload.workload_id}"),
        ),
        "rust_oracle": oracle,
        "sessions": sessions,
        "comparison": comparison(
            sessions,
            settings.bootstrap_resamples,
            seed(workload.workload_id),
        ),
        "profiler_evidence": {
            "nsight_systems": None,
            "nsight_compute": None,
            "missing": [
                "launch_gap_and_overlap",
                "dram_and_l2_traffic",
                "achieved_bandwidth",
                "occupancy",
                "registers_and_spills",
                "power_and_energy",
            ],
        },
        "promotion": {
            "registry_enabled": False,
            "headline_eligible": False,
            "reason": (
                "sustained queue lacks locked-host A/A calibration and "
                "complete pinned Rust-oracle receipt packaging"
            ),
        },
    }
