"""Fail-closed Native CUDA structural benchmark runner."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from autoresearch.cli.stwo_perf import stats
from scripts.native_cuda_diagnostic_lib.contract import (
    validate_artifact,
    validate_report,
)
from scripts.native_cuda_diagnostic_lib.model import (
    DiagnosticError,
    MAX_REPORT_BYTES,
    MAX_STDERR_BYTES,
)
from scripts.process_resources_lib import (
    ResourceMeasurementError,
    measurement_command,
    measurement_environment,
    parse_process_resources,
)

from .identity import validate_proof_identity
from .oracle import rust_oracle_receipt
from .model import (
    COVERAGE_MATRIX,
    MINIMUM_PORTFOLIO_RATIO,
    PRIMARY_PORTFOLIO_RATIO,
    REGRESSION_CEILING,
    SCHEMA,
    BenchmarkError,
    Settings,
    Workload,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_binary(path: Path, label: str) -> Path:
    binary = path.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise BenchmarkError(f"{label} CUDA product is not executable: {binary}")
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
        raise BenchmarkError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _write_exclusive(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise BenchmarkError(f"refusing to overwrite CUDA result: {path}") from error


def _summary(values: list[float]) -> dict[str, float]:
    if not values or any(not math.isfinite(value) for value in values):
        raise BenchmarkError("CUDA metric vector is empty or non-finite")
    median = statistics.median(values)
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "mad": statistics.median(abs(value - median) for value in values),
    }


def _command(
    binary: Path,
    workload: Workload,
    proof: Path,
    report: Path,
    repetitions: int,
) -> list[str]:
    shape = workload.shape
    if shape is None:
        raise BenchmarkError(f"CUDA workload is unavailable: {workload.workload_id}")
    return [
        str(binary),
        "prove",
        "--air",
        shape.application,
        "--backend",
        "cuda",
        "--protocol",
        shape.protocol,
        *shape.cli_shape_args(),
        "--output",
        str(proof),
        "--report-out",
        str(report),
        "--repeat",
        str(repetitions),
    ]


def _invoke(
    settings: Settings,
    binary: Path,
    workload: Workload,
    arm: str,
    phase: str,
    ordinal: int,
    repetitions: int,
) -> dict[str, Any]:
    sample_dir = (
        settings.artifact_root
        / workload.workload_id
        / phase
        / f"{ordinal:03d}-{arm}"
    )
    sample_dir.mkdir(parents=True)
    proof_path = sample_dir / "proof-artifact.json"
    report_path = sample_dir / "product-report.json"
    stderr_path = sample_dir / "process.stderr.txt"
    command = _command(
        binary,
        workload,
        proof_path,
        report_path,
        repetitions,
    )
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
        raise BenchmarkError("CUDA product stderr exceeds the capture bound")
    _write_exclusive(stderr_path, completed.stderr)
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise BenchmarkError(
            f"{workload.workload_id} {arm} exited {completed.returncode}; "
            f"stderr tail:\n{tail}"
        )
    if len(completed.stdout) > MAX_REPORT_BYTES:
        raise BenchmarkError("CUDA product stdout exceeds the report bound")
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError("CUDA product stdout is not one JSON object") from error
    try:
        report_file = report_path.read_bytes()
    except FileNotFoundError as error:
        raise BenchmarkError("CUDA product did not persist its report") from error
    if len(report_file) > MAX_REPORT_BYTES:
        raise BenchmarkError("CUDA persisted report exceeds its bound")
    if report_file.strip() != completed.stdout.strip():
        raise BenchmarkError("CUDA persisted report differs from stdout")
    shape = workload.shape
    assert shape is not None
    try:
        artifact = validate_artifact(proof_path, shape)
        validated = validate_report(
            report,
            shape,
            proof_path,
            artifact,
            expected_repetitions=repetitions,
            allow_historical_baseline=arm == "baseline",
        )
    except DiagnosticError as error:
        raise BenchmarkError(str(error)) from error
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
        "proof": artifact,
        "proof_path": str(proof_path),
        "report_schema_version": validated["schema_version"],
        "execution_mode": validated["execution_mode"],
        "semantic_sha256": validated["semantic_sha256"],
        "statement": validated["statement"],
        "protocol": validated["protocol"],
        "product_identity": validated["product_identity"],
        "plan": validated["plan"],
        "timing_ns": validated["timing_ns"],
        "repetition": validated["process_repetition"],
        "residency": validated["residency"],
        "device_stage_timing_ns": validated["device_stage_timing_ns"],
        "aot": validated["aot"],
        "device": validated["device"],
        "report_sha256": hashlib.sha256(report_file).hexdigest(),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def _steady_metrics(
    session: dict[str, Any],
    workload: Workload,
    warmups: int,
    samples: int,
) -> dict[str, Any]:
    repetition = session["repetition"]
    first_sample = 1 + warmups
    stop = first_sample + samples

    def vector(key: str) -> list[int]:
        values = repetition[key]
        selected = values[first_sample:stop]
        if len(selected) != samples:
            raise BenchmarkError(f"CUDA steady vector is incomplete: {key}")
        return selected

    resident = vector("resident_prove_ns")
    verified = vector("verified_request_ns")
    device = vector("device_elapsed_ns")
    decode = vector("terminal_decode_ns")
    verification = vector("independent_verification_ns")
    shape = workload.shape
    assert shape is not None
    resident_median = statistics.median(resident)
    verified_median = statistics.median(verified)
    device_median = statistics.median(device)
    return {
        "first_request": {
            "resident_ms": repetition["resident_prove_ns"][0] / 1_000_000.0,
            "verified_ms": repetition["verified_request_ns"][0] / 1_000_000.0,
            "device_ms": repetition["device_elapsed_ns"][0] / 1_000_000.0,
        },
        "steady": {
            "resident_ms": _summary(
                [value / 1_000_000.0 for value in resident]
            ),
            "verified_ms": _summary(
                [value / 1_000_000.0 for value in verified]
            ),
            "device_critical_path_ms": _summary(
                [value / 1_000_000.0 for value in device]
            ),
            "terminal_decode_ms": _summary(
                [value / 1_000_000.0 for value in decode]
            ),
            "independent_verification_ms": _summary(
                [value / 1_000_000.0 for value in verification]
            ),
            "host_gap_ms": _summary(
                [
                    (resident_value - device_value) / 1_000_000.0
                    for resident_value, device_value in zip(
                        resident,
                        device,
                        strict=True,
                    )
                ]
            ),
            "verified_row_mhz": shape.trace_rows * 1000.0 / verified_median,
            "resident_row_mhz": shape.trace_rows * 1000.0 / resident_median,
            "device_row_mhz": shape.trace_rows * 1000.0 / device_median,
            "verified_committed_mcells_per_second": (
                shape.trace_cells * 1000.0 / verified_median
            ),
            "resident_committed_mcells_per_second": (
                shape.trace_cells * 1000.0 / resident_median
            ),
            "device_committed_mcells_per_second": (
                shape.trace_cells * 1000.0 / device_median
            ),
        },
        "stage_ms_last_steady_sample": {
            key: value / 1_000_000.0
            for key, value in session["device_stage_timing_ns"].items()
        },
        "mechanism": {
            **session["residency"],
            "plan": session["plan"],
            "aot": session["aot"],
        },
        "resources": session["resources"],
        "raw_repetition": repetition,
        "proof": session["proof"],
    }


def _cold_metrics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "external_wall_ms": _summary(
            [sample["external_wall_ns"] / 1_000_000.0 for sample in samples]
        ),
        "runtime_init_ms": _summary(
            [sample["timing_ns"]["runtime_init"] / 1_000_000.0 for sample in samples]
        ),
        "shape_prepare_ms": _summary(
            [sample["timing_ns"]["shape_prepare"] / 1_000_000.0 for sample in samples]
        ),
        "first_verified_request_ms": _summary(
            [
                sample["timing_ns"]["verified_request"] / 1_000_000.0
                for sample in samples
            ]
        ),
        "runtime_teardown_ms": _summary(
            [
                sample["timing_ns"]["runtime_teardown"] / 1_000_000.0
                for sample in samples
            ]
        ),
        "lifecycle_sum_ms": _summary(
            [
                sum(
                    sample["timing_ns"][key]
                    for key in (
                        "runtime_init",
                        "shape_prepare",
                        "verified_request",
                        "runtime_teardown",
                    )
                )
                / 1_000_000.0
                for sample in samples
            ]
        ),
        "peak_rss_kib": _summary(
            [float(sample["resources"]["peak_rss_kib"]) for sample in samples]
        ),
    }


def _cold_comparison(
    cold: dict[str, list[dict[str, Any]]],
    resamples: int,
    seed: int,
) -> dict[str, Any] | None:
    if "baseline" not in cold:
        return None
    candidate = [
        sample["external_wall_ns"] / 1_000_000.0
        for sample in cold["candidate"]
    ]
    baseline = [
        sample["external_wall_ns"] / 1_000_000.0
        for sample in cold["baseline"]
    ]
    if len(candidate) != len(baseline):
        raise BenchmarkError("CUDA cold arms have different sample counts")
    ratios = [
        candidate_ms / baseline_ms
        for baseline_ms, candidate_ms in zip(baseline, candidate, strict=True)
    ]
    estimate = stats.hodges_lehmann(ratios)
    interval = (
        stats.bootstrap_ci(ratios, iterations=resamples, seed=seed)
        if len(ratios) >= 3
        else None
    )
    return {
        "boundary": "cold_process_external_wall",
        "estimator": "hodges_lehmann_paired_sample_ratio",
        "candidate_over_baseline": estimate,
        "confidence_interval_95": (
            {"low": interval[0], "high": interval[1]}
            if interval is not None
            else None
        ),
        "sample_ratios": ratios,
        "baseline_samples_ms": baseline,
        "candidate_samples_ms": candidate,
        "regression_ceiling": REGRESSION_CEILING,
        "passes_regression_ceiling": (
            interval[1] <= REGRESSION_CEILING
            if interval is not None
            else estimate <= REGRESSION_CEILING
        ),
    }


def _arm_round_medians(
    sessions: list[dict[str, Any]],
) -> dict[str, list[float]]:
    grouped: dict[tuple[str, int], list[float]] = {}
    for session in sessions:
        grouped.setdefault((session["arm"], session["round"]), []).append(
            session["metrics"]["steady"]["verified_ms"]["median"]
        )
    output: dict[str, list[float]] = {"candidate": [], "baseline": []}
    for arm in output:
        rounds = sorted(
            round_index
            for candidate_arm, round_index in grouped
            if candidate_arm == arm
        )
        output[arm] = [
            statistics.median(grouped[(arm, round_index)])
            for round_index in rounds
        ]
    return output


def _comparison(
    sessions: list[dict[str, Any]],
    resamples: int,
    seed: int,
) -> dict[str, Any] | None:
    medians = _arm_round_medians(sessions)
    if not medians["baseline"]:
        return None
    if len(medians["candidate"]) != len(medians["baseline"]):
        raise BenchmarkError("CUDA paired arms have different round counts")
    ratios = [
        candidate / baseline
        for baseline, candidate in zip(
            medians["baseline"],
            medians["candidate"],
            strict=True,
        )
    ]
    estimate = stats.hodges_lehmann(ratios)
    interval = (
        stats.bootstrap_ci(ratios, iterations=resamples, seed=seed)
        if len(ratios) >= 3
        else None
    )
    return {
        "estimator": "hodges_lehmann_paired_round_ratio",
        "candidate_over_baseline": estimate,
        "confidence_interval_95": (
            {"low": interval[0], "high": interval[1]}
            if interval is not None
            else None
        ),
        "round_ratios": ratios,
        "baseline_round_medians_ms": medians["baseline"],
        "candidate_round_medians_ms": medians["candidate"],
        "regression_ceiling": REGRESSION_CEILING,
        "passes_regression_ceiling": (
            interval[1] <= REGRESSION_CEILING
            if interval is not None
            else estimate <= REGRESSION_CEILING
        ),
    }


def _measure_workload(
    settings: Settings,
    workload: Workload,
    binaries: dict[str, Path],
) -> dict[str, Any]:
    cold: dict[str, list[dict[str, Any]]] = {
        arm: [] for arm in binaries
    }
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
                    1,
                )
            )
            cold_ordinal += 1
            _cooldown(settings)

    repetitions = 1 + settings.warmups + settings.samples
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
                repetitions,
            )
            sessions.append(
                {
                    "arm": arm,
                    "round": round_index,
                    "order_index": session_ordinal,
                    "metrics": _steady_metrics(
                        raw,
                        workload,
                        settings.warmups,
                        settings.samples,
                    ),
                    "raw": raw,
                }
            )
            session_ordinal += 1
            _cooldown(settings)
    gate = validate_proof_identity(cold, sessions)
    oracle = rust_oracle_receipt(
        settings,
        workload,
        Path(cold["candidate"][0]["proof_path"]),
    )
    result = {
        "workload_id": workload.workload_id,
        "structural_class": workload.structural_class,
        "statement": workload.shape.statement() if workload.shape else None,
        "proof_gate": gate,
        "cold": {
            arm: _cold_metrics(samples) for arm, samples in cold.items()
        },
        "cold_comparison": _cold_comparison(
            cold,
            settings.bootstrap_resamples,
            _seed(f"cold:{workload.workload_id}"),
        ),
        "rust_oracle": oracle,
        "sessions": sessions,
        "comparison": _comparison(
            sessions,
            settings.bootstrap_resamples,
            _seed(workload.workload_id),
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
    }
    return result


def _portfolio(workloads: list[dict[str, Any]], resamples: int) -> dict[str, Any]:
    comparisons = [
        workload for workload in workloads if workload["comparison"] is not None
    ]
    if not comparisons:
        return {
            "available": False,
            "reason": "candidate-only diagnostic; no baseline arm",
        }
    by_class: dict[str, list[dict[str, Any]]] = {}
    for workload in comparisons:
        by_class.setdefault(workload["structural_class"], []).append(workload)
    class_results = {}
    class_round_vectors = []
    for class_name, members in sorted(by_class.items()):
        estimates = [
            member["comparison"]["candidate_over_baseline"]
            for member in members
        ]
        round_count = len(members[0]["comparison"]["round_ratios"])
        if any(
            len(member["comparison"]["round_ratios"]) != round_count
            for member in members
        ):
            raise BenchmarkError("CUDA class has inconsistent round counts")
        round_ratios = [
            stats.geometric_mean(
                [
                    member["comparison"]["round_ratios"][round_index]
                    for member in members
                ]
            )
            for round_index in range(round_count)
        ]
        class_results[class_name] = {
            "workload_count": len(members),
            "ratio_geomean": stats.geometric_mean(estimates),
            "round_ratio_geomeans": round_ratios,
            "worst_workload_ratio": max(estimates),
        }
        class_round_vectors.append(round_ratios)
    estimate = stats.geometric_mean(
        [result["ratio_geomean"] for result in class_results.values()]
    )
    interval = (
        stats.portfolio_geomean_ci(
            class_round_vectors,
            iterations=resamples,
            seed=_seed("portfolio"),
        )[1]
        if all(len(values) >= 3 for values in class_round_vectors)
        else None
    )
    return {
        "available": True,
        "weighting": "equal_weight_structural_class_geometric_mean",
        "ratio": estimate,
        "speedup": 1.0 / estimate,
        "confidence_interval_95": (
            {"low": interval[0], "high": interval[1]}
            if interval is not None
            else None
        ),
        "classes": class_results,
        "minimum_target_ratio": MINIMUM_PORTFOLIO_RATIO,
        "primary_target_ratio": PRIMARY_PORTFOLIO_RATIO,
        "passes_1_3x_target": (
            interval[1] <= MINIMUM_PORTFOLIO_RATIO
            if interval is not None
            else estimate <= MINIMUM_PORTFOLIO_RATIO
        ),
        "passes_2x_target": (
            interval[1] <= PRIMARY_PORTFOLIO_RATIO
            if interval is not None
            else estimate <= PRIMARY_PORTFOLIO_RATIO
        ),
        "worst_workload_ratio": max(
            workload["comparison"]["candidate_over_baseline"]
            for workload in comparisons
        ),
    }


def _coverage() -> dict[str, Any]:
    classes: dict[str, dict[str, Any]] = {}
    for workload in COVERAGE_MATRIX:
        entry = classes.setdefault(
            workload.structural_class,
            {"enabled_workloads": [], "blockers": []},
        )
        if workload.enabled:
            entry["enabled_workloads"].append(workload.workload_id)
        else:
            entry["blockers"].append(
                {
                    "workload_id": workload.workload_id,
                    "reason": workload.unavailable_reason,
                }
            )
    missing = [
        class_name
        for class_name, entry in classes.items()
        if not entry["enabled_workloads"]
    ]
    return {
        "classes": classes,
        "required_class_count": len(classes),
        "covered_class_count": len(classes) - len(missing),
        "missing_classes": missing,
        "activation_ready": not missing,
    }


def _headline_eligible(
    settings: Settings,
    coverage: dict[str, Any],
    portfolio: dict[str, Any],
    workloads: list[dict[str, Any]],
) -> bool:
    return (
        settings.profile_name == "judge"
        and portfolio["available"]
        and portfolio["passes_1_3x_target"]
        and coverage["activation_ready"]
        and all(workload["rust_oracle"]["accepted"] for workload in workloads)
        and all(
            workload["comparison"]["passes_regression_ceiling"]
            for workload in workloads
        )
        and all(
            workload["cold_comparison"] is not None
            and workload["cold_comparison"]["passes_regression_ceiling"]
            for workload in workloads
        )
    )


def run_benchmark(settings: Settings) -> tuple[dict[str, Any], bytes]:
    settings.validate()
    candidate = _require_binary(settings.candidate_bin, "candidate")
    binaries = {"candidate": candidate}
    if settings.baseline_bin is not None:
        binaries["baseline"] = _require_binary(
            settings.baseline_bin,
            "baseline",
        )
    if settings.rust_oracle_bin is not None:
        oracle = _require_binary(settings.rust_oracle_bin, "Rust oracle")
        if _sha256_file(oracle) != settings.rust_oracle_sha256:
            raise BenchmarkError(
                "CUDA Rust oracle binary differs from its SHA-256 pin"
            )
    binary_digests = {
        arm: _sha256_file(binary) for arm, binary in binaries.items()
    }
    if settings.output_path.exists() or settings.artifact_root.exists():
        raise BenchmarkError("CUDA benchmark output or artifact root already exists")
    settings.artifact_root.mkdir(parents=True)

    workloads = [
        _measure_workload(settings, workload, binaries)
        for workload in settings.workloads
    ]
    for arm, binary in binaries.items():
        if _sha256_file(binary) != binary_digests[arm]:
            raise BenchmarkError(f"CUDA {arm} binary changed during measurement")
    coverage = _coverage()
    portfolio = _portfolio(workloads, settings.bootstrap_resamples)
    headline = _headline_eligible(settings, coverage, portfolio, workloads)
    document = {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": settings.profile_name,
        "headline_eligible": headline,
        "measurement_contract": {
            "schedule": (
                "paired_counterbalanced_ABBA"
                if "baseline" in binaries
                else "candidate_only_diagnostic"
            ),
            "cold_process_samples": settings.cold_samples,
            "rounds": settings.rounds,
            "first_request_samples_per_process": 1,
            "warmups_per_process": settings.warmups,
            "steady_verified_samples_per_process": settings.samples,
            "one_process_runtime_per_session": True,
            "shape_plan_compiled_once_per_process": True,
            "stage_timing_source": "CUDA events resolved at terminal proof fence",
            "proof_requirement": (
                "byte-identical, independently Zig-verified, and accepted "
                "per workload by the pinned Rust stwo oracle"
            ),
            "fallback_requirement": "zero CPU fallback attempts and completions",
            "portfolio_weighting": (
                "equal-weight geometric mean across structural classes"
            ),
            "regression_ceiling": REGRESSION_CEILING,
            "minimum_portfolio_speedup": 1.3,
            "cold_process_is_separate_gate": True,
            "profiler_replay_is_verdict": False,
        },
        "provenance": {
            "repository_commit": _git(settings.repo_root, "rev-parse", "HEAD"),
            "repository_dirty": bool(
                _git(
                    settings.repo_root,
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                )
            ),
            "binaries": {
                arm: {
                    "path": str(binary),
                    "sha256": binary_digests[arm],
                }
                for arm, binary in binaries.items()
            },
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "logical_cpu_count": os.cpu_count(),
            },
            "cuda_visible_devices": settings.device_ordinal,
        },
        "coverage": coverage,
        "portfolio": portfolio,
        "workloads": workloads,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(settings.output_path, encoded)
    return document, encoded


def _cooldown(settings: Settings) -> None:
    if settings.cooldown_seconds > 0:
        time.sleep(settings.cooldown_seconds)


def _seed(value: str) -> int:
    return int.from_bytes(
        hashlib.sha256(value.encode()).digest()[:8],
        "little",
    )
