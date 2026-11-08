"""Serial, fresh-process orchestration for the H-010 layout benchmark."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .contract import (
    BACKEND,
    BENCHMARK_ID,
    CLASSIFICATION,
    DEFAULT_LOGS,
    DIRECT_NODES,
    DIRECT_RETAINED_SCRATCH_BYTES,
    DIRECT_ROOTS,
    EVALUATOR,
    MAIN_COLUMNS,
    MATERIALIZATIONS,
    MEASURED_ROUNDS,
    MEASUREMENT_SCOPE,
    REPORT_KIND,
    REPORT_SCHEMA,
    SAMPLE_SCHEMA,
    SEMANTIC_RETAINED_SCRATCH_BYTES,
    STRESS_LOG,
    WARMUP_ROUNDS,
)
from .child import (
    ChildResult,
    ChildRunner,
    child_environment,
    default_child_runner,
    run_preflight,
    run_sample as run_sample_child,
)
from .cohort import (
    SampleFailure,
    all_samples,
    arm_table,
    collect_log,
    execution_identity as cohort_execution_identity,
    failure_record,
    integer_summary,
    launch_order,
    vector_table,
)
from .environment import ProvenanceError, gather_provenance
from .report import atomic_write_new, encode_report
from .report_provenance import ProvenanceValidationError, validate_provenance


RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class BenchmarkError(RuntimeError):
    """The requested benchmark cannot produce admissible evidence."""


class BenchmarkRunFailed(BenchmarkError):
    """A failure report was written, but the requested run did not complete."""

    def __init__(self, message: str, document: dict[str, object], encoded: bytes):
        super().__init__(message)
        self.document = document
        self.encoded = encoded


@dataclass(frozen=True)
class Settings:
    executable: Path
    output_path: Path
    repo_root: Path
    power_state: str
    include_log_18: bool = False
    timeout_seconds: float = 7_200.0
    run_id: str | None = None

    @property
    def logs(self) -> tuple[int, ...]:
        return (*DEFAULT_LOGS, STRESS_LOG) if self.include_log_18 else DEFAULT_LOGS


ProvenanceProvider = Callable[[Path, Path, str], dict[str, object]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"h010-{stamp}-{uuid.uuid4().hex[:12]}"


def _sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _file_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _validated_settings(settings: Settings) -> Settings:
    executable = settings.executable.resolve()
    repo_root = settings.repo_root.resolve()
    output = settings.output_path.resolve()
    if settings.timeout_seconds <= 0:
        raise BenchmarkError("timeout must be positive")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise BenchmarkError(f"benchmark executable is missing or not executable: {executable}")
    if not repo_root.is_dir():
        raise BenchmarkError(f"repository root is not a directory: {repo_root}")
    if output.exists():
        raise BenchmarkError(f"refusing to overwrite benchmark report: {output}")
    power_state = settings.power_state.strip()
    if (
        not power_state
        or len(power_state) > 256
        or any(ord(character) < 32 for character in power_state)
        or power_state.casefold() in {"unknown", "undeclared", "n/a"}
    ):
        raise BenchmarkError("power-state declaration must be explicit printable text")
    run_id = settings.run_id or _new_run_id()
    if RUN_ID_RE.fullmatch(run_id) is None:
        raise BenchmarkError("run ID must be 1-128 safe identifier characters")
    return Settings(
        executable=executable,
        output_path=output,
        repo_root=repo_root,
        power_state=power_state,
        include_log_18=settings.include_log_18,
        timeout_seconds=settings.timeout_seconds,
        run_id=run_id,
    )


def collect_benchmark(
    settings: Settings,
    *,
    child_runner: ChildRunner = default_child_runner,
    provenance_provider: ProvenanceProvider = gather_provenance,
) -> dict[str, object]:
    """Collect a complete requested run, including explicit invalid evidence."""

    normalized = _validated_settings(settings)
    started_at = _utc_now()
    identity_before = _file_identity(normalized.executable)
    executable_bytes, executable_digest = _sha256_file(normalized.executable)
    failures: list[dict[str, object]] = []
    cohorts: list[dict[str, object]] = []
    preflight: dict[str, object] | None = None
    provenance: dict[str, object] | None = None
    provenance_admitted = False
    try:
        provenance = provenance_provider(
            normalized.repo_root,
            normalized.executable,
            normalized.power_state,
        )
    except (ProvenanceError, OSError, ValueError) as error:
        failures.append(
            failure_record(
                "provenance-unavailable",
                f"provenance admission failed: {error}",
                "provenance",
            )
        )
    else:
        provenance_executable = provenance.get("executable")
        repository = provenance.get("repository")
        if not isinstance(provenance_executable, dict) or (
            provenance_executable.get("bytes") != executable_bytes
            or provenance_executable.get("sha256") != executable_digest
        ):
            failures.append(
                failure_record(
                    "provenance-executable-mismatch",
                    "provenance executable identity disagrees with sampled bytes",
                    "provenance",
                )
            )
        elif not isinstance(repository, dict) or repository.get("clean") is not True:
            failures.append(
                failure_record(
                    "repository-dirty",
                    "benchmark admission requires a clean immutable Git snapshot",
                    "provenance",
                )
            )
        else:
            try:
                validate_provenance(provenance)
            except ProvenanceValidationError as error:
                failures.append(
                    failure_record(
                        "provenance-schema",
                        f"provenance is incomplete: {error}",
                        "provenance",
                    )
                )
            else:
                provenance_admitted = True

    if provenance_admitted:
        try:
            preflight = run_preflight(
                normalized.executable,
                normalized.repo_root,
                normalized.timeout_seconds,
                child_runner,
            )
        except SampleFailure as error:
            failures.append(failure_record(error.code, str(error), "preflight"))

    if preflight is not None:
        def run_sample(arm: str, log_size: int) -> dict[str, object]:
            return run_sample_child(
                normalized.executable,
                normalized.repo_root,
                normalized.timeout_seconds,
                arm,
                log_size,
                child_runner,
            )

        for log_size in DEFAULT_LOGS:
            cohort = collect_log(log_size, run_sample)
            cohorts.append(cohort)
            if not cohort["valid"]:
                failure = cohort["failure"]
                assert isinstance(failure, dict)
                failures.append(failure)
                break
        defaults_valid = (
            len(cohorts) >= len(DEFAULT_LOGS)
            and all(
                cohort["valid"]
                for cohort in cohorts
                if cohort["log_size"] in DEFAULT_LOGS
            )
        )
        if defaults_valid and normalized.include_log_18:
            stress = collect_log(STRESS_LOG, run_sample)
            cohorts.append(stress)
            if not stress["valid"]:
                failure = stress["failure"]
                assert isinstance(failure, dict)
                failures.append(failure)
    else:
        defaults_valid = False

    if provenance_admitted:
        try:
            final_provenance = provenance_provider(
                normalized.repo_root,
                normalized.executable,
                normalized.power_state,
            )
        except (ProvenanceError, OSError, ValueError) as error:
            failures.append(
                failure_record(
                    "provenance-finalization-failed",
                    f"could not re-attest immutable snapshot: {error}",
                    "finalization",
                )
            )
            defaults_valid = False
        else:
            if final_provenance != provenance:
                failures.append(
                    failure_record(
                        "provenance-identity-drift",
                        "repository/source/artifact/host provenance changed during the run",
                        "finalization",
                    )
                )
                defaults_valid = False

    if _file_identity(normalized.executable) != identity_before:
        failures.append(
            failure_record(
                "executable-identity-drift",
                "benchmark executable metadata changed during the run",
                "finalization",
            )
        )
        defaults_valid = False
    else:
        final_bytes, final_digest = _sha256_file(normalized.executable)
        if (final_bytes, final_digest) != (executable_bytes, executable_digest):
            failures.append(
                failure_record(
                    "executable-content-drift",
                    "benchmark executable bytes changed during the run",
                    "finalization",
                )
            )
            defaults_valid = False

    try:
        execution_identity = cohort_execution_identity(cohorts)
    except SampleFailure as error:
        failures.append(failure_record(error.code, str(error), "finalization"))
        execution_identity = None
        defaults_valid = False
    if defaults_valid:
        expectation = (
            provenance.get("build_expectation")
            if isinstance(provenance, dict)
            else None
        )
        coherent = isinstance(expectation, dict) and isinstance(
            execution_identity, dict
        )
        if coherent:
            for key in (
                "zig_version",
                "optimization_mode",
                "allocator",
                "monotonic_clock",
            ):
                if execution_identity.get(key) != expectation.get(key):
                    coherent = False
            target = execution_identity.get("target")
            target_prefix = expectation.get("target_prefix")
            if (
                type(target) is not str
                or type(target_prefix) is not str
                or not target.startswith(target_prefix)
            ):
                coherent = False
        if not coherent:
            failures.append(
                failure_record(
                    "execution-provenance-mismatch",
                    "sample compiler/target/mode/allocator/clock disagrees with provenance",
                    "finalization",
                )
            )
            defaults_valid = False
    stress_cohort = next(
        (cohort for cohort in cohorts if cohort["log_size"] == STRESS_LOG),
        None,
    )
    requested_complete = defaults_valid and (
        not normalized.include_log_18
        or (stress_cohort is not None and bool(stress_cohort["valid"]))
    )
    rss_sources = sorted(
        {
            (str(sample["resource_source"]), str(sample["peak_rss_native_unit"]))
            for sample in all_samples(cohorts)
        }
    )
    return {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "kind": REPORT_KIND,
        "classification": CLASSIFICATION,
        "run_id": normalized.run_id,
        "started_at_utc": started_at,
        "completed_at_utc": _utc_now(),
        "benchmark_id": BENCHMARK_ID,
        "sample_schema": SAMPLE_SCHEMA,
        "evaluator": EVALUATOR,
        "backend": BACKEND,
        "measurement_scope": MEASUREMENT_SCOPE,
        "provenance": provenance,
        "execution_identity": execution_identity,
        "vectors": vector_table(cohorts),
        "logs": list(normalized.logs),
        "log_18_opted_in": normalized.include_log_18,
        "warmup_rounds": WARMUP_ROUNDS,
        "measured_rounds": MEASURED_ROUNDS,
        "worker_count": 1,
        "serial_execution": True,
        "automatic_retries": 0,
        "outlier_drops": 0,
        "environment_allowlist": child_environment(),
        "rss_adapters_observed": [
            {"source": source, "native_unit": unit} for source, unit in rss_sources
        ],
        "preflight": preflight,
        "arm_selection": {
            "policy": "removed-value-id-quantiles-q0-q50-q100-v1",
            "frontier_count": 126,
            "sort": ["removed_value_id", "proposal_digest"],
            "arms": arm_table(),
        },
        "geometry": {
            "main_columns": MAIN_COLUMNS,
            "materializations": MATERIALIZATIONS,
            "direct_nodes": DIRECT_NODES,
            "direct_roots": DIRECT_ROOTS,
            "semantic_retained_scratch_bytes": SEMANTIC_RETAINED_SCRATCH_BYTES,
            "direct_retained_scratch_bytes": DIRECT_RETAINED_SCRATCH_BYTES,
        },
        "cohorts": cohorts,
        "failures": failures,
        "default_logs_valid": defaults_valid,
        "requested_run_complete": requested_complete,
        "proof_executed": False,
        "verification_executed": False,
        "hash_component_shell_executed": False,
        "logup_executed": False,
        "commitment_executed": False,
        "pcs_executed": False,
        "metal_candidate_execution_supported": False,
        "production_layout_changed": False,
        "promotion_authority": False,
        "valid": defaults_valid,
    }


def run_benchmark(
    settings: Settings,
    *,
    child_runner: ChildRunner = default_child_runner,
    provenance_provider: ProvenanceProvider = gather_provenance,
) -> tuple[dict[str, object], bytes]:
    """Collect and atomically publish one valid or explicitly invalid report."""

    document = collect_benchmark(
        settings,
        child_runner=child_runner,
        provenance_provider=provenance_provider,
    )
    encoded = encode_report(document)
    atomic_write_new(settings.output_path, encoded)
    if not document["requested_run_complete"]:
        raise BenchmarkRunFailed(
            f"requested run failed; invalid report written to {settings.output_path}",
            document,
            encoded,
        )
    return document, encoded
