"""Closed final-report validation and non-overwriting atomic serialization."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .child import validate_check_object
from .cohort import SampleFailure, arm_table
from .contract import (
    ARMS,
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
    VECTOR_ARTIFACT_DIGESTS,
    VECTOR_CALL_DIGESTS,
    VECTOR_FORMAT,
    VECTOR_GENERATOR,
    VECTOR_OUTPUT_DIGESTS,
    VECTOR_SEALS,
    VECTOR_TRACE_DIGESTS,
    WARMUP_ROUNDS,
)
from .report_cohort import (
    CohortReportError,
    validate_cohort_document,
    validate_failure,
)
from .report_provenance import ProvenanceValidationError, validate_provenance


DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
REPORT_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "kind",
        "classification",
        "run_id",
        "started_at_utc",
        "completed_at_utc",
        "benchmark_id",
        "sample_schema",
        "evaluator",
        "backend",
        "measurement_scope",
        "provenance",
        "execution_identity",
        "vectors",
        "logs",
        "log_18_opted_in",
        "warmup_rounds",
        "measured_rounds",
        "worker_count",
        "serial_execution",
        "automatic_retries",
        "outlier_drops",
        "environment_allowlist",
        "rss_adapters_observed",
        "preflight",
        "arm_selection",
        "geometry",
        "cohorts",
        "failures",
        "default_logs_valid",
        "requested_run_complete",
        "proof_executed",
        "verification_executed",
        "hash_component_shell_executed",
        "logup_executed",
        "commitment_executed",
        "pcs_executed",
        "metal_candidate_execution_supported",
        "production_layout_changed",
        "promotion_authority",
        "valid",
    }
)
VECTOR_KEYS = frozenset(
    {
        "format",
        "generator",
        "log_size",
        "rows",
        "storage_class",
        "bytes",
        "seal",
        "artifact_sha256",
        "call_digest",
        "output_digest",
        "trace_digest_class",
        "trace_digests",
    }
)


class ReportError(ValueError):
    """A report is incomplete, contradictory, or unsafe to publish."""


def _object(value: Any, name: str, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReportError(f"{name} must be an object")
    actual = frozenset(value)
    if actual != keys:
        raise ReportError(
            f"{name} key set mismatch; missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def _exact(value: Any, expected: Any, name: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ReportError(f"{name} must equal {expected!r}")


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ReportError(f"{name} must be one lowercase SHA-256 digest")
    return value


def _environment() -> dict[str, str]:
    return {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"}


def _validate_vector(vector: Any) -> int:
    value = _object(vector, "vector", VECTOR_KEYS)
    log_size = value["log_size"]
    if type(log_size) is not int or log_size not in (*DEFAULT_LOGS, STRESS_LOG):
        raise ReportError("vector has unsupported log size")
    _exact(value["format"], VECTOR_FORMAT, "vector format")
    _exact(value["generator"], VECTOR_GENERATOR, "vector generator")
    _exact(value["rows"], 1 << log_size, "vector rows")
    _exact(value["bytes"], 130 + (1 << log_size) * 140, "vector bytes")
    _exact(value["seal"], VECTOR_SEALS[log_size], "vector seal")
    _exact(
        value["artifact_sha256"],
        VECTOR_ARTIFACT_DIGESTS[log_size],
        "vector artifact SHA-256",
    )
    expected_storage = (
        "generated_opt_in_uncommitted_non_receiptable"
        if log_size == STRESS_LOG
        else "checked_repository_artifact"
    )
    _exact(value["storage_class"], expected_storage, "vector storage class")
    _exact(
        value["trace_digest_class"],
        "candidate_layout_regression_pin_not_correctness_oracle",
        "trace digest class",
    )
    _exact(
        value["call_digest"],
        VECTOR_CALL_DIGESTS[log_size],
        "vector call digest",
    )
    _exact(
        value["output_digest"],
        VECTOR_OUTPUT_DIGESTS[log_size],
        "vector output digest",
    )
    traces = value["trace_digests"]
    if type(traces) is not dict or set(traces) != set(ARMS):
        raise ReportError("vector trace-digest arm set is incomplete")
    for ordinal, arm in enumerate(ARMS):
        _exact(
            traces[arm],
            VECTOR_TRACE_DIGESTS[log_size][ordinal],
            f"vector trace regression digest {arm}",
        )
    return log_size


def validate_report(document: dict[str, object]) -> None:
    """Fail closed on unknown versions, missing evidence, or contradictions."""

    report = _object(document, "report", REPORT_KEYS)
    exact = {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "kind": REPORT_KIND,
        "classification": CLASSIFICATION,
        "benchmark_id": BENCHMARK_ID,
        "sample_schema": SAMPLE_SCHEMA,
        "evaluator": EVALUATOR,
        "backend": BACKEND,
        "measurement_scope": MEASUREMENT_SCOPE,
        "warmup_rounds": WARMUP_ROUNDS,
        "measured_rounds": MEASURED_ROUNDS,
        "worker_count": 1,
        "serial_execution": True,
        "automatic_retries": 0,
        "outlier_drops": 0,
        "environment_allowlist": _environment(),
        "proof_executed": False,
        "verification_executed": False,
        "hash_component_shell_executed": False,
        "logup_executed": False,
        "commitment_executed": False,
        "pcs_executed": False,
        "metal_candidate_execution_supported": False,
        "production_layout_changed": False,
        "promotion_authority": False,
    }
    for key, expected in exact.items():
        _exact(report[key], expected, key)
    if type(report["run_id"]) is not str or RUN_ID_RE.fullmatch(report["run_id"]) is None:
        raise ReportError("run_id is not a safe stable identifier")
    for key in ("started_at_utc", "completed_at_utc"):
        if type(report[key]) is not str or UTC_RE.fullmatch(report[key]) is None:
            raise ReportError(f"{key} is not canonical UTC")
    for key in ("valid", "default_logs_valid", "requested_run_complete", "log_18_opted_in"):
        if type(report[key]) is not bool:
            raise ReportError(f"{key} must be boolean")
    _exact(report["valid"], report["default_logs_valid"], "valid/default relation")
    expected_logs = [10, 14, 18] if report["log_18_opted_in"] else [10, 14]
    _exact(report["logs"], expected_logs, "requested logs")
    if type(report["failures"]) is not list or type(report["cohorts"]) is not list:
        raise ReportError("failures and cohorts must be arrays")
    try:
        for failure in report["failures"]:
            validate_failure(failure)
    except CohortReportError as error:
        raise ReportError(str(error)) from error
    _exact(
        report["arm_selection"],
        {
            "policy": "removed-value-id-quantiles-q0-q50-q100-v1",
            "frontier_count": 126,
            "sort": ["removed_value_id", "proposal_digest"],
            "arms": arm_table(),
        },
        "arm selection",
    )
    _exact(
        report["geometry"],
        {
            "main_columns": MAIN_COLUMNS,
            "materializations": MATERIALIZATIONS,
            "direct_nodes": DIRECT_NODES,
            "direct_roots": DIRECT_ROOTS,
            "semantic_retained_scratch_bytes": SEMANTIC_RETAINED_SCRATCH_BYTES,
            "direct_retained_scratch_bytes": DIRECT_RETAINED_SCRATCH_BYTES,
        },
        "geometry",
    )
    if report["requested_run_complete"] and (
        not report["valid"] or report["failures"]
    ):
        raise ReportError("a complete requested run cannot carry failures")

    if report["valid"]:
        try:
            provenance = validate_provenance(report["provenance"])
        except ProvenanceValidationError as error:
            raise ReportError(str(error)) from error
        identity = report["execution_identity"]
        if type(identity) is not dict or set(identity) != {
            "optimization_mode",
            "zig_version",
            "target",
            "allocator",
            "monotonic_clock",
        }:
            raise ReportError("execution identity is incomplete")
        expectation = provenance["build_expectation"]
        for key in ("optimization_mode", "zig_version", "allocator", "monotonic_clock"):
            _exact(identity[key], expectation[key], f"execution identity {key}")
        if not identity["target"].startswith(expectation["target_prefix"]):
            raise ReportError("execution target disagrees with host provenance")
        if type(report["preflight"]) is not dict:
            raise ReportError("valid report is missing the untimed preflight")
        try:
            validate_check_object(report["preflight"])
        except SampleFailure as error:
            raise ReportError(f"preflight replay failed: {error}") from error
        try:
            cohort_logs = [
                validate_cohort_document(cohort) for cohort in report["cohorts"]
            ]
        except CohortReportError as error:
            raise ReportError(str(error)) from error
        vector_logs = [_validate_vector(vector) for vector in report["vectors"]]
        if not report["log_18_opted_in"]:
            if (
                not report["requested_run_complete"]
                or cohort_logs != [10, 14]
                or vector_logs != [10, 14]
                or report["failures"]
            ):
                raise ReportError("default run evidence sequence is not exact")
        elif report["requested_run_complete"]:
            if cohort_logs != [10, 14, 18] or vector_logs != [10, 14, 18]:
                raise ReportError("complete stress run is missing its log-18 evidence")
        else:
            if (
                cohort_logs != [10, 14, 18]
                or [cohort["valid"] for cohort in report["cohorts"]]
                != [True, True, False]
                or vector_logs != [10, 14]
                or len(report["failures"]) != 1
                or report["failures"][0].get("log_size") != 18
                or report["cohorts"][2]["failure"] != report["failures"][0]
            ):
                raise ReportError("failed stress evidence sequence is not exact")
        observed = report["rss_adapters_observed"]
        if type(observed) is not list or len(observed) != 1:
            raise ReportError("valid report must use exactly one RSS adapter pair")
        rss = observed[0]
        if type(rss) is not dict or set(rss) != {"source", "native_unit"}:
            raise ReportError("RSS adapter record is malformed")
        expected_rss = {
            "Darwin": ("getrusage-self-maxrss-native-bytes", "bytes"),
            "Linux": ("getrusage-self-maxrss-kib-normalized-bytes", "KiB"),
        }.get(provenance["host"]["os"])
        if expected_rss is None or (rss["source"], rss["native_unit"]) != expected_rss:
            raise ReportError("RSS adapter does not match the admitted host OS")
        _exact(report["preflight"]["rss_probe_source"], rss["source"], "RSS probe source")
    else:
        if not report["failures"]:
            raise ReportError("invalid report must carry at least one failure")
        if report["provenance"] is not None and type(report["provenance"]) is not dict:
            raise ReportError("invalid report provenance must be an object or null")
        if report["preflight"] is not None:
            try:
                validate_check_object(report["preflight"])
            except SampleFailure as error:
                raise ReportError(f"stored preflight is invalid: {error}") from error
        try:
            for cohort in report["cohorts"]:
                validate_cohort_document(cohort)
        except CohortReportError as error:
            raise ReportError(str(error)) from error


def encode_report(document: dict[str, object]) -> bytes:
    validate_report(document)
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def atomic_write_new(path: Path, payload: bytes) -> None:
    """Atomically publish complete bytes without ever replacing a destination."""

    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise ReportError(f"refusing to overwrite benchmark report: {destination}") from error
    finally:
        temporary.unlink(missing_ok=True)
