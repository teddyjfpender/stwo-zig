"""Versioned contracts for an honest native-versus-recursive CSP comparison.

The recursive report contract deliberately admits only a complete proof path.
Partial recursion work belongs in the measurement plan's source-boundary record,
not in a report that could be mistaken for an end-to-end performance result.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Iterable

from .codec import EvidenceError, content_digest, verify_document_seal


PLAN_SCHEMA = "stwo.riscv.recursion-csp-measurement-plan.v2"
RECURSIVE_REPORT_SCHEMA = "stwo.riscv.recursion-csp-producer-report.v2"
COMPARISON_SCHEMA = "stwo.riscv.recursion-csp-comparison.v2"
SCHEMA_VERSION = 2

PLAN_CLASSIFICATION = "measurement_plan_not_performance_evidence"
REPORT_CLASSIFICATION = "engineering_diagnostic"
COMPARISON_CLASSIFICATION = "engineering_diagnostic_not_publication_speedup"

PHASES = (
    "guest_execution",
    "base_witness",
    "base_prove",
    "base_verify",
    "recursive_prepare",
    "recursive_witness",
    "recursive_prove",
    "recursive_verify",
)
GENERATION_PHASES = (
    "guest_execution",
    "base_witness",
    "base_prove",
    # Verified capture is the recursive witness authority.  Omitting this
    # mandatory base verification would understate published-proof generation.
    "base_verify",
    "recursive_prepare",
    "recursive_witness",
    "recursive_prove",
)
VERIFICATION_PHASES = ("recursive_verify",)
AGGREGATES = (
    "verified_end_to_end_ns",
    "published_proof_generation_ns",
    "published_proof_verification_ns",
    "published_proof_bytes",
    "peak_rss_bytes",
    "proof_generation_poseidon2_permutations",
    "proof_verification_poseidon2_permutations",
)

DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
TARGET_RE = re.compile(r"[a-z0-9][a-z0-9_]{0,63}\Z")
MAX_U64 = (1 << 64) - 1
MAX_SAMPLES = 256
BENCHMARK_BACKENDS = frozenset({"cpu", "metal"})

METRIC_KEYS = frozenset({"status", "value", "unit", "method", "source", "reason"})
WORKLOAD_KEYS = frozenset(
    {
        "target",
        "input_size",
        "input_sha256",
        "guest_sha256",
        "expected_output_digest",
        "public_values_sha256",
        "statement_sha256",
    }
)
BOUNDARY_KEYS = frozenset(
    {
        "base_proof_produced",
        "base_proof_verified",
        "recursive_proof_produced",
        "recursive_proof_verified",
        "full_pipeline",
    }
)
RECURSIVE_REPORT_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "plan_digest",
        "cohort_id",
        "host_identity_sha256",
        "host",
        "producer",
        "security",
        "boundary",
        "samples",
        "limitations",
        "canonical_digest",
    }
)
PRODUCER_KEYS = frozenset(
    {
        "implementation_commit",
        "implementation_tree",
        "implementation_dirty",
        "executable_sha256",
        "backend",
        "optimization_mode",
        "warmups",
        "measured_samples",
        "serial_execution",
        "automatic_retries",
        "outlier_drops",
        "timing_statistic",
        "timer_source",
        "poseidon_counter_scope",
        "compiler_version",
        "target_triple",
        "rss_scope",
        "attempt_isolation",
        "invocation",
        "invocation_sha256",
        "artifact_contract",
        "captured_at",
    }
)
SAMPLE_KEYS = frozenset(
    {
        "workload_id",
        "workload",
        "status",
        "artifact",
        "attempts",
        "phases",
        "aggregates",
    }
)
INVOCATION_KEYS = frozenset({"argv", "working_directory", "environment"})
ARTIFACT_CONTRACT_KEYS = frozenset(
    {
        "artifact_kind",
        "artifact_schema_version",
        "exchange_mode",
        "payload_encoding",
        "payload_scope",
        "verification_receipt_schema",
    }
)
ARTIFACT_KEYS = ARTIFACT_CONTRACT_KEYS | frozenset(
    {
        "payload_sha256",
        "payload_bytes",
        "artifact_sha256",
        "artifact_bytes",
    }
)
RECURSIVE_ARTIFACT_CONTRACT = {
    "artifact_kind": "stwo_riscv_recursive_proof",
    "artifact_schema_version": 1,
    "exchange_mode": "fixed_recursive_proof_wire_v1",
    "payload_encoding": "postcard",
    "payload_scope": "recursive_proof_payload_excluding_json_envelope",
    "verification_receipt_schema": "riscv_recursive_verify_v1",
}
ATTEMPT_KEYS = frozenset(
    {
        "ordinal",
        "classification",
        "status",
        "workload_id",
        "artifact",
        "verification_receipt",
        "phases",
        "verified_end_to_end_ns",
    }
)
VERIFICATION_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "status",
        "workload_id",
        "artifact_sha256",
        "payload_sha256",
        "implementation_commit",
        "executable_sha256",
    }
)


def exact_object(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError(f"{label} must be an object")
    expected = frozenset(keys)
    actual = frozenset(value)
    if actual != expected:
        raise EvidenceError(
            f"{label} key set mismatch; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def expect_digest(value: Any, label: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def expect_commit(value: Any, label: str) -> str:
    if type(value) is not str or COMMIT_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a lowercase 40-hex Git identity")
    return value


def expect_positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}")
    if value > MAX_U64:
        raise EvidenceError(f"{label} exceeds the unsigned 64-bit evidence range")
    return value


def available_metric(value: int, unit: str, method: str, source: str) -> dict[str, Any]:
    return {
        "status": "available",
        "value": value,
        "unit": unit,
        "method": method,
        "source": source,
        "reason": None,
    }


def unavailable_metric(unit: str, source: str, reason: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "value": None,
        "unit": unit,
        "method": "not_exposed",
        "source": source,
        "reason": reason,
    }


def not_applicable_metric(unit: str, source: str, reason: str) -> dict[str, Any]:
    return {
        "status": "not_applicable",
        "value": None,
        "unit": unit,
        "method": "not_executed",
        "source": source,
        "reason": reason,
    }


def validate_metric(
    value: Any,
    *,
    unit: str,
    label: str,
    require_available: bool,
    available_method: str | None = None,
) -> dict[str, Any]:
    metric = exact_object(value, METRIC_KEYS, label)
    if metric["unit"] != unit:
        raise EvidenceError(f"{label}.unit must equal {unit!r}")
    if type(metric["source"]) is not str or not metric["source"]:
        raise EvidenceError(f"{label}.source must be a non-empty string")
    status = metric["status"]
    if require_available and status != "available":
        raise EvidenceError(f"{label} must be available for a complete recursive report")
    if status == "available":
        default_methods = {
            "ns": "producer_internal_monotonic_timer",
            "bytes": "canonical_artifact_length",
            "permutations": "instrumented_exact_counter",
        }
        expected_method = available_method or default_methods[unit]
        if metric["method"] != expected_method:
            raise EvidenceError(f"{label}.method is not admissible for {unit}")
        expect_positive_int(
            metric["value"],
            f"{label}.value",
            allow_zero=unit == "permutations",
        )
        if metric["reason"] is not None:
            raise EvidenceError(f"{label}.reason must be null when available")
    elif status in {"unavailable", "not_applicable"}:
        expected_method = "not_exposed" if status == "unavailable" else "not_executed"
        if metric["value"] is not None or metric["method"] != expected_method:
            raise EvidenceError(f"{label} has contradictory {status} fields")
        if type(metric["reason"]) is not str or not metric["reason"]:
            raise EvidenceError(f"{label}.reason must explain why it is {status}")
    else:
        raise EvidenceError(f"{label}.status is unsupported")
    return metric


def validate_workload(value: Any, *, label: str) -> dict[str, Any]:
    workload = exact_object(value, WORKLOAD_KEYS, label)
    if (
        type(workload["target"]) is not str
        or TARGET_RE.fullmatch(workload["target"]) is None
    ):
        raise EvidenceError(f"{label}.target is not a canonical target identifier")
    expect_positive_int(workload["input_size"], f"{label}.input_size")
    for key in (
        "input_sha256",
        "guest_sha256",
        "expected_output_digest",
        "public_values_sha256",
        "statement_sha256",
    ):
        expect_digest(workload[key], f"{label}.{key}")
    return workload


def validate_phase_metrics(
    value: Any,
    *,
    label: str,
    require_available: bool,
) -> dict[str, Any]:
    phases = exact_object(value, PHASES, label)
    for phase in PHASES:
        record = exact_object(
            phases[phase],
            {"duration_ns", "poseidon2_permutations"},
            f"{label}.{phase}",
        )
        validate_metric(
            record["duration_ns"],
            unit="ns",
            label=f"{label}.{phase}.duration_ns",
            require_available=require_available,
        )
        validate_metric(
            record["poseidon2_permutations"],
            unit="permutations",
            label=f"{label}.{phase}.poseidon2_permutations",
            require_available=require_available,
        )
    return phases


def validate_aggregates(
    value: Any,
    *,
    label: str,
    require_available: bool,
) -> dict[str, Any]:
    aggregates = exact_object(value, AGGREGATES, label)
    for name in AGGREGATES:
        if name.endswith("_ns"):
            unit = "ns"
        elif name.endswith("_bytes"):
            unit = "bytes"
        else:
            unit = "permutations"
        validate_metric(
            aggregates[name],
            unit=unit,
            label=f"{label}.{name}",
            require_available=require_available,
            available_method=(
                "os_process_lifetime_peak"
                if name == "peak_rss_bytes"
                else None
            ),
        )
    return aggregates


def _sum_metric(phases: dict[str, Any], names: Iterable[str], metric: str) -> int:
    return sum(phases[name][metric]["value"] for name in names)


def _rounded_mean(values: list[int]) -> int:
    if not values:
        raise EvidenceError("cannot summarize an empty measured-sample set")
    # Positive integer half-up rounding is deliberately independent of host
    # floating-point behavior and Python's bankers-rounding convention.
    return (sum(values) + len(values) // 2) // len(values)


def validate_artifact_contract(value: Any, *, label: str) -> dict[str, Any]:
    contract = exact_object(value, ARTIFACT_CONTRACT_KEYS, label)
    for key in (
        "artifact_kind",
        "exchange_mode",
        "payload_encoding",
        "payload_scope",
        "verification_receipt_schema",
    ):
        if type(contract[key]) is not str or not contract[key]:
            raise EvidenceError(f"{label}.{key} must be a non-empty string")
    expect_positive_int(
        contract["artifact_schema_version"],
        f"{label}.artifact_schema_version",
    )
    return contract


def validate_artifact(
    value: Any,
    *,
    contract: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    artifact = exact_object(value, ARTIFACT_KEYS, label)
    validate_artifact_contract(contract, label=f"{label}.contract")
    for key in ARTIFACT_CONTRACT_KEYS:
        if artifact[key] != contract[key]:
            raise EvidenceError(f"{label}.{key} differs from the producer contract")
    expect_digest(artifact["payload_sha256"], f"{label}.payload_sha256")
    expect_positive_int(artifact["payload_bytes"], f"{label}.payload_bytes")
    expect_digest(artifact["artifact_sha256"], f"{label}.artifact_sha256")
    expect_positive_int(artifact["artifact_bytes"], f"{label}.artifact_bytes")
    if artifact["artifact_bytes"] < artifact["payload_bytes"]:
        raise EvidenceError(f"{label}.artifact_bytes cannot be smaller than its payload")
    return artifact


def validate_invocation(value: Any, *, label: str) -> dict[str, Any]:
    invocation = exact_object(value, INVOCATION_KEYS, label)
    argv = invocation["argv"]
    if type(argv) is not list or not argv or any(
        type(item) is not str or not item for item in argv
    ):
        raise EvidenceError(f"{label}.argv must be a non-empty string array")
    secret_flags = ("--token", "--secret", "--password", "--api-key", "--private-key")
    if any(
        any(marker in item.casefold() for marker in secret_flags) for item in argv
    ):
        raise EvidenceError(f"{label}.argv contains a secret-like argument")
    if invocation["working_directory"] != ".":
        raise EvidenceError(f"{label}.working_directory must be repository root '.'")
    environment = invocation["environment"]
    if type(environment) is not dict or any(
        type(key) is not str
        or not key
        or type(item) is not str
        for key, item in environment.items()
    ):
        raise EvidenceError(f"{label}.environment must be a string map")
    forbidden = (
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    )
    for key in environment:
        if any(marker in key.upper() for marker in forbidden):
            raise EvidenceError(f"{label}.environment contains secret-like key {key!r}")
    return invocation


def validate_recursive_report(
    report: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Admit only complete, internally timed and exactly counted recursion runs."""

    exact_object(report, RECURSIVE_REPORT_KEYS, "recursive report")
    if (
        report["schema"] != RECURSIVE_REPORT_SCHEMA
        or type(report["schema_version"]) is not int
        or report["schema_version"] != SCHEMA_VERSION
    ):
        raise EvidenceError("recursive report schema identity drifted")
    if report["classification"] != REPORT_CLASSIFICATION:
        raise EvidenceError("recursive report classification drifted")
    verify_document_seal(report, label="recursive report")
    expect_digest(report["plan_digest"], "recursive report.plan_digest")
    expect_digest(report["cohort_id"], "recursive report.cohort_id")
    expect_digest(
        report["host_identity_sha256"],
        "recursive report.host_identity_sha256",
    )
    if type(report["host"]) is not dict or not report["host"]:
        raise EvidenceError("recursive report.host must be a non-empty object")
    if content_digest(report["host"]) != report["host_identity_sha256"]:
        raise EvidenceError("recursive report host identity digest drifted")

    producer = exact_object(report["producer"], PRODUCER_KEYS, "recursive report.producer")
    expect_commit(producer["implementation_commit"], "producer.implementation_commit")
    expect_commit(producer["implementation_tree"], "producer.implementation_tree")
    if producer["implementation_dirty"] is not False:
        raise EvidenceError("recursive report producer must be a clean build")
    expect_digest(producer["executable_sha256"], "producer.executable_sha256")
    if (
        type(producer["backend"]) is not str
        or producer["backend"] not in BENCHMARK_BACKENDS
    ):
        raise EvidenceError("recursive report producer backend is invalid")
    if producer["optimization_mode"] != "ReleaseFast":
        raise EvidenceError("recursive report producer must be built in ReleaseFast mode")
    captured_at = producer["captured_at"]
    if type(captured_at) is not str:
        raise EvidenceError("recursive report captured_at is missing")
    try:
        captured = dt.datetime.fromisoformat(captured_at)
    except ValueError as error:
        raise EvidenceError("recursive report captured_at is not ISO-8601") from error
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise EvidenceError("recursive report captured_at must include a UTC offset")
    expect_positive_int(producer["warmups"], "producer.warmups")
    expect_positive_int(producer["measured_samples"], "producer.measured_samples")
    if producer["warmups"] > MAX_SAMPLES:
        raise EvidenceError("recursive report producer has too many warmups")
    if not 3 <= producer["measured_samples"] <= MAX_SAMPLES:
        raise EvidenceError("recursive report producer requires at least three measured samples")
    if producer["serial_execution"] is not True:
        raise EvidenceError("recursive report measurements must execute serially")
    if (
        type(producer["automatic_retries"]) is not int
        or producer["automatic_retries"] != 0
        or type(producer["outlier_drops"]) is not int
        or producer["outlier_drops"] != 0
    ):
        raise EvidenceError("recursive report cannot hide retries or drop outliers")
    if (
        producer["timing_statistic"]
        != "arithmetic_mean_of_verified_samples_rounded_ns"
    ):
        raise EvidenceError("recursive report timing statistic is unsupported")
    if producer["timer_source"] != "producer_internal_monotonic_timer":
        raise EvidenceError("recursive report timer source is unsupported")
    if (
        producer["poseidon_counter_scope"]
        != "phase_scoped_instrumented_exact_counter"
    ):
        raise EvidenceError("recursive report Poseidon counter is not exact and phase scoped")
    if type(producer["compiler_version"]) is not str or not producer["compiler_version"]:
        raise EvidenceError("recursive report compiler version is missing")
    if type(producer["target_triple"]) is not str or not producer["target_triple"]:
        raise EvidenceError("recursive report target triple is missing")
    if (
        producer["rss_scope"]
        != "self_process_lifetime_peak_across_warmups_and_verified_samples_including_verification"
    ):
        raise EvidenceError("recursive report peak-RSS scope is not comparable")
    if (
        producer["attempt_isolation"]
        != "fresh_process_per_workload_serial_attempts_same_process"
    ):
        raise EvidenceError("recursive report attempt isolation is unsupported")
    invocation = validate_invocation(
        producer["invocation"], label="recursive report.producer.invocation"
    )
    expect_digest(
        producer["invocation_sha256"],
        "recursive report.producer.invocation_sha256",
    )
    if content_digest(invocation) != producer["invocation_sha256"]:
        raise EvidenceError("recursive report invocation digest drifted")
    artifact_contract = validate_artifact_contract(
        producer["artifact_contract"],
        label="recursive report.producer.artifact_contract",
    )
    if artifact_contract != RECURSIVE_ARTIFACT_CONTRACT:
        raise EvidenceError("recursive report artifact contract is unsupported")

    boundary = exact_object(report["boundary"], BOUNDARY_KEYS, "recursive report.boundary")
    if any(boundary[key] is not True for key in BOUNDARY_KEYS):
        raise EvidenceError(
            "recursive report may claim results only for a complete verified pipeline"
        )
    if (
        type(report["security"]) is not dict
        or report["security"].get("profile") != "secure"
    ):
        raise EvidenceError("recursive report.security must select the secure profile")
    if type(report["limitations"]) is not list or not report["limitations"] or any(
        type(item) is not str or not item for item in report["limitations"]
    ):
        raise EvidenceError("recursive report.limitations must be a non-empty string array")
    if (
        type(report["samples"]) is not list
        or not report["samples"]
        or len(report["samples"]) > MAX_SAMPLES
    ):
        raise EvidenceError(
            f"recursive report.samples must contain between 1 and {MAX_SAMPLES} rows"
        )

    expected_workloads: dict[str, dict[str, Any]] | None = None
    expected_peak_sources: dict[str, dict[str, Any]] | None = None
    if plan is not None:
        if report["plan_digest"] != plan["canonical_digest"]:
            raise EvidenceError("recursive report is bound to a different plan")
        for key in ("cohort_id", "host_identity_sha256", "security"):
            if report[key] != plan[key if key != "security" else "native_security"]:
                raise EvidenceError(f"recursive report {key} differs from the plan")
        if report["host"] != plan["native_host"]:
            raise EvidenceError("recursive report host differs from the native plan")
        native_backends = {sample["backend"] for sample in plan["native_samples"]}
        if native_backends != {producer["backend"]}:
            raise EvidenceError("recursive report backend differs from the native plan")
        native_warmups = plan["native_run"].get("warmups")
        native_samples = plan["native_run"].get("samples")
        if (
            producer["warmups"] != native_warmups
            or producer["measured_samples"] != native_samples
        ):
            raise EvidenceError(
                "recursive report warmup/sample counts differ from the native plan"
            )
        expected_workloads = {
            sample["workload_id"]: sample["workload"] for sample in plan["native_samples"]
        }
        expected_peak_sources = {
            sample["workload_id"]: sample["aggregates"]["peak_rss_bytes"]
            for sample in plan["native_samples"]
        }

    seen: set[str] = set()
    for index, raw_sample in enumerate(report["samples"]):
        label = f"recursive report.samples[{index}]"
        sample = exact_object(raw_sample, SAMPLE_KEYS, label)
        if (
            type(sample["workload_id"]) is not str
            or DIGEST_RE.fullmatch(sample["workload_id"]) is None
        ):
            raise EvidenceError(f"{label}.workload_id is invalid")
        if sample["workload_id"] in seen:
            raise EvidenceError(f"{label}.workload_id is duplicated")
        seen.add(sample["workload_id"])
        workload = validate_workload(sample["workload"], label=f"{label}.workload")
        if sample["workload_id"] != content_digest(workload):
            raise EvidenceError(f"{label}.workload_id does not bind its workload")
        if sample["status"] != "verified":
            raise EvidenceError(f"{label}.status must equal 'verified'")
        artifact = validate_artifact(
            sample["artifact"],
            contract=artifact_contract,
            label=f"{label}.artifact",
        )
        attempts = sample["attempts"]
        expected_attempt_count = producer["warmups"] + producer["measured_samples"]
        if type(attempts) is not list or len(attempts) != expected_attempt_count:
            raise EvidenceError(
                f"{label}.attempts must contain exactly {expected_attempt_count} attempts"
            )
        measured_attempts: list[dict[str, Any]] = []
        for ordinal, raw_attempt in enumerate(attempts):
            attempt_label = f"{label}.attempts[{ordinal}]"
            attempt = exact_object(raw_attempt, ATTEMPT_KEYS, attempt_label)
            if attempt["ordinal"] != ordinal:
                raise EvidenceError(f"{attempt_label}.ordinal is not contiguous")
            expected_classification = (
                "excluded_warmup"
                if ordinal < producer["warmups"]
                else "measured"
            )
            if attempt["classification"] != expected_classification:
                raise EvidenceError(
                    f"{attempt_label}.classification does not match the pinned schedule"
                )
            if attempt["status"] != "verified":
                raise EvidenceError(f"{attempt_label}.status must equal 'verified'")
            if attempt["workload_id"] != sample["workload_id"]:
                raise EvidenceError(f"{attempt_label} is bound to a different workload")
            attempt_artifact = validate_artifact(
                attempt["artifact"],
                contract=artifact_contract,
                label=f"{attempt_label}.artifact",
            )
            if attempt_artifact["payload_bytes"] != artifact["payload_bytes"]:
                raise EvidenceError(f"{attempt_label} proof byte length drifted")
            receipt = exact_object(
                attempt["verification_receipt"],
                VERIFICATION_RECEIPT_KEYS,
                f"{attempt_label}.verification_receipt",
            )
            expected_receipt = {
                "schema": artifact_contract["verification_receipt_schema"],
                "status": "verified",
                "workload_id": sample["workload_id"],
                "artifact_sha256": attempt_artifact["artifact_sha256"],
                "payload_sha256": attempt_artifact["payload_sha256"],
                "implementation_commit": producer["implementation_commit"],
                "executable_sha256": producer["executable_sha256"],
            }
            if receipt != expected_receipt:
                raise EvidenceError(
                    f"{attempt_label}.verification_receipt does not bind the attempt"
                )
            attempt_phases = validate_phase_metrics(
                attempt["phases"],
                label=f"{attempt_label}.phases",
                require_available=True,
            )
            end_to_end_ns = expect_positive_int(
                attempt["verified_end_to_end_ns"],
                f"{attempt_label}.verified_end_to_end_ns",
            )
            phase_sum_ns = sum(
                attempt_phases[phase]["duration_ns"]["value"] for phase in PHASES
            )
            if end_to_end_ns < phase_sum_ns:
                raise EvidenceError(
                    f"{attempt_label}.verified_end_to_end_ns is smaller than its phase sum"
                )
            if expected_classification == "measured":
                measured_attempts.append(
                    {"artifact": attempt_artifact, "phases": attempt_phases}
                )
        if measured_attempts[-1]["artifact"] != artifact:
            raise EvidenceError(
                f"{label}.artifact must equal the final measured verified artifact"
            )
        phases = validate_phase_metrics(
            sample["phases"],
            label=f"{label}.phases",
            require_available=True,
        )
        aggregates = validate_aggregates(
            sample["aggregates"], label=f"{label}.aggregates", require_available=True
        )

        expected_end_to_end = _rounded_mean(
            [attempt["verified_end_to_end_ns"] for attempt in attempts[producer["warmups"] :]]
        )
        if aggregates["verified_end_to_end_ns"]["value"] != expected_end_to_end:
            raise EvidenceError(f"{label} verified end-to-end timing mean drifted")

        for phase in PHASES:
            measured_durations = [
                attempt["phases"][phase]["duration_ns"]["value"]
                for attempt in measured_attempts
            ]
            if phases[phase]["duration_ns"]["value"] != _rounded_mean(
                measured_durations
            ):
                raise EvidenceError(f"{label}.{phase} duration mean drifted")
            measured_calls = [
                attempt["phases"][phase]["poseidon2_permutations"]["value"]
                for attempt in measured_attempts
            ]
            if len(set(measured_calls)) != 1:
                raise EvidenceError(
                    f"{label}.{phase} Poseidon count differs across attempts"
                )
            if phases[phase]["poseidon2_permutations"]["value"] != measured_calls[0]:
                raise EvidenceError(f"{label}.{phase} Poseidon summary drifted")

        expected_generation = _sum_metric(phases, GENERATION_PHASES, "duration_ns")
        if aggregates["published_proof_generation_ns"]["value"] != expected_generation:
            raise EvidenceError(f"{label} proof-generation timing partition drifted")
        expected_verification = _sum_metric(phases, VERIFICATION_PHASES, "duration_ns")
        if aggregates["published_proof_verification_ns"]["value"] != expected_verification:
            raise EvidenceError(f"{label} proof-verification timing partition drifted")
        expected_generation_calls = _sum_metric(
            phases, GENERATION_PHASES, "poseidon2_permutations"
        )
        if (
            aggregates["proof_generation_poseidon2_permutations"]["value"]
            != expected_generation_calls
        ):
            raise EvidenceError(f"{label} proof-generation Poseidon partition drifted")
        expected_verification_calls = _sum_metric(
            phases, VERIFICATION_PHASES, "poseidon2_permutations"
        )
        if (
            aggregates["proof_verification_poseidon2_permutations"]["value"]
            != expected_verification_calls
        ):
            raise EvidenceError(f"{label} proof-verification Poseidon partition drifted")
        if aggregates["published_proof_bytes"]["value"] != artifact["payload_bytes"]:
            raise EvidenceError(f"{label} published proof byte length drifted")
        if expected_peak_sources is not None:
            native_peak = expected_peak_sources.get(sample["workload_id"])
            if (
                native_peak is not None
                and native_peak["status"] == "available"
                and aggregates["peak_rss_bytes"]["source"] != native_peak["source"]
            ):
                raise EvidenceError(f"{label} peak-RSS source differs from the native plan")
        if expected_workloads is not None:
            expected = expected_workloads.get(sample["workload_id"])
            if expected is None or workload != expected:
                raise EvidenceError(f"{label} is not an exact planned workload")

    if expected_workloads is not None and seen != set(expected_workloads):
        raise EvidenceError("recursive report does not contain the plan's exact workload set")
    return report
