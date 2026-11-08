"""Strict integer-only adaptation of native CSP reports."""

from __future__ import annotations

import datetime as dt
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from .codec import EvidenceError, content_digest
from .contract import (
    AGGREGATES,
    BENCHMARK_BACKENDS,
    MAX_SAMPLES,
    PHASES,
    REPORT_CLASSIFICATION,
    SCHEMA_VERSION,
    available_metric,
    expect_commit,
    expect_digest,
    expect_positive_int,
    not_applicable_metric,
    unavailable_metric,
    validate_artifact,
    validate_workload,
)
from .native_contract import MAX_PHASE_SECONDS, NATIVE_SCHEMAS, NATIVE_TIMING_SOURCE


def _plain_json(value: Any, label: str) -> Any:
    """Copy a source subtree while rejecting floating-point benchmark identity."""

    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is list:
        return [_plain_json(item, f"{label}[]") for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise EvidenceError(f"{label} contains a non-string key")
        return {key: _plain_json(item, f"{label}.{key}") for key, item in value.items()}
    raise EvidenceError(f"{label} contains unsupported value type {type(value).__name__}")


def _seconds(value: Any, label: str) -> Decimal:
    if type(value) is int:
        result = Decimal(value)
    elif type(value) is Decimal:
        result = value
    else:
        raise EvidenceError(f"{label} must be a JSON number")
    if not result.is_finite() or result <= 0:
        raise EvidenceError(f"{label} must be finite and positive")
    if result > MAX_PHASE_SECONDS:
        raise EvidenceError(f"{label} exceeds the one-day phase bound")
    return result


def _round_ns(value: Decimal) -> int:
    return int(
        (value * Decimal(1_000_000_000)).to_integral_value(rounding=ROUND_HALF_UP)
    )


def _rounded_mean(values: list[int]) -> int:
    if not values:
        raise EvidenceError("cannot summarize an empty native sample series")
    return (sum(values) + len(values) // 2) // len(values)


def _native_end_to_end_samples(
    report: dict[str, Any], row: dict[str, Any], label: str
) -> list[int]:
    run = report.get("run")
    timing = row.get("timing")
    if type(run) is not dict or type(timing) is not dict:
        raise EvidenceError(f"{label} has no run/timing metadata")
    measured = expect_positive_int(run.get("samples"), "native report.run.samples")
    raw_series = timing.get("verified_end_to_end_sample_seconds")
    if type(raw_series) is not list or len(raw_series) != measured:
        raise EvidenceError(f"{label} verified end-to-end sample series drifted")
    return [
        _round_ns(_seconds(value, f"{label}.sample[{index}]"))
        for index, value in enumerate(raw_series)
    ]


def _row_protocol(report: dict[str, Any], row: dict[str, Any], label: str) -> None:
    security = report.get("security")
    protocol = row.get("protocol")
    if type(security) is not dict or type(protocol) is not dict:
        raise EvidenceError(f"{label} has no security/protocol object")
    if security.get("profile") != "secure" or protocol.get("name") != "secure":
        raise EvidenceError(f"{label} is not a secure-profile measurement")
    if protocol.get("pcs_config") != security.get("pcs_config"):
        raise EvidenceError(f"{label} PCS configuration differs from its report")


def _native_workload(row: dict[str, Any], label: str) -> dict[str, Any]:
    evidence = row.get("evidence")
    if type(evidence) is not dict:
        raise EvidenceError(f"{label}.evidence must be an object")
    if evidence.get("status") != "verified":
        raise EvidenceError(f"{label} is not verified")
    if evidence.get("output_digest") != evidence.get("expected_output_digest"):
        raise EvidenceError(f"{label} output differs from its expected digest")
    workload = {
        "target": row.get("target"),
        "input_size": row.get("input_size"),
        "input_sha256": evidence.get("input_sha256"),
        "guest_sha256": evidence.get("guest_sha256"),
        "expected_output_digest": evidence.get("expected_output_digest"),
        "public_values_sha256": evidence.get("public_values_sha256"),
        "statement_sha256": evidence.get("statement_sha256"),
    }
    return validate_workload(workload, label=f"{label}.workload")


def _native_phases_and_aggregates(
    report: dict[str, Any], row: dict[str, Any], label: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    timing = row.get("timing")
    if type(timing) is not dict:
        raise EvidenceError(f"{label}.timing must be an object")
    if timing.get("source") != NATIVE_TIMING_SOURCE:
        raise EvidenceError(f"{label} timing is not from production internal stage timers")
    if timing.get("proof_definition") != "execution + witness + proof generation":
        raise EvidenceError(f"{label} proof-duration definition drifted")
    if timing.get("verify_definition") != "production proof verification":
        raise EvidenceError(f"{label} verification definition drifted")

    raw = {
        "guest_execution": _seconds(
            timing.get("mean_execution_seconds"), f"{label}.mean_execution_seconds"
        ),
        "base_witness": _seconds(
            timing.get("mean_witness_seconds"), f"{label}.mean_witness_seconds"
        ),
        "base_prove": _seconds(
            timing.get("mean_proving_seconds"), f"{label}.mean_proving_seconds"
        ),
        "base_verify": _seconds(
            timing.get("mean_verification_seconds"), f"{label}.mean_verification_seconds"
        ),
    }
    proof_duration = expect_positive_int(row.get("proof_duration"), f"{label}.proof_duration")
    verify_duration = expect_positive_int(row.get("verify_duration"), f"{label}.verify_duration")
    if abs(
        proof_duration
        - _round_ns(raw["guest_execution"] + raw["base_witness"] + raw["base_prove"])
    ) > 1:
        raise EvidenceError(f"{label} proof_duration disagrees with internal phase means")
    if abs(verify_duration - _round_ns(raw["base_verify"])) > 1:
        raise EvidenceError(f"{label} verify_duration disagrees with its internal phase mean")

    # Preserve the producer's aggregate exactly. Rounding each mean independently
    # can leave a one-nanosecond residual, assigned deterministically to base_prove.
    execution_ns = _round_ns(raw["guest_execution"])
    witness_ns = _round_ns(raw["base_witness"])
    prove_ns = proof_duration - execution_ns - witness_ns
    if prove_ns <= 0 or abs(prove_ns - _round_ns(raw["base_prove"])) > 1:
        raise EvidenceError(f"{label} phase-rounding residual is not bounded")
    native_duration = {
        "guest_execution": execution_ns,
        "base_witness": witness_ns,
        "base_prove": prove_ns,
        "base_verify": verify_duration,
    }
    poseidon_reason = (
        "the native CSP producer does not expose phase-scoped Poseidon2 permutation counts; "
        "num_constraints is an unrelated AIR-constraint field and is never used as a "
        "Poseidon counter"
    )
    phases: dict[str, Any] = {}
    for phase in PHASES:
        if phase in native_duration:
            duration = available_metric(
                native_duration[phase],
                "ns",
                "producer_internal_monotonic_timer",
                NATIVE_TIMING_SOURCE,
            )
            calls = unavailable_metric("permutations", "native CSP report", poseidon_reason)
        else:
            reason = "the legacy native proof path does not execute recursive phases"
            duration = not_applicable_metric("ns", "legacy native proof path", reason)
            calls = not_applicable_metric("permutations", "legacy native proof path", reason)
        phases[phase] = {
            "duration_ns": duration,
            "poseidon2_permutations": calls,
        }

    proof_size = expect_positive_int(row.get("proof_size"), f"{label}.proof_size")
    peak_memory = row.get("peak_memory")
    memory = row.get("memory")
    if peak_memory is None:
        peak_metric = unavailable_metric(
            "bytes",
            "native CSP report",
            "the native producer explicitly reported peak memory as unavailable",
        )
    else:
        peak_value = expect_positive_int(peak_memory, f"{label}.peak_memory")
        if (
            type(memory) is not dict
            or memory.get("scope")
            != "self-process lifetime peak across verified samples"
            or memory.get("includes_mandatory_self_verification") is not True
            or type(memory.get("source")) is not str
            or not memory["source"]
        ):
            raise EvidenceError(f"{label}.memory peak-RSS scope is not comparable")
        peak_metric = available_metric(
            peak_value,
            "bytes",
            "os_process_lifetime_peak",
            memory["source"],
        )
    aggregates = {
        "verified_end_to_end_ns": available_metric(
            _rounded_mean(_native_end_to_end_samples(report, row, label)),
            "ns",
            "producer_internal_monotonic_timer",
            NATIVE_TIMING_SOURCE,
        ),
        "published_proof_generation_ns": available_metric(
            proof_duration,
            "ns",
            "producer_internal_monotonic_timer",
            NATIVE_TIMING_SOURCE,
        ),
        "published_proof_verification_ns": available_metric(
            verify_duration,
            "ns",
            "producer_internal_monotonic_timer",
            NATIVE_TIMING_SOURCE,
        ),
        "published_proof_bytes": available_metric(
            proof_size,
            "bytes",
            "canonical_artifact_length",
            "canonical Postcard proof bytes excluding JSON framing",
        ),
        "peak_rss_bytes": peak_metric,
        "proof_generation_poseidon2_permutations": unavailable_metric(
            "permutations", "native CSP report", poseidon_reason
        ),
        "proof_verification_poseidon2_permutations": unavailable_metric(
            "permutations", "native CSP report", poseidon_reason
        ),
    }
    return phases, aggregates


def _native_evidence(
    report: dict[str, Any], row: dict[str, Any], label: str
) -> dict[str, Any]:
    evidence = row["evidence"]
    receipt = evidence.get("retained_verify_receipt")
    if type(receipt) is not dict or receipt.get("status") != "verified":
        raise EvidenceError(f"{label} has no successful retained verification receipt")
    proof_size = row["proof_size"]
    proof_digest = evidence.get("proof_sha256")
    expect_digest(proof_digest, f"{label}.proof_sha256")
    if receipt.get("proof_bytes") != proof_size or receipt.get("proof_sha256") != proof_digest:
        raise EvidenceError(f"{label} retained receipt does not bind the reported proof")
    expect_digest(evidence.get("artifact_sha256"), f"{label}.artifact_sha256")
    expect_positive_int(evidence.get("artifact_bytes"), f"{label}.artifact_bytes")
    if receipt.get("statement_sha256") != evidence.get("statement_sha256"):
        raise EvidenceError(f"{label} retained receipt does not bind the statement")
    if (
        receipt.get("implementation_commit") != report.get("measurement_commit")
        or receipt.get("implementation_dirty") is not False
    ):
        raise EvidenceError(f"{label} retained receipt has a different implementation identity")
    cycles = expect_positive_int(row.get("cycles"), f"{label}.cycles")
    return {"cycles": cycles}


def _native_artifact(
    report: dict[str, Any], row: dict[str, Any], label: str
) -> dict[str, Any]:
    evidence = row.get("evidence")
    if type(evidence) is not dict:
        raise EvidenceError(f"{label}.evidence must be an object")
    receipt = evidence.get("retained_verify_receipt")
    if type(receipt) is not dict:
        raise EvidenceError(f"{label} has no retained verification receipt")
    identities = report.get("identities")
    if type(identities) is not dict:
        raise EvidenceError(f"{label} report has no executable identities")
    executable_digest = expect_digest(
        identities.get("prover_executable_sha256"),
        "native report.identities.prover_executable_sha256",
    )
    if receipt.get("executable_sha256") != executable_digest:
        raise EvidenceError(f"{label} receipt executable identity drifted")
    if (
        receipt.get("artifact_kind") != "stwo_riscv_proof"
        or receipt.get("artifact_schema_version") != 4
        or receipt.get("schema") != "riscv_verify_v1"
    ):
        raise EvidenceError(f"{label} retained artifact schema drifted")
    contract = {
        "artifact_kind": "stwo_riscv_proof",
        "artifact_schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "payload_encoding": "postcard",
        "payload_scope": "proof_bytes_excluding_json_envelope",
        "verification_receipt_schema": "riscv_verify_v1",
    }
    artifact = {
        **contract,
        "payload_sha256": evidence.get("proof_sha256"),
        "payload_bytes": row.get("proof_size"),
        "artifact_sha256": evidence.get("artifact_sha256"),
        "artifact_bytes": evidence.get("artifact_bytes"),
    }
    return validate_artifact(artifact, contract=contract, label=f"{label}.artifact")


def _native_sampling(
    report: dict[str, Any], row: dict[str, Any], label: str
) -> dict[str, Any]:
    run = report["run"]
    warmups = expect_positive_int(run.get("warmups"), "native report.run.warmups")
    measured = expect_positive_int(run.get("samples"), "native report.run.samples")
    if measured < 3:
        raise EvidenceError("native report requires at least three measured samples")
    sample_ns = _native_end_to_end_samples(report, row, label)
    return {
        "warmups_excluded": warmups,
        "measured_samples": measured,
        "verified_samples": measured,
        "serial_execution": True,
        "attempt_order": "excluded_warmups_then_measured_samples",
        "timing_statistic": "arithmetic_mean_of_verified_samples_rounded_ns",
        "raw_phase_samples_available": False,
        "verified_end_to_end_sample_ns": sample_ns,
    }


def _native_reproducibility(report: dict[str, Any]) -> dict[str, Any]:
    captured_at = report.get("captured_at")
    if type(captured_at) is not str:
        raise EvidenceError("native report.captured_at is missing")
    try:
        captured = dt.datetime.fromisoformat(captured_at)
    except ValueError as error:
        raise EvidenceError("native report.captured_at is not ISO-8601") from error
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise EvidenceError("native report.captured_at must include a UTC offset")
    identities = report.get("identities")
    if type(identities) is not dict:
        raise EvidenceError("native report.identities must be an object")
    prover_digest = expect_digest(
        identities.get("prover_executable_sha256"),
        "native report.identities.prover_executable_sha256",
    )
    trace_digest = expect_digest(
        identities.get("trace_executable_sha256"),
        "native report.identities.trace_executable_sha256",
    )
    compiler_version = identities.get("zig_version")
    if type(compiler_version) is not str or not compiler_version:
        raise EvidenceError("native report compiler version is missing")
    build_identity = identities.get("prover_build_identity")
    if build_identity is None:
        build_status = "unavailable"
        unavailable_reason = (
            "the superseded native report schema did not publish prover_build_identity"
        )
    else:
        build_identity = _plain_json(build_identity, "native prover build identity")
        if type(build_identity) is not dict or not build_identity:
            raise EvidenceError("native prover build identity is invalid")
        if build_identity.get("optimize") != "ReleaseFast":
            raise EvidenceError("native prover was not built in ReleaseFast mode")
        build_status = "available"
        unavailable_reason = None
    return {
        "captured_at": captured_at,
        "prover_executable_sha256": prover_digest,
        "trace_executable_sha256": trace_digest,
        "compiler_version": compiler_version,
        "prover_build_identity_status": build_status,
        "prover_build_identity": build_identity,
        "prover_build_identity_unavailable_reason": unavailable_reason,
    }


def adapt_native_report(report: dict[str, Any], *, raw_sha256: str) -> dict[str, Any]:
    """Normalize only fields that the production CSP report actually measures."""

    schema = report.get("schema")
    if schema not in NATIVE_SCHEMAS:
        raise EvidenceError(f"unsupported native CSP schema: {schema!r}")
    measurement_commit = expect_commit(
        report.get("measurement_commit"), "native report.measurement_commit"
    )
    repository_head = expect_commit(
        report.get("repository_head"), "native report.repository_head"
    )
    if repository_head != measurement_commit:
        raise EvidenceError("native measurement commit differs from repository HEAD")
    suite_digest = expect_digest(
        report.get("suite_manifest_sha256"), "native report.suite_manifest_sha256"
    )
    result_class = report.get("result_class")
    if type(result_class) is not str or not result_class:
        raise EvidenceError("native report.result_class must be a non-empty string")
    host = _plain_json(report.get("host"), "native report.host")
    run = _plain_json(report.get("run"), "native report.run")
    security = _plain_json(report.get("security"), "native report.security")
    if type(host) is not dict or not host:
        raise EvidenceError("native report.host must be a non-empty object")
    if type(run) is not dict or not run:
        raise EvidenceError("native report.run must be a non-empty object")
    if run.get("recursion_enabled") is not False:
        raise EvidenceError("native report must attest recursion_enabled=false")
    if run.get("recursion_environment_prefix") != "STWO_RECURSION_":
        raise EvidenceError("native report recursion environment boundary drifted")
    removed_recursion_env = run.get("removed_recursion_environment_variables")
    if (
        type(removed_recursion_env) is not list
        or any(
            type(name) is not str or not name.startswith("STWO_RECURSION_")
            for name in removed_recursion_env
        )
        or removed_recursion_env != sorted(set(removed_recursion_env))
    ):
        raise EvidenceError("native report recursion environment evidence is invalid")
    native_warmups = expect_positive_int(
        run.get("warmups"), "native report.run.warmups"
    )
    native_samples = expect_positive_int(
        run.get("samples"), "native report.run.samples"
    )
    if native_warmups > MAX_SAMPLES:
        raise EvidenceError("native report has too many warmups")
    if not 3 <= native_samples <= MAX_SAMPLES:
        raise EvidenceError("native report requires at least three measured samples")
    if type(security) is not dict or security.get("profile") != "secure":
        raise EvidenceError("native report.security must select the secure profile")
    methodology = report.get("methodology")
    expected_methodology = {
        "proof_duration": "mean execution + witness + proof generation",
        "verify_duration": "mean production verification",
        "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
        "num_constraints": "0 means not exposed; cycles are authoritative",
        "proof_scope": "native RISC-V leaf STARK; recursion and outer proving disabled",
    }
    if type(methodology) is not dict or any(
        methodology.get(key) != expected
        for key, expected in expected_methodology.items()
    ):
        raise EvidenceError("native report methodology does not preserve CSP metric meanings")
    measurements = report.get("measurements")
    summary = report.get("summary")
    if type(summary) is not dict or summary.get("all_recursion_disabled") is not True:
        raise EvidenceError("native report summary does not attest recursion isolation")
    if (
        type(measurements) is not list
        or not measurements
        or len(measurements) > MAX_SAMPLES
    ):
        raise EvidenceError(
            f"native report.measurements must contain between 1 and {MAX_SAMPLES} rows"
        )

    default_backend = run.get("backend", "cpu")
    if type(default_backend) is not str or default_backend not in BENCHMARK_BACKENDS:
        raise EvidenceError("native report backend is invalid")
    if "backend" not in run:
        run["backend"] = default_backend
    samples: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw_row in enumerate(measurements):
        label = f"native report.measurements[{index}]"
        if type(raw_row) is not dict:
            raise EvidenceError(f"{label} must be an object")
        row = raw_row
        if row.get("system") != "stwo-zig-riscv":
            raise EvidenceError(f"{label}.system drifted")
        if row.get("recursion_enabled") is not False:
            raise EvidenceError(f"{label} enables or omits recursion isolation")
        _row_protocol(report, row, label)
        workload = _native_workload(row, label)
        workload_id = content_digest(workload)
        if workload_id in seen:
            raise EvidenceError(f"{label} duplicates a native workload")
        seen.add(workload_id)
        backend = row.get("backend", default_backend)
        if type(backend) is not str or backend not in BENCHMARK_BACKENDS:
            raise EvidenceError(f"{label}.backend is invalid")
        phases, aggregates = _native_phases_and_aggregates(report, row, label)
        samples.append(
            {
                "workload_id": workload_id,
                "workload": workload,
                "status": "verified",
                "backend": backend,
                "sampling": _native_sampling(report, row, label),
                "artifact": _native_artifact(report, row, label),
                "evidence": _native_evidence(report, row, label),
                "phases": phases,
                "aggregates": aggregates,
            }
        )
    samples.sort(key=lambda item: (item["workload"]["target"], item["workload"]["input_size"]))
    return {
        "native_source": {
            "schema": schema,
            "report_sha256": raw_sha256,
            "result_class": result_class,
            "measurement_commit": measurement_commit,
            "repository_head": repository_head,
            "suite_manifest_sha256": suite_digest,
            "reproducibility": _native_reproducibility(report),
        },
        "native_security": security,
        "native_host": host,
        "native_run": run,
        "native_samples": samples,
    }
