"""Controller for canonical CSP verifier-subsystem proof attempts.

The native child writes the only attempt record consumed here.  Standard
output is discarded, never parsed.  A successful child must leave both its
attempt JSON and byte-exact outer-child wire; a failed child must leave only a
typed failure record.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.riscv_csp_benchmark_lib.contract import (
    BenchmarkError,
    MANIFEST,
    Case,
    validate_manifest,
)

from .codec import (
    EvidenceError,
    atomic_write_new,
    canonical_bytes,
    load_json,
    seal_document,
    sha256_bytes,
)
from .contract import PHASES, exact_object, expect_digest, expect_positive_int
from .pipeline import validate_plan


REQUEST_SCHEMA = "stwo.riscv.recursion-csp-workload.v3"
ATTEMPT_SCHEMA = "stwo.riscv.recursion-csp-attempt.v3"
REPORT_SCHEMA = "stwo.riscv.recursion-csp-subsystem-report.v1"
REPORT_CLASSIFICATION = (
    "verified_verifier_subsystem_diagnostic_not_full_recursive_proof"
)
ARTIFACT_CONTRACT = {
    "artifact_kind": "stwo_riscv_recursive_outer_wire",
    "artifact_schema_version": 1,
    "exchange_mode": "fixed_outer_proof_wire_v1",
    "payload_encoding": "canonical_little_endian_fixed_wire_v1",
    "payload_scope": "verified_outer_child_wire",
    "verification_receipt_schema": "riscv_recursive_outer_verify_v1",
}
MAX_STEPS = 10_000_000
MAX_WORKERS = 256

SUCCESS_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "status",
        "classification",
        "comparison_eligible",
        "unavailable_reason",
        "request",
        "source",
        "producer",
        "security",
        "timing",
        "poseidon2_counter",
        "resources",
        "identities",
        "artifact",
        "verification_receipt",
        "outer_receipt",
        "failure",
    }
)
FAILURE_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "status",
        "classification",
        "comparison_eligible",
        "request",
        "requested_artifact_path",
        "failure",
    }
)
REQUEST_RECORD_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "request_sha256",
        "plan_digest",
        "workload_id",
        "target",
        "input_size",
        "max_steps",
    }
)
SOURCE_KEYS = frozenset(
    {
        "guest_path",
        "guest_sha256",
        "input_path",
        "input_sha256",
        "expected_output_digest",
        "expected_cycles",
        "observed_cycles",
        "native_measurement_commit",
        "expected_public_values_sha256",
        "observed_public_values_sha256",
        "native_baseline_statement_sha256",
    }
)
SECURITY_KEYS = frozenset(
    {
        "leaf_protocol",
        "outer_protocol",
        "proof_scope",
        "production_ready",
        "roster_count",
        "active_verifier_rows",
        "active_provider_rows",
        "recursive_profile_id",
        "recursive_profile_shape_sha256",
        "profile_registry_sha256",
        "profile_dispatch_status",
    }
)
PHASE_KEYS = frozenset({"duration_ns", "poseidon2_permutations"})


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _relative_source(path: Path, repo_root: Path, label: str) -> str:
    try:
        return path.resolve(strict=True).relative_to(repo_root.resolve()).as_posix()
    except (OSError, ValueError) as error:
        raise EvidenceError(f"{label} must be a file inside the repository") from error


def _case_index(manifest_path: Path) -> tuple[dict[tuple[str, int], Case], str]:
    try:
        _, cases, _ = validate_manifest(manifest_path)
    except (BenchmarkError, OSError, ValueError) as error:
        raise EvidenceError(f"canonical CSP manifest is invalid: {error}") from error
    indexed = {(case.target, case.input_size): case for case in cases}
    if len(indexed) != len(cases):
        raise EvidenceError("canonical CSP manifest contains duplicate workloads")
    return indexed, _sha256_file(manifest_path)


def build_workload_request(
    plan: dict[str, Any],
    native_sample: dict[str, Any],
    case: Case,
    *,
    repo_root: Path,
    worker_count: int,
) -> dict[str, Any]:
    """Project one sealed plan row into the child's exact request schema."""

    if type(worker_count) is not int or not 1 <= worker_count <= MAX_WORKERS:
        raise EvidenceError(f"worker_count must be in [1, {MAX_WORKERS}]")
    workload = native_sample["workload"]
    if (case.target, case.input_size) != (
        workload["target"],
        workload["input_size"],
    ):
        raise EvidenceError("manifest case differs from the planned workload")
    expected = {
        "input_sha256": case.input_sha256,
        "guest_sha256": case.guest_sha256,
        "expected_output_digest": case.expected_digest,
        "cycles": case.expected_cycles,
    }
    observed = {
        "input_sha256": workload["input_sha256"],
        "guest_sha256": workload["guest_sha256"],
        "expected_output_digest": workload["expected_output_digest"],
        "cycles": native_sample["evidence"]["cycles"],
    }
    if observed != expected:
        raise EvidenceError("canonical manifest case differs from the sealed native row")
    coverage = plan.get("recursive_shape_coverage")
    if type(coverage) is not dict or type(coverage.get("cases")) is not list:
        raise EvidenceError("sealed plan has no recursive profile selection")
    matching_profiles = [
        row
        for row in coverage["cases"]
        if type(row) is dict and row.get("workload_id") == native_sample["workload_id"]
    ]
    if len(matching_profiles) != 1:
        raise EvidenceError("sealed plan does not uniquely select a recursive profile")
    selected = matching_profiles[0].get("selected_profile")
    registry = coverage.get("profile_registry")
    if (
        type(selected) is not dict
        or type(selected.get("profile_id")) is not str
        or not selected["profile_id"]
        or type(registry) is not dict
    ):
        raise EvidenceError("sealed plan recursive profile identity is incomplete")
    profile_shape_sha256 = expect_digest(
        selected.get("profile_shape_sha256"), "selected recursive profile"
    )
    registry_sha256 = expect_digest(
        registry.get("registry_sha256"), "recursive profile registry"
    )
    return {
        "schema": REQUEST_SCHEMA,
        "schema_version": 3,
        "plan_digest": plan["canonical_digest"],
        "workload_id": native_sample["workload_id"],
        "target": workload["target"],
        "input_size": workload["input_size"],
        "guest_path": _relative_source(case.guest_path, repo_root, "guest"),
        "guest_sha256": case.guest_sha256,
        "input_path": _relative_source(case.input_path, repo_root, "input"),
        "input_sha256": case.input_sha256,
        "expected_output_digest": case.expected_digest,
        "expected_cycles": case.expected_cycles,
        "native_measurement_commit": plan["native_source"]["measurement_commit"],
        "expected_public_values_sha256": workload["public_values_sha256"],
        "native_statement_sha256": workload["statement_sha256"],
        "expected_recursive_profile_id": selected["profile_id"],
        "expected_recursive_profile_shape_sha256": profile_shape_sha256,
        "expected_profile_registry_sha256": registry_sha256,
        "worker_count": worker_count,
        "max_steps": MAX_STEPS,
    }


def _validate_success_attempt(
    attempt: dict[str, Any],
    *,
    request: dict[str, Any],
    request_raw: bytes,
    artifact_path: Path,
    producer_sha256: str,
) -> dict[str, Any]:
    exact_object(attempt, SUCCESS_KEYS, "canonical producer attempt")
    if (
        attempt["schema"] != ATTEMPT_SCHEMA
        or attempt["schema_version"] != 3
        or attempt["status"] != "verified"
        or attempt["classification"] != "verified_verifier_subsystem_diagnostic"
        or attempt["comparison_eligible"] is not False
        or type(attempt["unavailable_reason"]) is not str
        or not attempt["unavailable_reason"]
        or attempt["failure"] is not None
    ):
        raise EvidenceError("canonical producer success classification drifted")

    request_record = exact_object(
        attempt["request"], REQUEST_RECORD_KEYS, "canonical attempt.request"
    )
    expected_request_record = {
        "schema": REQUEST_SCHEMA,
        "schema_version": 3,
        "request_sha256": sha256_bytes(request_raw),
        "plan_digest": request["plan_digest"],
        "workload_id": request["workload_id"],
        "target": request["target"],
        "input_size": request["input_size"],
        "max_steps": MAX_STEPS,
    }
    if request_record != expected_request_record:
        raise EvidenceError("canonical attempt does not bind the exact request bytes")

    source = exact_object(attempt["source"], SOURCE_KEYS, "canonical attempt.source")
    expected_source = {
        "guest_path": request["guest_path"],
        "guest_sha256": request["guest_sha256"],
        "input_path": request["input_path"],
        "input_sha256": request["input_sha256"],
        "expected_output_digest": request["expected_output_digest"],
        "expected_cycles": request["expected_cycles"],
        "observed_cycles": request["expected_cycles"],
        "native_measurement_commit": request["native_measurement_commit"],
        "expected_public_values_sha256": request["expected_public_values_sha256"],
        "observed_public_values_sha256": request["expected_public_values_sha256"],
        "native_baseline_statement_sha256": request["native_statement_sha256"],
    }
    if source != expected_source:
        raise EvidenceError("canonical attempt source/statement identity drifted")

    producer = attempt["producer"]
    if type(producer) is not dict:
        raise EvidenceError("canonical attempt producer identity is missing")
    if (
        producer.get("backend") != "cpu"
        or producer.get("optimization_mode") != "ReleaseFast"
        or producer.get("worker_count") != request["worker_count"]
        or producer.get("mutation_probe_mode") != "disabled"
        or producer.get("executable_sha256") != producer_sha256
        or producer.get("implementation_commit")
        != request["native_measurement_commit"]
        or producer.get("implementation_dirty") is not False
    ):
        raise EvidenceError("canonical attempt producer execution identity drifted")
    expect_digest(producer.get("product_identity_sha256"), "producer identity")

    security = exact_object(
        attempt["security"], SECURITY_KEYS, "canonical attempt.security"
    )
    if security != {
        "leaf_protocol": "poseidon2_m31_recursion_v1",
        "outer_protocol": "poseidon2_m31_functional_outer_v1",
        "proof_scope": "verifier_subsystem",
        "production_ready": False,
        "roster_count": 36,
        "active_verifier_rows": 34,
        "active_provider_rows": 2,
        "recursive_profile_id": request["expected_recursive_profile_id"],
        "recursive_profile_shape_sha256": request[
            "expected_recursive_profile_shape_sha256"
        ],
        "profile_registry_sha256": request["expected_profile_registry_sha256"],
        "profile_dispatch_status": "outer_wired",
    }:
        raise EvidenceError("canonical attempt outer proof scope/roster drifted")

    timing = attempt["timing"]
    if type(timing) is not dict or set(timing) != {
        "clock",
        "unit",
        "partition",
        "phase_partition_complete",
        "phases",
        "phase_sum_ns",
        "unattributed_ns",
        "verified_end_to_end_ns",
    }:
        raise EvidenceError("canonical attempt timing contract drifted")
    if (
        timing["clock"] != "monotonic"
        or timing["unit"] != "nanoseconds"
        or timing["phase_partition_complete"] is not False
    ):
        raise EvidenceError("canonical attempt timer authority drifted")
    expect_positive_int(timing["verified_end_to_end_ns"], "verified end-to-end ns")
    phases = timing["phases"]
    if type(phases) is not dict or tuple(phases) != PHASES:
        raise EvidenceError("canonical attempt phase order drifted")
    phase_poseidon = 0
    phase_sum_ns = 0
    for phase_name in PHASES:
        phase = exact_object(
            phases[phase_name], PHASE_KEYS, f"canonical attempt.{phase_name}"
        )
        phase_sum_ns += expect_positive_int(
            phase["duration_ns"], f"canonical attempt.{phase_name}.duration_ns"
        )
        phase_poseidon += expect_positive_int(
            phase["poseidon2_permutations"],
            f"canonical attempt.{phase_name}.poseidon2_permutations",
            allow_zero=True,
        )
    if (
        timing["phase_sum_ns"] != phase_sum_ns
        or type(timing["unattributed_ns"]) is not int
        or timing["unattributed_ns"] < 0
        or phase_sum_ns + timing["unattributed_ns"]
        != timing["verified_end_to_end_ns"]
    ):
        raise EvidenceError("canonical attempt timing partition is not additive")

    counter = attempt["poseidon2_counter"]
    if type(counter) is not dict or counter != {
        "scope": "authenticated_recursive_air_poseidon2_rows_materialized",
        "system_wide": False,
        "exact_within_scope": True,
        "permutations": phase_poseidon,
    }:
        raise EvidenceError("canonical attempt Poseidon2 counter scope drifted")

    identities = attempt["identities"]
    if type(identities) is not dict or not identities:
        raise EvidenceError("canonical attempt identities are missing")
    for key, value in identities.items():
        expect_digest(value, f"canonical attempt.identities.{key}")

    artifact = attempt["artifact"]
    if type(artifact) is not dict:
        raise EvidenceError("canonical attempt artifact is missing")
    for key, expected in ARTIFACT_CONTRACT.items():
        if artifact.get(key) != expected:
            raise EvidenceError(f"canonical attempt artifact {key} drifted")
    payload_sha = expect_digest(artifact.get("payload_sha256"), "artifact payload")
    artifact_sha = expect_digest(artifact.get("artifact_sha256"), "artifact")
    payload_bytes = expect_positive_int(artifact.get("payload_bytes"), "payload bytes")
    artifact_bytes = expect_positive_int(artifact.get("artifact_bytes"), "artifact bytes")
    if (
        artifact.get("path") != os.fspath(artifact_path)
        or payload_sha != artifact_sha
        or payload_bytes != artifact_bytes
        or not artifact_path.is_file()
        or artifact_path.stat().st_size != artifact_bytes
        or _sha256_file(artifact_path) != artifact_sha
    ):
        raise EvidenceError("canonical attempt artifact bytes do not match its record")

    receipt = attempt["verification_receipt"]
    if type(receipt) is not dict or (
        receipt.get("schema") != ARTIFACT_CONTRACT["verification_receipt_schema"]
        or receipt.get("status") != "verified"
        or receipt.get("proof_scope") != "verifier_subsystem"
        or receipt.get("production_ready") is not False
        or receipt.get("mutation_probe_mode") != "disabled"
        or receipt.get("mutation_rejections") != 0
        or receipt.get("proof_id") != identities.get("proof_id")
    ):
        raise EvidenceError("canonical attempt verification receipt drifted")
    outer = attempt["outer_receipt"]
    if type(outer) is not dict or (
        outer.get("roster_count") != 36
        or outer.get("active_verifier_rows") != 34
        or outer.get("active_provider_rows") != 2
        or outer.get("worker_count") != request["worker_count"]
        or outer.get("mutation_probe_mode") != "disabled"
        or outer.get("mutation_rejections") != 0
        or outer.get("poseidon2_call_count") != phase_poseidon
    ):
        raise EvidenceError("canonical attempt outer receipt drifted")
    return attempt


def validate_canonical_attempt(
    attempt: dict[str, Any],
    *,
    request: dict[str, Any],
    request_raw: bytes,
    artifact_path: Path,
    producer_sha256: str,
) -> dict[str, Any]:
    """Validate either a fail-atomic child failure or a verified artifact."""

    if attempt.get("status") == "verified":
        return _validate_success_attempt(
            attempt,
            request=request,
            request_raw=request_raw,
            artifact_path=artifact_path,
            producer_sha256=producer_sha256,
        )
    exact_object(attempt, FAILURE_KEYS, "canonical producer failure")
    if (
        attempt.get("schema") != ATTEMPT_SCHEMA
        or attempt.get("schema_version") != 3
        or attempt.get("status") != "failed"
        or attempt.get("comparison_eligible") is not False
        or type(attempt.get("failure")) is not dict
        or type(attempt["failure"].get("stage")) is not str
        or type(attempt["failure"].get("error_name")) is not str
        or artifact_path.exists()
    ):
        raise EvidenceError("canonical producer failure record is contradictory")
    request_record = attempt["request"]
    if type(request_record) is not dict or (
        request_record.get("request_sha256") not in {None, sha256_bytes(request_raw)}
        or request_record.get("plan_digest") not in {None, request["plan_digest"]}
        or request_record.get("workload_id") not in {None, request["workload_id"]}
    ):
        raise EvidenceError("canonical producer failure binds a different request")
    return attempt


def collect_canonical_outer_report(
    plan: dict[str, Any],
    *,
    repo_root: Path,
    manifest_path: Path = MANIFEST,
    producer: Path,
    artifact_directory: Path,
    worker_count: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run the exact plan schedule with one fresh native process per attempt."""

    validate_plan(plan, repo_root=repo_root)
    shape_coverage = plan["recursive_shape_coverage"]
    if shape_coverage.get("all_planned_workloads_admissible") is not True:
        raise EvidenceError(
            "recursive exact-profile dispatch blocks this cohort: "
            f"{shape_coverage.get('admissible_count')}/"
            f"{shape_coverage.get('planned_case_count')} planned workloads are admissible; "
            f"{shape_coverage.get('blocking_reason')}"
        )
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise EvidenceError("timeout_seconds must be positive")
    if plan["native_run"].get("backend") != "cpu":
        raise EvidenceError("the canonical outer producer currently supports CPU plans only")
    indexed_cases, manifest_sha256 = _case_index(manifest_path.resolve())
    if manifest_sha256 != plan["native_source"]["suite_manifest_sha256"]:
        raise EvidenceError("canonical CSP manifest differs from the sealed native plan")
    producer = producer.resolve(strict=True)
    if not producer.is_file() or not os.access(producer, os.X_OK):
        raise EvidenceError("canonical CSP producer is not an executable file")
    producer_sha256 = _sha256_file(producer)
    output_root = artifact_directory.resolve()
    try:
        output_root.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        raise EvidenceError(f"cannot create fresh artifact directory: {error}") from error

    warmups = plan["native_run"]["warmups"]
    measured = plan["native_run"]["samples"]
    attempts_per_workload = warmups + measured
    environment = os.environ.copy()
    sanitized = sorted(
        key for key in environment if key.startswith("STWO_RECURSION_")
    )
    for key in sanitized:
        del environment[key]

    samples: list[dict[str, Any]] = []
    all_verified = True
    for native_sample in plan["native_samples"]:
        workload = native_sample["workload"]
        case = indexed_cases.get((workload["target"], workload["input_size"]))
        if case is None:
            raise EvidenceError("sealed native workload is absent from the canonical manifest")
        request = build_workload_request(
            plan,
            native_sample,
            case,
            repo_root=repo_root,
            worker_count=worker_count,
        )
        workload_root = output_root / native_sample["workload_id"]
        workload_root.mkdir()
        attempt_records: list[dict[str, Any]] = []
        workload_verified = True
        for ordinal in range(attempts_per_workload):
            classification = "excluded_warmup" if ordinal < warmups else "measured"
            request_path = workload_root / f"{ordinal:03d}.request.json"
            artifact_path = workload_root / f"{ordinal:03d}.outer-wire.bin"
            attempt_path = workload_root / f"{ordinal:03d}.attempt.json"
            request_raw = canonical_bytes(request)
            atomic_write_new(request_path, request_raw)
            argv = [
                os.fspath(producer),
                "--request",
                os.fspath(request_path),
                "--artifact-out",
                os.fspath(artifact_path),
                "--attempt-out",
                os.fspath(attempt_path),
            ]
            started_ns = __import__("time").monotonic_ns()
            timed_out = False
            try:
                completed = subprocess.run(
                    argv,
                    cwd=repo_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                )
                return_code: int | None = completed.returncode
                stderr_sha256 = sha256_bytes(completed.stderr)
                stderr_bytes = len(completed.stderr)
            except subprocess.TimeoutExpired as error:
                timed_out = True
                return_code = None
                stderr = error.stderr or b""
                stderr_sha256 = sha256_bytes(stderr)
                stderr_bytes = len(stderr)
            command_wall_ns = __import__("time").monotonic_ns() - started_ns

            if not attempt_path.is_file():
                attempt = {
                    "schema": ATTEMPT_SCHEMA,
                    "schema_version": 3,
                    "status": "controller_failure",
                    "classification": "missing_native_attempt_record",
                    "comparison_eligible": False,
                    "failure": {
                        "stage": "child_process",
                        "error_name": "TimeoutExpired" if timed_out else "MissingAttemptRecord",
                    },
                }
                workload_verified = False
            else:
                attempt, _ = load_json(attempt_path)
                validate_canonical_attempt(
                    attempt,
                    request=request,
                    request_raw=request_raw,
                    artifact_path=artifact_path,
                    producer_sha256=producer_sha256,
                )
                if (attempt["status"] == "verified") != (return_code == 0):
                    raise EvidenceError("child return code contradicts its typed attempt record")
                workload_verified &= attempt["status"] == "verified"
            attempt_records.append(
                {
                    "ordinal": ordinal,
                    "classification": classification,
                    "return_code": return_code,
                    "timed_out": timed_out,
                    "command_wall_ns": command_wall_ns,
                    "stderr_sha256": stderr_sha256,
                    "stderr_bytes": stderr_bytes,
                    "request_path": request_path.relative_to(output_root).as_posix(),
                    "attempt_path": attempt_path.relative_to(output_root).as_posix()
                    if attempt_path.exists()
                    else None,
                    "artifact_path": artifact_path.relative_to(output_root).as_posix()
                    if artifact_path.exists()
                    else None,
                    "record": attempt,
                }
            )
            if not workload_verified:
                break
        all_verified &= workload_verified and len(attempt_records) == attempts_per_workload
        samples.append(
            {
                "workload_id": native_sample["workload_id"],
                "workload": workload,
                "status": "verified_verifier_subsystem"
                if workload_verified and len(attempt_records) == attempts_per_workload
                else "failed",
                "attempts": attempt_records,
            }
        )
        if not all_verified:
            break

    captured_at = dt.datetime.now(dt.timezone.utc).isoformat()
    return seal_document(
        {
            "schema": REPORT_SCHEMA,
            "schema_version": 1,
            "classification": REPORT_CLASSIFICATION,
            "status": "verified_verifier_subsystem" if all_verified else "failed",
            "comparison_eligible": False,
            "comparison_unavailable_reason": (
                "the canonical artifacts are independently verified 36-row outer-child "
                "wires, but the proof scope remains verifier_subsystem until a complete "
                "recursive parent proof is production-active"
            ),
            "plan_digest": plan["canonical_digest"],
            "cohort_id": plan["cohort_id"],
            "captured_at": captured_at,
            "producer": {
                "path": os.fspath(producer),
                "sha256": producer_sha256,
                "worker_count": worker_count,
                "timeout_seconds": timeout_seconds,
                "fresh_process_per_attempt": True,
                "automatic_retries": 0,
                "outlier_drops": 0,
                "stdout_evidence_transport": False,
                "sanitized_environment_keys": sanitized,
            },
            "manifest": {
                "path": _relative_source(manifest_path, repo_root, "manifest"),
                "sha256": manifest_sha256,
            },
            "sampling": {
                "warmups_excluded": warmups,
                "measured_samples": measured,
                "attempts_per_workload": attempts_per_workload,
                "attempt_order": "excluded_warmups_then_measured_samples",
            },
            "artifact_directory": os.fspath(output_root),
            "samples": samples,
            "limitations": [
                "This report is subsystem performance evidence, not a full recursive proof comparison.",
                "Poseidon2 counts cover authenticated recursive AIR rows only, not native PCS hashing.",
                "No ratio against the legacy native prover is published from this report.",
                (
                    "Historical native rows are contextual only; a paired comparison "
                    "requires a fresh clean native cohort from the recursive producer's "
                    "exact implementation commit and identical public-values statement."
                ),
            ],
        }
    )
