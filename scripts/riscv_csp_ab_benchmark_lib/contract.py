"""Fail-closed contracts for native-only EthProofs CSP A/B evidence.

The A/B layer does not reinterpret a historical report as a fresh baseline.
It validates two newly captured, arm-local CSP reports, preserves their exact
bytes, and computes only transparent descriptive statistics.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import statistics
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from scripts.riscv_csp_benchmark_lib import contract as csp_contract


ROOT = Path(__file__).resolve().parents[2]
PROFILE_AUDIT = ROOT / "vectors" / "riscv_csp" / "recursion-shape-audit-v2.json"
HISTORICAL_REPORT = ROOT / "vectors" / "reports" / "riscv_csp_benchmark_report.json"
PLAN_SCHEMA = "stwo_riscv_csp_native_ab_plan_v1"
REPORT_SCHEMA = "stwo_riscv_csp_native_ab_report_v1"
PLAN_VERSION = 1
REPORT_VERSION = 1
ARM_NAMES = ("baseline", "current")
BASELINE_COMMIT = "b6c4f6326aee9c4f57432ac30c55c5b1f2296fab"
EXPECTED_OUTER_SCHEMAS = {
    "stwo_riscv_csp_benchmark_v3",
    "stwo_riscv_csp_benchmark_v4",
}
MAX_JSON_BYTES = 128 * 1024 * 1024
HEX_32 = csp_contract.HEX_32
HEX_40 = csp_contract.HEX_40


class ABError(RuntimeError):
    """The proposed comparison cannot produce trustworthy evidence."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ABError(f"JSON repeats field {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ABError(f"cannot read JSON document {path}: {error}") from error
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ABError(f"JSON byte length is outside bounds: {path}")
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ABError(f"invalid JSON document {path}: {error}") from error
    if not isinstance(value, dict):
        raise ABError(f"JSON document is not an object: {path}")
    return value, raw


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as error:
        raise ABError(f"document is not canonical-JSON encodable: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ABError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def seal_document(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("seal_sha256", None)
    return sha256_bytes(canonical_bytes(body))


def attach_seal(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["seal_sha256"] = seal_document(result)
    return result


def validate_seal(value: Mapping[str, Any], label: str) -> None:
    supplied = value.get("seal_sha256")
    if not isinstance(supplied, str) or not HEX_32.fullmatch(supplied):
        raise ABError(f"{label} has no canonical seal")
    actual = seal_document(value)
    if supplied != actual:
        raise ABError(f"{label} seal mismatch")


def write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically publish a new document without replacing prior evidence."""

    encoded = json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if path.exists() or temporary.exists():
        raise ABError(f"refusing to replace benchmark evidence: {path}")
    try:
        with temporary.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ABError(f"refusing to replace benchmark evidence: {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ABError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        qualifier = "positive" if positive else "non-negative"
        raise ABError(f"{label} must be finite and {qualifier}")
    return result


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ABError(f"{label} must be an integer")
    if value < 0 or (positive and value <= 0):
        qualifier = "positive" if positive else "non-negative"
        raise ABError(f"{label} must be {qualifier}")
    return value


def nearest_rank(values: Sequence[float], percentile: int) -> float:
    if not values or not 1 <= percentile <= 100:
        raise ABError("nearest-rank input is invalid")
    ordered = sorted(values)
    index = math.ceil(percentile / 100 * len(ordered)) - 1
    return ordered[index]


def distribution(values: Iterable[int | float]) -> dict[str, int | float]:
    samples = [float(value) for value in values]
    if not samples or any(not math.isfinite(value) or value < 0 for value in samples):
        raise ABError("distribution samples must be finite and non-negative")
    median = statistics.median(samples)
    deviations = [abs(value - median) for value in samples]
    return {
        "count": len(samples),
        "min": min(samples),
        "p50": median,
        "p90": nearest_rank(samples, 90),
        "p95": nearest_rank(samples, 95),
        "p99": nearest_rank(samples, 99),
        "max": max(samples),
        "mad": statistics.median(deviations),
    }


def delta(baseline: float, current: float) -> dict[str, float | None]:
    absolute = current - baseline
    return {
        "baseline": baseline,
        "current": current,
        "absolute_delta": absolute,
        "percent_delta": None if baseline == 0 else absolute / baseline * 100.0,
        "baseline_over_current": None if current == 0 else baseline / current,
    }


def canonical_workloads() -> list[dict[str, Any]]:
    manifest, cases, _ = csp_contract.validate_manifest()
    audit, audit_raw = load_json(PROFILE_AUDIT)
    if (
        audit.get("schema") != "stwo.riscv.recursion-csp-shape-audit.v2"
        or audit.get("schema_version") != 2
    ):
        raise ABError("canonical profile audit schema drifted")
    profile_registry = audit.get("profile_registry")
    coverage = audit.get("coverage")
    audit_cases = audit.get("cases")
    if (
        not isinstance(profile_registry, dict)
        or profile_registry.get("canonical_case_count") != 16
        or profile_registry.get("profile_count") != 9
        or not isinstance(profile_registry.get("registry_sha256"), str)
        or not HEX_32.fullmatch(profile_registry["registry_sha256"])
        or not isinstance(coverage, dict)
        or coverage.get("case_count") != 16
        or coverage.get("all_canonical_cases_registry_matched") is not True
        or not isinstance(audit_cases, list)
        or len(audit_cases) != 16
        or len(cases) != 16
    ):
        raise ABError("canonical 16-case profile registry is incomplete")
    result: list[dict[str, Any]] = []
    for index, (case, profiled) in enumerate(zip(cases, audit_cases, strict=True)):
        if not isinstance(profiled, dict):
            raise ABError(f"profile audit case {index} is invalid")
        selected = profiled.get("selected_profile")
        facts = profiled.get("facts")
        if (
            profiled.get("target") != case.target
            or profiled.get("input_size") != case.input_size
            or profiled.get("input_sha256") != case.input_sha256
            or profiled.get("guest_sha256") != case.guest_sha256
            or profiled.get("expected_output_digest") != case.expected_digest
            or profiled.get("expected_cycles") != case.expected_cycles
            or not isinstance(selected, dict)
            or not isinstance(selected.get("profile_id"), str)
            or not isinstance(selected.get("profile_shape_sha256"), str)
            or not HEX_32.fullmatch(selected["profile_shape_sha256"])
            or not isinstance(facts, dict)
        ):
            raise ABError(f"profile audit case {index} does not match the CSP manifest")
        shape = {
            "component_count": facts.get("component_count"),
            "infrastructure_count": facts.get("infrastructure_count"),
            "preprocessed_column_count": facts.get("preprocessed_column_count"),
            "main_column_count": facts.get("main_column_count"),
            "interaction_column_count": facts.get("interaction_column_count"),
            "maximum_column_log_degree": facts.get("maximum_column_log_degree"),
        }
        for name, value in shape.items():
            _integer(value, f"profile audit case {index} {name}", positive=True)
        result.append(
            {
                "ordinal": index,
                "target": case.target,
                "input_size": case.input_size,
                "input_sha256": case.input_sha256,
                "guest_sha256": case.guest_sha256,
                "expected_output_digest": case.expected_digest,
                "expected_cycles": case.expected_cycles,
                "profile_id": selected["profile_id"],
                "profile_shape_sha256": selected["profile_shape_sha256"],
                "shape": shape,
            }
        )
    # The manifest object is deliberately read by its production validator;
    # this assertion prevents a caller from substituting another object while
    # retaining the same 16 profile rows.
    if manifest.get("schema") != "stwo_riscv_csp_suite_v2":
        raise ABError("canonical CSP manifest schema drifted")
    if sha256_bytes(audit_raw) != sha256_file(PROFILE_AUDIT):
        raise ABError("profile audit changed while it was read")
    return result


def workload_context() -> dict[str, Any]:
    audit, raw = load_json(PROFILE_AUDIT)
    workloads = canonical_workloads()
    return {
        "manifest_path": str(csp_contract.MANIFEST.relative_to(ROOT)),
        "manifest_sha256": sha256_file(csp_contract.MANIFEST),
        "profile_audit_path": str(PROFILE_AUDIT.relative_to(ROOT)),
        "profile_audit_sha256": sha256_bytes(raw),
        "profile_audit_canonical_digest": audit["canonical_digest"],
        "profile_registry_sha256": audit["profile_registry"]["registry_sha256"],
        "case_count": len(workloads),
        "profile_count": audit["profile_registry"]["profile_count"],
        "cases": workloads,
    }


def historical_context() -> dict[str, Any]:
    report, raw = load_json(HISTORICAL_REPORT)
    commit = report.get("measurement_commit")
    if (
        report.get("schema") != "stwo_riscv_csp_benchmark_v2"
        or not isinstance(commit, str)
        or not HEX_40.fullmatch(commit)
        or report.get("repository_head") != commit
        or not isinstance(report.get("measurements"), list)
        or len(report["measurements"]) != 16
    ):
        raise ABError("checked historical CSP report provenance drifted")
    return {
        "path": str(HISTORICAL_REPORT.relative_to(ROOT)),
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "schema": report["schema"],
        "captured_at": report.get("captured_at"),
        "measurement_commit": commit,
        "host": report.get("host"),
        "classification": "context_only_not_ab_denominator",
        "reason": (
            "schema v2 predates executable/power/native-recursion isolation; "
            "the host and capture time also differ from a future paired cohort"
        ),
    }


def canonical_schedule(rounds: int) -> list[dict[str, Any]]:
    if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= 8:
        raise ABError("rounds must be between 1 and 8")
    result: list[dict[str, Any]] = []
    ordinal = 0
    for round_index in range(rounds):
        for case in canonical_workloads():
            first = (case["ordinal"] + round_index) % 2
            arms = ARM_NAMES if first == 0 else tuple(reversed(ARM_NAMES))
            for launch_index, arm in enumerate(arms):
                result.append(
                    {
                        "ordinal": ordinal,
                        "round": round_index,
                        "case_ordinal": case["ordinal"],
                        "target": case["target"],
                        "input_size": case["input_size"],
                        "launch_index": launch_index,
                        "arm": arm,
                    }
                )
                ordinal += 1
    return result


def validate_plan(plan: Mapping[str, Any]) -> None:
    if plan.get("schema") != PLAN_SCHEMA or plan.get("schema_version") != PLAN_VERSION:
        raise ABError("A/B plan schema drifted")
    validate_seal(plan, "A/B plan")
    arms = plan.get("arms")
    settings = plan.get("settings")
    workload = plan.get("workload")
    schedule = plan.get("schedule")
    if not isinstance(arms, dict) or tuple(arms) != ARM_NAMES:
        raise ABError("A/B plan arm order drifted")
    if not isinstance(settings, dict):
        raise ABError("A/B plan settings are missing")
    rounds = _integer(settings.get("rounds"), "plan rounds", positive=True)
    _integer(settings.get("warmups"), "plan warmups")
    _integer(settings.get("samples"), "plan samples", positive=True)
    workers = _integer(settings.get("workers"), "plan workers", positive=True)
    if settings.get("backend") != "cpu" or settings.get("recursion_enabled") is not False:
        raise ABError("A/B plan is not native CPU only")
    if not 0 <= settings["warmups"] <= 10 or not 1 <= settings["samples"] <= 21:
        raise ABError("A/B plan sample settings exceed the production harness bounds")
    if workers > 32:
        raise ABError("A/B plan workers exceed the production harness bound")
    timeout = _integer(settings.get("timeout_seconds"), "plan timeout", positive=True)
    if timeout > 24 * 60 * 60:
        raise ABError("A/B plan timeout exceeds 24 hours per subprocess")
    host = plan.get("host")
    power = plan.get("power")
    environment = plan.get("environment")
    preflight = plan.get("publishable_preflight")
    if not isinstance(host, dict) or not isinstance(power, dict) or not isinstance(preflight, dict):
        raise ABError("A/B plan host/power evidence is missing")
    if not isinstance(power.get("admissible"), bool) or not isinstance(power.get("reasons"), list):
        raise ABError("A/B plan power classification is invalid")
    if (
        preflight.get("schema") != "stwo_native_ab_quiet_host_preflight_v1"
        or not isinstance(preflight.get("admissible"), bool)
        or not isinstance(preflight.get("reasons"), list)
        or preflight.get("power_admissible") is not power["admissible"]
    ):
        raise ABError("A/B plan quiet-host preflight is invalid")
    if (
        not isinstance(environment, dict)
        or environment.get("policy") != "native_ab_sanitized_v1"
        or environment.get("fixed", {}).get("STWO_ZIG_WORKERS")
        != str(settings["workers"])
        or environment.get("fixed", {}).get("STWO_ZIG_MERKLE_WORKERS")
        != str(settings["workers"])
        or not isinstance(environment.get("removed_stwo_names"), list)
    ):
        raise ABError("A/B plan environment policy drifted")
    expected_workload = workload_context()
    if workload != expected_workload:
        raise ABError("A/B plan workload/profile context drifted")
    if schedule != canonical_schedule(rounds):
        raise ABError("A/B plan launch schedule drifted")
    for name in ARM_NAMES:
        arm = arms[name]
        if not isinstance(arm, dict):
            raise ABError(f"A/B plan arm {name} is invalid")
        if arm.get("label") != name:
            raise ABError(f"A/B plan arm {name} label drifted")
        head = arm.get("head")
        if not isinstance(head, str) or not HEX_40.fullmatch(head):
            raise ABError(f"A/B plan arm {name} has no canonical HEAD")
        if arm.get("benchmark_tree_dirty") is not False:
            raise ABError(f"A/B plan arm {name} is not a clean benchmark tree")
        for digest_name in (
            "source_content_sha256",
            "manifest_sha256",
            "harness_sha256",
        ):
            digest = arm.get(digest_name)
            if not isinstance(digest, str) or not HEX_32.fullmatch(digest):
                raise ABError(f"A/B plan arm {name} {digest_name} is invalid")
        if arm["manifest_sha256"] != expected_workload["manifest_sha256"]:
            raise ABError(f"A/B plan arm {name} manifest drifted")
        guard = arm.get("native_guard")
        if not isinstance(guard, dict) or guard.get("kind") not in {
            "recursive_sources_absent_v1",
            "runtime_native_attestation_v1",
        }:
            raise ABError(f"A/B plan arm {name} native guard is invalid")
    baseline = arms["baseline"]
    current = arms["current"]
    if (
        baseline.get("source_kind") != "committed_baseline_v1"
        or baseline.get("head") != BASELINE_COMMIT
        or baseline["native_guard"].get("kind")
        != "recursive_sources_absent_v1"
    ):
        raise ABError("A/B baseline is not the frozen branch-start commit")
    snapshot = current.get("active_snapshot")
    if (
        current.get("source_kind") != "ephemeral_active_snapshot_v1"
        or current["native_guard"].get("kind")
        != "runtime_native_attestation_v1"
        or not isinstance(snapshot, dict)
        or not isinstance(snapshot.get("active_worktree_dirty"), bool)
        or snapshot.get("source_content_sha256")
        != current["source_content_sha256"]
    ):
        raise ABError("A/B current arm is not an honest ephemeral source snapshot")
    for field in (
        "base_head",
        "temporary_commit",
    ):
        value = snapshot.get(field)
        if not isinstance(value, str) or not HEX_40.fullmatch(value):
            raise ABError(f"A/B current snapshot {field} is invalid")
    if snapshot["temporary_commit"] != current["head"]:
        raise ABError("A/B current temporary commit does not match its arm HEAD")
    for field in (
        "source_content_sha256",
        "tracked_patch_sha256",
        "untracked_payload_sha256",
        "status_sha256",
        "temporary_tree_listing_sha256",
    ):
        value = snapshot.get(field)
        if not isinstance(value, str) or not HEX_32.fullmatch(value):
            raise ABError(f"A/B current snapshot {field} is invalid")
    tree_oid = snapshot.get("temporary_tree_git_oid")
    if not isinstance(tree_oid, str) or not HEX_40.fullmatch(tree_oid):
        raise ABError("A/B current snapshot Git tree object is invalid")
    _integer(snapshot.get("tracked_patch_bytes"), "tracked patch bytes")
    _integer(snapshot.get("untracked_file_count"), "untracked file count")
    _integer(snapshot.get("untracked_payload_bytes"), "untracked payload bytes")
    if snapshot.get("ignored_source_input_count") != 0:
        raise ABError("A/B current snapshot omits ignored source inputs")
    publishable = power["admissible"] and preflight["admissible"]
    expected_status = (
        "ready_ephemeral_current"
        if publishable
        else "diagnostic_smoke_only_host_interference"
    )
    if plan.get("status") != expected_status:
        raise ABError("A/B plan readiness classification is inconsistent")


def _methodology(report: Mapping[str, Any], label: str) -> dict[str, Any]:
    value = report.get("methodology")
    if not isinstance(value, dict):
        raise ABError(f"{label} has no methodology")
    required = {
        "canonical_inputs": True,
        "canonical_sizes": list(csp_contract.CANONICAL_SIZES),
        "target_sizes": {
            target: list(csp_contract.TARGET_SIZES[target])
            for target in csp_contract.TARGET_ORDER
        },
        "uses_precompile": False,
        "proof_duration": "mean execution + witness + proof generation",
        "verify_duration": "mean production verification",
        "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
        "preprocessing_size": "retained RV32IM ELF bytes",
        "peak_memory": "production process lifetime physical-footprint peak",
        "num_constraints": "0 means not exposed; cycles are authoritative",
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise ABError(f"{label} methodology {key} drifted")
    if report.get("schema") == "stwo_riscv_csp_benchmark_v4" and value.get(
        "proof_scope"
    ) != "native RISC-V leaf STARK; recursion and outer proving disabled":
        raise ABError(f"{label} has no native proof-scope attestation")
    return {key: value[key] for key in required}


def validate_partial_report(
    report: Mapping[str, Any],
    *,
    arm: Mapping[str, Any],
    case: Mapping[str, Any],
    settings: Mapping[str, Any],
    expected_host: Mapping[str, Any],
    require_publishable_power: bool = True,
) -> dict[str, Any]:
    label = f"{arm['label']} {case['target']}/{case['input_size']}"
    schema = report.get("schema")
    if schema not in EXPECTED_OUTER_SCHEMAS:
        raise ABError(f"{label} outer report schema is not A/B admissible")
    if report.get("measurement_commit") != arm.get("head") or report.get(
        "repository_head"
    ) != arm.get("head"):
        raise ABError(f"{label} report commit differs from the planned arm")
    if report.get("suite_manifest_sha256") != workload_context()["manifest_sha256"]:
        raise ABError(f"{label} manifest digest drifted")
    if report.get("host") != expected_host:
        raise ABError(f"{label} host/environment differs from the paired cohort")
    if require_publishable_power and report.get("power_conditions_admissible") is not True:
        raise ABError(f"{label} was captured under inadmissible power conditions")
    if not isinstance(report.get("power_conditions_admissible"), bool):
        raise ABError(f"{label} power classification is missing")
    _methodology(report, label)

    run = report.get("run")
    summary = report.get("summary")
    rows = report.get("measurements")
    if not isinstance(run, dict) or not isinstance(summary, dict) or not isinstance(rows, list):
        raise ABError(f"{label} report structure is incomplete")
    if (
        run.get("targets") != [case["target"]]
        or run.get("sizes") != [case["input_size"]]
        or run.get("warmups") != settings["warmups"]
        or run.get("samples") != settings["samples"]
        or run.get("workers") != settings["workers"]
        or run.get("complete_matrix") is not False
        or run.get("backend", "cpu") != "cpu"
        or len(rows) != 1
        or summary.get("row_count") != 1
        or summary.get("all_outputs_match") is not True
        or summary.get("all_proofs_verified") is not True
        or summary.get("all_peak_memory_available") is not True
    ):
        raise ABError(f"{label} partial-run contract drifted")

    guard = arm["native_guard"]
    if schema == "stwo_riscv_csp_benchmark_v4":
        if (
            run.get("recursion_enabled") is not False
            or summary.get("all_recursion_disabled") is not True
            or rows[0].get("recursion_enabled") is not False
        ):
            raise ABError(f"{label} native recursion attestation failed")
    elif guard.get("kind") != "recursive_sources_absent_v1":
        raise ABError(
            f"{label} predates runtime recursion attestation and its source tree "
            "does not prove recursive sources absent"
        )

    identities = report.get("identities")
    if not isinstance(identities, dict):
        raise ABError(f"{label} executable identities are absent")
    build = identities.get("prover_build_identity")
    trace = identities.get("trace_provenance")
    if (
        not isinstance(build, dict)
        or build.get("optimize") != "ReleaseFast"
        or not isinstance(trace, dict)
        or trace.get("implementation_commit") != arm["head"]
        or trace.get("implementation_dirty") is not False
    ):
        raise ABError(f"{label} build/trace provenance is not clean ReleaseFast")

    row = rows[0]
    evidence = row.get("evidence")
    timing = row.get("timing")
    receipt = evidence.get("retained_verify_receipt") if isinstance(evidence, dict) else None
    samples = timing.get("verified_end_to_end_sample_seconds") if isinstance(timing, dict) else None
    if (
        row.get("backend", "cpu") != "cpu"
        or row.get("target") != case["target"]
        or row.get("input_size") != case["input_size"]
        or row.get("cycles") != case["expected_cycles"]
        or row.get("uses_precompile") is not False
        or not isinstance(evidence, dict)
        or evidence.get("status") != "verified"
        or evidence.get("input_sha256") != case["input_sha256"]
        or evidence.get("guest_sha256") != case["guest_sha256"]
        or evidence.get("output_digest") != case["expected_output_digest"]
        or evidence.get("expected_output_digest") != case["expected_output_digest"]
        or not isinstance(receipt, dict)
        or receipt.get("status") != "verified"
        or receipt.get("implementation_commit") != arm["head"]
        or receipt.get("implementation_dirty") is not False
        or not isinstance(samples, list)
        or len(samples) != settings["samples"]
    ):
        raise ABError(f"{label} proof or workload evidence drifted")
    sample_values = [
        _number(value, f"{label} sample", positive=True) for value in samples
    ]
    proof_duration = _integer(row.get("proof_duration"), f"{label} proof duration", positive=True)
    verify_duration = _integer(row.get("verify_duration"), f"{label} verify duration", positive=True)
    peak_memory = _integer(row.get("peak_memory"), f"{label} peak memory", positive=True)
    proof_size = _integer(row.get("proof_size"), f"{label} proof size", positive=True)
    if receipt.get("proof_bytes") != proof_size:
        raise ABError(f"{label} retained receipt proof size drifted")
    proof_sha = receipt.get("proof_sha256")
    if not isinstance(proof_sha, str) or not HEX_32.fullmatch(proof_sha):
        raise ABError(f"{label} retained receipt proof digest is invalid")
    for name in ("prover_executable_sha256", "trace_executable_sha256"):
        digest = identities.get(name)
        if not isinstance(digest, str) or not HEX_32.fullmatch(digest):
            raise ABError(f"{label} {name} is invalid")
    return {
        "outer_schema": schema,
        "proof_duration_ns": proof_duration,
        "verify_duration_ns": verify_duration,
        "end_to_end_sample_seconds": sample_values,
        "peak_rss_bytes": peak_memory,
        "proof_bytes": proof_size,
        "proof_sha256": proof_sha,
        "prover_executable_sha256": identities.get("prover_executable_sha256"),
        "trace_executable_sha256": identities.get("trace_executable_sha256"),
    }


def summarize_case(
    records: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    arms: dict[str, Any] = {}
    for name in ARM_NAMES:
        values = list(records[name])
        if not values:
            raise ABError(f"case has no {name} records")
        end_to_end = [
            value
            for record in values
            for value in record["end_to_end_sample_seconds"]
        ]
        arms[name] = {
            "cohort_count": len(values),
            "proof_duration_ns": distribution(
                record["proof_duration_ns"] for record in values
            ),
            "verify_duration_ns": distribution(
                record["verify_duration_ns"] for record in values
            ),
            "end_to_end_seconds": distribution(end_to_end),
            "peak_rss_bytes": distribution(record["peak_rss_bytes"] for record in values),
            "proof_bytes": distribution(record["proof_bytes"] for record in values),
            "proof_sha256s": [record["proof_sha256"] for record in values],
        }
    metric_deltas = {}
    for metric in (
        "proof_duration_ns",
        "verify_duration_ns",
        "end_to_end_seconds",
        "peak_rss_bytes",
        "proof_bytes",
    ):
        metric_deltas[metric] = delta(
            float(arms["baseline"][metric]["p50"]),
            float(arms["current"][metric]["p50"]),
        )
    return {"arms": arms, "median_deltas": metric_deltas}
