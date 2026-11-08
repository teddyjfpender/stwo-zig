"""Native CSP adaptation, recursion-boundary plans, and diagnostic comparison."""

from __future__ import annotations

import datetime as dt
import re
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from .codec import (
    EvidenceError,
    content_digest,
    decode_json,
    seal_document,
    sha256_bytes,
    verify_document_seal,
)
from .contract import (
    AGGREGATES,
    ARTIFACT_CONTRACT_KEYS,
    BENCHMARK_BACKENDS,
    COMPARISON_CLASSIFICATION,
    COMPARISON_SCHEMA,
    GENERATION_PHASES,
    MAX_SAMPLES,
    PHASES,
    PLAN_CLASSIFICATION,
    PLAN_SCHEMA,
    RECURSIVE_REPORT_SCHEMA,
    REPORT_CLASSIFICATION,
    SCHEMA_VERSION,
    available_metric,
    exact_object,
    expect_commit,
    expect_digest,
    expect_positive_int,
    not_applicable_metric,
    unavailable_metric,
    validate_artifact,
    validate_artifact_contract,
    validate_aggregates,
    validate_phase_metrics,
    validate_recursive_report,
    validate_workload,
)
from .shape_coverage import project_plan_shape_coverage


from .native_contract import NATIVE_SCHEMAS
from .native_adapter import (
    _native_end_to_end_samples,
    _rounded_mean,
    adapt_native_report,
)
PAIR_NODE_RELATIVE = Path("src/frontends/riscv/recursion/pair_node.zig")
RECURSIVE_FRI_OUTER_RELATIVE = Path(
    "src/integrations/riscv_cpu/recursive_fri_outer.zig"
)
UNIVERSAL_RECURSION_TEST_RELATIVE = Path(
    "src/integrations/riscv_cpu/universal_recursive_air_proof_test.zig"
)
INTEGRATION_MOD_RELATIVE = Path("src/integrations/riscv_cpu/mod.zig")
INTEGRATION_BUILD_RELATIVE = Path("src/integrations/riscv_cpu/build.zig")

PLAN_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "native_source",
        "native_security",
        "native_host",
        "native_run",
        "host_identity_sha256",
        "cohort_id",
        "recursive_source_boundary",
        "recursive_shape_coverage",
        "recursive_report_contract",
        "native_samples",
        "limitations",
        "canonical_digest",
    }
)
NATIVE_SOURCE_KEYS = frozenset(
    {
        "schema",
        "report_sha256",
        "result_class",
        "measurement_commit",
        "repository_head",
        "suite_manifest_sha256",
        "reproducibility",
    }
)
BOUNDARY_SOURCE_KEYS = frozenset(
    {
        "source_evidence",
        "protocol_substrate_only",
        "recursive_proof_verification",
        "recursive_proof_production",
        "production_activation",
        "end_to_end_recursive_proof_evidence_available",
        "availability_assessment",
        "measurement_status",
        "static_poseidon_ledger_treatment",
    }
)
SOURCE_EVIDENCE_KEYS = frozenset(
    {"role", "source_path", "source_sha256", "required_markers"}
)
PLAN_SAMPLE_KEYS = frozenset(
    {
        "workload_id",
        "workload",
        "status",
        "backend",
        "sampling",
        "artifact",
        "evidence",
        "phases",
        "aggregates",
    }
)
NATIVE_EVIDENCE_KEYS = frozenset({"cycles"})
NATIVE_SAMPLING_KEYS = frozenset(
    {
        "warmups_excluded",
        "measured_samples",
        "verified_samples",
        "serial_execution",
        "attempt_order",
        "timing_statistic",
        "raw_phase_samples_available",
        "verified_end_to_end_sample_ns",
    }
)
NATIVE_REPRODUCIBILITY_KEYS = frozenset(
    {
        "captured_at",
        "prover_executable_sha256",
        "trace_executable_sha256",
        "compiler_version",
        "prover_build_identity_status",
        "prover_build_identity",
        "prover_build_identity_unavailable_reason",
    }
)
REPORT_CONTRACT_KEYS = frozenset(
    {
        "schema",
        "classification",
        "required_phase_order",
        "required_aggregates",
        "proof_generation_phase_partition",
        "published_verification_phase_partition",
        "duration_method",
        "proof_bytes_method",
        "poseidon_count_method",
        "peak_rss_method",
        "artifact_contract",
        "attempt_contract",
        "reproducibility_contract",
        "workload_alignment",
        "backend_alignment",
        "sampling_policy",
        "complete_pipeline_required",
    }
)

PAIR_FLAGS = {
    "PROTOCOL_SUBSTRATE_ONLY": True,
    "RECURSIVE_PROOF_VERIFICATION": False,
    "RECURSIVE_PROOF_PRODUCTION": False,
    "PRODUCTION_ACTIVATION": False,
}

AUDITED_RECURSION_SOURCES = (
    (
        "pair_node_authority",
        PAIR_NODE_RELATIVE,
        (
            "does **not** verify a STARK",
            "build a recursive circuit",
            "produce a recursive proof",
            "pub const AuthenticationPermutationCostV1 = struct",
        ),
    ),
    (
        "partial_fri_outer",
        RECURSIVE_FRI_OUTER_RELATIVE,
        (
            "This is deliberately a verifier-subsystem proof.",
            "Callers must not label this a complete recursive proof.",
            "const OUTER_CONFIG: stwo_core.pcs.PcsConfig",
            ".pow_bits = 0",
            ".n_queries = 3",
        ),
    ),
    (
        "inactive_universal_air_test",
        UNIVERSAL_RECURSION_TEST_RELATIVE,
        (
            "canonical inactive verifier schedule",
            "it does not yet verify child proof",
            "or claim a production recursive verifier.",
            "const FunctionalConfig: stwo_core.pcs.PcsConfig",
            ".pow_bits = 0",
            ".n_queries = 3",
        ),
    ),
    (
        "riscv_cpu_export_surface",
        INTEGRATION_MOD_RELATIVE,
        ('pub const recursive_fri_outer = @import("recursive_fri_outer.zig");',),
    ),
    (
        "riscv_cpu_build_surface",
        INTEGRATION_BUILD_RELATIVE,
        (
            '.root_source_file = b.path("universal_recursive_air_proof_test.zig")',
            '"test-recursion-full-air-proof"',
        ),
    ),
)



def inspect_recursive_boundary(
    repo_root: Path,
    pair_node_path: Path | None = None,
) -> dict[str, Any]:
    root = repo_root.resolve()
    sources: list[dict[str, Any]] = []
    pair_text: str | None = None
    for role, default_relative, markers in AUDITED_RECURSION_SOURCES:
        candidate = (
            pair_node_path
            if role == "pair_node_authority" and pair_node_path is not None
            else root / default_relative
        )
        source = candidate.resolve()
        try:
            relative = source.relative_to(root)
        except ValueError as error:
            raise EvidenceError(f"{role} source must be inside the repository") from error
        try:
            raw = source.read_bytes()
            text = raw.decode("utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as error:
            raise EvidenceError(f"cannot inspect {role} source: {error}") from error
        for marker in markers:
            if marker not in text:
                raise EvidenceError(f"{role} no longer carries marker {marker!r}")
        sources.append(
            {
                "role": role,
                "source_path": relative.as_posix(),
                "source_sha256": sha256_bytes(raw),
                "required_markers": list(markers),
            }
        )
        if role == "pair_node_authority":
            pair_text = text
    if pair_text is None:  # pragma: no cover - fixed source inventory invariant.
        raise EvidenceError("pair-node audit source is missing")
    observed: dict[str, bool] = {}
    for name, expected in PAIR_FLAGS.items():
        matches = re.findall(
            rf"^pub const {re.escape(name)} = (true|false);$",
            pair_text,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            raise EvidenceError(f"pair-node flag {name} is missing or ambiguous")
        observed[name] = matches[0] == "true"
        if observed[name] is not expected:
            raise EvidenceError(f"pair-node flag {name} changed; version the benchmark boundary")
    return {
        "source_evidence": sources,
        "protocol_substrate_only": observed["PROTOCOL_SUBSTRATE_ONLY"],
        "recursive_proof_verification": observed["RECURSIVE_PROOF_VERIFICATION"],
        "recursive_proof_production": observed["RECURSIVE_PROOF_PRODUCTION"],
        "production_activation": observed["PRODUCTION_ACTIVATION"],
        "end_to_end_recursive_proof_evidence_available": False,
        "availability_assessment": (
            "no complete recursive producer report was supplied; audited existing "
            "lanes self-identify as substrate-only, partial, or inactive"
        ),
        "measurement_status": "not_measured",
        "static_poseidon_ledger_treatment": (
            "excluded_from_end_to_end_counts_and_timings; it authenticates a native pair-node "
            "root and is not an executed recursive proof pipeline"
        ),
    }


def build_plan(
    native_report: dict[str, Any],
    *,
    native_raw: bytes,
    repo_root: Path,
    pair_node_path: Path | None = None,
) -> dict[str, Any]:
    decoded_source = decode_json(native_raw, label="native report bytes")
    if decoded_source != native_report:
        raise EvidenceError("native report object does not match its hashed source bytes")
    adapted = adapt_native_report(native_report, raw_sha256=sha256_bytes(native_raw))
    shape_coverage = project_plan_shape_coverage(
        adapted["native_samples"],
        repo_root=repo_root,
        expected_manifest_sha256=adapted["native_source"]["suite_manifest_sha256"],
    )
    host_digest = content_digest(adapted["native_host"])
    cohort_id = content_digest(
        {
            "native_report_sha256": adapted["native_source"]["report_sha256"],
            "measurement_commit": adapted["native_source"]["measurement_commit"],
            "repository_head": adapted["native_source"]["repository_head"],
            "suite_manifest_sha256": adapted["native_source"]["suite_manifest_sha256"],
            "reproducibility": adapted["native_source"]["reproducibility"],
            "host_identity_sha256": host_digest,
            "run": adapted["native_run"],
        }
    )
    unsigned = {
        "schema": PLAN_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "classification": PLAN_CLASSIFICATION,
        **adapted,
        "host_identity_sha256": host_digest,
        "cohort_id": cohort_id,
        "recursive_source_boundary": inspect_recursive_boundary(repo_root, pair_node_path),
        "recursive_shape_coverage": shape_coverage,
        "recursive_report_contract": {
            "schema": RECURSIVE_REPORT_SCHEMA,
            "classification": REPORT_CLASSIFICATION,
            "required_phase_order": list(PHASES),
            "required_aggregates": list(AGGREGATES),
            "proof_generation_phase_partition": list(GENERATION_PHASES),
            "published_verification_phase_partition": ["recursive_verify"],
            "duration_method": "producer_internal_monotonic_timer",
            "proof_bytes_method": "canonical_artifact_length",
            "poseidon_count_method": "phase_scoped_instrumented_exact_counter",
            "peak_rss_method": "os_process_lifetime_peak",
            "artifact_contract": (
                "versioned artifact kind/schema/exchange mode plus canonical payload "
                "encoding, scope, byte length, SHA-256, and verification receipt schema"
            ),
            "attempt_contract": (
                "fresh process per workload; contiguous serial excluded-warmup then "
                "measured attempts in that process; every attempt completes and verifies "
                "the full pipeline, retains an artifact-bound verification receipt, and "
                "records end-to-end plus phase timings; summaries derive only from "
                "measured attempts"
            ),
            "reproducibility_contract": (
                "offset-aware capture timestamp; clean commit/tree and executable digest; "
                "ReleaseFast compiler/target; canonical invocation digest; exact host, "
                "backend, security, workload, warmup, and sample alignment"
            ),
            "workload_alignment": (
                "exact target/size/input/guest/output/public-values/statement digest identity"
            ),
            "backend_alignment": "exact native backend",
            "sampling_policy": (
                "ReleaseFast; serial; exact native warmup/sample counts (at least three "
                "measured after at least one excluded verified warmup); positive-integer "
                "half-up arithmetic means; no automatic retries or outlier drops"
            ),
            "complete_pipeline_required": True,
        },
        "limitations": [
            "This plan is not recursive performance evidence.",
            (
                "The audited pair-node, partial FRI outer, and inactive universal AIR "
                "lanes do not establish an end-to-end recursive proof path."
            ),
            "Static pair-node Poseidon cost ledgers and partial frontier estimates are excluded.",
            (
                "A recursive cohort is blocked unless the sealed proof-independent "
                "shape audit selects every planned workload from the bounded exact "
                "registry and every selected profile is outer-circuit executable."
            ),
            (
                "Native Poseidon2 permutation counts are unavailable and are never "
                "inferred from cycles, rows, constraints, or proof size."
            ),
            (
                "A future recursive producer report must use internal phase timers, "
                "canonical versioned artifact payloads, comparable lifetime peak RSS, "
                "exact phase-scoped counters, raw warmup/measured attempts, and the exact "
                "planned workloads."
            ),
        ],
    }
    plan = seal_document(unsigned)
    validate_plan(plan, repo_root=repo_root)
    return plan


def _validate_native_sample(sample: Any, index: int) -> str:
    label = f"plan.native_samples[{index}]"
    value = exact_object(sample, PLAN_SAMPLE_KEYS, label)
    workload_id = expect_digest(value["workload_id"], f"{label}.workload_id")
    workload = validate_workload(value["workload"], label=f"{label}.workload")
    if workload_id != content_digest(workload):
        raise EvidenceError(f"{label}.workload_id does not bind its workload")
    if (
        value["status"] != "verified"
        or type(value["backend"]) is not str
        or value["backend"] not in BENCHMARK_BACKENDS
    ):
        raise EvidenceError(f"{label} status/backend is invalid")
    sampling = exact_object(
        value["sampling"], NATIVE_SAMPLING_KEYS, f"{label}.sampling"
    )
    warmups = expect_positive_int(
        sampling["warmups_excluded"], f"{label}.sampling.warmups_excluded"
    )
    measured = expect_positive_int(
        sampling["measured_samples"], f"{label}.sampling.measured_samples"
    )
    if measured < 3 or sampling["verified_samples"] != measured:
        raise EvidenceError(f"{label}.sampling measured/verified counts drifted")
    if (
        sampling["serial_execution"] is not True
        or sampling["attempt_order"]
        != "excluded_warmups_then_measured_samples"
        or sampling["timing_statistic"]
        != "arithmetic_mean_of_verified_samples_rounded_ns"
        or sampling["raw_phase_samples_available"] is not False
    ):
        raise EvidenceError(f"{label}.sampling methodology drifted")
    end_to_end = sampling["verified_end_to_end_sample_ns"]
    if type(end_to_end) is not list or len(end_to_end) != measured:
        raise EvidenceError(f"{label}.sampling sample series drifted")
    for ordinal, sample_ns in enumerate(end_to_end):
        expect_positive_int(sample_ns, f"{label}.sampling.sample[{ordinal}]")
    if type(value["artifact"]) is not dict:
        raise EvidenceError(f"{label}.artifact must be an object")
    artifact_contract = {
        key: value["artifact"].get(key) for key in ARTIFACT_CONTRACT_KEYS
    }
    validate_artifact(
        value["artifact"], contract=artifact_contract, label=f"{label}.artifact"
    )
    evidence = exact_object(value["evidence"], NATIVE_EVIDENCE_KEYS, f"{label}.evidence")
    expect_positive_int(evidence["cycles"], f"{label}.evidence.cycles")
    phases = validate_phase_metrics(
        value["phases"],
        label=f"{label}.phases",
        require_available=False,
    )
    aggregates = validate_aggregates(
        value["aggregates"], label=f"{label}.aggregates", require_available=False
    )
    for phase in PHASES:
        duration = phases[phase]["duration_ns"]
        calls = phases[phase]["poseidon2_permutations"]
        if phase in {"guest_execution", "base_witness", "base_prove", "base_verify"}:
            if duration["status"] != "available" or calls["status"] != "unavailable":
                raise EvidenceError(f"{label}.{phase} native availability classification drifted")
        elif duration["status"] != "not_applicable" or calls["status"] != "not_applicable":
            raise EvidenceError(f"{label}.{phase} must be not_applicable for the native lane")
    expected_generation = sum(
        phases[name]["duration_ns"]["value"]
        for name in ("guest_execution", "base_witness", "base_prove")
    )
    if aggregates["published_proof_generation_ns"]["value"] != expected_generation:
        raise EvidenceError(f"{label} native proof-generation partition drifted")
    if (
        aggregates["published_proof_verification_ns"]["value"]
        != phases["base_verify"]["duration_ns"]["value"]
    ):
        raise EvidenceError(f"{label} native verification partition drifted")
    for name in (
        "verified_end_to_end_ns",
        "published_proof_generation_ns",
        "published_proof_verification_ns",
        "published_proof_bytes",
    ):
        if aggregates[name]["status"] != "available":
            raise EvidenceError(f"{label}.{name} must be available")
    if aggregates["verified_end_to_end_ns"]["value"] != _rounded_mean(end_to_end):
        raise EvidenceError(f"{label} native end-to-end timing summary drifted")
    if aggregates["published_proof_bytes"]["value"] != value["artifact"]["payload_bytes"]:
        raise EvidenceError(f"{label} native proof artifact length drifted")
    if aggregates["peak_rss_bytes"]["status"] not in {"available", "unavailable"}:
        raise EvidenceError(f"{label}.peak_rss_bytes availability drifted")
    for name in (
        "proof_generation_poseidon2_permutations",
        "proof_verification_poseidon2_permutations",
    ):
        if aggregates[name]["status"] != "unavailable":
            raise EvidenceError(f"{label}.{name} must remain explicitly unavailable")
    _ = warmups
    return workload_id


def validate_plan(plan: dict[str, Any], *, repo_root: Path | None = None) -> dict[str, Any]:
    exact_object(plan, PLAN_KEYS, "plan")
    if (
        plan["schema"] != PLAN_SCHEMA
        or type(plan["schema_version"]) is not int
        or plan["schema_version"] != SCHEMA_VERSION
        or plan["classification"] != PLAN_CLASSIFICATION
    ):
        raise EvidenceError("plan schema identity drifted")
    verify_document_seal(plan, label="plan")
    source = exact_object(plan["native_source"], NATIVE_SOURCE_KEYS, "plan.native_source")
    if source["schema"] not in NATIVE_SCHEMAS:
        raise EvidenceError("plan native source schema is unsupported")
    expect_digest(source["report_sha256"], "plan.native_source.report_sha256")
    expect_commit(source["measurement_commit"], "plan.native_source.measurement_commit")
    expect_commit(source["repository_head"], "plan.native_source.repository_head")
    if source["repository_head"] != source["measurement_commit"]:
        raise EvidenceError("plan native source commit/HEAD identity drifted")
    expect_digest(source["suite_manifest_sha256"], "plan.native_source.suite_manifest_sha256")
    if type(source["result_class"]) is not str or not source["result_class"]:
        raise EvidenceError("plan.native_source.result_class is invalid")
    reproducibility = exact_object(
        source["reproducibility"],
        NATIVE_REPRODUCIBILITY_KEYS,
        "plan.native_source.reproducibility",
    )
    for key in ("prover_executable_sha256", "trace_executable_sha256"):
        expect_digest(reproducibility[key], f"plan.native_source.reproducibility.{key}")
    if (
        type(reproducibility["captured_at"]) is not str
        or not reproducibility["captured_at"]
        or type(reproducibility["compiler_version"]) is not str
        or not reproducibility["compiler_version"]
    ):
        raise EvidenceError("plan native reproducibility metadata is incomplete")
    try:
        captured = dt.datetime.fromisoformat(reproducibility["captured_at"])
    except ValueError as error:
        raise EvidenceError("plan native captured_at is not ISO-8601") from error
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise EvidenceError("plan native captured_at must include a UTC offset")
    build_status = reproducibility["prover_build_identity_status"]
    if build_status == "available":
        if (
            type(reproducibility["prover_build_identity"]) is not dict
            or reproducibility["prover_build_identity"].get("optimize") != "ReleaseFast"
            or reproducibility["prover_build_identity_unavailable_reason"] is not None
        ):
            raise EvidenceError("plan native build identity is contradictory")
    elif build_status == "unavailable":
        if (
            reproducibility["prover_build_identity"] is not None
            or type(reproducibility["prover_build_identity_unavailable_reason"])
            is not str
            or not reproducibility["prover_build_identity_unavailable_reason"]
        ):
            raise EvidenceError("plan native unavailable build identity is contradictory")
    else:
        raise EvidenceError("plan native build identity status is unsupported")
    if (
        type(plan["native_security"]) is not dict
        or plan["native_security"].get("profile") != "secure"
    ):
        raise EvidenceError("plan.native_security is invalid")
    if type(plan["native_host"]) is not dict or not plan["native_host"]:
        raise EvidenceError("plan.native_host is invalid")
    if type(plan["native_run"]) is not dict or not plan["native_run"]:
        raise EvidenceError("plan.native_run is invalid")
    native_backend = plan["native_run"].get("backend")
    if type(native_backend) is not str or native_backend not in BENCHMARK_BACKENDS:
        raise EvidenceError("plan.native_run.backend is invalid")
    native_warmups = expect_positive_int(
        plan["native_run"].get("warmups"), "plan.native_run.warmups"
    )
    native_sample_count = expect_positive_int(
        plan["native_run"].get("samples"), "plan.native_run.samples"
    )
    if native_sample_count < 3:
        raise EvidenceError("plan native run has fewer than three measured samples")
    if native_warmups > MAX_SAMPLES or native_sample_count > MAX_SAMPLES:
        raise EvidenceError("plan native run exceeds the bounded sampling schedule")
    expect_digest(plan["host_identity_sha256"], "plan.host_identity_sha256")
    if plan["host_identity_sha256"] != content_digest(plan["native_host"]):
        raise EvidenceError("plan host identity digest drifted")
    expect_digest(plan["cohort_id"], "plan.cohort_id")
    expected_cohort = content_digest(
        {
            "native_report_sha256": source["report_sha256"],
            "measurement_commit": source["measurement_commit"],
            "repository_head": source["repository_head"],
            "suite_manifest_sha256": source["suite_manifest_sha256"],
            "reproducibility": source["reproducibility"],
            "host_identity_sha256": plan["host_identity_sha256"],
            "run": plan["native_run"],
        }
    )
    if plan["cohort_id"] != expected_cohort:
        raise EvidenceError("plan cohort identity drifted")

    boundary = exact_object(
        plan["recursive_source_boundary"], BOUNDARY_SOURCE_KEYS, "plan.recursive_source_boundary"
    )
    expected_boundary = {
        "protocol_substrate_only": True,
        "recursive_proof_verification": False,
        "recursive_proof_production": False,
        "production_activation": False,
        "end_to_end_recursive_proof_evidence_available": False,
        "availability_assessment": (
            "no complete recursive producer report was supplied; audited existing "
            "lanes self-identify as substrate-only, partial, or inactive"
        ),
        "measurement_status": "not_measured",
    }
    for key, expected in expected_boundary.items():
        matches = (
            boundary[key] is expected
            if type(expected) is bool
            else type(boundary[key]) is type(expected) and boundary[key] == expected
        )
        if not matches:
            raise EvidenceError(f"plan recursive boundary {key} drifted")
    evidence = boundary["source_evidence"]
    expected_roles = [item[0] for item in AUDITED_RECURSION_SOURCES]
    if type(evidence) is not list or len(evidence) != len(expected_roles):
        raise EvidenceError("plan recursive source evidence inventory is incomplete")
    for index, (entry, expected_role) in enumerate(zip(evidence, expected_roles)):
        label = f"plan.recursive_source_boundary.source_evidence[{index}]"
        value = exact_object(entry, SOURCE_EVIDENCE_KEYS, label)
        if value["role"] != expected_role:
            raise EvidenceError(f"{label}.role drifted")
        if type(value["source_path"]) is not str or not value["source_path"]:
            raise EvidenceError(f"{label}.source_path is invalid")
        expect_digest(value["source_sha256"], f"{label}.source_sha256")
        expected_markers = list(AUDITED_RECURSION_SOURCES[index][2])
        if value["required_markers"] != expected_markers:
            raise EvidenceError(f"{label}.required_markers drifted")
    if (
        type(boundary["static_poseidon_ledger_treatment"]) is not str
        or "excluded" not in boundary["static_poseidon_ledger_treatment"]
    ):
        raise EvidenceError("plan does not explicitly exclude the static Poseidon ledger")
    if repo_root is not None:
        pair_source = repo_root / evidence[0]["source_path"]
        current = inspect_recursive_boundary(repo_root, pair_source)
        if current != boundary:
            raise EvidenceError("plan recursive source boundary is stale")

    contract = exact_object(
        plan["recursive_report_contract"], REPORT_CONTRACT_KEYS, "plan.recursive_report_contract"
    )
    expected_contract = {
        "schema": RECURSIVE_REPORT_SCHEMA,
        "classification": REPORT_CLASSIFICATION,
        "required_phase_order": list(PHASES),
        "required_aggregates": list(AGGREGATES),
        "proof_generation_phase_partition": list(GENERATION_PHASES),
        "published_verification_phase_partition": ["recursive_verify"],
        "duration_method": "producer_internal_monotonic_timer",
        "proof_bytes_method": "canonical_artifact_length",
        "poseidon_count_method": "phase_scoped_instrumented_exact_counter",
        "peak_rss_method": "os_process_lifetime_peak",
        "artifact_contract": (
            "versioned artifact kind/schema/exchange mode plus canonical payload "
            "encoding, scope, byte length, SHA-256, and verification receipt schema"
        ),
        "attempt_contract": (
            "fresh process per workload; contiguous serial excluded-warmup then measured "
            "attempts in that process; every attempt completes and verifies the full "
            "pipeline, retains an artifact-bound verification receipt, and records "
            "end-to-end plus phase timings; summaries derive only from measured attempts"
        ),
        "reproducibility_contract": (
            "offset-aware capture timestamp; clean commit/tree and executable digest; "
            "ReleaseFast compiler/target; canonical invocation digest; exact host, "
            "backend, security, workload, warmup, and sample alignment"
        ),
        "workload_alignment": (
            "exact target/size/input/guest/output/public-values/statement digest identity"
        ),
        "backend_alignment": "exact native backend",
        "sampling_policy": (
            "ReleaseFast; serial; exact native warmup/sample counts (at least three "
            "measured after at least one excluded verified warmup); positive-integer "
            "half-up arithmetic means; no automatic retries or outlier drops"
        ),
        "complete_pipeline_required": True,
    }
    if contract != expected_contract or contract["complete_pipeline_required"] is not True:
        raise EvidenceError("plan recursive report contract drifted")
    if (
        type(plan["limitations"]) is not list
        or not plan["limitations"]
        or any(type(item) is not str or not item for item in plan["limitations"])
    ):
        raise EvidenceError("plan.limitations must be non-empty")
    samples = plan["native_samples"]
    if type(samples) is not list or not samples or len(samples) > MAX_SAMPLES:
        raise EvidenceError(
            f"plan.native_samples must contain between 1 and {MAX_SAMPLES} rows"
        )
    seen = {_validate_native_sample(sample, index) for index, sample in enumerate(samples)}
    if len(seen) != len(samples):
        raise EvidenceError("plan.native_samples contains duplicate workloads")
    expected_order = sorted(
        samples, key=lambda item: (item["workload"]["target"], item["workload"]["input_size"])
    )
    if samples != expected_order:
        raise EvidenceError("plan.native_samples is not in canonical workload order")
    for index, sample in enumerate(samples):
        if (
            sample["sampling"]["warmups_excluded"] != native_warmups
            or sample["sampling"]["measured_samples"] != native_sample_count
        ):
            raise EvidenceError(
                f"plan.native_samples[{index}] sampling differs from native_run"
            )
        if sample["backend"] != native_backend:
            raise EvidenceError(
                f"plan.native_samples[{index}] backend differs from native_run"
            )
    if repo_root is not None:
        current_shape_coverage = project_plan_shape_coverage(
            samples,
            repo_root=repo_root,
            expected_manifest_sha256=source["suite_manifest_sha256"],
        )
        if plan["recursive_shape_coverage"] != current_shape_coverage:
            raise EvidenceError("plan recursive shape coverage is stale")
    elif type(plan["recursive_shape_coverage"]) is not dict:
        raise EvidenceError("plan recursive shape coverage is missing")
    return plan


def build_comparison(
    plan: dict[str, Any],
    *,
    recursive_report: dict[str, Any] | None,
    repo_root: Path,
    active_outer_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .comparison import build_comparison as build

    return build(
        plan,
        recursive_report=recursive_report,
        repo_root=repo_root,
        active_outer_probe=active_outer_probe,
    )
