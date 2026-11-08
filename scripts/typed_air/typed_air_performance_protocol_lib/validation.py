"""Fail-closed decoding and semantic validation for the performance protocol."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .contract import (
    MAX_PROTOCOL_BYTES,
    SCHEMA,
    SCHEMA_VERSION,
    STATUS,
    REPOSITORY,
    DIGEST_RE,
    ROOT_FIELDS,
    SECTION_FIELDS,
    EXPECTED_AUTHORITY,
    EXPECTED_CORPUS_AUTHORITY,
    EXPECTED_LANES,
    EXPECTED_BUDGETS,
    EXPECTED_OPTIMIZATION_CONTRACT,
    EXPECTED_M5_CASES,
    WORKLOADS,
    EXPECTED_M5_WORKLOADS,
    EXPECTED_M8_FAMILIES,
    EXPECTED_M8_WORKLOADS,
    EXPECTED_PRIMARY_TARGETS,
    MILESTONE_FIELDS,
    M6_BASE_ZERO,
    M6_EXTENSION_ZERO,
    M7_OVERRIDES,
    M9_OVERRIDES,
)


class ProtocolError(ValueError):
    """The protocol is malformed, drifted, or no longer locally authenticated."""


@dataclass(frozen=True)
class ProtocolSummary:
    path: Path
    sha256: str
    schema: str
    schema_version: int
    milestones: tuple[str, ...]
    lanes: tuple[str, ...]

    def render(self) -> str:
        return (
            "typed-air performance protocol: PASS "
            f"schema={self.schema} version={self.schema_version} "
            f"milestones={','.join(self.milestones)} "
            f"lanes={','.join(self.lanes)} sha256={self.sha256}"
        )


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-standard JSON number is forbidden: {value}")


def _parse_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ProtocolError(f"non-finite JSON number is forbidden: {value}")
    return result


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_strict_json(raw: bytes, *, label: str = "protocol") -> dict[str, Any]:
    """Decode one UTF-8 JSON object while rejecting duplicates and extensions."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProtocolError(f"{label} is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except ProtocolError:
        raise
    except json.JSONDecodeError as error:
        raise ProtocolError(f"{label} is not valid JSON: {error.msg}") from error
    if type(value) is not dict:
        raise ProtocolError(f"{label} root must be an object")
    return value


def _closed_object(
    value: Any,
    expected_fields: Iterable[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProtocolError(f"{label} must be an object")
    expected = frozenset(expected_fields)
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ProtocolError(
            f"{label} field set mismatch; missing={missing}, unknown={unknown}"
        )
    return value


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _strict_equal(got, want) for got, want in zip(actual, expected)
        )
    return bool(actual == expected)


def _expect_exact(actual: Any, expected: Any, label: str) -> None:
    if not _strict_equal(actual, expected):
        raise ProtocolError(f"{label} drifted from the frozen protocol")


def _expect_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ProtocolError(f"{label} must be a nonempty string")
    return value


def _expect_unique_strings(value: Any, label: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise ProtocolError(f"{label} must be a list of nonempty strings")
    if len(set(value)) != len(value):
        raise ProtocolError(f"{label} contains duplicates")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _owned_file(root: Path, relative: Any, label: str) -> Path:
    relative = _expect_string(relative, label)
    raw_path = Path(relative)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        raise ProtocolError(f"{label} must be a normalized repository-relative path")
    root = root.resolve()
    candidate = (root / raw_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ProtocolError(f"{label} escapes the repository") from error
    if not candidate.is_file():
        raise ProtocolError(f"{label} does not name a repository file: {relative}")
    return candidate


def _validate_reference(
    root: Path,
    owner: Mapping[str, Any],
    *,
    path_key: str,
    digest_key: str,
    expected_path: str,
    expected_digest: str,
    label: str,
) -> None:
    _expect_exact(owner[path_key], expected_path, f"{label} path")
    digest = owner[digest_key]
    if type(digest) is not str or DIGEST_RE.fullmatch(digest) is None:
        raise ProtocolError(f"{label} digest must be lowercase SHA-256")
    _expect_exact(digest, expected_digest, f"{label} digest")
    path = _owned_file(root, owner[path_key], f"{label} path")
    if _sha256_file(path) != digest:
        raise ProtocolError(f"{label} file hash mismatch")


def _validate_workload_paths(root: Path, workloads: Sequence[Any], label: str) -> None:
    for index, raw in enumerate(workloads):
        item = _closed_object(raw, {"id", "elf", "input"}, f"{label}[{index}]")
        _expect_string(item["id"], f"{label}[{index}].id")
        _owned_file(root, item["elf"], f"{label}[{index}].elf")
        if item["input"] is not None:
            _owned_file(root, item["input"], f"{label}[{index}].input")


def _validate_sampling(protocol: Mapping[str, Any]) -> None:
    sampling = protocol["sampling_protocol"]
    expected_scalars = {
        "process_isolation": "one fresh child process for every warmup and measured attempt",
        "serial_attempts": True,
        "excluded_verified_warmups_per_arm": 10,
        "paired_rounds": 3,
        "measured_verified_proofs_per_arm_per_round": 10,
        "measured_verified_proofs_per_arm": 30,
        "pairing": "round-level alternating AB/BA",
        "cooldown_seconds_between_attempts": 1.0,
        "early_stopping": False,
        "retry_failed_attempts": False,
        "drop_outliers": False,
        "retain_raw_attempts": True,
    }
    for key, expected in expected_scalars.items():
        _expect_exact(sampling[key], expected, f"sampling_protocol.{key}")
    if (
        sampling["paired_rounds"]
        * sampling["measured_verified_proofs_per_arm_per_round"]
        != sampling["measured_verified_proofs_per_arm"]
    ):
        raise ProtocolError("sampling measured-proof arithmetic does not close")
    _expect_unique_strings(sampling["host_requirements"], "sampling host requirements")
    calibration = _closed_object(
        sampling["a_a_calibration"],
        {
            "required_per_host_backend_session",
            "workload_id",
            "arms",
            "sampling",
            "required_metrics",
            "ratio_ci_must_contain",
            "maximum_ci_width",
            "failure_outcome",
        },
        "sampling_protocol.a_a_calibration",
    )
    expected_calibration = {
        "required_per_host_backend_session": True,
        "workload_id": "multi_shard_addi",
        "arms": "the same executable and source identity in both arms",
        "sampling": "the complete warmup, paired-round, and cooldown protocol above",
        "required_metrics": ["verified_request_ns", "proving_ns", "peak_rss_bytes"],
        "ratio_ci_must_contain": 1.0,
        "maximum_ci_width": 0.06,
        "failure_outcome": "NO_VERDICT",
    }
    _expect_exact(calibration, expected_calibration, "A/A calibration")


def _validate_primary_target(milestone: Mapping[str, Any]) -> None:
    milestone_id = milestone["id"]
    expected = EXPECTED_PRIMARY_TARGETS[milestone_id]
    target = _closed_object(
        milestone["primary_target"], expected, f"{milestone_id}.primary_target"
    )
    _expect_exact(target, expected, f"{milestone_id} primary target")
    if target["lane"] not in milestone["required_lanes"]:
        raise ProtocolError(f"{milestone_id} primary target lane is not required")


def _validate_m5(root: Path, milestone: Mapping[str, Any]) -> None:
    micro = _closed_object(
        milestone["family_microbenchmarks"],
        {"generator", "seed", "cases", "log_rows"},
        "M5.family_microbenchmarks",
    )
    _expect_exact(micro["generator"], "typed-air-family-isolated-v1", "M5 generator")
    _expect_exact(micro["seed"], "stwo-typed-air-m5-family-v1", "M5 seed")
    _expect_exact(micro["cases"], EXPECTED_M5_CASES, "M5 family cases")
    _expect_exact(micro["log_rows"], [10, 14, 18], "M5 row matrix")
    _expect_exact(milestone["full_proof_workloads"], EXPECTED_M5_WORKLOADS, "M5 workloads")
    _validate_workload_paths(root, milestone["full_proof_workloads"], "M5 workloads")


def _validate_m6(milestone: Mapping[str, Any]) -> None:
    corpus = _closed_object(
        milestone["corpus"],
        {"generator", "seed", "call_counts", "arms", "shapes", "input_rule"},
        "M6.corpus",
    )
    expected_corpus = {
        "generator": "poseidon2-software-precompile-equivalence-v1",
        "seed": "stwo-typed-air-m6-poseidon2-v1",
        "call_counts": [0, 1, 8, 64, 512, 4096],
        "arms": ["guest_software", "guest_precompile"],
        "shapes": ["core_only", "balanced_core_and_poseidon2", "poseidon2_dominant"],
    }
    for key, expected in expected_corpus.items():
        _expect_exact(corpus[key], expected, f"M6 corpus {key}")
    _expect_exact(
        corpus["input_rule"],
        "software and precompile arms consume byte-identical ordered inputs and publish byte-identical ordered outputs",
        "M6 corpus input rule",
    )

    gates = _closed_object(
        milestone["exact_gates"],
        {
            "base_profile_zero_calls",
            "extension_profile_zero_calls",
            "semantic_outputs",
            "call_and_relation_multiplicity",
            "committed_cells_at_512_calls_candidate_over_software",
            "committed_cells_at_4096_calls_candidate_over_software",
            "proof_size_at_4096_calls_candidate_over_software",
        },
        "M6.exact_gates",
    )
    _expect_exact(gates["base_profile_zero_calls"], M6_BASE_ZERO, "M6 base-profile zero-call gate")
    _expect_exact(
        gates["extension_profile_zero_calls"],
        M6_EXTENSION_ZERO,
        "M6 extension-profile zero-call gate",
    )
    if gates["base_profile_zero_calls"] == gates["extension_profile_zero_calls"]:
        raise ProtocolError("M6 base and extension zero-call profiles collapsed")
    for key, expected in {
        "semantic_outputs": "exact equality for every call count and shape",
        "call_and_relation_multiplicity": "exact equality to the admitted call stream",
        "committed_cells_at_512_calls_candidate_over_software": 0.85,
        "committed_cells_at_4096_calls_candidate_over_software": 0.75,
        "proof_size_at_4096_calls_candidate_over_software": 1.10,
    }.items():
        _expect_exact(gates[key], expected, f"M6 exact gate {key}")

    statistical = _closed_object(
        milestone["statistical_gates"],
        {
            "crossover",
            "cpu_speed_lower_ci_at_4096_calls",
            "metal_speed_lower_ci_at_4096_calls",
            "native_verification_upper_ci_at_4096_calls",
            "process_cpu_upper_ci_at_4096_calls",
            "peak_rss_upper_ci_at_4096_calls",
            "all_other_rows",
        },
        "M6.statistical_gates",
    )
    for key, expected in {
        "crossover": "the first call count with committed-cell ratio below 1.0 and verified-request speed lower CI above 1.0 is no greater than 512",
        "cpu_speed_lower_ci_at_4096_calls": 1.10,
        "metal_speed_lower_ci_at_4096_calls": 1.05,
        "native_verification_upper_ci_at_4096_calls": 1.05,
        "process_cpu_upper_ci_at_4096_calls": 1.05,
        "peak_rss_upper_ci_at_4096_calls": 1.05,
        "all_other_rows": "universal budgets",
    }.items():
        _expect_exact(statistical[key], expected, f"M6 statistical gate {key}")


def _validate_m7(root: Path, milestone: Mapping[str, Any]) -> None:
    expected_corpus = [
        {
            "id": "multi_shard_addi",
            "elf": WORKLOADS["multi_shard_addi"][0],
            "input": None,
        },
        {"id": "memcpy_loop", "elf": WORKLOADS["memcpy_loop"][0], "input": None},
        {
            "id": "balanced_core_and_poseidon2",
            "generator": "poseidon2-software-precompile-equivalence-v1",
            "seed": "stwo-typed-air-m7-balanced-poseidon2-v1",
            "shape": "balanced_core_and_poseidon2",
        },
        {
            "id": "poseidon2_dominant",
            "generator": "poseidon2-software-precompile-equivalence-v1",
            "seed": "stwo-typed-air-m7-dominant-poseidon2-v1",
            "shape": "poseidon2_dominant",
        },
    ]
    _expect_exact(milestone["corpus"], expected_corpus, "M7 corpus")
    _validate_workload_paths(root, milestone["corpus"][:2], "M7 local workloads")
    _expect_exact(
        milestone["worker_counts"], [1, 2, 4, "min(8,physical_cores)"], "M7 worker matrix"
    )
    _expect_exact(
        milestone["host_admission"],
        "the promotion host has at least four physical cores; otherwise M7 is NO_VERDICT",
        "M7 host admission",
    )
    parallel = _closed_object(
        milestone["parallelizable_fraction"],
        {
            "symbol",
            "definition",
            "qualifying_minimum",
            "qualifying_minimum_eligible_ns",
            "minimum_qualifying_workloads",
            "amdahl_ideal",
            "required_speed_lower_ci",
        },
        "M7.parallelizable_fraction",
    )
    for key, expected in {
        "symbol": "p",
        "definition": "sum of one-worker durations of dependency-ready parallel-eligible tasks divided by one-worker verified-request duration",
        "qualifying_minimum": 0.40,
        "qualifying_minimum_eligible_ns": 500_000_000,
        "minimum_qualifying_workloads": 2,
        "amdahl_ideal": "1 / ((1 - p) + p / N)",
        "required_speed_lower_ci": "max(1.05, 0.70 / ((1 - p) + p / N)) at N = min(8, physical_cores)",
    }.items():
        _expect_exact(parallel[key], expected, f"M7 parallel gate {key}")
    statistical = _closed_object(
        milestone["statistical_gates"],
        {
            "candidate_one_worker_against_predecessor_one_worker",
            "largest_worker_count_speed",
            "largest_worker_count_total_resource_work_over_one_worker_upper_ci",
            "largest_worker_count_peak_rss_over_one_worker_upper_ci",
        },
        "M7.statistical_gates",
    )
    _expect_exact(
        statistical["candidate_one_worker_against_predecessor_one_worker"],
        "universal budgets",
        "M7 predecessor comparison",
    )
    _expect_exact(
        statistical["largest_worker_count_speed"],
        "required_speed_lower_ci formula above for every qualifying workload",
        "M7 largest-worker speed gate",
    )
    _expect_exact(
        statistical["largest_worker_count_total_resource_work_over_one_worker_upper_ci"],
        1.15,
        "M7 total-work override",
    )
    _expect_exact(
        statistical["largest_worker_count_peak_rss_over_one_worker_upper_ci"],
        1.25,
        "M7 RSS override",
    )
    _expect_exact(milestone["universal_budget_overrides"], M7_OVERRIDES, "M7 resource overrides")


def _validate_m8(root: Path, milestone: Mapping[str, Any]) -> None:
    micro = _closed_object(
        milestone["family_microbenchmarks"],
        {"generator", "seed", "families", "log_rows"},
        "M8.family_microbenchmarks",
    )
    _expect_exact(micro["generator"], "typed-air-family-isolated-v1", "M8 generator")
    _expect_exact(micro["seed"], "stwo-typed-air-m8-all-families-v1", "M8 seed")
    _expect_exact(micro["families"], EXPECTED_M8_FAMILIES, "M8 17-family corpus")
    if len(set(micro["families"])) != 17:
        raise ProtocolError("M8 family corpus must contain 17 unique families")
    _expect_exact(micro["log_rows"], [10, 14, 18], "M8 row matrix")
    _expect_exact(milestone["full_proof_workloads"], EXPECTED_M8_WORKLOADS, "M8 workloads")
    if len(milestone["full_proof_workloads"]) != 9:
        raise ProtocolError("M8 must contain exactly nine full-proof workloads")
    _validate_workload_paths(root, milestone["full_proof_workloads"], "M8 workloads")


def _validate_m9(milestone: Mapping[str, Any]) -> None:
    corpus = _closed_object(
        milestone["corpus"],
        {
            "generator",
            "seed",
            "leaf_log_rows",
            "leaf_counts",
            "worker_counts",
            "aggregation_tree",
            "comparators",
        },
        "M9.corpus",
    )
    for key, expected in {
        "generator": "typed-air-recursion-leaf-corpus-v1",
        "seed": "stwo-typed-air-m9-recursion-v1",
        "leaf_log_rows": [14, 16, 18],
        "leaf_counts": [2, 4, 8, 16, 32],
        "worker_counts": [1, 4, 8],
        "aggregation_tree": "balanced deterministic two-to-one",
        "comparators": [
            "the same leaf proofs independently verified without aggregation",
            "one semantically equivalent monolithic proof",
        ],
    }.items():
        _expect_exact(corpus[key], expected, f"M9 corpus {key}")

    exact = _closed_object(
        milestone["exact_gates"],
        {
            "leaf_and_parent_summaries",
            "root_proof_size_32_over_2",
            "root_proof_size_over_single_leaf_for_every_leaf_count",
            "aggregation_tree_shape",
            "worker_bound_and_cleanup",
        },
        "M9.exact_gates",
    )
    _expect_exact(exact["root_proof_size_32_over_2"], 1.05, "M9 proof-size scaling")
    _expect_exact(
        exact["root_proof_size_over_single_leaf_for_every_leaf_count"],
        1.10,
        "M9 proof-size leaf bound",
    )
    for key, expected in {
        "leaf_and_parent_summaries": "every leaf summary, parent relation summary, transcript binding, and root statement matches the deterministic aggregation manifest and verifies independently",
        "aggregation_tree_shape": "exact equality to the balanced canonical tree for every leaf count",
        "worker_bound_and_cleanup": "all M7 bounded-worker and failure-cleanup gates",
    }.items():
        _expect_exact(exact[key], expected, f"M9 exact gate {key}")
    statistical = _closed_object(
        milestone["statistical_gates"],
        {
            "root_verification_time_32_over_2_upper_ci",
            "fixed_worker_coordinator_peak_rss_32_over_2_upper_ci",
            "total_recursive_resource_work_over_flat_leaf_work_upper_ci",
            "eight_leaf_four_worker_speed_lower_ci",
            "time_crossover",
            "peak_rss_at_crossover_over_equivalent_monolithic_upper_ci",
        },
        "M9.statistical_gates",
    )
    for key, expected in {
        "root_verification_time_32_over_2_upper_ci": 1.10,
        "fixed_worker_coordinator_peak_rss_32_over_2_upper_ci": 1.10,
        "total_recursive_resource_work_over_flat_leaf_work_upper_ci": 1.50,
        "eight_leaf_four_worker_speed_lower_ci": 1.25,
        "time_crossover": "recursive wall-time lower CI is above 1.0 relative to sequential flat proving no later than eight leaves",
        "peak_rss_at_crossover_over_equivalent_monolithic_upper_ci": 0.60,
    }.items():
        _expect_exact(statistical[key], expected, f"M9 statistical gate {key}")
    _expect_exact(milestone["universal_budget_overrides"], M9_OVERRIDES, "M9 resource overrides")


def _validate_receipt_contract(protocol: Mapping[str, Any]) -> None:
    receipt = protocol["receipt_contract"]
    _expect_exact(receipt["schema"], "stwo-typed-air-performance-receipt-v1", "receipt schema")
    for key in (
        "required_root_fields",
        "protocol_identity_fields",
        "source_identity_fields",
        "attempt_fields",
        "timing_fields",
        "resource_fields",
        "allocation_fields",
        "geometry_fields",
        "proof_fields",
        "artifact_fields",
        "required_raw_properties",
        "validator_rejections",
    ):
        _expect_unique_strings(receipt[key], f"receipt_contract.{key}")
    for required in ("protocol", "attempts", "gates", "primary_target", "content_sha256"):
        if required not in receipt["required_root_fields"]:
            raise ProtocolError(f"receipt root omits required field {required}")


def validate_protocol_value(root: Path, protocol: dict[str, Any]) -> None:
    """Validate an already decoded protocol against the frozen v1 contract."""

    root = root.resolve()
    _closed_object(protocol, ROOT_FIELDS, "protocol")
    _expect_exact(protocol["schema"], SCHEMA, "schema")
    _expect_exact(protocol["schema_version"], SCHEMA_VERSION, "schema version")
    _expect_exact(protocol["status"], STATUS, "status")
    _expect_exact(protocol["repository"], REPOSITORY, "repository")
    _expect_exact(protocol["documentation"], "design/typed-air/PERFORMANCE.md", "documentation")
    _owned_file(root, protocol["documentation"], "documentation")

    for section, fields in SECTION_FIELDS.items():
        _closed_object(protocol[section], fields, section)

    _expect_exact(protocol["scope"]["milestones"], ["M5", "M6", "M7", "M8", "M9"], "scope milestone order")
    _expect_unique_strings(protocol["scope"]["non_goals"], "scope.non_goals")

    authority = protocol["statistical_authority"]
    for key, expected in EXPECTED_AUTHORITY.items():
        _expect_exact(authority[key], expected, f"statistical_authority.{key}")
    _validate_reference(
        root,
        authority,
        path_key="amendment_path",
        digest_key="amendment_sha256",
        expected_path=EXPECTED_AUTHORITY["amendment_path"],
        expected_digest=EXPECTED_AUTHORITY["amendment_sha256"],
        label="performance authority amendment",
    )
    _validate_reference(
        root,
        authority,
        path_key="statistics_path",
        digest_key="statistics_sha256",
        expected_path=EXPECTED_AUTHORITY["statistics_path"],
        expected_digest=EXPECTED_AUTHORITY["statistics_sha256"],
        label="performance statistics",
    )

    corpus_authority = protocol["corpus_authority"]
    for key, expected in EXPECTED_CORPUS_AUTHORITY.items():
        _expect_exact(corpus_authority[key], expected, f"corpus_authority.{key}")
    _validate_reference(
        root,
        corpus_authority,
        path_key="canonical_trace_manifest_path",
        digest_key="canonical_trace_manifest_sha256",
        expected_path=EXPECTED_CORPUS_AUTHORITY["canonical_trace_manifest_path"],
        expected_digest=EXPECTED_CORPUS_AUTHORITY["canonical_trace_manifest_sha256"],
        label="canonical trace corpus",
    )
    _validate_reference(
        root,
        corpus_authority,
        path_key="crypto_provenance_path",
        digest_key="crypto_provenance_sha256",
        expected_path=EXPECTED_CORPUS_AUTHORITY["crypto_provenance_path"],
        expected_digest=EXPECTED_CORPUS_AUTHORITY["crypto_provenance_sha256"],
        label="crypto corpus provenance",
    )

    _validate_sampling(protocol)
    _expect_exact(protocol["universal_hard_budgets"], EXPECTED_BUDGETS, "universal budgets")
    _expect_exact(protocol["lanes"], EXPECTED_LANES, "performance lanes")

    _expect_exact(
        protocol["optimization_claim_contract"],
        EXPECTED_OPTIMIZATION_CONTRACT,
        "optimization claim contract",
    )

    allocation = protocol["allocation_accounting"]
    _expect_exact(allocation["applicable_milestones"], ["M5", "M8"], "allocation milestones")
    for key in ("hot_allocation_calls", "hot_allocated_bytes", "hot_reallocation_calls", "hot_free_calls"):
        _expect_exact(allocation[key], 0, f"allocation_accounting.{key}")
    scaling = _closed_object(
        allocation["time_scaling"],
        {"log_rows", "maximum_adjacent_time_ratio", "ratio", "decision", "meaning"},
        "allocation_accounting.time_scaling",
    )
    _expect_exact(scaling["log_rows"], [10, 14, 18], "allocation scaling rows")
    _expect_exact(scaling["maximum_adjacent_time_ratio"], 17.6, "allocation scaling ratio")

    milestones_raw = protocol["milestones"]
    if type(milestones_raw) is not list:
        raise ProtocolError("milestones must be a list")
    milestone_ids = [item.get("id") if type(item) is dict else None for item in milestones_raw]
    _expect_exact(milestone_ids, ["M5", "M6", "M7", "M8", "M9"], "milestone order")
    milestones: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(milestones_raw):
        milestone_id = milestone_ids[index]
        if type(milestone_id) is not str:
            raise ProtocolError(f"milestones[{index}].id must be a string")
        milestone = _closed_object(raw, MILESTONE_FIELDS[milestone_id], f"milestones[{index}]")
        _expect_exact(milestone["required_lanes"], ["cpu-native", "metal-hybrid"], f"{milestone_id} lanes")
        _validate_primary_target(milestone)
        milestones[milestone_id] = milestone

    _validate_m5(root, milestones["M5"])
    _validate_m6(milestones["M6"])
    _validate_m7(root, milestones["M7"])
    _validate_m8(root, milestones["M8"])
    _validate_m9(milestones["M9"])
    _validate_receipt_contract(protocol)


def validate_protocol(root: Path, path: Path) -> ProtocolSummary:
    """Load, authenticate, and validate one repository-owned protocol file."""

    root = root.resolve()
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ProtocolError("protocol path escapes the repository") from error
    if not path.is_file():
        raise ProtocolError(f"protocol file is missing: {path}")
    size = path.stat().st_size
    if size == 0 or size > MAX_PROTOCOL_BYTES:
        raise ProtocolError("protocol file is empty or oversized")
    raw = path.read_bytes()
    protocol = decode_strict_json(raw, label="performance protocol")
    validate_protocol_value(root, protocol)
    return ProtocolSummary(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        schema=protocol["schema"],
        schema_version=protocol["schema_version"],
        milestones=tuple(item["id"] for item in protocol["milestones"]),
        lanes=tuple(item["id"] for item in protocol["lanes"]),
    )
