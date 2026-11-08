"""Frozen data contract for the typed-AIR M5--M9 performance protocol."""

from __future__ import annotations

import re
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROTOCOL = (
    REPOSITORY_ROOT / "design/typed-air/performance/m5-m9-protocol-v1.json"
)
MAX_PROTOCOL_BYTES = 1 << 20
SCHEMA = "stwo-typed-air-m5-m9-performance-protocol-v1"
SCHEMA_VERSION = 1
STATUS = "normative-for-m5-through-m9-performance-promotion"
REPOSITORY = "https://github.com/teddyjfpender/stwo-zig"
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

ROOT_FIELDS = frozenset(
    {
        "schema",
        "schema_version",
        "status",
        "repository",
        "documentation",
        "scope",
        "strictness",
        "statistical_authority",
        "comparison_contract",
        "corpus_authority",
        "sampling_protocol",
        "outcomes",
        "metric_classes",
        "universal_hard_budgets",
        "optimization_claim_contract",
        "geometry_accounting",
        "allocation_accounting",
        "lanes",
        "milestones",
        "receipt_contract",
    }
)

SECTION_FIELDS = {
    "scope": frozenset({"milestones", "claim", "non_goals"}),
    "strictness": frozenset(
        {
            "encoding",
            "object_policy",
            "number_policy",
            "null_policy",
            "path_policy",
            "identity_policy",
            "mutation_policy",
            "failure_policy",
        }
    ),
    "statistical_authority": frozenset(
        {
            "relationship",
            "amendment_path",
            "amendment_sha256",
            "statistics_path",
            "statistics_sha256",
            "estimator",
            "confidence_level",
            "bootstrap",
            "bootstrap_iterations",
            "bootstrap_seed",
            "subject_id",
        }
    ),
    "comparison_contract": frozenset(
        {
            "arm_a",
            "arm_b",
            "baseline",
            "candidate",
            "build_mode",
            "same_between_arms",
            "required_source_identity",
            "required_build_identity",
            "speed_ratio",
            "resource_ratio",
            "round_ratio",
            "proof_timing_boundary",
            "timing_partition",
            "independent_verification_timing",
            "same_candidate_comparisons",
        }
    ),
    "corpus_authority": frozenset(
        {
            "canonical_trace_manifest_path",
            "canonical_trace_manifest_sha256",
            "crypto_provenance_path",
            "crypto_provenance_sha256",
            "generated_workloads",
            "capture_rule",
        }
    ),
    "sampling_protocol": frozenset(
        {
            "process_isolation",
            "serial_attempts",
            "excluded_verified_warmups_per_arm",
            "paired_rounds",
            "measured_verified_proofs_per_arm_per_round",
            "measured_verified_proofs_per_arm",
            "pairing",
            "first_order",
            "cooldown_seconds_between_attempts",
            "early_stopping",
            "retry_failed_attempts",
            "drop_outliers",
            "retain_raw_attempts",
            "host_requirements",
            "a_a_calibration",
        }
    ),
    "outcomes": frozenset(
        {
            "allowed",
            "pass",
            "hard_fail_conditions",
            "no_verdict_conditions",
            "promotion_rule",
        }
    ),
    "metric_classes": frozenset(
        {"exact", "statistical", "observational", "material_stage_rule"}
    ),
    "universal_hard_budgets": frozenset(
        {
            "verified_request_speed_lower_ci",
            "proving_speed_lower_ci",
            "native_verification_candidate_over_baseline_upper_ci",
            "peak_rss_candidate_over_baseline_upper_ci",
            "peak_rss_candidate_max_over_baseline_max",
            "process_cpu_candidate_over_baseline_upper_ci",
            "retired_instructions_candidate_over_baseline_upper_ci",
            "gpu_command_time_candidate_over_baseline_upper_ci",
            "protocol_preserving_proof_bytes",
            "protocol_changing_proof_size_candidate_over_baseline",
            "application",
            "override_policy",
        }
    ),
    "optimization_claim_contract": frozenset(
        {
            "predeclaration",
            "postselection",
            "optimization_minimum_speed_lower_ci",
            "compatibility_migration",
            "optimization_milestones",
        }
    ),
    "geometry_accounting": frozenset(
        {
            "rows_per_component",
            "preprocessed_cells",
            "main_cells",
            "interaction_cells",
            "committed_cells",
            "quotient_cells",
            "required_disclosures",
            "comparison_rule",
        }
    ),
    "allocation_accounting": frozenset(
        {
            "applicable_milestones",
            "prepare_boundary",
            "hot_boundary",
            "hot_allocation_calls",
            "hot_allocated_bytes",
            "hot_reallocation_calls",
            "hot_free_calls",
            "prepare_allocation_call_count",
            "output_bytes",
            "time_scaling",
        }
    ),
    "receipt_contract": frozenset(
        {
            "schema",
            "canonical_encoding",
            "content_sha256_definition",
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
        }
    ),
}

EXPECTED_AUTHORITY = {
    "amendment_path": "conformance/2026-07-21-performance-authority-epoch-3-amendment.md",
    "amendment_sha256": "481e2c995eadb8cdd1240e4a205d63fc15550d03a3ee3635ba434286f8033606",
    "statistics_path": "conformance/performance-authority/epoch-3/stats.py",
    "statistics_sha256": "6c5b887033273e2e523841509c3387395245b63e5a32c7b0f17304d7b99c9ec7",
    "estimator": "Hodges-Lehmann Walsh-average location over round ratios",
    "confidence_level": 0.95,
    "bootstrap": "deterministic percentile",
    "bootstrap_iterations": 4000,
    "bootstrap_seed": "first 32 bits, big-endian, of SHA-256 over subject_id + ':0'",
    "subject_id": "milestone_id + ':' + lane_id + ':' + workload_id + ':' + metric_id",
}

EXPECTED_CORPUS_AUTHORITY = {
    "canonical_trace_manifest_path": "vectors/riscv_elfs/trace_vectors.json",
    "canonical_trace_manifest_sha256": "0c0cddc58a38c9533a0a8581d253dcf2b6e604292aeb30b54348f897e2b508b1",
    "crypto_provenance_path": "vectors/riscv_elfs/crypto/provenance.json",
    "crypto_provenance_sha256": "c2a86cf401284f155270a45d303cb9951fe65932dec1ace79a279490df53274d",
}

EXPECTED_LANES = [
    {
        "id": "cpu-native",
        "backend": "cpu",
        "runtime_mode": "native",
        "required": True,
        "proof_equality_group": "canonical-functional",
    },
    {
        "id": "metal-hybrid",
        "backend": "metal-hybrid",
        "runtime_mode": "source-jit-or-frozen-binary-as-declared",
        "required": True,
        "proof_equality_group": "canonical-functional",
        "required_evidence": [
            "Metal runtime identity",
            "resident dispatch count",
            "zero fallback dispatches",
        ],
    },
]

EXPECTED_BUDGETS = {
    "verified_request_speed_lower_ci": 0.97,
    "proving_speed_lower_ci": 0.97,
    "native_verification_candidate_over_baseline_upper_ci": 1.03,
    "peak_rss_candidate_over_baseline_upper_ci": 1.05,
    "peak_rss_candidate_max_over_baseline_max": 1.10,
    "process_cpu_candidate_over_baseline_upper_ci": 1.05,
    "retired_instructions_candidate_over_baseline_upper_ci": 1.05,
    "gpu_command_time_candidate_over_baseline_upper_ci": 1.05,
    "protocol_preserving_proof_bytes": "exact equality",
    "protocol_changing_proof_size_candidate_over_baseline": 1.10,
    "application": "every required workload and lane passes independently; an aggregate or geometric mean cannot hide a failing row",
    "override_policy": "only an explicit narrower milestone gate in this protocol may replace a universal resource budget",
}

EXPECTED_OPTIMIZATION_CONTRACT = {
    "predeclaration": "each capture plan names exactly one primary target from the milestone entry before candidate execution",
    "postselection": "forbidden",
    "optimization_minimum_speed_lower_ci": 1.05,
    "compatibility_migration": "M5 and M8 declare non-inferiority targets and make no speedup claim",
    "optimization_milestones": "M6, M7, and M9 must pass their predeclared improvement target in addition to all non-regression gates",
}

EXPECTED_M5_CASES = [
    {"id": "lui", "family": "lui", "operation": "LUI"},
    {"id": "addi", "family": "base_alu_imm", "operation": "ADDI"},
    {
        "id": "signed_load",
        "family": "load_store",
        "operation": "LB with the loaded high bit set",
    },
    {"id": "jalr", "family": "jalr", "operation": "JALR"},
    {
        "id": "div",
        "family": "div",
        "operation": "signed DIV with a nonzero divisor",
    },
]

WORKLOADS = {
    "alu_test": ("vectors/riscv_elfs/alu_test.elf", None),
    "branch_fib": ("vectors/riscv_elfs/branch_fib.elf", None),
    "mem_ls": ("vectors/riscv_elfs/mem_ls.elf", None),
    "jal_jalr": ("vectors/riscv_elfs/jal_jalr.elf", None),
    "mul_div": ("vectors/riscv_elfs/mul_div.elf", None),
    "shift_logic": ("vectors/riscv_elfs/shift_logic.elf", None),
    "memcpy_loop": ("vectors/riscv_elfs/memcpy_loop.elf", None),
    "multi_shard_addi": ("vectors/riscv_elfs/multi_shard_addi.elf", None),
    "sha2_input_128B": (
        "vectors/riscv_elfs/crypto/sha2_input.elf",
        "vectors/riscv_elfs/crypto/inputs/msg_128.bin",
    ),
}

EXPECTED_M5_WORKLOADS = [
    {"id": name, "elf": WORKLOADS[name][0], "input": WORKLOADS[name][1]}
    for name in ("alu_test", "mem_ls", "jal_jalr", "mul_div", "branch_fib")
]

EXPECTED_M8_FAMILIES = [
    "auipc",
    "base_alu_imm",
    "base_alu_reg",
    "branch_eq",
    "branch_lt",
    "div",
    "jal",
    "jalr",
    "load_store",
    "lt_imm",
    "lt_reg",
    "lui",
    "mul",
    "mulh",
    "shifts_imm",
    "shifts_reg",
    "fence",
]

EXPECTED_M8_WORKLOADS = [
    {"id": name, "elf": WORKLOADS[name][0], "input": WORKLOADS[name][1]}
    for name in (
        "alu_test",
        "branch_fib",
        "mem_ls",
        "jal_jalr",
        "mul_div",
        "shift_logic",
        "memcpy_loop",
        "multi_shard_addi",
        "sha2_input_128B",
    )
]

EXPECTED_PRIMARY_TARGETS = {
    "M5": {
        "claim_kind": "non-inferiority",
        "lane": "cpu-native",
        "workload": "typed-air-family-isolated-v1:div:log_rows=18",
        "metric": "witness_speed",
        "decision": "lower_ci_greater_than_or_equal",
        "threshold": 0.97,
    },
    "M6": {
        "claim_kind": "improvement",
        "lane": "cpu-native",
        "workload": "poseidon2_dominant:calls=4096",
        "metric": "verified_request_speed",
        "decision": "lower_ci_greater_than_or_equal",
        "threshold": 1.10,
    },
    "M7": {
        "claim_kind": "improvement",
        "lane": "cpu-native",
        "workload": "multi_shard_addi",
        "comparison": "four workers over one worker on the same candidate",
        "metric": "verified_request_speed",
        "decision": "lower CI is at least max(1.05, 0.70 times the Amdahl ideal)",
        "threshold_floor": 1.05,
    },
    "M8": {
        "claim_kind": "non-inferiority",
        "lane": "cpu-native",
        "workload": "multi_shard_addi",
        "metric": "witness_speed",
        "decision": "lower_ci_greater_than_or_equal",
        "threshold": 0.97,
    },
    "M9": {
        "claim_kind": "improvement",
        "lane": "cpu-native",
        "workload": "leaf_log_rows=18:leaf_count=8:workers=4",
        "comparison": "recursive wall time over sequential independently verified flat leaves",
        "metric": "verified_request_speed",
        "decision": "lower_ci_greater_than_or_equal",
        "threshold": 1.25,
    },
}

MILESTONE_FIELDS = {
    "M5": frozenset(
        {
            "id",
            "name",
            "promotion_class",
            "required_lanes",
            "family_microbenchmarks",
            "full_proof_workloads",
            "primary_target",
            "exact_gates",
            "statistical_gates",
            "observational_metrics",
        }
    ),
    "M6": frozenset(
        {
            "id",
            "name",
            "promotion_class",
            "required_lanes",
            "corpus",
            "primary_target",
            "exact_gates",
            "statistical_gates",
            "observational_metrics",
        }
    ),
    "M7": frozenset(
        {
            "id",
            "name",
            "promotion_class",
            "required_lanes",
            "corpus",
            "worker_counts",
            "host_admission",
            "primary_target",
            "parallelizable_fraction",
            "exact_gates",
            "statistical_gates",
            "universal_budget_overrides",
            "observational_metrics",
        }
    ),
    "M8": frozenset(
        {
            "id",
            "name",
            "promotion_class",
            "required_lanes",
            "family_microbenchmarks",
            "full_proof_workloads",
            "primary_target",
            "exact_gates",
            "statistical_gates",
            "observational_metrics",
        }
    ),
    "M9": frozenset(
        {
            "id",
            "name",
            "promotion_class",
            "required_lanes",
            "corpus",
            "primary_target",
            "exact_gates",
            "statistical_gates",
            "universal_budget_overrides",
            "observational_metrics",
        }
    ),
}

M6_BASE_ZERO = (
    "the candidate prover running an unchanged base-profile zero-call ELF has no "
    "extension component, descriptor, committed cell, transcript field, or "
    "proof-byte change relative to the predecessor"
)
M6_EXTENSION_ZERO = (
    "an admitted extension-profile zero-call ELF binds its distinct profile and "
    "extension manifest, canonical empty call buffer, two fixed log-four extension "
    "descriptors with sixteen all-zero rows each, fixed extension column geometry, "
    "and thirteenth relation draw exactly; it is an overhead cohort and is not "
    "required or permitted to impersonate base-profile statement or proof identity"
)

M7_OVERRIDES = [
    "the 1.15 process-CPU, retired-instruction, and GPU-command-work scaling caps and 1.25 peak-RSS scaling cap replace the corresponding universal caps only when comparing candidate N workers to candidate one worker",
    "the candidate one-worker comparison to its predecessor keeps every universal budget",
]

M9_OVERRIDES = [
    "the 1.50 recursive process-CPU, retired-instruction, and GPU-command-work caps replace their universal 1.05 caps only for recursive aggregation against flat leaves",
    "the 0.60 crossover memory target and 1.10 fixed-worker scaling cap replace the universal 1.05 RSS cap only for the named M9 comparisons",
]
