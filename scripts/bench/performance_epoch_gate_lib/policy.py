"""Load and authenticate the repository-owned epoch-2 protocol manifest."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import sha256_file, strict_json
from .model import EvidenceError, exact_object, require_hex, require_int, require_number


PROTOCOL_FIELDS = {
    "schema", "schema_version", "receipt_schema", "plan_schema", "repository",
    "authority", "baseline_source", "statistics", "budgets", "workloads",
    "performance_lanes", "build_comparisons", "host_roles", "trusted_stark_v",
    "artifact_kinds", "limits",
}
AUTHORITY_FIELDS = {
    "amendment_path", "amendment_sha256", "baseline_receipt_path",
    "baseline_receipt_sha256", "runner_path", "runner_sha256", "stats_path",
    "stats_sha256", "autoresearch_manifest_path", "autoresearch_manifest_sha256",
}
STATISTICS_FIELDS = {
    "pairing", "arm_a", "arm_b", "estimator", "confidence_level", "bootstrap",
    "bootstrap_iterations", "seed", "first_order", "minimum_paired_rounds",
    "minimum_excluded_verified_warmups",
    "minimum_measured_verified_proofs_per_arm_per_round", "cooldown_seconds",
    "early_stopping",
}
BUDGET_FIELDS = {
    "minimum_throughput_ci_lower", "maximum_peak_rss_ratio",
    "maximum_focused_cold_build_ratio",
    "riscv_static_cold_build_seconds", "riscv_warm_noop_build_seconds",
    "riscv_hosted_challenge_seconds",
}
EXPECTED_AUTHORITY = {
    "amendment_path": "conformance/2026-07-21-performance-authority-epoch-3-amendment.md",
    "amendment_sha256": "481e2c995eadb8cdd1240e4a205d63fc15550d03a3ee3635ba434286f8033606",
    "baseline_receipt_path": "conformance/build-monorepo-baseline-v1.json",
    "baseline_receipt_sha256": "69a6fa54fb9263122fa7851e68343c4dd0fc2ade4426d0b2c72dff2f701be9f0",
    "runner_path": "conformance/performance-authority/epoch-3/runner.py.txt",
    "runner_sha256": "bf86d66188783e3b1e9695a2a39c1571096ffa82d92890d494ef68a91f2a6641",
    "stats_path": "conformance/performance-authority/epoch-3/stats.py",
    "stats_sha256": "6c5b887033273e2e523841509c3387395245b63e5a32c7b0f17304d7b99c9ec7",
    "autoresearch_manifest_path": "conformance/performance-authority/epoch-3/MANIFEST.json",
    "autoresearch_manifest_sha256": "086f5d1c8265b8ef75d4a85349fef0a2c0de4c4f97e75914adf93b80c8762f62",
}
EXPECTED_BUDGETS = {
    "minimum_throughput_ci_lower": 0.97,
    "maximum_peak_rss_ratio": 1.05,
    "maximum_focused_cold_build_ratio": 1.0,
    "riscv_static_cold_build_seconds": 60.0,
    "riscv_warm_noop_build_seconds": 2.0,
    "riscv_hosted_challenge_seconds": 180.0,
}
EXPECTED_WORKLOADS = (
    ("wide_fibonacci:log_n_rows=10,sequence_len=8", "wide_fibonacci", {"log_n_rows": 10, "sequence_len": 8}, {"unit": "trace_rows", "units": 1024}),
    ("xor:log_size=10,log_step=2,offset=3", "xor", {"log_size": 10, "log_step": 2, "offset": 3}, {"unit": "xor_rows", "units": 1024}),
    ("plonk:log_n_rows=10", "plonk", {"log_n_rows": 10}, {"unit": "plonk_rows", "units": 1024}),
    ("state_machine:log_n_rows=10,initial_x=9,initial_y=3", "state_machine", {"log_n_rows": 10, "initial_x": 9, "initial_y": 3}, {"unit": "state_transitions", "units": 1024}),
    ("blake:log_n_rows=8,n_rounds=2", "blake", {"log_n_rows": 8, "n_rounds": 2}, {"unit": "blake_round_instances", "units": 512}),
    ("poseidon:log_n_instances=13", "poseidon", {"log_n_instances": 13}, {"unit": "poseidon_instances", "units": 8192}),
)


def _owned_digest(root: Path, relative: object, expected: object, label: str) -> None:
    if not isinstance(relative, str) or not relative:
        raise EvidenceError(f"{label} path is invalid")
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        raise EvidenceError(f"{label} is not a repository-owned file")
    require_hex(expected, 64, f"{label} digest")
    if sha256_file(candidate) != expected:
        raise EvidenceError(f"{label} digest mismatch")


def _validate_workloads(workloads: object) -> None:
    if not isinstance(workloads, list) or len(workloads) != 6:
        raise EvidenceError("protocol must define exactly six Native workloads")
    seen: set[str] = set()
    for index, item in enumerate(workloads):
        row = exact_object(item, {"id", "name", "parameters", "numerator"}, f"workload[{index}]")
        if not isinstance(row["id"], str) or row["id"] in seen:
            raise EvidenceError("workload IDs must be unique nonempty strings")
        seen.add(row["id"])
        if not isinstance(row["parameters"], dict) or not row["parameters"]:
            raise EvidenceError("workload parameters must be a nonempty object")
        numerator = exact_object(row["numerator"], {"unit", "units"}, "workload numerator")
        require_int(numerator["units"], "workload numerator units", 1)


def load_protocol(root: Path, path: Path) -> tuple[dict[str, Any], str]:
    root = root.resolve()
    path = path.resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise EvidenceError("protocol must be a repository-owned file")
    value = strict_json(path, 1024 * 1024, canonical=False)
    exact_object(value, PROTOCOL_FIELDS, "protocol")
    if value["schema"] != "build-monorepo-performance-baseline-v2-protocol-v2":
        raise EvidenceError("unsupported performance protocol")
    if value["schema_version"] != 2:
        raise EvidenceError("unsupported performance protocol version")
    authority = exact_object(value["authority"], AUTHORITY_FIELDS, "authority")
    if authority != EXPECTED_AUTHORITY:
        raise EvidenceError("frozen epoch authority drifted")
    for prefix in ("amendment", "baseline_receipt", "runner", "stats", "autoresearch_manifest"):
        _owned_digest(root, authority[f"{prefix}_path"], authority[f"{prefix}_sha256"], prefix)
    baseline = exact_object(value["baseline_source"], {"commit", "tree"}, "baseline source")
    require_hex(baseline["commit"], 40, "baseline commit")
    require_hex(baseline["tree"], 40, "baseline tree")
    stark_v = exact_object(value["trusted_stark_v"], {"repository", "commit"}, "trusted Stark-V")
    require_hex(stark_v["commit"], 40, "trusted Stark-V commit")
    statistics = exact_object(value["statistics"], STATISTICS_FIELDS, "statistics")
    expected_statistics = {
        "pairing": "round-level alternating AB/BA",
        "arm_a": "baseline",
        "arm_b": "candidate",
        "estimator": "Hodges-Lehmann Walsh-average location",
        "confidence_level": 0.95,
        "bootstrap": "deterministic percentile",
        "bootstrap_iterations": 4000,
        "seed": "sha256-workload-id-colon-zero-first-32-bits-big-endian",
        "first_order": "sha256-workload-id-low-bit-zero-is-AB",
        "minimum_paired_rounds": 3,
        "minimum_excluded_verified_warmups": 10,
        "minimum_measured_verified_proofs_per_arm_per_round": 10,
        "cooldown_seconds": 1.0,
        "early_stopping": False,
    }
    if statistics != expected_statistics:
        raise EvidenceError("frozen statistical policy drifted")
    budgets = exact_object(value["budgets"], BUDGET_FIELDS, "budgets")
    for key, item in budgets.items():
        require_number(item, f"budgets.{key}")
    if budgets != EXPECTED_BUDGETS:
        raise EvidenceError("frozen performance budgets drifted")
    _validate_workloads(value["workloads"])
    expected_workloads = [
        {"id": identifier, "name": name, "parameters": parameters, "numerator": numerator}
        for identifier, name, parameters, numerator in EXPECTED_WORKLOADS
    ]
    if value["workloads"] != expected_workloads:
        raise EvidenceError("frozen Native workload basket drifted")
    expected_lanes = [
        {"host_role": "macos", "backend": "cpu", "runtime_mode": "native", "proof_equality_group": "canonical-functional"},
        {"host_role": "macos", "backend": "metal-hybrid", "runtime_mode": "source-jit", "proof_equality_group": "canonical-functional"},
        {"host_role": "linux", "backend": "cpu", "runtime_mode": "native", "proof_equality_group": "canonical-functional"},
    ]
    if value["performance_lanes"] != expected_lanes:
        raise EvidenceError("frozen performance lanes drifted")
    expected_steps = {
        "macos-native-cpu": "stwo-native-cpu",
        "macos-native-metal": "stwo-native-metal",
        "linux-native-cpu": "stwo-native-cpu",
        "linux-riscv-cpu-static": "stwo-zig-riscv-cpu-static",
    }
    if {
        item.get("id"): item.get("candidate_step")
        for item in value["build_comparisons"] if isinstance(item, dict)
    } != expected_steps:
        raise EvidenceError("focused build step authority drifted")
    roles = value["host_roles"]
    if not isinstance(roles, dict) or set(roles) != {"linux", "macos"}:
        raise EvidenceError("host roles must be exactly linux and macos")
    build_ids = {item["id"] for item in value["build_comparisons"] if isinstance(item, dict)}
    for role, spec in roles.items():
        exact_object(spec, {"os", "requires_gpu", "requires_metal", "required_builds"}, role)
        if not isinstance(spec["required_builds"], list) or not set(spec["required_builds"]).issubset(build_ids):
            raise EvidenceError(f"{role} required build set is invalid")
    limits = value["limits"]
    if not isinstance(limits, dict):
        raise EvidenceError("limits must be an object")
    for key, item in limits.items():
        require_int(item, f"limits.{key}", 1)
    if value["trusted_stark_v"] != {
        "repository": "https://github.com/ClementWalter/stark-v",
        "commit": "d478f783055aa0d73a93768a433a3c6c31c91d1c",
    }:
        raise EvidenceError("pinned Stark-V benchmark reference drifted")
    return value, sha256_file(path)
