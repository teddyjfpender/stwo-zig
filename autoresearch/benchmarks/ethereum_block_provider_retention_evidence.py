"""Strict adapter for the retained provider coefficient-retention sweep."""

from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_provider_raw_batch_evidence as batch_support  # noqa: E402
import ethereum_block_provider_raw_pair_evidence as pair_support  # noqa: E402
import ethereum_block_provider_topology_evidence as topology_support  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.poseidon-provider-retention-sweep.v1"
EVIDENCE_SCHEMA = "stwo.ethereum.optimization-provider-retention-evidence.v1"
MAX_TOTAL_NS = 60_000_000_000
POLICIES = ("always", "never")


class ProviderRetentionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderRetentionEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    try:
        return pair_support._identity(path, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    try:
        return pair_support._validate_identity(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error


def _timing(value: Any, where: str) -> dict[str, int]:
    try:
        return pair_support._timing(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error


def _sha(value: Any, where: str) -> str:
    try:
        return pair_support._sha(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error


def _profile(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "build_mode", "composition_columns", "coefficient_retention",
        "host_power_classification", "main_columns", "preprocessed_columns",
        "provider_profile", "synthetic_core_stage_a", "tree2_columns",
    }, "provider retention profile")
    _require(value == {
        "build_mode": "ReleaseFast",
        "composition_columns": 8,
        "coefficient_retention": "sweep(always,never)",
        "host_power_classification": "ac-high-power-pinned",
        "main_columns": 445,
        "preprocessed_columns": 2,
        "provider_profile": "standalone-provider-v1",
        "synthetic_core_stage_a": False,
        "tree2_columns": 8,
    }, "provider retention profile differs")
    return value


def _proof(value: Any, ordinal: int, policy: str, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "canonical_proof_bytes_equal", "cold_verify", "committed_column_count",
        "exact_cross_retention_proof_bytes_equal", "fresh_verified", "ordinal",
        "proof", "prove_wall_ns", "retained_coefficient_columns",
        "roots_equal_cross_retention", "roots_equal_proof",
        "statement_identity_sha256", "statement_equal_cross_retention",
    }, where)
    boolean_fields = (
        "canonical_proof_bytes_equal", "exact_cross_retention_proof_bytes_equal",
        "fresh_verified", "roots_equal_cross_retention", "roots_equal_proof",
        "statement_equal_cross_retention",
    )
    _require(
        value["ordinal"] == ordinal
        and all(value[field] is True for field in boolean_fields)
        and type(value["committed_column_count"]) is int
        and value["committed_column_count"] == 455
        and type(value["prove_wall_ns"]) is int and value["prove_wall_ns"] > 0
        and type(value["retained_coefficient_columns"]) is int
        and value["retained_coefficient_columns"]
        == (455 if policy == "always" else 0),
        f"{where} correctness differs",
    )
    _validate_identity(value["proof"], f"{where} proof")
    _timing(value["cold_verify"], f"{where} cold verification")
    _sha(value["statement_identity_sha256"], f"{where} statement identity")
    return value


def _receipt(path: Path, executable_custody: Path, *,
             require_declared_path: bool) -> dict[str, Any]:
    try:
        value = pair_support._read_zig(
            path, RECEIPT_SCHEMA, "provider retention receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error
    _exact(value, {
        "content_sha256", "admission", "arms", "benchmark_executable",
        "performance_claim_eligible", "production_eligible", "profile",
        "recursive_admissible", "retention_speedup_milli", "schema", "status",
        "timing_scope", "total_hard_cap_ns", "total_wall_ns", "workload",
    }, "provider retention receipt")
    _require(
        value["status"] == "diagnostic-retention-sweep-fresh-verified"
        and value["timing_scope"]
        == "retained-provider-retention-sweep-self-process"
        and value["performance_claim_eligible"] is True
        and value["production_eligible"] is False
        and value["recursive_admissible"] is False
        and value["total_hard_cap_ns"] == 118_000_000_000
        and type(value["total_wall_ns"]) is int
        and 0 < value["total_wall_ns"] <= MAX_TOTAL_NS,
        "provider retention claim boundary differs",
    )
    declared = _exact(value["benchmark_executable"], {
        "path", "bytes", "sha256",
    }, "provider retention declared executable")
    custody = _identity(executable_custody, "provider retention executable custody")
    _require(
        {key: declared[key] for key in ("bytes", "sha256")}
        == {key: custody[key] for key in ("bytes", "sha256")}
        and (not require_declared_path or declared["path"] == custody["path"]),
        "provider retention executable custody differs",
    )
    if require_declared_path:
        _require(os.access(executable_custody, os.X_OK),
                 "provider retention executable is not executable")
    _profile(value["profile"])
    try:
        workload = batch_support._workload(value["workload"])
        admission = pair_support._admission(
            value["admission"], "provider retention admission",
        )
    except (
        batch_support.ProviderRawBatchEvidenceError,
        pair_support.ProviderRawPairEvidenceError,
    ) as error:
        raise ProviderRetentionEvidenceError(str(error)) from error
    batch_size = workload["batch_size"]
    _require(
        batch_size == 4 and workload["ordinals"] == list(range(batch_size))
        and admission["requested_concurrent_jobs"]
        == admission["admitted_concurrent_jobs"] == batch_size
        and admission["work_items"] == batch_size,
        "provider retention workload/admission differs",
    )
    arms = value["arms"]
    _require(type(arms) is list and len(arms) == len(POLICIES),
             "provider retention arm count differs")
    reference: list[tuple[int, str, str]] | None = None
    arm_total = 0
    proof_batches: list[int] = []
    for arm_index, (arm, policy) in enumerate(zip(arms, POLICIES, strict=True)):
        arm = _exact(arm, {
            "arm_index", "cold_verify_wall_ns", "hard_cap_ns", "policy",
            "proof_batch_wall_ns", "proofs", "resource_usage", "total",
        }, f"provider retention arm {arm_index}")
        _require(
            arm["arm_index"] == arm_index and arm["policy"] == policy
            and arm["hard_cap_ns"] == 50_000_000_000
            and type(arm["proof_batch_wall_ns"]) is int
            and arm["proof_batch_wall_ns"] > 0
            and type(arm["cold_verify_wall_ns"]) is int
            and arm["cold_verify_wall_ns"] > 0,
            f"provider retention arm {arm_index} authority differs",
        )
        total = _timing(arm["total"], f"provider retention arm {arm_index} total")
        try:
            topology_support._resource(
                arm["resource_usage"], f"provider retention arm {arm_index} resource",
            )
        except topology_support.ProviderTopologyEvidenceError as error:
            raise ProviderRetentionEvidenceError(str(error)) from error
        _require(
            total["wall_ns"] <= arm["hard_cap_ns"]
            and total["wall_ns"] >= arm["proof_batch_wall_ns"]
            + arm["cold_verify_wall_ns"],
            f"provider retention arm {arm_index} timing closure differs",
        )
        proofs = arm["proofs"]
        _require(type(proofs) is list and len(proofs) == batch_size,
                 f"provider retention arm {arm_index} proof count differs")
        current = []
        verify_sum = 0
        for ordinal, proof in enumerate(proofs):
            proof = _proof(
                proof, ordinal, policy,
                f"provider retention arm {arm_index} proof {ordinal}",
            )
            verify_sum += proof["cold_verify"]["wall_ns"]
            current.append((
                proof["proof"]["bytes"], proof["proof"]["sha256"],
                proof["statement_identity_sha256"],
            ))
        _require(arm["cold_verify_wall_ns"] >= verify_sum,
                 f"provider retention arm {arm_index} verification closure differs")
        if reference is None:
            reference = current
        else:
            _require(current == reference,
                     "provider retention cross-policy proof authority differs")
        proof_batches.append(arm["proof_batch_wall_ns"])
        arm_total += total["wall_ns"]
    expected_speedup = proof_batches[1] * 1000 // proof_batches[0]
    _require(
        value["retention_speedup_milli"] == expected_speedup
        and proof_batches[0] < proof_batches[1]
        and value["total_wall_ns"] >= arm_total,
        "provider retention speedup/total closure differs",
    )
    return value


def _normalized(receipt_path: Path, executable_custody: Path) -> dict[str, Any]:
    receipt = _receipt(
        receipt_path, executable_custody, require_declared_path=False,
    )
    arms = [{
        "policy": arm["policy"],
        "proof_batch_wall_ns": arm["proof_batch_wall_ns"],
        "cold_verify_wall_ns": arm["cold_verify_wall_ns"],
        "arm_total_wall_ns": arm["total"]["wall_ns"],
        "retained_coefficient_columns": arm["proofs"][0][
            "retained_coefficient_columns"
        ],
        "peak_physical_footprint_bytes": arm["resource_usage"][
            "lifetime_peak_after_bytes"
        ],
    } for arm in receipt["arms"]]
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "provider-retention-stage-diagnostic-fresh-verified",
        "receipt": _identity(receipt_path, "provider retention receipt"),
        "receipt_content_sha256": receipt["content_sha256"],
        "declared_benchmark_executable": copy.deepcopy(
            receipt["benchmark_executable"]
        ),
        "benchmark_executable_custody": _identity(
            executable_custody, "provider retention executable custody",
        ),
        "source_receipt": copy.deepcopy(receipt),
        "measured_arms": arms,
        "measured_retention_speedup_milli": receipt["retention_speedup_milli"],
        "ranking": {
            "scope": "standalone-provider-coefficient-retention-stage-only",
            "metric": "measured-proof-batch-wall-ns",
            "best_policy": "always",
            "fresh_verification": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def capture(receipt_path: Path, output: Path, staging: Path) -> dict[str, Any]:
    receipt_path, output, staging = (
        receipt_path.absolute(), output.absolute(), staging.absolute()
    )
    store.require_directory(output.parent, "provider retention evidence parent")
    store.require_directory(staging, "provider retention staging", create=True)
    try:
        raw = pair_support._read_zig(
            receipt_path, RECEIPT_SCHEMA, "provider retention receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRetentionEvidenceError(str(error)) from error
    declared = Path(raw["benchmark_executable"]["path"])
    _receipt(receipt_path, declared, require_declared_path=True)
    executable = store.read_regular(declared, "provider retention executable")
    custody = output.with_name(f"{output.stem}.benchmark-executable")
    store.publish_new_or_identical(custody, executable, staging_directory=staging)
    value = _normalized(receipt_path, custody)
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "receipt", "receipt_content_sha256",
        "declared_benchmark_executable", "benchmark_executable_custody",
        "source_receipt", "measured_arms", "measured_retention_speedup_milli",
        "ranking", "content_sha256",
    }, "provider retention evidence keys differ")
    _require(
        value["schema"] == EVIDENCE_SCHEMA
        and value["status"]
        == "provider-retention-stage-diagnostic-fresh-verified"
        and value["content_sha256"] == protocol.content_sha256(value),
        "provider retention evidence authority differs",
    )
    receipt = _validate_identity(value["receipt"], "provider retention receipt")
    custody = _validate_identity(
        value["benchmark_executable_custody"],
        "provider retention executable custody",
    )
    expected = _normalized(Path(receipt["path"]), Path(custody["path"]))
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "provider retention evidence replay differs",
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "provider retention evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider retention evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("capture")
    create.add_argument("--receipt", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        capture(arguments.receipt, arguments.output, arguments.staging_directory)
        return 0
    except (
        ProviderRetentionEvidenceError,
        pair_support.ProviderRawPairEvidenceError,
        batch_support.ProviderRawBatchEvidenceError,
        topology_support.ProviderTopologyEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
