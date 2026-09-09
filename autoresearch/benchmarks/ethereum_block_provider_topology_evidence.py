"""Strict adapter for the retained provider topology-sweep diagnostic."""

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
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.poseidon-provider-topology-sweep.v1"
EVIDENCE_SCHEMA = "stwo.ethereum.optimization-provider-topology-evidence.v1"
MAX_TOTAL_NS = 60_000_000_000
CONFIGURATIONS = (
    {"concurrent_jobs": 2, "hard_cap_ns": 35_000_000_000,
     "per_job_engine_workers": 8},
    {"concurrent_jobs": 3, "hard_cap_ns": 35_000_000_000,
     "per_job_engine_workers": 5},
    {"concurrent_jobs": 4, "hard_cap_ns": 35_000_000_000,
     "per_job_engine_workers": 4},
)


class ProviderTopologyEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderTopologyEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    try:
        return pair_support._identity(path, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    try:
        return pair_support._validate_identity(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error


def _timing(value: Any, where: str) -> dict[str, int]:
    try:
        return pair_support._timing(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error


def _sha(value: Any, where: str) -> str:
    try:
        return pair_support._sha(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error


def _proof(value: Any, ordinal: int, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "canonical_proof_bytes_equal", "claim_identity_sha256", "cold_verify",
        "exact_reference_proof_bytes_equal", "fresh_verified",
        "native_claim_equal_reference", "ordered_claim_equal_reference",
        "ordinal", "proof", "prove_wall_ns", "roots_equal_proof",
        "statement_identity_equal_reference", "statement_identity_sha256",
    }, where)
    _require(value["ordinal"] == ordinal
             and all(value[field] is True for field in (
                 "canonical_proof_bytes_equal",
                 "exact_reference_proof_bytes_equal", "fresh_verified",
                 "native_claim_equal_reference", "ordered_claim_equal_reference",
                 "roots_equal_proof", "statement_identity_equal_reference",
             )) and type(value["prove_wall_ns"]) is int
             and value["prove_wall_ns"] > 0,
             f"{where} correctness differs")
    _validate_identity(value["proof"], f"{where} proof")
    _timing(value["cold_verify"], f"{where} cold verify")
    _sha(value["claim_identity_sha256"], f"{where} claim")
    _sha(value["statement_identity_sha256"], f"{where} statement")
    return value


def _resource(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "availability", "cycles", "energy_nj", "instructions",
        "lifetime_peak_after_bytes", "lifetime_peak_before_bytes",
        "rss_scope", "source",
    }, where)
    _require(value["availability"] == "available" and value["rss_scope"]
             == "self-process-lifetime-peak-before-after-arm"
             and value["source"] == "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
             and all(type(value[field]) is int and value[field] > 0 for field in (
                 "cycles", "energy_nj", "instructions",
                 "lifetime_peak_after_bytes", "lifetime_peak_before_bytes",
             )) and value["lifetime_peak_after_bytes"]
             >= value["lifetime_peak_before_bytes"],
             f"{where} differs")
    return value


def _receipt(path: Path, executable_custody: Path, *,
             require_declared_path: bool) -> dict[str, Any]:
    try:
        value = pair_support._read_zig(
            path, RECEIPT_SCHEMA, "provider topology receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error
    _exact(value, {
        "arms", "benchmark_executable", "configurations", "content_sha256",
        "performance_claim_eligible", "production_eligible", "profile",
        "recursive_admissible", "schema", "status", "timing_scope",
        "total_hard_cap_ns", "total_wall_ns", "workload",
    }, "provider topology receipt")
    _require(value["status"] == "diagnostic-topology-sweep-fresh-verified"
             and value["timing_scope"]
             == "retained-provider-topology-sweep-self-process"
             and value["performance_claim_eligible"] is True
             and value["production_eligible"] is False
             and value["recursive_admissible"] is False
             and value["configurations"] == list(CONFIGURATIONS)
             and value["total_hard_cap_ns"] == 118_000_000_000
             and type(value["total_wall_ns"]) is int
             and 0 < value["total_wall_ns"] <= MAX_TOTAL_NS,
             "provider topology claim boundary differs")
    declared = _exact(value["benchmark_executable"], {
        "path", "bytes", "sha256",
    }, "provider topology declared executable")
    custody = _identity(executable_custody, "provider topology executable custody")
    _require({key: declared[key] for key in ("bytes", "sha256")}
             == {key: custody[key] for key in ("bytes", "sha256")}
             and (not require_declared_path or declared["path"] == custody["path"]),
             "provider topology executable custody differs")
    if require_declared_path:
        _require(os.access(executable_custody, os.X_OK),
                 "provider topology executable is not executable")
    try:
        pair_support._profile(value["profile"])
        workload = batch_support._workload(value["workload"])
    except (pair_support.ProviderRawPairEvidenceError,
            batch_support.ProviderRawBatchEvidenceError) as error:
        raise ProviderTopologyEvidenceError(str(error)) from error
    _require(workload["batch_size"] == 4 and workload["log_size"] == 16,
             "provider topology workload differs")

    arms = value["arms"]
    _require(type(arms) is list and len(arms) == len(CONFIGURATIONS),
             "provider topology arm count differs")
    reference: list[tuple[int, str, str, str]] | None = None
    arm_total = 0
    for index, (arm, configuration) in enumerate(zip(
        arms, CONFIGURATIONS, strict=True,
    )):
        arm = _exact(arm, {
            "admission", "arm_index", "cold_verify_wall_ns",
            "configuration_index", "proof_batch_wall_ns", "proofs",
            "resource_usage", "stage_a", "stage_a_roots_equal_reference",
            "total",
        }, f"provider topology arm {index}")
        _require(arm["arm_index"] == arm["configuration_index"] == index
                 and arm["stage_a_roots_equal_reference"] is True,
                 f"provider topology arm {index} authority differs")
        try:
            admission = pair_support._admission(
                arm["admission"], f"provider topology arm {index} admission",
            )
        except pair_support.ProviderRawPairEvidenceError as error:
            raise ProviderTopologyEvidenceError(str(error)) from error
        _require(admission["requested_concurrent_jobs"]
                 == admission["admitted_concurrent_jobs"]
                 == configuration["concurrent_jobs"]
                 and admission["per_job_engine_workers"]
                 == configuration["per_job_engine_workers"]
                 and admission["work_items"] == workload["batch_size"],
                 f"provider topology arm {index} admission differs")
        stage = _timing(arm["stage_a"], f"provider topology arm {index} Stage-A")
        total = _timing(arm["total"], f"provider topology arm {index} total")
        _resource(arm["resource_usage"], f"provider topology arm {index} resource")
        _require(type(arm["proof_batch_wall_ns"]) is int
                 and type(arm["cold_verify_wall_ns"]) is int
                 and arm["proof_batch_wall_ns"] > 0
                 and arm["cold_verify_wall_ns"] > 0
                 and total["wall_ns"] <= configuration["hard_cap_ns"]
                 and total["wall_ns"] >= stage["wall_ns"]
                 + arm["proof_batch_wall_ns"] + arm["cold_verify_wall_ns"],
                 f"provider topology arm {index} timing closure differs")
        proofs = arm["proofs"]
        _require(type(proofs) is list and len(proofs) == workload["batch_size"],
                 f"provider topology arm {index} proof count differs")
        current = []
        cold_sum = 0
        for ordinal, proof in enumerate(proofs):
            proof = _proof(proof, ordinal,
                           f"provider topology arm {index} proof {ordinal}")
            cold_sum += proof["cold_verify"]["wall_ns"]
            current.append((
                proof["proof"]["bytes"], proof["proof"]["sha256"],
                proof["claim_identity_sha256"],
                proof["statement_identity_sha256"],
            ))
        _require(arm["cold_verify_wall_ns"] >= cold_sum,
                 f"provider topology arm {index} verification timing differs")
        if reference is None:
            reference = current
        else:
            _require(current == reference,
                     "provider topology cross-arm proof parity differs")
        arm_total += total["wall_ns"]
    _require(value["total_wall_ns"] >= arm_total,
             "provider topology total timing closure differs")
    return value


def _normalized(receipt_path: Path, executable_custody: Path) -> dict[str, Any]:
    receipt = _receipt(
        receipt_path, executable_custody, require_declared_path=False,
    )
    arms = [{
        "concurrent_jobs": arm["admission"]["admitted_concurrent_jobs"],
        "per_job_engine_workers": arm["admission"]["per_job_engine_workers"],
        "stage_a_wall_ns": arm["stage_a"]["wall_ns"],
        "proof_batch_wall_ns": arm["proof_batch_wall_ns"],
        "cold_verify_wall_ns": arm["cold_verify_wall_ns"],
        "arm_total_wall_ns": arm["total"]["wall_ns"],
        "peak_physical_footprint_bytes": arm["resource_usage"][
            "lifetime_peak_after_bytes"
        ],
    } for arm in receipt["arms"]]
    best = min(arms, key=lambda item: (
        item["proof_batch_wall_ns"], item["concurrent_jobs"],
    ))
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "provider-topology-stage-diagnostic-fresh-verified",
        "receipt": _identity(receipt_path, "provider topology receipt"),
        "receipt_content_sha256": receipt["content_sha256"],
        "declared_benchmark_executable": copy.deepcopy(
            receipt["benchmark_executable"]
        ),
        "benchmark_executable_custody": _identity(
            executable_custody, "provider topology executable custody",
        ),
        "source_receipt": copy.deepcopy(receipt),
        "measured_arms": arms,
        "best_measured_arm": copy.deepcopy(best),
        "ranking": {
            "scope": "provider-n4-topology-stage-local-only",
            "metric": "measured-proof-batch-wall-ns",
            "fresh_verification": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def capture(receipt_path: Path, output: Path, staging: Path) -> dict[str, Any]:
    receipt_path, output = receipt_path.absolute(), output.absolute()
    staging = staging.absolute()
    store.require_directory(output.parent, "provider topology evidence parent")
    store.require_directory(staging, "provider topology staging", create=True)
    try:
        raw = pair_support._read_zig(
            receipt_path, RECEIPT_SCHEMA, "provider topology receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderTopologyEvidenceError(str(error)) from error
    declared = Path(raw["benchmark_executable"]["path"])
    _receipt(receipt_path, declared, require_declared_path=True)
    executable = store.read_regular(declared, "provider topology executable")
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
        "source_receipt", "measured_arms", "best_measured_arm", "ranking",
        "content_sha256",
    }, "provider topology evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["status"]
             == "provider-topology-stage-diagnostic-fresh-verified"
             and value["content_sha256"] == protocol.content_sha256(value),
             "provider topology evidence authority differs")
    receipt = _validate_identity(value["receipt"], "provider topology receipt")
    custody = _validate_identity(
        value["benchmark_executable_custody"],
        "provider topology executable custody",
    )
    _require(value == _normalized(Path(receipt["path"]), Path(custody["path"])),
             "provider topology evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "provider topology evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider topology evidence is not canonical JSON")
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
        ProviderTopologyEvidenceError,
        pair_support.ProviderRawPairEvidenceError,
        batch_support.ProviderRawBatchEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
