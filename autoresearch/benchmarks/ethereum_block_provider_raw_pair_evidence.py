"""Strict diagnostic adapter for measured two-shard provider proof receipts."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import os
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_provider_hpc_evidence as provider_support  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.poseidon-provider-raw-pair-hpc-benchmark.v1"
EVIDENCE_SCHEMA = "stwo.ethereum.optimization-provider-raw-pair-evidence.v1"
MAX_TRIAL_NS = 60_000_000_000


class ProviderRawPairEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderRawPairEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    try:
        return provider_support._sha(value, where)
    except provider_support.ProviderHpcEvidenceError as error:
        raise ProviderRawPairEvidenceError(str(error)) from error


def _identity(path: Path, where: str) -> dict[str, Any]:
    return provider_support._identity(path, where)


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    try:
        return provider_support._validate_identity(value, where)
    except provider_support.ProviderHpcEvidenceError as error:
        raise ProviderRawPairEvidenceError(str(error)) from error


def _read_zig(path: Path, schema: str, where: str) -> dict[str, Any]:
    try:
        return provider_support._read_zig(path, schema, where)
    except provider_support.ProviderHpcEvidenceError as error:
        raise ProviderRawPairEvidenceError(str(error)) from error


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values())
             and value["wall_ns"] > 0, f"{where} differs")
    return value


def _admission(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "admitted_concurrent_jobs", "aggregate_engine_stack_reservation_bytes",
        "aggregate_engine_workers", "aggregate_rss_reservation_bytes",
        "available_cpu_workers", "controller_reserve_bytes", "host_byte_budget",
        "identity_sha256", "per_job_engine_workers", "per_job_rss_budget_bytes",
        "requested_concurrent_jobs", "work_items",
    }, where)
    integer_fields = set(value) - {"identity_sha256"}
    _require(all(type(value[field]) is int and value[field] > 0
                 for field in integer_fields), f"{where} values differ")
    _sha(value["identity_sha256"], f"{where} identity")
    jobs = value["admitted_concurrent_jobs"]
    _require(jobs <= value["requested_concurrent_jobs"] <= value["work_items"]
             and value["aggregate_engine_workers"]
             == jobs * value["per_job_engine_workers"]
             and value["aggregate_rss_reservation_bytes"]
             == jobs * value["per_job_rss_budget_bytes"]
             and value["aggregate_engine_workers"] <= value["available_cpu_workers"]
             and value["controller_reserve_bytes"]
             + value["aggregate_rss_reservation_bytes"]
             <= value["host_byte_budget"], f"{where} closure differs")
    return value


def _profile(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "build_mode", "composition_columns", "coefficient_retention",
        "host_power_classification", "main_columns", "preprocessed_columns",
        "provider_profile", "synthetic_core_stage_a", "tree2_columns",
    }, "provider raw-pair profile")
    _require(value == {
        "build_mode": "ReleaseFast",
        "composition_columns": 8,
        "coefficient_retention": "never",
        "host_power_classification": "ac-high-power-pinned",
        "main_columns": 445,
        "preprocessed_columns": 2,
        "provider_profile": "ordered-provider-v2",
        "synthetic_core_stage_a": True,
        "tree2_columns": 12,
    }, "provider raw-pair profile differs")
    return value


def _workload(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "call_artifact", "call_artifact_content_sha256", "full_call_count",
        "full_call_list_commitment_sha256", "log_size", "ordinals",
        "raw_call_file", "session_sha256", "shard_count", "slice_call_count",
        "slice_call_list_commitment_sha256", "slice_offset",
        "source_producer_sha256",
    }, "provider raw-pair workload")
    call_identity = _validate_identity(
        value["call_artifact"], "provider raw-pair call artifact",
    )
    raw_identity = _validate_identity(
        value["raw_call_file"], "provider raw-pair raw calls",
    )
    call = _read_zig(
        Path(call_identity["path"]), provider_support.CALL_SCHEMA,
        "provider raw-pair call artifact",
    )
    _require(call["content_sha256"] == value["call_artifact_content_sha256"]
             and call["calls"] == raw_identity
             and call["call_count"] == value["full_call_count"]
             and call["call_list_commitment_sha256"]
             == value["full_call_list_commitment_sha256"]
             and call["session_sha256"] == value["session_sha256"]
             and call["producer_sha256"] == value["source_producer_sha256"],
             "provider raw-pair call authority differs")
    for field in (
        "call_artifact_content_sha256", "full_call_list_commitment_sha256",
        "session_sha256", "slice_call_list_commitment_sha256",
        "source_producer_sha256",
    ):
        _sha(value[field], f"provider raw-pair workload {field}")
    for field in (
        "full_call_count", "log_size", "shard_count", "slice_call_count",
        "slice_offset",
    ):
        _require(type(value[field]) is int and value[field] >= 0,
                 f"provider raw-pair workload {field} differs")
    _require(value["full_call_count"] > 0 and value["log_size"] >= 4
             and value["shard_count"] > 0
             and value["ordinals"] == list(range(value["shard_count"]))
             and value["slice_call_count"]
             == value["shard_count"] * (1 << value["log_size"])
             and value["slice_offset"] + value["slice_call_count"]
             <= value["full_call_count"],
             "provider raw-pair workload range differs")
    return value


def _proofs(value: Any, shard_count: int) -> dict[str, list[dict[str, Any]]]:
    value = _exact(value, {"serial", "parallel"}, "provider raw-pair proofs")
    _require(all(type(value[mode]) is list and len(value[mode]) == shard_count
                 for mode in ("serial", "parallel")),
             "provider raw-pair proof count differs")
    for mode in ("serial", "parallel"):
        for index, identity in enumerate(value[mode]):
            _validate_identity(identity, f"provider raw-pair {mode} proof {index}")
    for index in range(shard_count):
        serial = value["serial"][index]
        parallel = value["parallel"][index]
        _require({key: serial[key] for key in ("bytes", "sha256")}
                 == {key: parallel[key] for key in ("bytes", "sha256")},
                 "provider raw-pair canonical proof parity differs")
    return value


def _correctness(value: Any, shard_count: int) -> dict[str, Any]:
    array_fields = {
        "parallel_canonical_proof_bytes_equal", "parallel_fresh_verified",
        "parallel_roots_equal_proof", "serial_canonical_proof_bytes_equal",
        "serial_fresh_verified", "serial_roots_equal_proof",
        "statement_identities_equal", "native_claims_equal",
        "ordered_claims_equal",
    }
    value = _exact(
        value, array_fields | {"stage_a_serial_parallel_roots_equal"},
        "provider raw-pair correctness",
    )
    _require(value["stage_a_serial_parallel_roots_equal"] is True
             and all(type(value[field]) is list
                     and value[field] == [True] * shard_count
                     for field in array_fields),
             "provider raw-pair correctness differs")
    return value


def _receipt(path: Path) -> dict[str, Any]:
    value = _read_zig(path, RECEIPT_SCHEMA, "provider raw-pair receipt")
    _exact(value, {
        "content_sha256", "benchmark_executable", "correctness",
        "parallel_admission", "parallel_proof_speedup_milli",
        "performance_claim_eligible", "production_eligible", "profile",
        "proofs", "recursive_admissible", "resource_usage", "schema",
        "serial_admission", "status", "timing_scope", "timings", "workload",
    }, "provider raw-pair receipt")
    _require(value["status"] == "diagnostic-pair-fresh-verified"
             and value["timing_scope"] == "retained-provider-pair-self-process"
             and value["performance_claim_eligible"] is True
             and value["production_eligible"] is False
             and value["recursive_admissible"] is False,
             "provider raw-pair claim boundary differs")
    executable = _validate_identity(
        value["benchmark_executable"], "provider raw-pair executable",
    )
    _require(os.access(executable["path"], os.X_OK),
             "provider raw-pair executable is not executable")
    _profile(value["profile"])
    workload = _workload(value["workload"])
    serial_admission = _admission(
        value["serial_admission"], "provider raw-pair serial admission",
    )
    parallel_admission = _admission(
        value["parallel_admission"], "provider raw-pair parallel admission",
    )
    _require(serial_admission["admitted_concurrent_jobs"] == 1
             and parallel_admission["admitted_concurrent_jobs"] == 2
             and serial_admission["work_items"]
             == parallel_admission["work_items"] == workload["shard_count"],
             "provider raw-pair admission pairing differs")
    _proofs(value["proofs"], workload["shard_count"])
    _correctness(value["correctness"], workload["shard_count"])
    timings = _exact(value["timings"], {
        "parallel_cold_verify_wall_ns", "parallel_proof_batch_wall_ns",
        "parallel_stage_a", "serial_cold_verify_wall_ns",
        "serial_proof_batch_wall_ns", "serial_stage_a", "total_wall_ns",
    }, "provider raw-pair timings")
    serial_stage = _timing(
        timings["serial_stage_a"], "provider raw-pair serial Stage-A",
    )
    parallel_stage = _timing(
        timings["parallel_stage_a"], "provider raw-pair parallel Stage-A",
    )
    scalar_fields = (
        "parallel_cold_verify_wall_ns", "parallel_proof_batch_wall_ns",
        "serial_cold_verify_wall_ns", "serial_proof_batch_wall_ns",
        "total_wall_ns",
    )
    _require(all(type(timings[field]) is int and timings[field] > 0
                 for field in scalar_fields)
             and timings["total_wall_ns"] <= MAX_TRIAL_NS
             and timings["total_wall_ns"] >= (
                 serial_stage["wall_ns"] + parallel_stage["wall_ns"]
                 + timings["serial_proof_batch_wall_ns"]
                 + timings["parallel_proof_batch_wall_ns"]
                 + timings["serial_cold_verify_wall_ns"]
                 + timings["parallel_cold_verify_wall_ns"]
             )
             and value["parallel_proof_speedup_milli"]
             == timings["serial_proof_batch_wall_ns"] * 1000
             // timings["parallel_proof_batch_wall_ns"],
             "provider raw-pair timing closure differs")
    usage = _exact(value["resource_usage"], {
        "availability", "cycles", "energy_nj", "instructions",
        "lifetime_peak_physical_footprint_bytes", "source",
    }, "provider raw-pair resource usage")
    _require(usage["availability"] == "available"
             and usage["source"] == "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
             and all(type(usage[field]) is int and usage[field] > 0 for field in (
                 "cycles", "energy_nj", "instructions",
                 "lifetime_peak_physical_footprint_bytes",
             )), "provider raw-pair resource usage differs")
    return value


def adapt(receipt_path: Path) -> dict[str, Any]:
    receipt_path = receipt_path.absolute()
    receipt = _receipt(receipt_path)
    timings = receipt["timings"]
    serial_proof = timings["serial_proof_batch_wall_ns"]
    parallel_proof = timings["parallel_proof_batch_wall_ns"]
    serial_stage = timings["serial_stage_a"]["wall_ns"]
    parallel_stage = timings["parallel_stage_a"]["wall_ns"]
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "provider-pair-stage-diagnostic-fresh-verified",
        "receipt": _identity(receipt_path, "provider raw-pair receipt"),
        "receipt_content_sha256": receipt["content_sha256"],
        "benchmark_executable": copy.deepcopy(receipt["benchmark_executable"]),
        "source_receipt": copy.deepcopy(receipt),
        "measured": {
            "serial_concurrent_jobs": receipt["serial_admission"][
                "admitted_concurrent_jobs"
            ],
            "parallel_concurrent_jobs": receipt["parallel_admission"][
                "admitted_concurrent_jobs"
            ],
            "stage_a_serial": copy.deepcopy(timings["serial_stage_a"]),
            "stage_a_parallel": copy.deepcopy(timings["parallel_stage_a"]),
            "stage_a_speedup": {
                "numerator": serial_stage,
                "denominator": parallel_stage,
                "milli": serial_stage * 1000 // parallel_stage,
            },
            "proof_batch_serial_wall_ns": serial_proof,
            "proof_batch_parallel_wall_ns": parallel_proof,
            "proof_batch_speedup": {
                "numerator": serial_proof,
                "denominator": parallel_proof,
                "milli": receipt["parallel_proof_speedup_milli"],
            },
            "serial_cold_verify_wall_ns": timings[
                "serial_cold_verify_wall_ns"
            ],
            "parallel_cold_verify_wall_ns": timings[
                "parallel_cold_verify_wall_ns"
            ],
            "typed_total_wall_ns": timings["total_wall_ns"],
            "peak_physical_footprint_bytes": receipt["resource_usage"][
                "lifetime_peak_physical_footprint_bytes"
            ],
            "slice_call_count": receipt["workload"]["slice_call_count"],
        },
        "correctness": copy.deepcopy(receipt["correctness"]),
        "ranking": {
            "scope": "provider-two-shard-proof-batch-measured-only",
            "ranking_metric": "measured-proof-batch-wall-reduction",
            "measured_raw_proof_concurrency": True,
            "performance_claim_eligible": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "receipt", "receipt_content_sha256",
        "benchmark_executable", "source_receipt", "measured", "correctness",
        "ranking", "content_sha256",
    }, "provider raw-pair evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["status"]
             == "provider-pair-stage-diagnostic-fresh-verified"
             and value["content_sha256"] == protocol.content_sha256(value),
             "provider raw-pair evidence authority differs")
    receipt = _validate_identity(value["receipt"], "provider raw-pair receipt")
    _validate_identity(
        value["benchmark_executable"], "provider raw-pair executable",
    )
    _require(value == adapt(Path(receipt["path"])),
             "provider raw-pair evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "provider raw-pair evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider raw-pair evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
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
        value = adapt(arguments.receipt)
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "provider raw-pair evidence parent")
        store.require_directory(staging, "provider raw-pair staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        ProviderRawPairEvidenceError,
        provider_support.ProviderHpcEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
