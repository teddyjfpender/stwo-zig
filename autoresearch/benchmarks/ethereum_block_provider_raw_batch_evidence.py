"""Strict adapter for measured N-way provider proof-batch diagnostics."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_provider_raw_pair_evidence as pair_support  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.poseidon-provider-raw-batch-hpc-benchmark.v2"
EVIDENCE_SCHEMA = "stwo.ethereum.optimization-provider-raw-batch-evidence.v2"
MAX_TRIAL_NS = 60_000_000_000


class ProviderRawBatchEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderRawBatchEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    return pair_support._identity(path, where)


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    try:
        return pair_support._validate_identity(value, where)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error


def _workload(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "batch_size", "call_artifact", "call_artifact_content_sha256",
        "full_call_count", "full_call_list_commitment_sha256", "log_size",
        "ordinals", "raw_call_file", "session_sha256", "shard_count",
        "slice_call_count", "slice_call_list_commitment_sha256", "slice_offset",
        "source_producer_sha256",
    }, "provider raw-batch workload")
    projection = {key: item for key, item in value.items() if key != "batch_size"}
    try:
        pair_support._workload(projection)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    _require(value["batch_size"] == value["shard_count"],
             "provider raw-batch size differs")
    return value


def _proofs(value: Any, batch_size: int) -> dict[str, Any]:
    value = _exact(value, {"serial", "concurrent"}, "provider raw-batch proofs")
    try:
        pair_support._proofs({
            "serial": value["serial"], "parallel": value["concurrent"],
        }, batch_size)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    return value


def _correctness(value: Any, batch_size: int) -> dict[str, Any]:
    extra = "exact_serial_parallel_proof_bytes_equal"
    _require(type(value) is dict and extra in value,
             "provider raw-batch correctness keys differ")
    projection = {key: item for key, item in value.items() if key != extra}
    try:
        pair_support._correctness(projection, batch_size)
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    _require(value[extra] == [True] * batch_size,
             "provider raw-batch exact proof parity differs")
    return value


def _receipt(path: Path, executable_custody: Path, *,
             require_declared_path: bool) -> dict[str, Any]:
    try:
        value = pair_support._read_zig(
            path, RECEIPT_SCHEMA, "provider raw-batch receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    _exact(value, {
        "content_sha256", "benchmark_executable", "concurrent_admission",
        "correctness", "parallel_proof_speedup_milli",
        "parallel_stage_a_speedup_milli", "performance_claim_eligible",
        "production_eligible", "profile", "proofs", "recursive_admissible",
        "resource_usage", "schema", "serial_admission", "status",
        "timing_scope", "timings", "workload",
    }, "provider raw-batch receipt")
    _require(value["status"] == "diagnostic-batch-fresh-verified"
             and value["timing_scope"] == "retained-provider-batch-self-process"
             and value["performance_claim_eligible"] is True
             and value["production_eligible"] is False
             and value["recursive_admissible"] is False,
             "provider raw-batch claim boundary differs")
    declared = _exact(
        value["benchmark_executable"], {"path", "bytes", "sha256"},
        "provider raw-batch declared executable",
    )
    custody = _identity(executable_custody, "provider raw-batch executable custody")
    _require({key: custody[key] for key in ("bytes", "sha256")}
             == {key: declared[key] for key in ("bytes", "sha256")}
             and (not require_declared_path
                  or custody["path"] == declared["path"]),
             "provider raw-batch executable custody differs")
    try:
        pair_support._profile(value["profile"])
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    workload = _workload(value["workload"])
    batch_size = workload["batch_size"]
    try:
        serial = pair_support._admission(
            value["serial_admission"], "provider raw-batch serial admission",
        )
        concurrent = pair_support._admission(
            value["concurrent_admission"],
            "provider raw-batch concurrent admission",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    _require(serial["admitted_concurrent_jobs"] == 1
             and concurrent["admitted_concurrent_jobs"] == batch_size
             and serial["work_items"] == concurrent["work_items"] == batch_size,
             "provider raw-batch admission pairing differs")
    _proofs(value["proofs"], batch_size)
    _correctness(value["correctness"], batch_size)
    timings = _exact(value["timings"], {
        "concurrent_cold_verify_wall_ns", "concurrent_proof_batch_wall_ns",
        "concurrent_stage_a", "serial_cold_verify_wall_ns",
        "serial_proof_batch_wall_ns", "serial_stage_a", "total_wall_ns",
    }, "provider raw-batch timings")
    try:
        serial_stage = pair_support._timing(
            timings["serial_stage_a"], "provider raw-batch serial Stage-A",
        )
        concurrent_stage = pair_support._timing(
            timings["concurrent_stage_a"],
            "provider raw-batch concurrent Stage-A",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    scalar_fields = (
        "concurrent_cold_verify_wall_ns", "concurrent_proof_batch_wall_ns",
        "serial_cold_verify_wall_ns", "serial_proof_batch_wall_ns",
        "total_wall_ns",
    )
    _require(all(type(timings[field]) is int and timings[field] > 0
                 for field in scalar_fields)
             and timings["total_wall_ns"] <= MAX_TRIAL_NS
             and timings["total_wall_ns"] >= (
                 serial_stage["wall_ns"] + concurrent_stage["wall_ns"]
                 + timings["serial_proof_batch_wall_ns"]
                 + timings["concurrent_proof_batch_wall_ns"]
                 + timings["serial_cold_verify_wall_ns"]
                 + timings["concurrent_cold_verify_wall_ns"]
             )
             and value["parallel_proof_speedup_milli"]
             == timings["serial_proof_batch_wall_ns"] * 1000
             // timings["concurrent_proof_batch_wall_ns"]
             and value["parallel_stage_a_speedup_milli"]
             == serial_stage["wall_ns"] * 1000 // concurrent_stage["wall_ns"],
             "provider raw-batch timing closure differs")
    usage = _exact(value["resource_usage"], {
        "availability", "cycles", "energy_nj", "instructions",
        "lifetime_peak_physical_footprint_bytes", "source",
    }, "provider raw-batch resource usage")
    _require(usage["availability"] == "available"
             and usage["source"] == "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
             and all(type(usage[field]) is int and usage[field] > 0 for field in (
                 "cycles", "energy_nj", "instructions",
                 "lifetime_peak_physical_footprint_bytes",
             )), "provider raw-batch resource usage differs")
    return value


def _normalized(receipt_path: Path, executable_custody: Path) -> dict[str, Any]:
    receipt = _receipt(
        receipt_path, executable_custody, require_declared_path=False,
    )
    timings = receipt["timings"]
    serial_proof = timings["serial_proof_batch_wall_ns"]
    concurrent_proof = timings["concurrent_proof_batch_wall_ns"]
    serial_stage = timings["serial_stage_a"]["wall_ns"]
    concurrent_stage = timings["concurrent_stage_a"]["wall_ns"]
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "provider-batch-stage-diagnostic-fresh-verified",
        "receipt": _identity(receipt_path, "provider raw-batch receipt"),
        "receipt_content_sha256": receipt["content_sha256"],
        "declared_benchmark_executable": copy.deepcopy(
            receipt["benchmark_executable"]
        ),
        "benchmark_executable_custody": _identity(
            executable_custody, "provider raw-batch executable custody",
        ),
        "source_receipt": copy.deepcopy(receipt),
        "measured": {
            "batch_size": receipt["workload"]["batch_size"],
            "serial_concurrent_jobs": receipt["serial_admission"][
                "admitted_concurrent_jobs"
            ],
            "concurrent_jobs": receipt["concurrent_admission"][
                "admitted_concurrent_jobs"
            ],
            "stage_a_serial": copy.deepcopy(timings["serial_stage_a"]),
            "stage_a_concurrent": copy.deepcopy(timings["concurrent_stage_a"]),
            "stage_a_speedup": {
                "numerator": serial_stage,
                "denominator": concurrent_stage,
                "milli": receipt["parallel_stage_a_speedup_milli"],
            },
            "proof_batch_serial_wall_ns": serial_proof,
            "proof_batch_concurrent_wall_ns": concurrent_proof,
            "proof_batch_speedup": {
                "numerator": serial_proof,
                "denominator": concurrent_proof,
                "milli": receipt["parallel_proof_speedup_milli"],
            },
            "serial_cold_verify_wall_ns": timings[
                "serial_cold_verify_wall_ns"
            ],
            "concurrent_cold_verify_wall_ns": timings[
                "concurrent_cold_verify_wall_ns"
            ],
            "typed_total_wall_ns": timings["total_wall_ns"],
            "peak_physical_footprint_bytes": receipt["resource_usage"][
                "lifetime_peak_physical_footprint_bytes"
            ],
            "slice_call_count": receipt["workload"]["slice_call_count"],
        },
        "correctness": copy.deepcopy(receipt["correctness"]),
        "ranking": {
            "scope": "provider-n-shard-proof-batch-measured-only",
            "ranking_metric": "measured-proof-batch-wall-reduction",
            "measured_raw_proof_concurrency": True,
            "performance_claim_eligible": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def capture(
    receipt_path: Path, output: Path, staging: Path,
) -> dict[str, Any]:
    receipt_path = receipt_path.absolute()
    output = output.absolute()
    staging = staging.absolute()
    store.require_directory(output.parent, "provider raw-batch evidence parent")
    store.require_directory(staging, "provider raw-batch staging", create=True)
    try:
        raw_receipt = pair_support._read_zig(
            receipt_path, RECEIPT_SCHEMA, "provider raw-batch receipt",
        )
    except pair_support.ProviderRawPairEvidenceError as error:
        raise ProviderRawBatchEvidenceError(str(error)) from error
    declared_path = Path(raw_receipt["benchmark_executable"]["path"])
    _receipt(receipt_path, declared_path, require_declared_path=True)
    executable_raw = store.read_regular(
        declared_path, "provider raw-batch declared executable",
    )
    custody_path = output.with_name(f"{output.stem}.benchmark-executable")
    store.publish_new_or_identical(
        custody_path, executable_raw, staging_directory=staging,
    )
    value = _normalized(receipt_path, custody_path)
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "receipt", "receipt_content_sha256",
        "declared_benchmark_executable", "benchmark_executable_custody",
        "source_receipt", "measured", "correctness", "ranking",
        "content_sha256",
    }, "provider raw-batch evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["status"]
             == "provider-batch-stage-diagnostic-fresh-verified"
             and value["content_sha256"] == protocol.content_sha256(value),
             "provider raw-batch evidence authority differs")
    receipt = _validate_identity(value["receipt"], "provider raw-batch receipt")
    custody = _validate_identity(
        value["benchmark_executable_custody"],
        "provider raw-batch executable custody",
    )
    _require(value == _normalized(Path(receipt["path"]), Path(custody["path"])),
             "provider raw-batch evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "provider raw-batch evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider raw-batch evidence is not canonical JSON")
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
        ProviderRawBatchEvidenceError,
        pair_support.ProviderRawPairEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
