"""Strict adapter and stage-only ranking for provider HPC benchmark receipts."""

from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import hashlib
import os
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_optimization_evidence as baseline_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.poseidon-provider-hpc-benchmark.v1"
EVIDENCE_SCHEMA = "stwo.ethereum.optimization-provider-hpc-evidence.v1"
RANKING_SCHEMA = "stwo.ethereum.optimization-provider-stage-a-ranking.v1"
CALL_SCHEMA = "stwo.ethereum.poseidon-provider-call-artifact.v1"
MAX_TRIAL_NS = 120_000_000_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProviderHpcEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderHpcEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value) is not None,
             f"{where} differs")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"path", "bytes", "sha256"}, where)
    path = Path(value["path"])
    _require(path.is_absolute(), f"{where}.path differs")
    store.validate_file_identity(path, {
        "bytes": value["bytes"], "sha256": value["sha256"],
    }, where)
    return value


def _read_zig(path: Path, schema: str, where: str) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    baseline_evidence._zig_content(path, value, schema, where)
    return value


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values())
             and value["wall_ns"] > 0, f"{where} differs")
    return value


def _receipt(path: Path, executable: Path) -> dict[str, Any]:
    value = _read_zig(path, RECEIPT_SCHEMA, "provider HPC receipt")
    _exact(value, {
        "content_sha256", "admission", "benchmark_executable_sha256",
        "candidate", "correctness", "performance_claim_eligible",
        "production_eligible", "profile", "proof",
        "proof_statement_identity_sha256", "provider_claim_identity_sha256",
        "recursive_admissible", "resource_usage", "schema", "status",
        "timing_scope", "timings", "workload",
    }, "provider HPC receipt")
    _require(value["status"] == "diagnostic-fresh-verified"
             and value["timing_scope"] == "retained-provider-slice-self-process"
             and value["performance_claim_eligible"] is True
             and value["production_eligible"] is False
             and value["recursive_admissible"] is False,
             "provider HPC claim boundary differs")
    executable_identity = _identity(executable, "provider HPC executable")
    _require(os.access(executable, os.X_OK)
             and executable_identity["sha256"]
             == value["benchmark_executable_sha256"],
             "provider HPC executable differs")
    proof = _validate_identity(value["proof"], "provider HPC proof")
    for field in (
        "proof_statement_identity_sha256", "provider_claim_identity_sha256",
        "benchmark_executable_sha256",
    ):
        _sha(value[field], f"provider HPC {field}")
    correctness = _exact(value["correctness"], {
        "canonical_proof_bytes_equal", "fresh_verified", "native_claim_equal",
        "ordered_claim_equal", "stage_a_parallel_roots_equal",
        "stage_a_roots_equal_proof", "statement_identity_equal",
    }, "provider HPC correctness")
    _require(all(item is True for item in correctness.values()),
             "provider HPC correctness differs")
    profile = _exact(value["profile"], {
        "build_mode", "composition_columns", "coefficient_retention",
        "host_power_classification", "main_columns", "preprocessed_columns",
        "provider_profile", "synthetic_core_stage_a", "tree2_columns",
    }, "provider HPC profile")
    _require(profile == {
        "build_mode": "ReleaseFast",
        "composition_columns": 8,
        "coefficient_retention": "never",
        "host_power_classification": "ac-high-power-pinned",
        "main_columns": 445,
        "preprocessed_columns": 2,
        "provider_profile": "ordered-provider-v2",
        "synthetic_core_stage_a": True,
        "tree2_columns": 12,
    }, "provider HPC profile differs")
    workload = _exact(value["workload"], {
        "call_artifact", "call_artifact_content_sha256", "full_call_count",
        "full_call_list_commitment_sha256", "log_size", "proved_ordinal",
        "raw_call_file", "session_sha256", "shard_count", "slice_call_count",
        "slice_call_list_commitment_sha256", "slice_offset",
        "source_producer_sha256",
    }, "provider HPC workload")
    call_identity = _validate_identity(
        workload["call_artifact"], "provider HPC call artifact",
    )
    raw_identity = _validate_identity(
        workload["raw_call_file"], "provider HPC raw call file",
    )
    call_value = _read_zig(
        Path(call_identity["path"]), CALL_SCHEMA, "provider HPC call artifact",
    )
    _require(call_value["content_sha256"] == workload["call_artifact_content_sha256"]
             and call_value["calls"] == raw_identity
             and call_value["call_count"] == workload["full_call_count"]
             and call_value["call_list_commitment_sha256"]
             == workload["full_call_list_commitment_sha256"]
             and call_value["session_sha256"] == workload["session_sha256"]
             and call_value["producer_sha256"] == workload["source_producer_sha256"],
             "provider HPC call authority differs")
    _require(all(type(workload[field]) is int and workload[field] >= 0 for field in (
        "full_call_count", "log_size", "proved_ordinal", "shard_count",
        "slice_call_count", "slice_offset",
    )) and workload["full_call_count"] > 0
             and workload["slice_call_count"] > 0
             and workload["shard_count"] > 0
             and workload["proved_ordinal"] < workload["shard_count"]
             and workload["slice_offset"] + workload["slice_call_count"]
             <= workload["full_call_count"],
             "provider HPC workload range differs")
    for field in (
        "call_artifact_content_sha256", "full_call_list_commitment_sha256",
        "session_sha256", "slice_call_list_commitment_sha256",
        "source_producer_sha256",
    ):
        _sha(workload[field], f"provider HPC workload {field}")
    admission = _exact(value["admission"], {
        "admitted_workers", "available_cpu_workers",
        "concurrent_worker_reservation_bytes", "controller_reserve_bytes",
        "host_byte_budget", "identity_sha256", "requested_workers",
        "worker_rss_budget_bytes", "work_items",
    }, "provider HPC admission")
    _require(all(type(admission[field]) is int and admission[field] > 0 for field in (
        "admitted_workers", "available_cpu_workers",
        "concurrent_worker_reservation_bytes", "controller_reserve_bytes",
        "host_byte_budget", "requested_workers", "worker_rss_budget_bytes",
        "work_items",
    )) and admission["admitted_workers"] <= admission["requested_workers"]
             <= admission["available_cpu_workers"]
             and admission["work_items"] == workload["shard_count"],
             "provider HPC admission differs")
    _sha(admission["identity_sha256"], "provider HPC admission identity")
    timings = _exact(value["timings"], {
        "cold_verify", "parallel_stage_a", "provider_prove_wall_ns",
        "serial_stage_a", "total_wall_ns",
    }, "provider HPC timings")
    serial = _timing(timings["serial_stage_a"], "provider HPC serial Stage-A")
    parallel = _timing(timings["parallel_stage_a"], "provider HPC parallel Stage-A")
    verify = _timing(timings["cold_verify"], "provider HPC cold verify")
    _require(type(timings["provider_prove_wall_ns"]) is int
             and timings["provider_prove_wall_ns"] > 0
             and type(timings["total_wall_ns"]) is int
             and 0 < timings["total_wall_ns"] <= MAX_TRIAL_NS
             and timings["total_wall_ns"] >= max(
                 serial["wall_ns"], parallel["wall_ns"],
                 timings["provider_prove_wall_ns"], verify["wall_ns"],
             ), "provider HPC timing scope differs")
    candidate = _exact(value["candidate"], {
        "ideal_parallel_batch_wall_ns", "ideal_parallel_speedup_milli", "model",
        "parallel_stage_a_speedup_milli",
    }, "provider HPC candidate")
    _require(candidate["model"] == "single-shard-linear-upper-bound"
             and candidate["parallel_stage_a_speedup_milli"]
             == serial["wall_ns"] * 1000 // parallel["wall_ns"]
             and candidate["ideal_parallel_batch_wall_ns"]
             == timings["provider_prove_wall_ns"] * workload["shard_count"]
             // admission["admitted_workers"]
             and candidate["ideal_parallel_speedup_milli"]
             == min(admission["admitted_workers"], workload["shard_count"]) * 1000,
             "provider HPC modeled candidate differs")
    usage = _exact(value["resource_usage"], {
        "availability", "cycles", "energy_nj", "instructions",
        "lifetime_peak_physical_footprint_bytes", "source",
    }, "provider HPC resource usage")
    _require(usage["availability"] == "available"
             and usage["source"] == "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
             and all(type(usage[field]) is int and usage[field] > 0 for field in (
                 "cycles", "energy_nj", "instructions",
                 "lifetime_peak_physical_footprint_bytes",
             )), "provider HPC resource usage differs")
    _require(proof["bytes"] > 0, "provider HPC proof is empty")
    return value


def adapt(receipt_path: Path, executable_path: Path) -> dict[str, Any]:
    receipt_path = receipt_path.absolute()
    executable_path = executable_path.absolute()
    receipt = _receipt(receipt_path, executable_path)
    timings = receipt["timings"]
    admission = receipt["admission"]
    workload = receipt["workload"]
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "provider-stage-diagnostic-fresh-verified",
        "receipt": _identity(receipt_path, "provider HPC receipt"),
        "receipt_content_sha256": receipt["content_sha256"],
        "benchmark_executable": _identity(executable_path, "provider HPC executable"),
        "source_receipt": copy.deepcopy(receipt),
        "measured": {
            "admitted_workers": admission["admitted_workers"],
            "stage_a_serial": copy.deepcopy(timings["serial_stage_a"]),
            "stage_a_parallel": copy.deepcopy(timings["parallel_stage_a"]),
            "stage_a_speedup": {
                "numerator": timings["serial_stage_a"]["wall_ns"],
                "denominator": timings["parallel_stage_a"]["wall_ns"],
                "milli": receipt["candidate"]["parallel_stage_a_speedup_milli"],
            },
            "single_provider_prove_wall_ns": timings["provider_prove_wall_ns"],
            "single_cold_verify": copy.deepcopy(timings["cold_verify"]),
            "typed_total_wall_ns": timings["total_wall_ns"],
            "peak_physical_footprint_bytes": receipt["resource_usage"][
                "lifetime_peak_physical_footprint_bytes"
            ],
            "slice_call_count": workload["slice_call_count"],
        },
        "modeled": {
            "model": receipt["candidate"]["model"],
            "ideal_parallel_batch_wall_ns": receipt["candidate"][
                "ideal_parallel_batch_wall_ns"
            ],
            "ideal_parallel_speedup_milli": receipt["candidate"][
                "ideal_parallel_speedup_milli"
            ],
            "measured_raw_proof_concurrency": False,
            "ranking_eligible": False,
        },
        "correctness": copy.deepcopy(receipt["correctness"]),
        "ranking": {
            "scope": "provider-stage-a-measured-only",
            "performance_claim_eligible": True,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "receipt", "receipt_content_sha256",
        "benchmark_executable", "source_receipt", "measured", "modeled",
        "correctness", "ranking", "content_sha256",
    }, "provider HPC evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "provider HPC evidence authority differs")
    receipt = _validate_identity(value["receipt"], "provider HPC receipt")
    executable = _validate_identity(
        value["benchmark_executable"], "provider HPC executable",
    )
    _require(value == adapt(Path(receipt["path"]), Path(executable["path"])),
             "provider HPC evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "provider HPC evidence",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider HPC evidence is not canonical JSON")
    return validate(value)


def rank(evidence_paths: list[Path]) -> dict[str, Any]:
    _require(evidence_paths, "provider HPC ranking is empty")
    values = [(path.absolute(), load(path.absolute())) for path in evidence_paths]
    workers = [value["measured"]["admitted_workers"] for _, value in values]
    _require(len(set(workers)) == len(workers),
             "provider HPC ranking repeats a worker count")
    ordered = sorted(values, key=lambda item: (
        -Fraction(
            item[1]["measured"]["stage_a_speedup"]["numerator"],
            item[1]["measured"]["stage_a_speedup"]["denominator"],
        ),
        item[1]["measured"]["peak_physical_footprint_bytes"],
        item[1]["measured"]["admitted_workers"],
    ))
    rows = []
    for index, (path, value) in enumerate(ordered, 1):
        rows.append({
            "rank": index,
            "evidence": _identity(path, "provider HPC evidence"),
            "admitted_workers": value["measured"]["admitted_workers"],
            "stage_a_speedup": value["measured"]["stage_a_speedup"],
            "stage_a_parallel_wall_ns": value["measured"]["stage_a_parallel"][
                "wall_ns"
            ],
            "peak_physical_footprint_bytes": value["measured"][
                "peak_physical_footprint_bytes"
            ],
            "raw_proof_concurrency_measured": False,
        })
    return protocol.seal({
        "schema": RANKING_SCHEMA,
        "status": "ranked-provider-stage-a-diagnostic-only",
        "ranking_metric": "measured-stage-a-speedup-desc-then-rss",
        "entries": rows,
        "ideal_parallel_proof_model_ranked": False,
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    })


def validate_ranking(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "ranking_metric", "entries",
        "ideal_parallel_proof_model_ranked", "estimated_end_to_end_wall_ns",
        "production_promotion_eligible", "content_sha256",
    } and value["schema"] == RANKING_SCHEMA
             and value["content_sha256"] == protocol.content_sha256(value),
             "provider HPC ranking authority differs")
    entries = value["entries"]
    _require(type(entries) is list and entries,
             "provider HPC ranking entries differ")
    paths = []
    for index, entry in enumerate(entries):
        _require(type(entry) is dict and "evidence" in entry,
                 f"provider HPC ranking entry {index} differs")
        identity = _validate_identity(
            entry["evidence"], f"provider HPC ranked evidence {index}",
        )
        paths.append(Path(identity["path"]))
    _require(value == rank(paths), "provider HPC ranking replay differs")
    return value


def load_ranking(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "provider HPC ranking",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "provider HPC ranking is not canonical JSON")
    return validate_ranking(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--receipt", type=Path, required=True)
    create.add_argument("--executable", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    ranking = commands.add_parser("create-ranking")
    ranking.add_argument("--evidence", type=Path, action="append", required=True)
    ranking.add_argument("--output", type=Path, required=True)
    ranking.add_argument("--staging-directory", type=Path, required=True)
    replay_ranking = commands.add_parser("replay-ranking")
    replay_ranking.add_argument("--ranking", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        if arguments.command == "replay-ranking":
            load_ranking(arguments.ranking)
            return 0
        if arguments.command == "create":
            value = adapt(arguments.receipt, arguments.executable)
        else:
            value = rank(arguments.evidence)
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "provider HPC evidence parent")
        store.require_directory(staging, "provider HPC staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        ProviderHpcEvidenceError, protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
