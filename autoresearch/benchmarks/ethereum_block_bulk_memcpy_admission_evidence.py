"""Seal the exact bulk-memcpy admission observation as a projection.

The Zig observer replays the complete retained candidate execution and applies
the exact word-copy admission predicate.  This adapter reopens all authorities,
checks every bucket and journal total, and exposes only a predicted execution
row reduction.  It makes no AIR, proof, fresh-verification, or E2E claim.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_keccak_words_execution_evidence as execution  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.bulk-memcpy-admission-evidence.v1"
STATUS = "exact-execution-admission-projection-diagnostic-nonpromotable"
OBSERVATION_SCHEMA = "stwo.riscv.bulk-memcpy-admission-observation.v1"
OBSERVATION_STATUS = "captured-diagnostic-only"
PREDICATE = (
    "length>=32 && source_mod4==destination_mod4 && endpoints<=2^30 && "
    "byte_spans_disjoint && aligned_word_spans_disjoint"
)
BUCKET_NAMES = (
    "admitted", "aligned_word_overlap", "alignment_mismatch", "byte_overlap",
    "endpoint_invalid", "too_short",
)
BUCKET_KEYS = ("calls", "requested_bytes", "software_rows", "word_rows")
OBSERVATION_KEYS = (
    "admission_predicate", "admitted", "aligned_word_overlap",
    "alignment_mismatch", "byte_overlap", "clock_frame",
    "completed_call_count", "content_sha256", "elf_sha256",
    "endpoint_invalid", "execution_profile", "first_global_cycle",
    "first_segment_index", "input_sha256", "journal_sha256",
    "memcpy_entry_pc", "production", "removable_core_rows",
    "retired_instructions", "sampled_cycles", "schema", "segment_count",
    "status", "too_short", "total_software_rows_in_memcpy",
    "validated_register_reads",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BulkMemcpyAdmissionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BulkMemcpyAdmissionEvidenceError(message)


def _integer(value: Any, where: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _load_observation(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    path = path.absolute()
    raw = store.read_regular(
        path, "bulk memcpy admission observation", maximum=store.MAX_JSON_BYTES,
    )
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BulkMemcpyAdmissionEvidenceError(
            "bulk memcpy observation JSON differs",
        ) from error
    _require(type(value) is dict and tuple(value) == OBSERVATION_KEYS
             and raw == protocol.canonical_bytes(value),
             "bulk memcpy observation canonical shape differs")
    _require(
        value["schema"] == OBSERVATION_SCHEMA
        and value["status"] == OBSERVATION_STATUS
        and value["production"] is False
        and value["execution_profile"] == "rv32im-zkvm-ethereum-v1"
        and value["clock_frame"] == "leaf_local"
        and value["admission_predicate"] == PREDICATE
        and value["first_segment_index"] == 0
        and value["memcpy_entry_pc"] == 0x880
        and type(value["content_sha256"]) is str
        and SHA256.fullmatch(value["content_sha256"]) is not None
        and value["content_sha256"] == protocol.content_sha256(value),
        "bulk memcpy observation authority differs",
    )
    for field in (
        "completed_call_count", "first_global_cycle", "first_segment_index",
        "memcpy_entry_pc", "removable_core_rows", "retired_instructions",
        "sampled_cycles", "segment_count", "total_software_rows_in_memcpy",
        "validated_register_reads",
    ):
        _integer(value[field], f"bulk memcpy observation {field}")
    for field in ("elf_sha256", "input_sha256", "journal_sha256"):
        _require(type(value[field]) is str and SHA256.fullmatch(value[field]),
                 f"bulk memcpy observation {field} differs")
    for name in BUCKET_NAMES:
        bucket = value[name]
        _require(type(bucket) is dict and tuple(bucket) == BUCKET_KEYS,
                 f"bulk memcpy {name} bucket differs")
        for field in BUCKET_KEYS:
            _integer(bucket[field], f"bulk memcpy {name} {field}")
    _require(
        sum(value[name]["calls"] for name in BUCKET_NAMES)
        == value["completed_call_count"] > 0
        and sum(value[name]["software_rows"] for name in BUCKET_NAMES)
        == value["total_software_rows_in_memcpy"] > 0
        and value["admitted"]["calls"] > 0
        and value["admitted"]["software_rows"]
        >= value["admitted"]["calls"]
        and value["removable_core_rows"]
        == value["admitted"]["software_rows"]
        - value["admitted"]["calls"],
        "bulk memcpy observation bucket closure differs",
    )
    return value, _identity(path, "bulk memcpy admission observation")


def _build_loaded(
    execution_evidence: dict[str, Any], execution_identity: dict[str, Any],
    observation_path: Path, observer_executable: Path, observer_source: Path,
    timing_log: Path,
) -> dict[str, Any]:
    _require(execution_evidence["schema"] == execution.SCHEMA,
             "bulk memcpy execution evidence schema differs")
    boundary = execution_evidence["claim_boundary"]
    _require(
        boundary["production_active"] is False
        and boundary["candidate_air_complete"] is None
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_proving_end_to_end_wall_ns"] is None
        and boundary["production_promotion_eligible"] is False,
        "bulk memcpy execution claim boundary differs",
    )
    observation, observation_identity = _load_observation(observation_path)
    inputs = execution_evidence["inputs"]
    candidate = execution_evidence["executions"]["keccak_words_candidate"]
    _require(
        observation["elf_sha256"] == inputs["candidate_elf"]["sha256"]
        == candidate["elf_sha256"]
        and observation["input_sha256"] == inputs["common_input"]["sha256"]
        == candidate["input_sha256"]
        and observation["journal_sha256"]
        == inputs["candidate_journal"]["sha256"]
        == candidate["journal"]["sha256"]
        and observation["segment_count"] == candidate["segment_count"]
        and observation["sampled_cycles"] == candidate["total_cycles"]
        and observation["retired_instructions"]
        == candidate["total_core_trace_rows"]
        and observation["removable_core_rows"]
        < candidate["total_core_trace_rows"],
        "bulk memcpy observation/execution join differs",
    )
    try:
        timing_identity, timing = allocator_evidence._timing(timing_log)
    except allocator_evidence.AllocatorExecutionEvidenceError as error:
        raise BulkMemcpyAdmissionEvidenceError(str(error)) from error
    predicted_core = (
        candidate["total_core_trace_rows"] - observation["removable_core_rows"]
    )
    predicted_cycles = candidate["total_cycles"] - observation["removable_core_rows"]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "keccak_words_execution_evidence": execution_identity,
            "observation": observation_identity,
            "observer_executable": _identity(
                observer_executable, "bulk memcpy observer executable",
            ),
            "observer_source": _identity(
                observer_source, "bulk memcpy observer source",
            ),
            "observer_timing_log": timing_identity,
            "candidate_elf": inputs["candidate_elf"],
            "candidate_journal": inputs["candidate_journal"],
            "input": inputs["common_input"],
        },
        "argv_projection": {
            "argv_process_receipt_retained": False,
            "arguments": [
                str(observer_executable.absolute()),
                "--elf", inputs["candidate_elf"]["path"],
                "--input", inputs["common_input"]["path"],
                "--execution-journal", inputs["candidate_journal"]["path"],
                "--first-segment-index", "0",
                "--segment-count", str(observation["segment_count"]),
                "--memcpy-entry-pc", "0x880",
            ],
        },
        "observation": copy.deepcopy(observation),
        "sample": {
            "scope": "complete-candidate-execution",
            "segment_count": observation["segment_count"],
            "sampled_cycles": observation["sampled_cycles"],
            "retired_instructions": observation["retired_instructions"],
            "sample_is_complete_execution": True,
            "no_extrapolation": True,
        },
        "execution_projection": {
            "model": "one-bulk-row-per-admitted-software-call",
            "admitted_call_count": observation["admitted"]["calls"],
            "admitted_requested_bytes": observation["admitted"][
                "requested_bytes"
            ],
            "admitted_software_rows": observation["admitted"]["software_rows"],
            "candidate_word_rows": observation["admitted"]["word_rows"],
            "observed_removable_core_rows": observation["removable_core_rows"],
            "baseline_core_trace_rows": candidate["total_core_trace_rows"],
            "predicted_core_trace_rows": predicted_core,
            "baseline_total_cycles": candidate["total_cycles"],
            "predicted_total_cycles": predicted_cycles,
            "measured_candidate_execution": False,
            "candidate_air_complete": None,
            "candidate_proof_complete": None,
        },
        "process_measurement": {
            **timing,
            "scope": "observer-cli-process-only",
            "performance_claim_eligible": False,
        },
        "claim_boundary": {
            "scope": "receipt-bound-complete-execution-admission-projection",
            "production_active": False,
            "no_extrapolation": True,
            "predicted_execution_only": True,
            "candidate_execution_measured": False,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_promotion_eligible": False,
        },
    })


def _capture_path(
    source: Path, destination: Path, staging: Path, where: str,
) -> Path:
    raw = store.read_regular(source.absolute(), where)
    store.publish_new_or_identical(
        destination.absolute(), raw, staging_directory=staging.absolute(),
    )
    return destination.absolute()


def create(
    execution_path: Path, observation_path: Path, observer_executable: Path,
    observer_source: Path, timing_log: Path, output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "bulk memcpy evidence parent")
    store.require_directory(staging, "bulk memcpy evidence staging", create=True)
    custody = output.with_name(f"{output.stem}.custody")
    store.require_directory(custody, "bulk memcpy evidence custody", create=True)
    captured = {
        "observation": _capture_path(
            observation_path, custody / "observation.json", staging,
            "bulk memcpy observation",
        ),
        "executable": _capture_path(
            observer_executable, custody / "riscv-memcpy-admission-observer",
            staging, "bulk memcpy observer executable",
        ),
        "source": _capture_path(
            observer_source, custody / "observer-main.zig", staging,
            "bulk memcpy observer source",
        ),
        "timing": _capture_path(
            timing_log, custody / "stderr-time.log", staging,
            "bulk memcpy observer timing log",
        ),
    }
    execution_path = execution_path.absolute()
    value = _build_loaded(
        execution.load(execution_path),
        _identity(execution_path, "word-sponge execution evidence"),
        captured["observation"], captured["executable"], captured["source"],
        captured["timing"],
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "argv_projection", "observation",
        "sample", "execution_projection", "process_measurement",
        "claim_boundary", "content_sha256",
    }, "bulk memcpy evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "bulk memcpy evidence authority differs")
    inputs = value["inputs"]
    input_names = (
        "keccak_words_execution_evidence", "observation",
        "observer_executable", "observer_source", "observer_timing_log",
        "candidate_elf", "candidate_journal", "input",
    )
    _require(type(inputs) is dict and set(inputs) == set(input_names),
             "bulk memcpy evidence inputs differ")
    for name in input_names:
        _validate_identity(inputs[name], f"bulk memcpy {name}")
    execution_path = Path(inputs["keccak_words_execution_evidence"]["path"])
    expected = _build_loaded(
        execution.load(execution_path),
        inputs["keccak_words_execution_evidence"],
        Path(inputs["observation"]["path"]),
        Path(inputs["observer_executable"]["path"]),
        Path(inputs["observer_source"]["path"]),
        Path(inputs["observer_timing_log"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "bulk memcpy evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "bulk memcpy admission evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "bulk memcpy admission evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    for name in (
        "execution-evidence", "observation", "observer-executable",
        "observer-source", "timing-log", "output", "staging-directory",
    ):
        create_parser.add_argument(f"--{name}", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        create(
            arguments.execution_evidence, arguments.observation,
            arguments.observer_executable, arguments.observer_source,
            arguments.timing_log, arguments.output, arguments.staging_directory,
        )
        return 0
    except (
        BulkMemcpyAdmissionEvidenceError,
        execution.KeccakWordsExecutionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
