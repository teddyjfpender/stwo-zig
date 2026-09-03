"""Seal bulk-memcpy admission over the successful-path ECRECOVER guest.

This is a complete retained-execution call census and a one-row-per-admitted-
call execution projection.  It is not a synthesized post-bulk journal, AIR,
proof, fresh verification, E2E timing, or production result.
"""

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

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_bulk_memcpy_admission_evidence as bulk_support  # noqa: E402
import ethereum_block_ecrecover_execution_evidence as execution  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.ecrecover-bulk-memcpy-admission-evidence.v1"
STATUS = "exact-execution-admission-projection-diagnostic-nonpromotable"


class EcrecoverBulkMemcpyEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EcrecoverBulkMemcpyEvidenceError(message)


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


def _build_loaded(
    execution_value: dict[str, Any], execution_identity: dict[str, Any],
    observation_path: Path, observer_executable: Path, observer_source: Path,
    timing_log: Path,
) -> dict[str, Any]:
    _require(execution_value["schema"] == execution.SCHEMA,
             "ECRECOVER bulk execution schema differs")
    boundary = execution_value["claim_boundary"]
    semantics = execution_value["semantics"]
    _require(
        boundary["production_active"] is False
        and boundary["candidate_air_complete"] is None
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_proving_end_to_end_wall_ns"] is None
        and boundary["production_promotion_eligible"] is False
        and semantics["general_invalid_input_semantics_satisfied"] is False
        and semantics["full_program_semantic_equivalence"] is None,
        "ECRECOVER bulk execution boundary differs",
    )
    try:
        observation, observation_identity = bulk_support._load_observation(
            observation_path,
        )
        timing_identity, timing = allocator_evidence._timing(timing_log)
    except (
        bulk_support.BulkMemcpyAdmissionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
    ) as error:
        raise EcrecoverBulkMemcpyEvidenceError(str(error)) from error
    inputs = execution_value["inputs"]
    candidate = execution_value["executions"]["ecrecover_success_candidate"]
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
        "ECRECOVER bulk observation/execution join differs",
    )
    predicted_core = (
        candidate["total_core_trace_rows"] - observation["removable_core_rows"]
    )
    predicted_cycles = candidate["total_cycles"] - observation["removable_core_rows"]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "ecrecover_execution_evidence": execution_identity,
            "observation": observation_identity,
            "observer_executable": _identity(
                observer_executable, "ECRECOVER bulk observer executable",
            ),
            "observer_source": _identity(
                observer_source, "ECRECOVER bulk observer source",
            ),
            "observer_timing_log": timing_identity,
            "candidate_elf": inputs["candidate_elf"],
            "candidate_journal": inputs["candidate_journal"],
            "input": inputs["common_input"],
        },
        "observation": copy.deepcopy(observation),
        "sample": {
            "scope": "complete-ecrecover-candidate-execution",
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
            "synthesized_post_bulk_journal": None,
            "measured_candidate_execution": False,
            "candidate_air_complete": None,
            "candidate_proof_complete": None,
        },
        "process_measurement": {
            **timing,
            "scope": "observer-cli-process-only",
            "argv_process_receipt_retained": False,
            "performance_claim_eligible": False,
        },
        "claim_boundary": {
            "scope": "receipt-bound-complete-execution-admission-projection",
            "production_active": False,
            "general_invalid_ecrecover_semantics_satisfied": False,
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
    store.require_directory(output.parent, "ECRECOVER bulk evidence parent")
    store.require_directory(staging, "ECRECOVER bulk evidence staging", create=True)
    custody = output.with_name(f"{output.stem}.custody")
    store.require_directory(custody, "ECRECOVER bulk custody", create=True)
    captured = {
        "observation": _capture_path(
            observation_path, custody / "observation.json", staging,
            "ECRECOVER bulk observation",
        ),
        "executable": _capture_path(
            observer_executable, custody / "riscv-memcpy-admission-observer",
            staging, "ECRECOVER bulk observer executable",
        ),
        "source": _capture_path(
            observer_source, custody / "observer-main.zig", staging,
            "ECRECOVER bulk observer source",
        ),
        "timing": _capture_path(
            timing_log, custody / "stderr-time.log", staging,
            "ECRECOVER bulk timing log",
        ),
    }
    execution_path = execution_path.absolute()
    value = _build_loaded(
        execution.load(execution_path),
        _identity(execution_path, "ECRECOVER execution evidence"),
        captured["observation"], captured["executable"], captured["source"],
        captured["timing"],
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "observation", "sample",
        "execution_projection", "process_measurement", "claim_boundary",
        "content_sha256",
    }, "ECRECOVER bulk evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "ECRECOVER bulk evidence authority differs")
    inputs = value["inputs"]
    names = (
        "ecrecover_execution_evidence", "observation", "observer_executable",
        "observer_source", "observer_timing_log", "candidate_elf",
        "candidate_journal", "input",
    )
    _require(type(inputs) is dict and set(inputs) == set(names),
             "ECRECOVER bulk evidence inputs differ")
    for name in names:
        _validate_identity(inputs[name], f"ECRECOVER bulk {name}")
    execution_path = Path(inputs["ecrecover_execution_evidence"]["path"])
    expected = _build_loaded(
        execution.load(execution_path), inputs["ecrecover_execution_evidence"],
        Path(inputs["observation"]["path"]),
        Path(inputs["observer_executable"]["path"]),
        Path(inputs["observer_source"]["path"]),
        Path(inputs["observer_timing_log"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "ECRECOVER bulk evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "ECRECOVER bulk evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "ECRECOVER bulk evidence is not canonical JSON")
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
        EcrecoverBulkMemcpyEvidenceError,
        execution.EcrecoverExecutionEvidenceError,
        bulk_support.BulkMemcpyAdmissionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
