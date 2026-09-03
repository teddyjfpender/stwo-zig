"""Seal the successful-path native ECRECOVER execution diagnostic.

The complete candidate V3 journal is joined to the retained word-sponge
execution over the same Ethereum input.  Output and Keccak rows match while 12
successful signer recoveries move onto the typed external family.  General
invalid-input semantics are explicitly incomplete, so this is execution-only,
nonproduction evidence with no AIR/proof/E2E promotion.
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
import ethereum_block_keccak_words_execution_evidence as baseline_evidence  # noqa: E402
import ethereum_block_memcpy_execution_evidence as journal_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.ecrecover-success-rv32-execution-evidence.v1"
STATUS = "successful-path-execution-diagnostic-semantics-incomplete"
KECCAK_FAMILY = "stwo.keccakf-1600.permute-in-place@1"
RECOVERY_FAMILY = "stwo.secp256k1.recover-signer@1"
EXPECTED_ADDED_RECOVERY_CALLS = 12


class EcrecoverExecutionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EcrecoverExecutionEvidenceError(message)


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


def _ratio(saved: int, baseline: int) -> dict[str, int]:
    _require(type(saved) is int and type(baseline) is int
             and 0 < saved < baseline, "ECRECOVER reduction differs")
    return {
        "saved": saved,
        "baseline": baseline,
        "millionths": saved * 1_000_000 // baseline,
    }


def _external_map(value: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    _require(type(value) is list and len(value) == 2,
             "ECRECOVER external family roster differs")
    result = {}
    for row in value:
        _require(type(row) is dict
                 and set(row) == {"family", "calls", "execution_rows"}
                 and type(row["family"]) is str
                 and type(row["calls"]) is int and row["calls"] >= 0
                 and type(row["execution_rows"]) is int
                 and row["execution_rows"] == row["calls"],
                 "ECRECOVER external family row differs")
        result[row["family"]] = row
    _require(set(result) == {KECCAK_FAMILY, RECOVERY_FAMILY},
             "ECRECOVER external family names differ")
    return result


def _build_loaded(
    baseline: dict[str, Any], baseline_identity: dict[str, Any],
    candidate_journal: Path, candidate_elf: Path, candidate_timing_log: Path,
    build_timing_log: Path, trace_executable: Path, candidate_source: Path,
) -> dict[str, Any]:
    _require(baseline["schema"] == baseline_evidence.SCHEMA,
             "ECRECOVER baseline evidence schema differs")
    boundary = baseline["claim_boundary"]
    _require(
        boundary["production_active"] is False
        and boundary["candidate_air_complete"] is None
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_proving_end_to_end_wall_ns"] is None
        and boundary["production_promotion_eligible"] is False,
        "ECRECOVER baseline boundary differs",
    )
    inputs = baseline["inputs"]
    input_identity = inputs["common_input"]
    baseline_elf = inputs["candidate_elf"]
    try:
        comparator = journal_evidence._journal(
            Path(inputs["candidate_journal"]["path"]), baseline_elf,
            input_identity, "word-sponge comparator V3 journal",
        )
        candidate_elf_identity = _identity(
            candidate_elf, "ECRECOVER candidate ELF",
        )
        candidate = journal_evidence._journal(
            candidate_journal, candidate_elf_identity, input_identity,
            "ECRECOVER candidate V3 journal",
        )
        timing_identity, candidate_timing = allocator_evidence._timing(
            candidate_timing_log,
        )
        build_identity, build_timing = allocator_evidence._timing(
            build_timing_log,
        )
    except (
        journal_evidence.MemcpyExecutionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
    ) as error:
        raise EcrecoverExecutionEvidenceError(str(error)) from error
    _require(
        comparator == baseline["executions"]["keccak_words_candidate"]
        and comparator["journal"] == inputs["candidate_journal"]
        and candidate["input_sha256"] == comparator["input_sha256"]
        and candidate["output_bytes"] == comparator["output_bytes"]
        and candidate["output_sha256"] == comparator["output_sha256"]
        and candidate["elf_sha256"] != comparator["elf_sha256"]
        and candidate["final_cpu_sha256"] != comparator["final_cpu_sha256"]
        and candidate["final_rw_memory_sha256"]
        != comparator["final_rw_memory_sha256"]
        and candidate["segment_count"] < comparator["segment_count"]
        and candidate["total_cycles"] < comparator["total_cycles"]
        and candidate["total_core_trace_rows"]
        < comparator["total_core_trace_rows"],
        "ECRECOVER execution/output boundary differs",
    )
    comparator_external = _external_map(comparator["external_family_rows"])
    candidate_external = _external_map(candidate["external_family_rows"])
    _require(
        candidate_external[KECCAK_FAMILY] == comparator_external[KECCAK_FAMILY]
        and candidate_external[RECOVERY_FAMILY]["calls"]
        == comparator_external[RECOVERY_FAMILY]["calls"]
        + EXPECTED_ADDED_RECOVERY_CALLS
        and candidate["total_external_trace_rows"]
        == comparator["total_external_trace_rows"]
        + EXPECTED_ADDED_RECOVERY_CALLS,
        "ECRECOVER successful recovery inventory differs",
    )
    comparator_timing = baseline["measurements"][
        "keccak_words_candidate_process"
    ]
    _require(
        comparator_timing["retained_process_log"] is True
        and candidate_timing["retained_process_log"] is True
        and candidate_timing["wall_ns"] < comparator_timing["wall_ns"]
        and build_timing["retained_process_log"] is True,
        "ECRECOVER timing boundary differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "keccak_words_execution_evidence": baseline_identity,
            "baseline_journal": comparator["journal"],
            "baseline_elf": baseline_elf,
            "candidate_journal": candidate["journal"],
            "candidate_elf": candidate_elf_identity,
            "common_input": input_identity,
            "candidate_timing_log": timing_identity,
            "build_timing_log": build_identity,
            "trace_executable": _identity(
                trace_executable, "ECRECOVER trace executable",
            ),
            "candidate_source": _identity(
                candidate_source, "ECRECOVER candidate source",
            ),
        },
        "executions": {
            "keccak_words_comparator": comparator,
            "ecrecover_success_candidate": candidate,
        },
        "observed_equivalence": {
            "same_input_bytes_and_sha256": True,
            "same_output_bytes_and_sha256": True,
            "same_keccak_family_rows": True,
            "added_successful_recovery_calls": EXPECTED_ADDED_RECOVERY_CALLS,
            "program_and_elf_equal": False,
            "final_cpu_sha256_equal": False,
            "final_rw_memory_sha256_equal": False,
            "full_state_equivalence_claim": None,
        },
        "reductions": {
            "cycles": _ratio(
                comparator["total_cycles"] - candidate["total_cycles"],
                comparator["total_cycles"],
            ),
            "core_trace_rows": _ratio(
                comparator["total_core_trace_rows"]
                - candidate["total_core_trace_rows"],
                comparator["total_core_trace_rows"],
            ),
            "segments": _ratio(
                comparator["segment_count"] - candidate["segment_count"],
                comparator["segment_count"],
            ),
            "measured_wall_ns": _ratio(
                comparator_timing["wall_ns"] - candidate_timing["wall_ns"],
                comparator_timing["wall_ns"],
            ),
            "external_trace_rows_delta": EXPECTED_ADDED_RECOVERY_CALLS,
        },
        "measurements": {
            "keccak_words_comparator_process": copy.deepcopy(comparator_timing),
            "ecrecover_success_candidate_process": candidate_timing,
            "candidate_build_process": build_timing,
            "execution_wall_comparison_fully_file_backed": True,
            "scope": "two-whole-segmented-execution-cli-processes",
        },
        "semantics": {
            "successful_recovery_path_observed": True,
            "general_invalid_input_semantics_satisfied": False,
            "invalid_input_semantics_unavailable_reason": (
                "successful-only-native-recovery-candidate"
            ),
            "full_program_semantic_equivalence": None,
        },
        "claim_boundary": {
            "scope": "successful-path-execution-output-diagnostic-only",
            "production_active": False,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
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
    baseline_path: Path, candidate_journal: Path, candidate_elf: Path,
    candidate_timing_log: Path, build_timing_log: Path,
    trace_executable: Path, candidate_source: Path,
    output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "ECRECOVER evidence parent")
    store.require_directory(staging, "ECRECOVER evidence staging", create=True)
    custody = output.with_name(f"{output.stem}.custody")
    store.require_directory(custody, "ECRECOVER evidence custody", create=True)
    captured_trace = _capture_path(
        trace_executable, custody / "riscv-trace-dump", staging,
        "ECRECOVER trace executable",
    )
    captured_source = _capture_path(
        candidate_source, custody / "ecrecover-candidate.rs", staging,
        "ECRECOVER candidate source",
    )
    baseline_path = baseline_path.absolute()
    value = _build_loaded(
        baseline_evidence.load(baseline_path),
        _identity(baseline_path, "word-sponge execution evidence"),
        candidate_journal.absolute(), candidate_elf.absolute(),
        candidate_timing_log.absolute(), build_timing_log.absolute(),
        captured_trace, captured_source,
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "executions", "observed_equivalence",
        "reductions", "measurements", "semantics", "claim_boundary",
        "content_sha256",
    }, "ECRECOVER evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "ECRECOVER evidence authority differs")
    inputs = value["inputs"]
    names = (
        "keccak_words_execution_evidence", "baseline_journal", "baseline_elf",
        "candidate_journal", "candidate_elf", "common_input",
        "candidate_timing_log", "build_timing_log", "trace_executable",
        "candidate_source",
    )
    _require(type(inputs) is dict and set(inputs) == set(names),
             "ECRECOVER evidence inputs differ")
    for name in names:
        _validate_identity(inputs[name], f"ECRECOVER {name}")
    baseline_path = Path(inputs["keccak_words_execution_evidence"]["path"])
    expected = _build_loaded(
        baseline_evidence.load(baseline_path),
        inputs["keccak_words_execution_evidence"],
        Path(inputs["candidate_journal"]["path"]),
        Path(inputs["candidate_elf"]["path"]),
        Path(inputs["candidate_timing_log"]["path"]),
        Path(inputs["build_timing_log"]["path"]),
        Path(inputs["trace_executable"]["path"]),
        Path(inputs["candidate_source"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "ECRECOVER evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "ECRECOVER execution evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "ECRECOVER execution evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    for name in (
        "baseline-evidence", "candidate-journal", "candidate-elf",
        "candidate-timing-log", "build-timing-log", "trace-executable",
        "candidate-source", "output", "staging-directory",
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
            arguments.baseline_evidence, arguments.candidate_journal,
            arguments.candidate_elf, arguments.candidate_timing_log,
            arguments.build_timing_log, arguments.trace_executable,
            arguments.candidate_source, arguments.output,
            arguments.staging_directory,
        )
        return 0
    except (
        EcrecoverExecutionEvidenceError,
        baseline_evidence.KeccakWordsExecutionEvidenceError,
        journal_evidence.MemcpyExecutionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
