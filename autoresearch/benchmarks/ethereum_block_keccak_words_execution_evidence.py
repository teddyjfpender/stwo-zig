"""Seal the combined memcpy-v6 + word-sponge RV32 execution result.

The complete candidate V3 journal is compared with the retained memcpy-v6
execution evidence over the same Ethereum input.  Equal output and exact
external-family rows are execution evidence only: program and final state
differ, and no AIR, proof, fresh verification, or proving-E2E claim is made.
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
import ethereum_block_memcpy_execution_evidence as memcpy_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.keccak-words-rv32-execution-equivalence-evidence.v1"
STATUS = "output-and-external-equivalent-execution-diagnostic-nonpromotable"
SOURCE_ROLES = (
    "workspace-keccak-sponge-source",
    "frozen-built-keccak-sponge-source",
    "frozen-candidate-main",
    "frozen-cargo-manifest",
    "frozen-cargo-config",
)


class KeccakWordsExecutionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise KeccakWordsExecutionEvidenceError(message)


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
             and 0 < saved < baseline, "word-sponge reduction differs")
    return {
        "saved": saved,
        "baseline": baseline,
        "millionths": saved * 1_000_000 // baseline,
    }


def _source_authorities(paths: list[tuple[str, Path]]) -> list[dict[str, Any]]:
    _require(tuple(role for role, _ in paths) == SOURCE_ROLES,
             "word-sponge source roles differ")
    return [{
        "role": role,
        "identity": _identity(path, f"{role} source"),
    } for role, path in paths]


def _build_loaded(
    baseline_evidence: dict[str, Any], baseline_identity: dict[str, Any],
    candidate_journal: Path, candidate_elf: Path, candidate_timing_log: Path,
    build_timing_log: Path, trace_executable: Path,
    source_paths: list[tuple[str, Path]],
) -> dict[str, Any]:
    _require(baseline_evidence["schema"] == memcpy_evidence.SCHEMA,
             "word-sponge baseline evidence schema differs")
    boundary = baseline_evidence["claim_boundary"]
    _require(
        boundary["production_active"] is False
        and boundary["candidate_air_complete"] is None
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_proving_end_to_end_wall_ns"] is None
        and boundary["production_promotion_eligible"] is False
        and baseline_evidence["equivalence"][
            "same_output_bytes_and_sha256"
        ] is True
        and baseline_evidence["equivalence"][
            "same_external_family_rows"
        ] is True,
        "word-sponge baseline claim boundary differs",
    )
    inputs = baseline_evidence["inputs"]
    input_identity = inputs["common_input"]
    baseline_elf = inputs["candidate_elf"]
    try:
        baseline = memcpy_evidence._journal(
            Path(inputs["candidate_journal"]["path"]), baseline_elf,
            input_identity, "memcpy-v6 comparator V3 journal",
        )
        candidate_elf_identity = _identity(
            candidate_elf, "word-sponge candidate ELF",
        )
        candidate = memcpy_evidence._journal(
            candidate_journal, candidate_elf_identity, input_identity,
            "word-sponge candidate V3 journal",
        )
        timing_identity, candidate_timing = allocator_evidence._timing(
            candidate_timing_log,
        )
        build_timing_identity, build_timing = allocator_evidence._timing(
            build_timing_log,
        )
    except (
        memcpy_evidence.MemcpyExecutionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
    ) as error:
        raise KeccakWordsExecutionEvidenceError(str(error)) from error
    _require(
        baseline == baseline_evidence["executions"]["memcpy_candidate"]
        and baseline["journal"] == inputs["candidate_journal"]
        and candidate["input_sha256"] == baseline["input_sha256"]
        and candidate["output_bytes"] == baseline["output_bytes"]
        and candidate["output_sha256"] == baseline["output_sha256"]
        and candidate["total_external_trace_rows"]
        == baseline["total_external_trace_rows"]
        and candidate["external_family_rows"] == baseline["external_family_rows"]
        and candidate["elf_sha256"] != baseline["elf_sha256"]
        and candidate["final_cpu_sha256"] != baseline["final_cpu_sha256"]
        and candidate["final_rw_memory_sha256"]
        != baseline["final_rw_memory_sha256"]
        and candidate["segment_count"] < baseline["segment_count"]
        and candidate["total_cycles"] < baseline["total_cycles"]
        and candidate["total_core_trace_rows"]
        < baseline["total_core_trace_rows"],
        "word-sponge execution equivalence/reduction differs",
    )
    baseline_timing = baseline_evidence["measurements"][
        "memcpy_candidate_process"
    ]
    _require(
        baseline_timing["retained_process_log"] is True
        and candidate_timing["retained_process_log"] is True
        and candidate_timing["wall_ns"] < baseline_timing["wall_ns"]
        and build_timing["retained_process_log"] is True,
        "word-sponge retained timing boundary differs",
    )
    cycle_saved = baseline["total_cycles"] - candidate["total_cycles"]
    core_saved = (
        baseline["total_core_trace_rows"]
        - candidate["total_core_trace_rows"]
    )
    wall_saved = baseline_timing["wall_ns"] - candidate_timing["wall_ns"]
    sources = _source_authorities(source_paths)
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "memcpy_v6_execution_evidence": baseline_identity,
            "baseline_journal": baseline["journal"],
            "baseline_elf": baseline_elf,
            "candidate_journal": candidate["journal"],
            "candidate_elf": candidate_elf_identity,
            "common_input": input_identity,
            "candidate_timing_log": timing_identity,
            "build_timing_log": build_timing_identity,
            "trace_executable": _identity(
                trace_executable, "word-sponge trace executable",
            ),
        },
        "source_authorities": sources,
        "executions": {
            "memcpy_v6_comparator": baseline,
            "keccak_words_candidate": candidate,
        },
        "equivalence": {
            "same_input_bytes_and_sha256": True,
            "same_output_bytes_and_sha256": True,
            "same_external_family_rows": True,
            "same_external_trace_rows": True,
            "program_and_elf_equal": False,
            "final_cpu_sha256_equal": False,
            "final_rw_memory_sha256_equal": False,
            "full_state_equivalence_claim": None,
        },
        "reductions": {
            "cycles": _ratio(cycle_saved, baseline["total_cycles"]),
            "core_trace_rows": _ratio(
                core_saved, baseline["total_core_trace_rows"],
            ),
            "segments": _ratio(
                baseline["segment_count"] - candidate["segment_count"],
                baseline["segment_count"],
            ),
            "external_trace_rows_delta": 0,
            "measured_wall_ns": _ratio(wall_saved, baseline_timing["wall_ns"]),
        },
        "measurements": {
            "memcpy_v6_comparator_process": copy.deepcopy(baseline_timing),
            "keccak_words_candidate_process": candidate_timing,
            "candidate_build_process": build_timing,
            "execution_wall_comparison_fully_file_backed": True,
            "scope": "two-whole-segmented-execution-cli-processes",
        },
        "claim_boundary": {
            "scope": "changed-program-execution-output-and-external-equivalence",
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
    trace_executable: Path, workspace_source: Path, frozen_source: Path,
    frozen_main: Path, cargo_manifest: Path, cargo_config: Path,
    output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "word-sponge evidence parent")
    store.require_directory(staging, "word-sponge evidence staging", create=True)
    custody = output.with_name(f"{output.stem}.custody")
    store.require_directory(custody, "word-sponge evidence custody", create=True)
    captured_workspace = _capture_path(
        workspace_source, custody / "workspace-keccak-sponge-source.rs",
        staging, "word-sponge workspace source",
    )
    captured_trace = _capture_path(
        trace_executable, custody / "riscv-trace-dump", staging,
        "word-sponge trace executable",
    )
    baseline_path = baseline_path.absolute()
    value = _build_loaded(
        memcpy_evidence.load(baseline_path),
        _identity(baseline_path, "memcpy-v6 execution evidence"),
        candidate_journal.absolute(), candidate_elf.absolute(),
        candidate_timing_log.absolute(), build_timing_log.absolute(),
        captured_trace,
        [
            (SOURCE_ROLES[0], captured_workspace),
            (SOURCE_ROLES[1], frozen_source.absolute()),
            (SOURCE_ROLES[2], frozen_main.absolute()),
            (SOURCE_ROLES[3], cargo_manifest.absolute()),
            (SOURCE_ROLES[4], cargo_config.absolute()),
        ],
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "source_authorities", "executions",
        "equivalence", "reductions", "measurements", "claim_boundary",
        "content_sha256",
    }, "word-sponge evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "word-sponge evidence authority differs")
    inputs = value["inputs"]
    input_names = (
        "memcpy_v6_execution_evidence", "baseline_journal", "baseline_elf",
        "candidate_journal", "candidate_elf", "common_input",
        "candidate_timing_log", "build_timing_log", "trace_executable",
    )
    _require(type(inputs) is dict and set(inputs) == set(input_names),
             "word-sponge evidence inputs differ")
    for name in input_names:
        _validate_identity(inputs[name], f"word-sponge {name}")
    sources = value["source_authorities"]
    _require(type(sources) is list and len(sources) == len(SOURCE_ROLES),
             "word-sponge source authorities differ")
    source_paths = []
    for index, (role, authority) in enumerate(zip(SOURCE_ROLES, sources)):
        _require(type(authority) is dict
                 and set(authority) == {"role", "identity"}
                 and authority["role"] == role,
                 f"word-sponge source authority {index} differs")
        _validate_identity(authority["identity"], f"word-sponge {role}")
        source_paths.append((role, Path(authority["identity"]["path"])))
    baseline_path = Path(inputs["memcpy_v6_execution_evidence"]["path"])
    expected = _build_loaded(
        memcpy_evidence.load(baseline_path),
        inputs["memcpy_v6_execution_evidence"],
        Path(inputs["candidate_journal"]["path"]),
        Path(inputs["candidate_elf"]["path"]),
        Path(inputs["candidate_timing_log"]["path"]),
        Path(inputs["build_timing_log"]["path"]),
        Path(inputs["trace_executable"]["path"]), source_paths,
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "word-sponge evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "word-sponge execution evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "word-sponge execution evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    for name in (
        "baseline-evidence", "candidate-journal", "candidate-elf",
        "candidate-timing-log", "build-timing-log", "trace-executable",
        "workspace-source", "frozen-source", "frozen-main",
        "cargo-manifest", "cargo-config", "output", "staging-directory",
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
            arguments.workspace_source, arguments.frozen_source,
            arguments.frozen_main, arguments.cargo_manifest,
            arguments.cargo_config, arguments.output,
            arguments.staging_directory,
        )
        return 0
    except (
        KeccakWordsExecutionEvidenceError,
        memcpy_evidence.MemcpyExecutionEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
