"""Seal ordinary-RV32 memcpy execution evidence against the allocator baseline.

Both executions are complete V3 segmented journals over the same Ethereum
input.  Equal output and external-call inventories are execution evidence only:
the ELF and final CPU/memory states intentionally differ, and no AIR, proof,
fresh verification, or end-to-end proving claim is made.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_post_allocator_opportunity_ledger as post_ledger  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


SCHEMA = "stwo.ethereum.memcpy-rv32-execution-equivalence-evidence.v1"
STATUS = "output-and-external-equivalent-execution-diagnostic-nonpromotable"
MEMCPY_SOURCE = REPOSITORY / "autoresearch/benchmarks/guest_runtime/fast_word_memcpy_v3.rs"


class MemcpyExecutionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MemcpyExecutionEvidenceError(message)


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
             and 0 < saved < baseline, "memcpy execution reduction differs")
    return {
        "saved": saved,
        "baseline": baseline,
        "millionths": saved * 1_000_000 // baseline,
    }


def _journal(path: Path, elf: dict[str, Any], input_identity: dict[str, Any],
             where: str) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where, maximum=segmented.MAX_JOURNAL_BYTES)
    lines = raw.splitlines(keepends=True)
    try:
        summary = segmented.validate_records(lines, require_complete=True)
        header = json.loads(lines[0])["payload"]
        final = json.loads(lines[-1])["payload"]
    except (segmented.ContractError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise MemcpyExecutionEvidenceError(str(error)) from error
    _require(
        summary is not None
        and header["schema"] == segmented.HEADER_SCHEMA
        and final["schema"] == segmented.SUMMARY_SCHEMA
        and header["profile"] == segmented.PROFILE_ETHEREUM
        and header["clock_frame"] == segmented.CLOCK_FRAME_LEAF_LOCAL
        and header["claim_boundary"] == segmented.CLAIM_BOUNDARY
        and header["strict_completion"] is True
        and header["trace_retention"] == "segment-owned"
        and final["completed"] is True
        and final["completion_reason"] == "halt_flag"
        and final["exit_code"] is None
        and header["elf_bytes"] == elf["bytes"]
        and header["elf_sha256"] == elf["sha256"]
        and header["input_bytes"] == input_identity["bytes"]
        and header["input_sha256"] == input_identity["sha256"]
        and summary["segment_count"] > 0
        and summary["total_cycles"] > 0
        and summary["total_core_trace_rows"] > 0
        and summary["output_bytes"] > 0,
        f"{where} authority differs",
    )
    return {
        "journal": _identity(path, where),
        "journal_schema": header["schema"],
        "summary_schema": final["schema"],
        "profile": header["profile"],
        "clock_frame": header["clock_frame"],
        "segment_step_budget": header["segment_step_budget"],
        "elf_bytes": header["elf_bytes"],
        "elf_sha256": header["elf_sha256"],
        "input_bytes": header["input_bytes"],
        "input_sha256": header["input_sha256"],
        "segment_count": summary["segment_count"],
        "total_cycles": summary["total_cycles"],
        "total_core_trace_rows": summary["total_core_trace_rows"],
        "total_external_trace_rows": summary["total_external_trace_rows"],
        "external_family_rows": copy.deepcopy(summary["external_family_rows"]),
        "opcode_family_rows": copy.deepcopy(summary["opcode_family_rows"]),
        "output_bytes": summary["output_bytes"],
        "output_sha256": summary["output_sha256"],
        "final_cpu_sha256": summary["final_cpu_sha256"],
        "final_rw_memory_sha256": summary["final_rw_memory_sha256"],
        "final_access_clocks_sha256": summary["final_access_clocks_sha256"],
        "segment_statement_v2_admissible": summary[
            "segment_statement_v2_admissible"
        ],
    }


def _build_loaded(
    post: dict[str, Any], post_identity: dict[str, Any],
    allocator: dict[str, Any], allocator_identity: dict[str, Any],
    candidate_journal: Path, candidate_elf: Path, candidate_timing_log: Path,
    memcpy_source: Path = MEMCPY_SOURCE,
) -> dict[str, Any]:
    _require(post["schema"] == post_ledger.SCHEMA
             and allocator["schema"] == allocator_evidence.SCHEMA,
             "memcpy execution source evidence schema differs")
    allocator_inputs = allocator["inputs"]
    baseline_elf = allocator_inputs["candidate_elf"]
    input_identity = allocator_inputs["common_input"]
    baseline_journal = post["inputs"]["candidate_v3_journal"]
    candidate_elf_identity = _identity(candidate_elf, "memcpy candidate ELF")
    _require(
        post["inputs"]["allocator_execution_evidence"] == allocator_identity
        and post["corpus"]["identity"] == baseline_journal
        and post["corpus"]["header"]["elf_sha256"] == baseline_elf["sha256"]
        and post["corpus"]["header"]["input_sha256"] == input_identity["sha256"]
        and post["claims"]["full_block_proof_complete"] is None
        and post["claims"]["measured_end_to_end_wall_ns"] is None,
        "memcpy execution post-allocator baseline join differs",
    )
    baseline = _journal(
        Path(baseline_journal["path"]), baseline_elf, input_identity,
        "allocator V3 baseline journal",
    )
    candidate = _journal(
        candidate_journal, candidate_elf_identity, input_identity,
        "memcpy candidate V3 journal",
    )
    _require(baseline["journal"] == baseline_journal,
             "memcpy execution baseline journal identity differs")
    try:
        timing_identity, candidate_timing = allocator_evidence._timing(
            candidate_timing_log,
        )
    except allocator_evidence.AllocatorExecutionEvidenceError as error:
        raise MemcpyExecutionEvidenceError(str(error)) from error
    baseline_timing = allocator["measurements"]["candidate_process"]
    _require(
        baseline_timing["retained_process_log"] is True
        and baseline_timing["scope"] == "whole-segmented-execution-cli-process"
        and candidate_timing["retained_process_log"] is True
        and candidate_timing["scope"] == "whole-segmented-execution-cli-process"
        and candidate_timing["wall_ns"] < baseline_timing["wall_ns"]
        and candidate["segment_count"] < baseline["segment_count"]
        and candidate["total_cycles"] < baseline["total_cycles"]
        and candidate["total_core_trace_rows"] < baseline["total_core_trace_rows"]
        and candidate["total_external_trace_rows"]
        == baseline["total_external_trace_rows"]
        and candidate["external_family_rows"] == baseline["external_family_rows"]
        and candidate["output_bytes"] == baseline["output_bytes"]
        and candidate["output_sha256"] == baseline["output_sha256"]
        and candidate["elf_sha256"] != baseline["elf_sha256"]
        and candidate["final_cpu_sha256"] != baseline["final_cpu_sha256"]
        and candidate["final_rw_memory_sha256"]
        != baseline["final_rw_memory_sha256"],
        "memcpy execution equivalence/reduction boundary differs",
    )
    cycle_saved = baseline["total_cycles"] - candidate["total_cycles"]
    core_saved = (
        baseline["total_core_trace_rows"] - candidate["total_core_trace_rows"]
    )
    segment_saved = baseline["segment_count"] - candidate["segment_count"]
    wall_saved = baseline_timing["wall_ns"] - candidate_timing["wall_ns"]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "post_allocator_ledger": post_identity,
            "allocator_execution_evidence": allocator_identity,
            "baseline_journal": baseline["journal"],
            "baseline_elf": baseline_elf,
            "candidate_journal": candidate["journal"],
            "candidate_elf": candidate_elf_identity,
            "common_input": input_identity,
            "candidate_timing_log": timing_identity,
            "candidate_source": _identity(memcpy_source, "memcpy candidate source"),
        },
        "executions": {
            "allocator_baseline": baseline,
            "memcpy_candidate": candidate,
        },
        "measurements": {
            "allocator_baseline_process": copy.deepcopy(baseline_timing),
            "memcpy_candidate_process": candidate_timing,
            "wall_comparison_fully_file_backed": True,
            "scope": "two-whole-segmented-execution-cli-processes",
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
            "segments": _ratio(segment_saved, baseline["segment_count"]),
            "measured_wall_ns": _ratio(wall_saved, baseline_timing["wall_ns"]),
            "external_trace_rows_delta": 0,
        },
        "claim_boundary": {
            "scope": "execution-output-and-external-family-equivalence-only",
            "production_active": False,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_proving_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    post_path: Path, allocator_path: Path, candidate_journal: Path,
    candidate_elf: Path, candidate_timing_log: Path,
    memcpy_source: Path = MEMCPY_SOURCE,
) -> dict[str, Any]:
    post_path, allocator_path = post_path.absolute(), allocator_path.absolute()
    post = post_ledger.load(post_path)
    allocator = allocator_evidence.load(allocator_path)
    return _build_loaded(
        post, _identity(post_path, "post-allocator opportunity ledger"),
        allocator, _identity(allocator_path, "allocator execution evidence"),
        candidate_journal.absolute(), candidate_elf.absolute(),
        candidate_timing_log.absolute(), memcpy_source.absolute(),
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "executions", "measurements",
        "equivalence", "reductions", "claim_boundary", "content_sha256",
    }, "memcpy execution evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "memcpy execution evidence authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "post_allocator_ledger", "allocator_execution_evidence",
        "baseline_journal", "baseline_elf", "candidate_journal",
        "candidate_elf", "common_input", "candidate_timing_log",
        "candidate_source",
    }, "memcpy execution evidence inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"memcpy execution {name}")
    expected = build(
        Path(inputs["post_allocator_ledger"]["path"]),
        Path(inputs["allocator_execution_evidence"]["path"]),
        Path(inputs["candidate_journal"]["path"]),
        Path(inputs["candidate_elf"]["path"]),
        Path(inputs["candidate_timing_log"]["path"]),
        Path(inputs["candidate_source"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "memcpy execution evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "memcpy execution evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "memcpy execution evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "post-allocator-ledger", "allocator-evidence", "candidate-journal",
        "candidate-elf", "candidate-timing-log", "candidate-source", "output",
        "staging-directory",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "memcpy execution evidence parent")
        store.require_directory(staging, "memcpy execution staging", create=True)
        value = build(
            arguments.post_allocator_ledger, arguments.allocator_evidence,
            arguments.candidate_journal, arguments.candidate_elf,
            arguments.candidate_timing_log, arguments.candidate_source,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        MemcpyExecutionEvidenceError,
        post_ledger.PostAllocatorOpportunityLedgerError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
        segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
