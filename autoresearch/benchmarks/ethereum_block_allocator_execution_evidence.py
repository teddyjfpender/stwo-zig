"""Seal the retained allocator-candidate execution equivalence diagnostic.

This contract compares two different RISC-V programs on the same retained
Ethereum input.  Equal guest output is useful execution evidence, but it is
not a proof, a full-state-equivalence claim, or an end-to-end benchmark.  The
baseline wall time currently has no retained process receipt, so the reported
wall reduction is preserved while remaining ineligible for ranking.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
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

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


SCHEMA = "stwo.ethereum.allocator-execution-equivalence-evidence.v1"
STATUS = "execution-output-equivalent-diagnostic-nonpromotable"
BASELINE_WALL_AUTHORITY = "frozen-controller-handoff-no-retained-process-receipt"
EXPECTED_BASELINE_WALL_NS = 70_490_000_000
TIME_LOG_MAX_BYTES = 64 * 1024
DECIMAL_SECONDS = re.compile(r"(?m)^(real|user|sys) ([0-9]+(?:\.[0-9]+)?)$")
INTEGER_METRIC = re.compile(
    r"(?m)^\s*([0-9]+)\s+"
    r"(maximum resident set size|peak memory footprint|swaps)$",
)


class AllocatorExecutionEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AllocatorExecutionEvidenceError(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(
        type(value) is dict and set(value) == {"path", "bytes", "sha256"},
        f"{where} keys differ",
    )
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where} path differs")
    expected = _identity(Path(value["path"]), where)
    _require(value == expected, f"{where} identity differs")
    return value


def _seconds_ns(value: str, where: str) -> int:
    try:
        seconds = Decimal(value)
    except InvalidOperation as error:
        raise AllocatorExecutionEvidenceError(f"{where} differs") from error
    nanoseconds = seconds * Decimal(1_000_000_000)
    _require(
        seconds >= 0 and nanoseconds == nanoseconds.to_integral_value(),
        f"{where} precision differs",
    )
    return int(nanoseconds)


def _timing(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = store.read_regular(
        path.absolute(), "candidate execution timing log", maximum=TIME_LOG_MAX_BYTES,
    )
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise AllocatorExecutionEvidenceError(
            "candidate execution timing log is not ASCII",
        ) from error
    decimals = DECIMAL_SECONDS.findall(text)
    _require(
        len(decimals) == 3 and {name for name, _ in decimals} == {"real", "user", "sys"},
        "candidate execution timing fields differ",
    )
    integers = INTEGER_METRIC.findall(text)
    integer_values = {name: int(value) for value, name in integers}
    _require(
        len(integers) == 3 and set(integer_values) == {
            "maximum resident set size", "peak memory footprint", "swaps",
        },
        "candidate execution resource fields differ",
    )
    seconds = {name: _seconds_ns(value, f"candidate {name}")
               for name, value in decimals}
    _require(
        seconds["real"] > 0 and integer_values["maximum resident set size"] > 0
        and integer_values["peak memory footprint"] > 0,
        "candidate execution timing values differ",
    )
    return _identity(path, "candidate execution timing log"), {
        "scope": "whole-segmented-execution-cli-process",
        "wall_ns": seconds["real"],
        "user_ns": seconds["user"],
        "system_ns": seconds["sys"],
        "maximum_resident_set_size_bytes": integer_values[
            "maximum resident set size"
        ],
        "peak_memory_footprint_bytes": integer_values["peak memory footprint"],
        "swaps": integer_values["swaps"],
        "retained_process_log": True,
    }


def _journal(path: Path, where: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = store.read_regular(path.absolute(), where, maximum=segmented.MAX_JOURNAL_BYTES)
    lines = raw.splitlines(keepends=True)
    try:
        summary = segmented.validate_records(lines, require_complete=True)
    except segmented.ContractError as error:
        raise AllocatorExecutionEvidenceError(str(error)) from error
    _require(summary is not None, f"{where} summary is absent")
    try:
        header = json.loads(lines[0])["payload"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise AllocatorExecutionEvidenceError(f"{where} header differs") from error
    _require(
        header["profile"] == segmented.PROFILE_ETHEREUM
        and header["clock_frame"] == segmented.CLOCK_FRAME_LEAF_LOCAL
        and header["claim_boundary"] == segmented.CLAIM_BOUNDARY
        and header["strict_completion"] is True
        and summary["completed"] is True
        and summary["claim_boundary"] == segmented.CLAIM_BOUNDARY
        and summary["completion_reason"] == "halt_flag"
        and summary["exit_code"] is None,
        f"{where} execution boundary differs",
    )
    projection = {
        "journal_schema": header["schema"],
        "summary_schema": summary["schema"],
        "profile": header["profile"],
        "clock_frame": header["clock_frame"],
        "elf_bytes": header["elf_bytes"],
        "elf_sha256": header["elf_sha256"],
        "input_bytes": header["input_bytes"],
        "input_sha256": header["input_sha256"],
        "segment_step_budget": header["segment_step_budget"],
        "segment_count": summary["segment_count"],
        "total_cycles": summary["total_cycles"],
        "total_core_trace_rows": summary["total_core_trace_rows"],
        "total_external_trace_rows": summary["total_external_trace_rows"],
        "output_bytes": summary["output_bytes"],
        "output_sha256": summary["output_sha256"],
        "final_cpu_sha256": summary["final_cpu_sha256"],
        "final_rw_memory_sha256": summary["final_rw_memory_sha256"],
        "final_access_clocks_sha256": summary["final_access_clocks_sha256"],
    }
    integer_fields = {
        "elf_bytes", "input_bytes", "segment_step_budget", "segment_count",
        "total_cycles", "total_core_trace_rows", "total_external_trace_rows",
        "output_bytes",
    }
    _require(
        all(type(projection[field]) is int and projection[field] >= 0
            for field in integer_fields)
        and projection["segment_count"] > 0
        and projection["total_cycles"]
        == projection["total_core_trace_rows"]
        + projection["total_external_trace_rows"],
        f"{where} totals differ",
    )
    return _identity(path, where), projection


def _source_request(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = store.read_regular(path.absolute(), "baseline source request", maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and value.get("schema")
             == "stwo.ethereum.block-proof-leaf-stream-source.v2",
             "baseline source request schema differs")
    _require(set(value["input"]) == {"path", "bytes", "sha256"}
             and set(value["elf"]) == {"path", "bytes", "sha256"}
             and set(value["execution_journal"]) == {"path", "bytes", "sha256"},
             "baseline source request identities differ")
    for field in ("input", "elf", "execution_journal"):
        _validate_identity(value[field], f"baseline source request {field}")
    return _identity(path, "baseline source request"), {
        field: value[field] for field in ("input", "elf", "execution_journal")
    }


def _ratio(saved: int, baseline: int) -> dict[str, int]:
    _require(type(saved) is int and type(baseline) is int
             and 0 <= saved <= baseline and baseline > 0,
             "allocator reduction ratio differs")
    return {
        "saved": saved,
        "baseline": baseline,
        "millionths": saved * 1_000_000 // baseline,
    }


def build(
    *,
    baseline_journal: Path,
    candidate_journal: Path,
    baseline_elf: Path,
    candidate_elf: Path,
    source_request: Path,
    candidate_timing_log: Path,
    workspace_allocator_source: Path,
    allocator_snapshot: Path,
    main_snapshot: Path,
    cargo_snapshot: Path,
    baseline_wall_ns: int,
    baseline_wall_authority: str,
) -> dict[str, Any]:
    _require(
        type(baseline_wall_ns) is int and baseline_wall_ns == EXPECTED_BASELINE_WALL_NS
        and baseline_wall_authority == BASELINE_WALL_AUTHORITY,
        "baseline wall authority differs",
    )
    baseline_identity, baseline = _journal(
        baseline_journal, "baseline execution journal",
    )
    candidate_identity, candidate = _journal(
        candidate_journal, "candidate execution journal",
    )
    baseline_elf_identity = _identity(baseline_elf, "baseline ELF")
    candidate_elf_identity = _identity(candidate_elf, "candidate ELF")
    request_identity, request = _source_request(source_request)
    timing_identity, candidate_timing = _timing(candidate_timing_log)
    snapshots = {
        "workspace_allocator_source": _identity(
            workspace_allocator_source, "workspace allocator source",
        ),
        "retained_allocator_source": _identity(
            allocator_snapshot, "retained allocator source snapshot",
        ),
        "retained_guest_main": _identity(main_snapshot, "retained guest main snapshot"),
        "retained_cargo_manifest": _identity(cargo_snapshot, "retained Cargo snapshot"),
    }
    _require(
        {"bytes": baseline["elf_bytes"], "sha256": baseline["elf_sha256"]}
        == {key: baseline_elf_identity[key] for key in ("bytes", "sha256")}
        and {"bytes": candidate["elf_bytes"], "sha256": candidate["elf_sha256"]}
        == {key: candidate_elf_identity[key] for key in ("bytes", "sha256")},
        "journal ELF binding differs",
    )
    _require(
        request["elf"] == baseline_elf_identity
        and request["execution_journal"] == baseline_identity
        and baseline["input_bytes"] == candidate["input_bytes"]
        == request["input"]["bytes"]
        and baseline["input_sha256"] == candidate["input_sha256"]
        == request["input"]["sha256"],
        "execution input authority differs",
    )
    _require(
        baseline_elf_identity["sha256"] != candidate_elf_identity["sha256"]
        and baseline["output_bytes"] == candidate["output_bytes"]
        and baseline["output_sha256"] == candidate["output_sha256"]
        and baseline["total_external_trace_rows"]
        == candidate["total_external_trace_rows"]
        and candidate["segment_count"] < baseline["segment_count"]
        and candidate["total_cycles"] < baseline["total_cycles"]
        and candidate_timing["wall_ns"] < baseline_wall_ns,
        "allocator execution comparison differs",
    )
    cycle_saved = baseline["total_cycles"] - candidate["total_cycles"]
    core_saved = baseline["total_core_trace_rows"] - candidate[
        "total_core_trace_rows"
    ]
    segment_saved = baseline["segment_count"] - candidate["segment_count"]
    wall_saved = baseline_wall_ns - candidate_timing["wall_ns"]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "claim_boundary": {
            "scope": "two-program-execution-output-equivalence",
            "production_active": False,
            "proof_generated": False,
            "fresh_proof_verification": False,
            "end_to_end_proof_timing": None,
            "no_extrapolation": True,
        },
        "inputs": {
            "baseline_journal": baseline_identity,
            "candidate_journal": candidate_identity,
            "baseline_elf": baseline_elf_identity,
            "candidate_elf": candidate_elf_identity,
            "baseline_source_request": request_identity,
            "common_input": request["input"],
            "candidate_timing_log": timing_identity,
            "candidate_source_snapshots": snapshots,
        },
        "executions": {"baseline": baseline, "candidate": candidate},
        "equivalence": {
            "same_input_bytes_and_sha256": True,
            "same_output_bytes_and_sha256": True,
            "same_total_external_trace_rows": True,
            "program_and_elf_equal": False,
            "output_equivalent_execution_observed": True,
            "final_cpu_sha256_equal": (
                baseline["final_cpu_sha256"] == candidate["final_cpu_sha256"]
            ),
            "final_rw_memory_sha256_equal": (
                baseline["final_rw_memory_sha256"]
                == candidate["final_rw_memory_sha256"]
            ),
            "final_access_clocks_sha256_equal": (
                baseline["final_access_clocks_sha256"]
                == candidate["final_access_clocks_sha256"]
            ),
            "full_state_equivalence_claim": None,
            "candidate_reproducible_build_claim": None,
            "workspace_allocator_matches_retained_snapshot": (
                snapshots["workspace_allocator_source"]["sha256"]
                == snapshots["retained_allocator_source"]["sha256"]
            ),
        },
        "measurements": {
            "candidate_process": candidate_timing,
            "baseline_process": {
                "wall_ns": baseline_wall_ns,
                "authority": baseline_wall_authority,
                "retained_process_log": False,
                "user_ns": None,
                "system_ns": None,
                "maximum_resident_set_size_bytes": None,
            },
            "wall_comparison_fully_file_backed": False,
            "wall_performance_claim_eligible": False,
        },
        "reductions": {
            "cycles": _ratio(cycle_saved, baseline["total_cycles"]),
            "core_trace_rows": _ratio(core_saved, baseline["total_core_trace_rows"]),
            "segments": _ratio(segment_saved, baseline["segment_count"]),
            "reported_wall_ns": _ratio(wall_saved, baseline_wall_ns),
            "external_trace_rows_delta": 0,
            "journal_backed_reductions": ["cycles", "core_trace_rows", "segments"],
            "reported_only_reductions": ["wall_ns"],
        },
        "promotion": {
            "execution_correctness_diagnostic_complete": True,
            "proof_completion": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "claim_boundary", "inputs", "executions",
        "equivalence", "measurements", "reductions", "promotion",
        "content_sha256",
    }, "allocator execution evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "allocator execution evidence authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "baseline_journal", "candidate_journal", "baseline_elf", "candidate_elf",
        "baseline_source_request", "common_input", "candidate_timing_log",
        "candidate_source_snapshots",
    }, "allocator execution evidence inputs differ")
    snapshots = inputs["candidate_source_snapshots"]
    _require(type(snapshots) is dict and set(snapshots) == {
        "workspace_allocator_source", "retained_allocator_source",
        "retained_guest_main", "retained_cargo_manifest",
    }, "allocator source snapshot keys differ")
    expected = build(
        baseline_journal=Path(inputs["baseline_journal"]["path"]),
        candidate_journal=Path(inputs["candidate_journal"]["path"]),
        baseline_elf=Path(inputs["baseline_elf"]["path"]),
        candidate_elf=Path(inputs["candidate_elf"]["path"]),
        source_request=Path(inputs["baseline_source_request"]["path"]),
        candidate_timing_log=Path(inputs["candidate_timing_log"]["path"]),
        workspace_allocator_source=Path(snapshots["workspace_allocator_source"]["path"]),
        allocator_snapshot=Path(snapshots["retained_allocator_source"]["path"]),
        main_snapshot=Path(snapshots["retained_guest_main"]["path"]),
        cargo_snapshot=Path(snapshots["retained_cargo_manifest"]["path"]),
        baseline_wall_ns=value["measurements"]["baseline_process"]["wall_ns"],
        baseline_wall_authority=value["measurements"]["baseline_process"]["authority"],
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "allocator execution evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "allocator execution evidence",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "allocator execution evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "baseline-journal", "candidate-journal", "baseline-elf", "candidate-elf",
        "source-request", "candidate-timing-log", "workspace-allocator-source",
        "allocator-snapshot", "main-snapshot", "cargo-snapshot", "output",
        "staging-directory",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)
    create.add_argument("--baseline-wall-ns", type=int, required=True)
    create.add_argument("--baseline-wall-authority", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.evidence)
            return 0
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "allocator evidence parent")
        store.require_directory(staging, "allocator evidence staging", create=True)
        value = build(
            baseline_journal=arguments.baseline_journal,
            candidate_journal=arguments.candidate_journal,
            baseline_elf=arguments.baseline_elf,
            candidate_elf=arguments.candidate_elf,
            source_request=arguments.source_request,
            candidate_timing_log=arguments.candidate_timing_log,
            workspace_allocator_source=arguments.workspace_allocator_source,
            allocator_snapshot=arguments.allocator_snapshot,
            main_snapshot=arguments.main_snapshot,
            cargo_snapshot=arguments.cargo_snapshot,
            baseline_wall_ns=arguments.baseline_wall_ns,
            baseline_wall_authority=arguments.baseline_wall_authority,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        AllocatorExecutionEvidenceError, protocol.ProofProtocolError,
        segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
