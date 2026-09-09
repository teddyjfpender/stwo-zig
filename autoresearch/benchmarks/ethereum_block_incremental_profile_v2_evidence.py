"""Capture and replay the changed-only incremental-memory V2 profiler."""

from __future__ import annotations

import argparse
from decimal import Decimal, ROUND_HALF_UP
import json
from pathlib import Path
import os
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_incremental_cost_evidence as process_support  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SOURCE_SCHEMA = "stwo.ethereum.incremental-memory-profile-v2"
EVIDENCE_SCHEMA = "stwo.ethereum.incremental-memory-profile-v2-evidence.v1"
CLAIM_BOUNDARY = "changed-only-topology-cell-diagnostic-not-a-proof"
MAX_TRIAL_SECONDS = 60
MAX_OUTPUT_BYTES = 1024 * 1024
D6_POSEIDON_MAIN_COLUMNS = 161
D6_POSEIDON_INTERACTION_COLUMNS = 8
BRIDGE_MAIN_COLUMNS = 7
BRIDGE_INTERACTION_COLUMNS = 4
FIXED_MAIN_COLUMNS = 445
FIXED_LOG_SIZE = 24
OUTPUT_KEYS = {
    "schema", "segment_index", "touched_words", "changed_words",
    "changed_bytes", "entry_hash_calls", "exit_hash_calls",
    "total_hash_calls", "bridge_rows", "provider_log_size",
    "bridge_log_size", "d6_poseidon_main_cells", "bridge_main_cells",
    "d6_committed_cells", "production", "path",
}
REFERENCE_65 = {
    "segment_count": 65,
    "touched_words": 3_525_764,
    "changed_words": 1_404_655,
    "changed_bytes": 5_181_423,
    "entry_hash_calls": 14_697_863,
    "exit_hash_calls": 5_665_139,
    "total_hash_calls": 20_363_002,
    "bridge_rows": 9_596_869,
    "d6_poseidon_main_cells": 4_970_979_328,
    "bridge_main_cells": 95_019_008,
    "combined_main_cells": 5_065_998_336,
    "d6_committed_cells": 5_367_300_096,
}


class IncrementalProfileV2EvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IncrementalProfileV2EvidenceError(message)


def _identity(path: Path, where: str, *, allow_empty: bool = False) -> dict[str, Any]:
    return process_support._identity(path, where, allow_empty=allow_empty)


def _validate_identity(value: Any, where: str, *,
                       allow_empty: bool = False) -> dict[str, Any]:
    try:
        return process_support._validate_identity(
            value, where, allow_empty=allow_empty,
        )
    except process_support.IncrementalCostEvidenceError as error:
        raise IncrementalProfileV2EvidenceError(str(error)) from error


def _positive(value: Any, where: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _rows(log_size: int) -> int:
    return 0 if log_size == 0 else 1 << log_size


def _trace_log(row_count: int) -> int:
    return 0 if row_count == 0 else max(4, (row_count - 1).bit_length())


def _canonical_output(line: bytes, where: str) -> dict[str, Any]:
    _require(line.endswith(b"\n"), f"{where} framing differs")
    value = store.decode_strict(line)
    _require(type(value) is dict and set(value) == OUTPUT_KEYS,
             f"{where} keys differ")
    encoded = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    _require(line == encoded, f"{where} is not canonical JSON")
    return value


def _record(line: bytes, tape: dict[str, Any], index: int) -> dict[str, Any]:
    value = _canonical_output(line, f"incremental profile V2 output {index}")
    _require(value["schema"] == SOURCE_SCHEMA
             and value["segment_index"] == index
             and value["path"] == tape["path"]
             and value["production"] is False,
             "incremental profile V2 row authority differs")
    for field in (
        "touched_words", "changed_words", "changed_bytes",
        "entry_hash_calls", "exit_hash_calls", "total_hash_calls",
        "bridge_rows", "provider_log_size", "bridge_log_size",
        "d6_poseidon_main_cells", "bridge_main_cells",
        "d6_committed_cells",
    ):
        _positive(value[field], f"incremental profile V2 {field}", allow_zero=True)
    provider_rows = _rows(value["provider_log_size"])
    bridge_padded_rows = _rows(value["bridge_log_size"])
    expected_committed = (
        provider_rows
        * (D6_POSEIDON_MAIN_COLUMNS + D6_POSEIDON_INTERACTION_COLUMNS)
        + bridge_padded_rows
        * (BRIDGE_MAIN_COLUMNS + BRIDGE_INTERACTION_COLUMNS)
    )
    _require(value["changed_words"] <= value["touched_words"]
             and value["changed_bytes"] <= value["changed_words"] * 4
             and value["total_hash_calls"]
             == value["entry_hash_calls"] + value["exit_hash_calls"]
             and value["provider_log_size"]
             == _trace_log(value["total_hash_calls"])
             and value["bridge_log_size"] == _trace_log(value["bridge_rows"])
             and value["d6_poseidon_main_cells"]
             == provider_rows * D6_POSEIDON_MAIN_COLUMNS
             and value["bridge_main_cells"]
             == bridge_padded_rows * BRIDGE_MAIN_COLUMNS
             and value["d6_committed_cells"] == expected_committed,
             "incremental profile V2 row does not close")
    return value


def _records(stderr: bytes, tapes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lines = stderr.splitlines(keepends=True)
    _require(len(lines) == len(tapes) and lines,
             "incremental profile V2 output count differs")
    return [
        _record(line, tape, index)
        for index, (line, tape) in enumerate(zip(lines, tapes, strict=True))
    ]


def _histogram(records: list[dict[str, Any]], field: str) -> list[dict[str, int]]:
    counts: dict[int, int] = {}
    for record in records:
        value = record[field]
        counts[value] = counts.get(value, 0) + 1
    return [
        {"log_size": log_size, "segment_count": counts[log_size]}
        for log_size in sorted(counts)
    ]


def _aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "touched_words", "changed_words", "changed_bytes",
        "entry_hash_calls", "exit_hash_calls", "total_hash_calls",
        "bridge_rows", "d6_poseidon_main_cells", "bridge_main_cells",
        "d6_committed_cells",
    )
    totals = {field: sum(record[field] for record in records) for field in fields}
    return {
        "segment_count": len(records),
        **totals,
        "combined_main_cells": (
            totals["d6_poseidon_main_cells"] + totals["bridge_main_cells"]
        ),
        "provider_padded_rows_sum": (
            totals["d6_poseidon_main_cells"] // D6_POSEIDON_MAIN_COLUMNS
        ),
        "bridge_padded_rows_sum": (
            totals["bridge_main_cells"] // BRIDGE_MAIN_COLUMNS
        ),
        "provider_log_histogram": _histogram(records, "provider_log_size"),
        "bridge_log_histogram": _histogram(records, "bridge_log_size"),
    }


def _decimal_ratio(numerator: int, denominator: int, places: str) -> str:
    return format(
        (Decimal(numerator) / Decimal(denominator)).quantize(
            Decimal(places), rounding=ROUND_HALF_UP,
        ),
        "f",
    )


def _models(aggregate: dict[str, Any]) -> dict[str, Any]:
    baseline = aggregate["segment_count"] * (1 << FIXED_LOG_SIZE) * FIXED_MAIN_COLUMNS
    candidate = aggregate["combined_main_cells"]
    reduction = baseline - candidate
    return {
        "model_boundary": "column-cell-geometry-only-no-proof-or-e2e-timing",
        "fixed_legacy_main_cells": baseline,
        "changed_only_poseidon_main_cells": aggregate["d6_poseidon_main_cells"],
        "changed_only_bridge_main_cells": aggregate["bridge_main_cells"],
        "changed_only_combined_main_cells": candidate,
        "changed_only_committed_cells": aggregate["d6_committed_cells"],
        "main_cell_reduction": {
            "numerator": reduction,
            "denominator": baseline,
            "percent_rounded_9dp": _decimal_ratio(
                reduction * 100, baseline, "0.000000001",
            ),
        },
        "baseline_to_candidate_ratio": {
            "numerator": baseline,
            "denominator": candidate,
            "multiple_rounded_6dp": _decimal_ratio(
                baseline, candidate, "0.000001",
            ),
        },
        "estimated_end_to_end_wall_ns": None,
    }


def _reference_admitted(aggregate: dict[str, Any]) -> bool:
    return all(aggregate.get(key) == value for key, value in REFERENCE_65.items())


def capture(
    *, tool: Path, tool_source: Path, tape_directory: Path,
    segment_count: int, timeout_seconds: int, output: Path, staging: Path,
) -> dict[str, Any]:
    tool = tool.absolute()
    tool_source = tool_source.absolute()
    tape_directory = tape_directory.absolute()
    output = output.absolute()
    staging = staging.absolute()
    _require(type(timeout_seconds) is int
             and 0 < timeout_seconds <= MAX_TRIAL_SECONDS,
             "incremental profile V2 timeout differs")
    _require(os.access(tool, os.X_OK),
             "incremental profile V2 tool is not executable")
    store.require_directory(tape_directory, "incremental profile V2 tape directory")
    store.require_directory(output.parent, "incremental profile V2 evidence parent")
    store.require_directory(staging, "incremental profile V2 staging", create=True)
    _positive(segment_count, "incremental profile V2 segment count")
    tapes = [
        _identity(
            tape_directory / f"segment-{index:06d}.stwemt01",
            f"incremental profile V2 tape {index}",
        )
        for index in range(segment_count)
    ]
    argv = [str(tool), *(tape["path"] for tape in tapes)]
    try:
        stdout_raw, stderr_raw, process = process_support._run(
            argv, staging, timeout_seconds,
        )
    except process_support.IncrementalCostEvidenceError as error:
        raise IncrementalProfileV2EvidenceError(str(error)) from error
    _require(stdout_raw == b"", "incremental profile V2 stdout is not empty")
    records = _records(stderr_raw, tapes)
    aggregate = _aggregate(records)
    stdout_path = output.with_name(f"{output.stem}.stdout")
    stderr_path = output.with_name(f"{output.stem}.stderr")
    store.publish_new_or_identical(
        stdout_path, stdout_raw, staging_directory=staging,
    )
    store.publish_new_or_identical(
        stderr_path, stderr_raw, staging_directory=staging,
    )
    value = protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": "captured-changed-only-geometry-diagnostic",
        "claim_boundary": CLAIM_BOUNDARY,
        "tool": _identity(tool, "incremental profile V2 tool"),
        "tool_source": _identity(tool_source, "incremental profile V2 source"),
        "argv": argv,
        "tapes": tapes,
        "transport": {
            "stdout": _identity(
                stdout_path, "incremental profile V2 stdout", allow_empty=True,
            ),
            "stderr": _identity(stderr_path, "incremental profile V2 stderr"),
        },
        "process": process,
        "aggregate": aggregate,
        "segment0": records[0],
        "models": _models(aggregate),
        "ranking": {
            "scope": "changed-only-topology-cell-geometry",
            "reference_65_admitted": _reference_admitted(aggregate),
            "diagnostic_eligible": True,
            "proof_correctness": None,
            "fresh_verification": None,
            "production_promotion_eligible": False,
        },
    })
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "claim_boundary", "tool", "tool_source", "argv",
        "tapes", "transport", "process", "aggregate", "segment0", "models",
        "ranking", "content_sha256",
    }, "incremental profile V2 evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA
             and value["status"] == "captured-changed-only-geometry-diagnostic"
             and value["claim_boundary"] == CLAIM_BOUNDARY
             and value["content_sha256"] == protocol.content_sha256(value),
             "incremental profile V2 evidence authority differs")
    tool = _validate_identity(value["tool"], "incremental profile V2 tool")
    _validate_identity(value["tool_source"], "incremental profile V2 source")
    _require(os.access(tool["path"], os.X_OK),
             "incremental profile V2 tool is not executable")
    tapes = value["tapes"]
    _require(type(tapes) is list and tapes,
             "incremental profile V2 tapes differ")
    for index, tape in enumerate(tapes):
        _validate_identity(tape, f"incremental profile V2 tape {index}")
        _require(Path(tape["path"]).name == f"segment-{index:06d}.stwemt01",
                 "incremental profile V2 tape order differs")
    _require(value["argv"] == [tool["path"], *(item["path"] for item in tapes)],
             "incremental profile V2 argv differs")
    transport = value["transport"]
    _require(type(transport) is dict and set(transport) == {"stdout", "stderr"},
             "incremental profile V2 transport differs")
    _validate_identity(
        transport["stdout"], "incremental profile V2 stdout", allow_empty=True,
    )
    _validate_identity(transport["stderr"], "incremental profile V2 stderr")
    stdout = store.read_regular(
        Path(transport["stdout"]["path"]), "incremental profile V2 stdout",
        maximum=MAX_OUTPUT_BYTES,
    )
    stderr = store.read_regular(
        Path(transport["stderr"]["path"]), "incremental profile V2 stderr",
        maximum=MAX_OUTPUT_BYTES,
    )
    _require(stdout == b"", "incremental profile V2 stdout is not empty")
    records = _records(stderr, tapes)
    aggregate = _aggregate(records)
    _require(value["aggregate"] == aggregate
             and value["segment0"] == records[0]
             and value["models"] == _models(aggregate),
             "incremental profile V2 replay differs")
    process = value["process"]
    _require(type(process) is dict and set(process) == {
        "exit_code", "timeout_seconds", "timing", "maximum_resident_set_bytes",
        "maximum_resident_set_source", "process_group_drained",
    } and process["exit_code"] == 0
             and type(process["timeout_seconds"]) is int
             and 0 < process["timeout_seconds"] <= MAX_TRIAL_SECONDS
             and process["process_group_drained"] is True
             and type(process["maximum_resident_set_bytes"]) is int
             and process["maximum_resident_set_bytes"] > 0,
             "incremental profile V2 process receipt differs")
    timing = process["timing"]
    _require(type(timing) is dict
             and set(timing) == {"wall_ns", "user_ns", "system_ns"}
             and all(type(item) is int and item >= 0 for item in timing.values())
             and 0 < timing["wall_ns"] <= MAX_TRIAL_SECONDS * 1_000_000_000,
             "incremental profile V2 timing differs")
    _require(value["ranking"] == {
        "scope": "changed-only-topology-cell-geometry",
        "reference_65_admitted": _reference_admitted(aggregate),
        "diagnostic_eligible": True,
        "proof_correctness": None,
        "fresh_verification": None,
        "production_promotion_eligible": False,
    }, "incremental profile V2 ranking boundary differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "incremental profile V2 evidence",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "incremental profile V2 evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("capture")
    create.add_argument("--tool", type=Path, required=True)
    create.add_argument("--tool-source", type=Path, required=True)
    create.add_argument("--tape-directory", type=Path, required=True)
    create.add_argument("--segment-count", type=int, required=True)
    create.add_argument("--timeout-seconds", type=int, default=MAX_TRIAL_SECONDS)
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
        capture(
            tool=arguments.tool,
            tool_source=arguments.tool_source,
            tape_directory=arguments.tape_directory,
            segment_count=arguments.segment_count,
            timeout_seconds=arguments.timeout_seconds,
            output=arguments.output,
            staging=arguments.staging_directory,
        )
        return 0
    except (
        IncrementalProfileV2EvidenceError,
        process_support.IncrementalCostEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
