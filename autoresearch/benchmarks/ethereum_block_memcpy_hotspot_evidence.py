"""Seal and replay the retained memcpy-observer prefix diagnostic."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
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

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


OBSERVATION_SCHEMA = "stwo.riscv.memcpy-call-hotspot-observation.v1"
EVIDENCE_SCHEMA = "stwo.ethereum.memcpy-hotspot-evidence.v1"
STATUS = "memcpy-prefix-observed-diagnostic-nonpromotable"
MAX_SAMPLE_SEGMENTS = 64
MAX_WALL_NS = 60_000_000_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OBSERVATION_KEYS = (
    "alignment_histogram", "call_count", "clock_frame", "content_sha256",
    "distinct_alignment_count", "distinct_length_count", "elf_sha256",
    "execution_profile", "first_global_cycle", "first_segment_index",
    "input_sha256", "length_histogram", "maximum_requested_bytes",
    "memcpy_entry_pc", "production", "retired_instructions", "sampled_cycles",
    "schema", "segment_count", "source_sha256", "status",
    "total_requested_bytes", "validated_register_reads", "zero_length_calls",
)


class MemcpyHotspotEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MemcpyHotspotEvidenceError(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where} path differs")
    _require(value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value) is not None,
             f"{where} differs")
    return value


def _int(value: Any, where: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _observation(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "memcpy observation", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and tuple(value) == OBSERVATION_KEYS,
             "memcpy observation keys/order differ")
    canonical = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    _require(raw == canonical, "memcpy observation is not canonical JSON")
    unsigned = {key: item for key, item in value.items() if key != "content_sha256"}
    expected = hashlib.sha256((json.dumps(
        unsigned, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")).hexdigest()
    _require(
        value["schema"] == OBSERVATION_SCHEMA
        and value["status"] == "captured-diagnostic-only"
        and value["production"] is False
        and value["execution_profile"] == segmented.PROFILE_ETHEREUM
        and value["clock_frame"] == segmented.CLOCK_FRAME_LEAF_LOCAL
        and value["first_segment_index"] == 0
        and value["first_global_cycle"] == 1
        and value["content_sha256"] == expected,
        "memcpy observation authority differs",
    )
    for field in ("elf_sha256", "input_sha256", "source_sha256"):
        _sha(value[field], f"memcpy observation {field}")
    for field in (
        "call_count", "distinct_alignment_count", "distinct_length_count",
        "first_global_cycle", "first_segment_index", "maximum_requested_bytes",
        "memcpy_entry_pc", "retired_instructions", "sampled_cycles",
        "segment_count", "total_requested_bytes", "validated_register_reads",
        "zero_length_calls",
    ):
        _int(value[field], f"memcpy observation {field}")
    _require(
        0 < value["segment_count"] <= MAX_SAMPLE_SEGMENTS
        and value["call_count"] > 0
        and value["retired_instructions"] > 0
        and value["sampled_cycles"] >= value["retired_instructions"]
        and value["validated_register_reads"] >= value["retired_instructions"]
        and value["zero_length_calls"] <= value["call_count"],
        "memcpy observation totals differ",
    )
    lengths = value["length_histogram"]
    _require(type(lengths) is list
             and len(lengths) == value["distinct_length_count"] > 0,
             "memcpy length histogram count differs")
    prior_length = -1
    length_calls = length_bytes = zero_calls = 0
    for index, row in enumerate(lengths):
        _require(type(row) is dict
                 and tuple(row) == ("call_count", "length", "total_bytes"),
                 f"memcpy length row {index} keys/order differ")
        calls = _int(row["call_count"], f"memcpy length row {index} calls", minimum=1)
        length = _int(row["length"], f"memcpy length row {index} length")
        total = _int(row["total_bytes"], f"memcpy length row {index} bytes")
        _require(length > prior_length and total == calls * length,
                 f"memcpy length row {index} closure differs")
        prior_length = length
        length_calls += calls
        length_bytes += total
        if length == 0:
            zero_calls = calls
    _require(
        length_calls == value["call_count"]
        and length_bytes == value["total_requested_bytes"]
        and zero_calls == value["zero_length_calls"]
        and prior_length == value["maximum_requested_bytes"],
        "memcpy length histogram totals differ",
    )
    alignments = value["alignment_histogram"]
    _require(type(alignments) is list
             and len(alignments) == value["distinct_alignment_count"] > 0,
             "memcpy alignment histogram count differs")
    prior_pair: tuple[int, int] | None = None
    alignment_calls = alignment_bytes = 0
    for index, row in enumerate(alignments):
        _require(type(row) is dict and tuple(row) == (
            "call_count", "destination_mod_16", "source_mod_16", "total_bytes",
        ), f"memcpy alignment row {index} keys/order differ")
        calls = _int(row["call_count"], f"memcpy alignment row {index} calls", minimum=1)
        destination = _int(
            row["destination_mod_16"], f"memcpy alignment row {index} destination",
        )
        source = _int(row["source_mod_16"], f"memcpy alignment row {index} source")
        total = _int(row["total_bytes"], f"memcpy alignment row {index} bytes")
        pair = (destination, source)
        _require(destination < 16 and source < 16
                 and (prior_pair is None or pair > prior_pair),
                 f"memcpy alignment row {index} order differs")
        prior_pair = pair
        alignment_calls += calls
        alignment_bytes += total
    _require(alignment_calls == value["call_count"]
             and alignment_bytes == value["total_requested_bytes"],
             "memcpy alignment histogram totals differ")
    return value


def _journal_prefix(path: Path, segment_count: int) -> tuple[dict[str, Any], dict[str, int]]:
    raw = store.read_regular(
        path.absolute(), "allocator candidate journal", maximum=segmented.MAX_JOURNAL_BYTES,
    )
    lines = raw.splitlines(keepends=True)
    try:
        summary = segmented.validate_records(lines, require_complete=True)
    except segmented.ContractError as error:
        raise MemcpyHotspotEvidenceError(str(error)) from error
    _require(summary is not None and segment_count <= summary["segment_count"],
             "memcpy journal prefix range differs")
    try:
        header = json.loads(lines[0])["payload"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise MemcpyHotspotEvidenceError("memcpy journal header differs") from error
    records = []
    for index, line in enumerate(lines[1:segment_count + 1]):
        try:
            record = json.loads(line)["payload"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise MemcpyHotspotEvidenceError(
                f"memcpy journal segment {index} differs",
            ) from error
        _require(record["segment_index"] == index,
                 "memcpy journal prefix order differs")
        records.append(record)
    return _identity(path, "allocator candidate journal"), {
        "segment_count": len(records),
        "first_global_cycle": records[0]["global_first_cycle"],
        "sampled_cycles": sum(record["cycle_count"] for record in records),
        "retired_instructions": sum(record["core_trace_rows"] for record in records),
        "full_journal_segment_count": summary["segment_count"],
        "full_journal_total_cycles": summary["total_cycles"],
        "full_journal_total_core_trace_rows": summary["total_core_trace_rows"],
        "full_journal_total_external_trace_rows": summary[
            "total_external_trace_rows"
        ],
        "full_journal_output_bytes": summary["output_bytes"],
        "full_journal_output_sha256": summary["output_sha256"],
        "full_journal_elf_sha256": header["elf_sha256"],
        "full_journal_input_sha256": header["input_sha256"],
    }


def _normalized(
    *, observation_path: Path, executable_custody: Path, observer_source: Path,
    candidate_elf: Path, candidate_journal: Path, input_path: Path,
    timing_log: Path, allocator_evidence_path: Path,
) -> dict[str, Any]:
    observation = _observation(observation_path)
    observation_identity = _identity(observation_path, "memcpy observation")
    executable = _identity(executable_custody, "memcpy observer executable custody")
    source = _identity(observer_source, "memcpy observer source")
    elf = _identity(candidate_elf, "allocator candidate ELF")
    input_identity = _identity(input_path, "Ethereum block input")
    journal, prefix = _journal_prefix(candidate_journal, observation["segment_count"])
    try:
        allocator = allocator_evidence.load(allocator_evidence_path)
        timing_identity, timing = allocator_evidence._timing(timing_log)
    except allocator_evidence.AllocatorExecutionEvidenceError as error:
        raise MemcpyHotspotEvidenceError(str(error)) from error
    timing = {**timing, "scope": "whole-memcpy-observer-cli-process"}
    allocator_identity = _identity(
        allocator_evidence_path, "allocator execution evidence",
    )
    allocator_inputs = allocator["inputs"]
    candidate_execution = allocator["executions"]["candidate"]
    _require(
        observation["elf_sha256"] == elf["sha256"]
        == allocator_inputs["candidate_elf"]["sha256"]
        and observation["input_sha256"] == input_identity["sha256"]
        == allocator_inputs["common_input"]["sha256"]
        and observation["source_sha256"] == journal["sha256"]
        and prefix["full_journal_elf_sha256"] == observation["elf_sha256"]
        and prefix["full_journal_input_sha256"] == observation["input_sha256"]
        and observation["segment_count"] == prefix["segment_count"]
        and observation["first_global_cycle"] == prefix["first_global_cycle"]
        and observation["sampled_cycles"] == prefix["sampled_cycles"]
        and observation["retired_instructions"] == prefix["retired_instructions"]
        and prefix["full_journal_segment_count"]
        == candidate_execution["segment_count"]
        and prefix["full_journal_total_cycles"]
        == candidate_execution["total_cycles"]
        and prefix["full_journal_total_core_trace_rows"]
        == candidate_execution["total_core_trace_rows"]
        and prefix["full_journal_total_external_trace_rows"]
        == candidate_execution["total_external_trace_rows"]
        and prefix["full_journal_output_bytes"]
        == candidate_execution["output_bytes"]
        and prefix["full_journal_output_sha256"]
        == candidate_execution["output_sha256"]
        and timing["wall_ns"] <= MAX_WALL_NS,
        "memcpy observation custody/prefix binding differs",
    )
    return protocol.seal({
        "schema": EVIDENCE_SCHEMA,
        "status": STATUS,
        "inputs": {
            "observation": observation_identity,
            "observer_executable_custody": executable,
            "observer_source": source,
            "candidate_elf": elf,
            "candidate_journal": journal,
            "input": input_identity,
            "process_timing_log": timing_identity,
            "allocator_execution_evidence": allocator_identity,
        },
        "source_observation": copy.deepcopy(observation),
        "sample": {
            **prefix,
            "call_count": observation["call_count"],
            "total_requested_bytes": observation["total_requested_bytes"],
            "zero_length_calls": observation["zero_length_calls"],
            "distinct_length_count": observation["distinct_length_count"],
            "distinct_alignment_count": observation["distinct_alignment_count"],
            "maximum_requested_bytes": observation["maximum_requested_bytes"],
            "memcpy_entry_pc": observation["memcpy_entry_pc"],
            "length_histogram_sha256": protocol.sha256_bytes(
                protocol.canonical_bytes(observation["length_histogram"])
            ),
            "alignment_histogram_sha256": protocol.sha256_bytes(
                protocol.canonical_bytes(observation["alignment_histogram"])
            ),
        },
        "process_measurement": timing,
        "claim_boundary": {
            "scope": "candidate-program-first-64-segment-retirement-observation",
            "prefix_only": True,
            "no_extrapolation": True,
            "production_active": False,
            "observer_executable_source_build_claim": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def capture(
    *, observation_path: Path, observer_executable: Path, observer_source: Path,
    candidate_elf: Path, candidate_journal: Path, input_path: Path,
    timing_log: Path, allocator_evidence_path: Path, output: Path, staging: Path,
) -> dict[str, Any]:
    output, staging = output.absolute(), staging.absolute()
    store.require_directory(output.parent, "memcpy evidence parent")
    store.require_directory(staging, "memcpy evidence staging", create=True)
    _observation(observation_path)
    _require(os.access(observer_executable.absolute(), os.X_OK),
             "memcpy observer executable is not executable")
    executable_raw = store.read_regular(
        observer_executable.absolute(), "memcpy observer executable",
    )
    custody = output.with_name(f"{output.stem}.observer-executable")
    store.publish_new_or_identical(custody, executable_raw, staging_directory=staging)
    value = _normalized(
        observation_path=observation_path.absolute(), executable_custody=custody,
        observer_source=observer_source.absolute(), candidate_elf=candidate_elf.absolute(),
        candidate_journal=candidate_journal.absolute(), input_path=input_path.absolute(),
        timing_log=timing_log.absolute(),
        allocator_evidence_path=allocator_evidence_path.absolute(),
    )
    store.publish_new_or_identical(
        output, protocol.canonical_bytes(value), staging_directory=staging,
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "source_observation", "sample",
        "process_measurement", "claim_boundary", "content_sha256",
    }, "memcpy evidence keys differ")
    _require(value["schema"] == EVIDENCE_SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "memcpy evidence authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "observation", "observer_executable_custody", "observer_source",
        "candidate_elf", "candidate_journal", "input", "process_timing_log",
        "allocator_execution_evidence",
    }, "memcpy evidence inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"memcpy evidence {name}")
    expected = _normalized(
        observation_path=Path(inputs["observation"]["path"]),
        executable_custody=Path(inputs["observer_executable_custody"]["path"]),
        observer_source=Path(inputs["observer_source"]["path"]),
        candidate_elf=Path(inputs["candidate_elf"]["path"]),
        candidate_journal=Path(inputs["candidate_journal"]["path"]),
        input_path=Path(inputs["input"]["path"]),
        timing_log=Path(inputs["process_timing_log"]["path"]),
        allocator_evidence_path=Path(inputs["allocator_execution_evidence"]["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "memcpy evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "memcpy evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "memcpy evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("capture")
    for name in (
        "observation", "observer-executable", "observer-source", "candidate-elf",
        "candidate-journal", "input", "timing-log", "allocator-evidence",
        "output", "staging-directory",
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
        capture(
            observation_path=arguments.observation,
            observer_executable=arguments.observer_executable,
            observer_source=arguments.observer_source,
            candidate_elf=arguments.candidate_elf,
            candidate_journal=arguments.candidate_journal,
            input_path=arguments.input,
            timing_log=arguments.timing_log,
            allocator_evidence_path=arguments.allocator_evidence,
            output=arguments.output,
            staging=arguments.staging_directory,
        )
        return 0
    except (
        MemcpyHotspotEvidenceError,
        allocator_evidence.AllocatorExecutionEvidenceError,
        protocol.ProofProtocolError,
        segmented.ContractError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
