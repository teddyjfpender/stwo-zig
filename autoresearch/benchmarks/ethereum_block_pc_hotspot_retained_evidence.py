"""Seal a retained PC-hotspot observation against memcpy execution evidence.

Unlike the live observer wrapper, this adapter does not rerun the guest.  It
reopens and fully validates the retained canonical observation, its exact V3
journal prefix, executable/source identities, and the external time log.  The
timing attachment is diagnostic-only because no child-process receipt was
retained with the raw observation.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_allocator_execution_evidence as allocator_evidence  # noqa: E402
import ethereum_block_memcpy_execution_evidence as execution_evidence  # noqa: E402
import ethereum_block_pc_hotspot_contract as hotspot_contract  # noqa: E402
import ethereum_block_pc_hotspot_evidence as hotspot_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.retained-pc-hotspot-evidence.v1"
STATUS = "retained-prefix-observation-replayed-diagnostic-nonpromotable"
WRAP_RANGE_START = 0x870
WRAP_RANGE_END_EXCLUSIVE = 0xA8C


class RetainedPcHotspotEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RetainedPcHotspotEvidenceError(message)


def _identity(path: Path, where: str, *, allow_empty: bool = False) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or raw, f"{where} is empty")
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": protocol.sha256_bytes(raw),
    }


def _validate_identity(value: Any, where: str,
                       *, allow_empty: bool = False) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(Path(value["path"]), where,
                                    allow_empty=allow_empty),
             f"{where} identity differs")
    return value


def _normalized(
    *, observation_path: Path, executable_path: Path, observer_source_path: Path,
    timing_log_path: Path, execution: dict[str, Any],
    execution_identity: dict[str, Any], first_segment_index: int,
    segment_count: int,
) -> dict[str, Any]:
    _require(execution["schema"] == execution_evidence.SCHEMA,
             "retained PC execution evidence schema differs")
    inputs = execution["inputs"]
    candidate = execution["executions"]["memcpy_candidate"]
    elf = inputs["candidate_elf"]
    input_identity = inputs["common_input"]
    journal = inputs["candidate_journal"]
    executable = _identity(executable_path, "retained PC observer executable")
    observer_source = _identity(
        observer_source_path, "retained PC observer source",
    )
    _require(os.access(executable["path"], os.X_OK),
             "retained PC observer is not executable")
    try:
        sample = hotspot_contract.sample_authority(
            journal_path=Path(journal["path"]), elf=elf,
            input_identity=input_identity,
            first_segment_index=first_segment_index, segment_count=segment_count,
        )
        observation_raw = store.read_regular(
            observation_path.absolute(), "retained PC observation",
            maximum=hotspot_evidence.MAX_OBSERVATION_BYTES,
        )
        observation = hotspot_contract.decode_observation(
            observation_raw, sample=sample, elf=elf,
            input_identity=input_identity, source=journal,
        )
        timing_identity, timing = allocator_evidence._timing(timing_log_path)
    except (
        hotspot_contract.PcHotspotContractError,
        allocator_evidence.AllocatorExecutionEvidenceError,
    ) as error:
        raise RetainedPcHotspotEvidenceError(str(error)) from error
    _require(
        candidate["journal"] == journal
        and candidate["elf_sha256"] == elf["sha256"]
        and candidate["input_sha256"] == input_identity["sha256"]
        and sample["first_segment_index"] == 0
        and 0 < sample["segment_count"] <= candidate["segment_count"]
        and execution["equivalence"]["same_output_bytes_and_sha256"] is True
        and execution["claim_boundary"]["proof_correctness"] is None,
        "retained PC execution/sample join differs",
    )
    per_pc = observation["per_pc"]
    range_rows = sum(
        row["count"] for row in per_pc
        if WRAP_RANGE_START <= row["pc"] < WRAP_RANGE_END_EXCLUSIVE
    )
    entry = next((row for row in per_pc if row["pc"] == WRAP_RANGE_START), None)
    _require(entry is not None and range_rows > 0,
             "retained PC candidate range is absent")
    argv = [
        executable["path"], "--elf", elf["path"], "--input",
        input_identity["path"], "--execution-journal", journal["path"],
        "--first-segment-index", str(first_segment_index),
        "--segment-count", str(segment_count),
    ]
    try:
        hotspot_evidence._require_safe_argv(argv, 58)
    except hotspot_contract.PcHotspotContractError as error:
        raise RetainedPcHotspotEvidenceError(str(error)) from error
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "memcpy_execution_evidence": execution_identity,
            "observation": _identity(
                observation_path, "retained PC observation",
            ),
            "observer_executable": executable,
            "observer_source": observer_source,
            "candidate_elf": copy.deepcopy(elf),
            "candidate_journal": copy.deepcopy(journal),
            "input": copy.deepcopy(input_identity),
            "external_timing_log": timing_identity,
        },
        "argv": argv,
        "sample": sample,
        "observation_content_sha256": observation["content_sha256"],
        "canonical_totals": {
            "retired_instructions": observation["retired_instructions"],
            "per_pc_count_sum": sum(row["count"] for row in per_pc),
            "transition_count": observation["transition_count"],
            "opcode_transition_count_sum": sum(
                row["count"] for row in observation["opcode_transitions"]
            ),
            "basic_edge_count_sum": sum(
                row["count"] for row in observation["basic_edges"]
            ),
            "distinct_pc_count": observation["distinct_pc_count"],
            "distinct_basic_edge_count": observation["distinct_basic_edge_count"],
        },
        "candidate_pc_range_projection": {
            "range_start": WRAP_RANGE_START,
            "range_end_exclusive": WRAP_RANGE_END_EXCLUSIVE,
            "observed_rows": range_rows,
            "entry_pc": WRAP_RANGE_START,
            "entry_count": entry["count"],
            "range_name_authority": "controller-labeled-v5-wrap-range",
            "symbol_map_receipt": None,
        },
        "process_measurement": {
            **timing,
            "scope": "external-time-wrapper-around-retained-observer-argv",
            "argv_process_receipt_retained": False,
            "performance_claim_eligible": False,
        },
        "claim_boundary": {
            "scope": "canonical-contiguous-prefix-retirement-observation-only",
            "prefix_only": True,
            "no_extrapolation": True,
            "production_active": False,
            "candidate_air_complete": None,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def build(
    *, observation_path: Path, executable_path: Path, observer_source_path: Path,
    timing_log_path: Path, execution_evidence_path: Path,
    first_segment_index: int = 0, segment_count: int = 64,
) -> dict[str, Any]:
    execution_evidence_path = execution_evidence_path.absolute()
    execution = execution_evidence.load(execution_evidence_path)
    return _normalized(
        observation_path=observation_path.absolute(),
        executable_path=executable_path.absolute(),
        observer_source_path=observer_source_path.absolute(),
        timing_log_path=timing_log_path.absolute(), execution=execution,
        execution_identity=_identity(
            execution_evidence_path, "memcpy execution evidence",
        ), first_segment_index=first_segment_index, segment_count=segment_count,
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "argv", "sample",
        "observation_content_sha256", "canonical_totals",
        "candidate_pc_range_projection", "process_measurement",
        "claim_boundary", "content_sha256",
    }, "retained PC evidence keys differ")
    _require(value["schema"] == SCHEMA and value["status"] == STATUS
             and value["content_sha256"] == protocol.content_sha256(value),
             "retained PC evidence authority differs")
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "memcpy_execution_evidence", "observation", "observer_executable",
        "observer_source", "candidate_elf", "candidate_journal", "input",
        "external_timing_log",
    }, "retained PC evidence inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"retained PC {name}")
    expected = build(
        observation_path=Path(inputs["observation"]["path"]),
        executable_path=Path(inputs["observer_executable"]["path"]),
        observer_source_path=Path(inputs["observer_source"]["path"]),
        timing_log_path=Path(inputs["external_timing_log"]["path"]),
        execution_evidence_path=Path(inputs["memcpy_execution_evidence"]["path"]),
        first_segment_index=value["sample"]["first_segment_index"],
        segment_count=value["sample"]["segment_count"],
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "retained PC evidence replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "retained PC evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "retained PC evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "observation", "observer-executable", "observer-source", "timing-log",
        "execution-evidence", "output", "staging-directory",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)
    create.add_argument("--first-segment-index", type=int, default=0)
    create.add_argument("--segment-count", type=int, default=64)
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
        store.require_directory(output.parent, "retained PC evidence parent")
        store.require_directory(staging, "retained PC staging", create=True)
        value = build(
            observation_path=arguments.observation,
            executable_path=arguments.observer_executable,
            observer_source_path=arguments.observer_source,
            timing_log_path=arguments.timing_log,
            execution_evidence_path=arguments.execution_evidence,
            first_segment_index=arguments.first_segment_index,
            segment_count=arguments.segment_count,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        RetainedPcHotspotEvidenceError,
        execution_evidence.MemcpyExecutionEvidenceError,
        hotspot_contract.PcHotspotContractError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
