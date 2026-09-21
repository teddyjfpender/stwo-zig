#!/usr/bin/env python3
"""Seal compact exact analyze_legacy quantities without an AIR savings claim."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARKS = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARKS)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_analyze_legacy_semantic_evidence as semantic_v1  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.analyze-legacy-opportunity-diagnostic.v1"
STATUS = "exact-observed-quantities-no-candidate-compiler"
IDENTITY_FIELDS = (
    "elf",
    "execution_journal",
    "function_value_evidence",
    "input",
    "nm_map",
    "observer_executable",
    "observer_semantics_source",
    "observer_source",
    "observer_witness_source",
    "pc_observation",
    "revm_cargo_lock",
    "revm_source",
)
METRICS = (
    ("input_length_bytes", "length", "length_sum"),
    ("scan_iterations", "scan_iterations", "scan_iterations_sum"),
    ("bitmap_bytes", "bitmap_bytes", "bitmap_bytes_sum"),
    ("push_count", "push_count", "push_count_sum"),
    ("jumpdest_count", "jumpdest_count", "jumpdest_count_sum"),
    ("push_overflow", "push_overflow", "push_overflow_sum"),
    (
        "eof_immediate_padding",
        "eof_immediate_padding",
        "eof_immediate_padding_sum",
    ),
    ("total_padding", "total_padding", "total_padding_sum"),
)


class AnalyzeLegacyOpportunityError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalyzeLegacyOpportunityError(message)


def _integer(value: Any, where: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _sha(value: Any, where: str) -> str:
    _require(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{where} differs",
    )
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.resolve(strict=True)
    raw = store.read_regular(path, where)
    _require(raw, f"{where} is empty")
    return {
        "bytes": len(raw),
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {"bytes", "path", "sha256"}
        and type(value["path"]) is str
        and Path(value["path"]).is_absolute(),
        f"{where} identity shape differs",
    )
    _integer(value["bytes"], f"{where}.bytes", minimum=1)
    _sha(value["sha256"], f"{where}.sha256")
    _require(value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _histogram(values: list[int]) -> list[dict[str, int]]:
    counts: dict[int, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return [
        {"call_count": counts[value], "value": value}
        for value in sorted(counts)
    ]


def _metric(calls: list[dict[str, Any]], field: str) -> dict[str, Any]:
    values = [
        _integer(call.get(field), f"analyze_legacy call {field}")
        for call in calls
    ]
    _require(values, f"analyze_legacy {field} values are absent")
    return {
        "histogram": _histogram(values),
        "maximum": max(values),
        "minimum": min(values),
        "sum": sum(values),
    }


def _claim_boundary() -> dict[str, Any]:
    return {
        "candidate_air_columns": None,
        "candidate_compiler_artifact": None,
        "candidate_end_to_end_wall_ns": None,
        "candidate_padded_cells": None,
        "candidate_padded_domains": None,
        "candidate_proof": None,
        "candidate_savings": None,
        "fresh_candidate_verification": None,
        "gain_multiplication_allowed": False,
        "performance_claim_eligible": False,
        "production_active": False,
    }


def summarize(observation: dict[str, Any]) -> dict[str, Any]:
    calls = observation.get("calls") if type(observation) is dict else None
    aggregate = observation.get("aggregate") if type(observation) is dict else None
    function = observation.get("function_authority") if type(observation) is dict else None
    inventory = observation.get("witness_code_inventory") if type(observation) is dict else None
    _require(
        type(calls) is list
        and calls
        and type(aggregate) is dict
        and type(function) is dict
        and type(inventory) is dict,
        "analyze_legacy observation summary inputs differ",
    )
    call_count = _integer(aggregate.get("call_count"), "call count", minimum=1)
    _require(len(calls) == call_count, "analyze_legacy call count closure differs")
    metrics = {}
    for name, field, aggregate_field in METRICS:
        metric = _metric(calls, field)
        _require(
            metric["sum"]
            == _integer(aggregate.get(aggregate_field), aggregate_field),
            f"analyze_legacy {name} aggregate differs",
        )
        metrics[name] = metric
    opcode_position_count = sum(
        len(call.get("opcode_positions", ())) for call in calls
    )
    _require(
        opcode_position_count == metrics["scan_iterations"]["sum"],
        "analyze_legacy opcode-position count differs",
    )
    opcode_position_index_sum = sum(
        sum(
            _integer(position, "opcode position")
            for position in call["opcode_positions"]
        )
        for call in calls
    )
    _require(
        opcode_position_index_sum
        == _integer(aggregate.get("opcode_positions_sum"), "opcode position sum"),
        "analyze_legacy opcode-position sum differs",
    )
    witness_indices = [
        _integer(call.get("witness_code_index"), "witness code index")
        for call in calls
    ]
    _require(
        len(set(witness_indices))
        == _integer(inventory.get("accessed_legacy_code_count"), "accessed codes")
        == call_count,
        "analyze_legacy call/code bijection differs",
    )
    symbol_rows = _integer(function.get("symbol_rows"), "function symbol rows", minimum=1)
    source_chain = _sha(
        aggregate.get("source_bytes_chain_sha256"), "source byte chain",
    )
    return {
        "call_authority": {
            "call_count": call_count,
            "distinct_accessed_witness_code_count": len(set(witness_indices)),
            "opcode_position_count": opcode_position_count,
            "opcode_position_index_sum": opcode_position_index_sum,
            "source_bytes_chain_sha256": source_chain,
        },
        "function_rows": {
            "observed_symbol_rows": symbol_rows,
            "rows_per_observed_call": {
                "denominator_observed_calls": call_count,
                "numerator_rows": symbol_rows,
                "scaled_million_floor": symbol_rows * 1_000_000 // call_count,
            },
        },
        "metrics": metrics,
        "routing": copy.deepcopy(inventory),
    }


def build(observation_path: Path) -> dict[str, Any]:
    observation_path = observation_path.resolve(strict=True)
    identity = _identity(observation_path, "analyze_legacy semantic observation")
    observation = semantic_v1.load(observation_path)
    _require(
        observation["schema"] == semantic_v1.SCHEMA
        and observation["production"] is False
        and observation["promotion"]["performance_claim_eligible"] is False
        and observation["promotion"]["proof_correctness"] is None
        and observation["promotion"]["end_to_end_wall_ns"] is None,
        "analyze_legacy source claim boundary differs",
    )
    authorities = {
        name: copy.deepcopy(observation[name]) for name in IDENTITY_FIELDS
    }
    return protocol.seal({
        "claim_boundary": _claim_boundary(),
        "exact_observation": summarize(observation),
        "inputs": {
            "authorities": authorities,
            "semantic_observation": identity,
            "semantic_observation_content_sha256": observation["content_sha256"],
        },
        "production": False,
        "sample": {
            "clock_frame": observation["clock_frame"],
            "execution_profile": observation["execution_profile"],
            "first_global_cycle": observation["first_global_cycle"],
            "first_segment_index": observation["first_segment_index"],
            "no_extrapolation": True,
            "retired_instructions": observation["retired_instructions"],
            "sampled_cycles": observation["sampled_cycles"],
            "segment_count": observation["segment_count"],
        },
        "schema": SCHEMA,
        "status": STATUS,
    })


def _validate_metric(value: Any, where: str, call_count: int) -> None:
    _require(
        type(value) is dict
        and set(value) == {"histogram", "maximum", "minimum", "sum"},
        f"{where} shape differs",
    )
    minimum = _integer(value["minimum"], f"{where}.minimum")
    maximum = _integer(value["maximum"], f"{where}.maximum")
    total = _integer(value["sum"], f"{where}.sum")
    histogram = value["histogram"]
    _require(type(histogram) is list and histogram, f"{where} histogram differs")
    previous = -1
    count_sum = weighted_sum = 0
    for row in histogram:
        _require(
            type(row) is dict and set(row) == {"call_count", "value"},
            f"{where} histogram row differs",
        )
        observed = _integer(row["value"], f"{where} value")
        count = _integer(row["call_count"], f"{where} count", minimum=1)
        _require(observed > previous, f"{where} histogram order differs")
        previous = observed
        count_sum += count
        weighted_sum += count * observed
    _require(
        histogram[0]["value"] == minimum
        and histogram[-1]["value"] == maximum
        and count_sum == call_count
        and weighted_sum == total,
        f"{where} histogram closure differs",
    )


def _validate_summary(value: Any) -> None:
    _require(
        type(value) is dict
        and set(value) == {
            "call_authority", "function_rows", "metrics", "routing",
        },
        "analyze_legacy exact summary shape differs",
    )
    calls = value["call_authority"]
    _require(
        type(calls) is dict
        and set(calls) == {
            "call_count", "distinct_accessed_witness_code_count",
            "opcode_position_count", "opcode_position_index_sum",
            "source_bytes_chain_sha256",
        },
        "analyze_legacy call authority differs",
    )
    call_count = _integer(calls["call_count"], "call count", minimum=1)
    _require(
        _integer(
            calls["distinct_accessed_witness_code_count"], "distinct codes",
            minimum=1,
        ) == call_count
        and _integer(calls["opcode_position_count"], "opcode position count") > 0,
        "analyze_legacy call/code closure differs",
    )
    _integer(calls["opcode_position_index_sum"], "opcode position sum")
    _sha(calls["source_bytes_chain_sha256"], "source byte chain")
    metrics = value["metrics"]
    _require(
        type(metrics) is dict
        and set(metrics) == {name for name, _, _ in METRICS},
        "analyze_legacy metric order differs",
    )
    for name, _, _ in METRICS:
        _validate_metric(metrics[name], name, call_count)
    _require(
        calls["opcode_position_count"] == metrics["scan_iterations"]["sum"],
        "analyze_legacy scan/opcode-position closure differs",
    )
    function = value["function_rows"]
    _require(
        type(function) is dict
        and set(function) == {"observed_symbol_rows", "rows_per_observed_call"},
        "analyze_legacy function row shape differs",
    )
    symbol_rows = _integer(
        function["observed_symbol_rows"], "symbol rows", minimum=1,
    )
    ratio = function["rows_per_observed_call"]
    _require(
        type(ratio) is dict
        and ratio == {
            "denominator_observed_calls": call_count,
            "numerator_rows": symbol_rows,
            "scaled_million_floor": symbol_rows * 1_000_000 // call_count,
        },
        "analyze_legacy rows/call ratio differs",
    )
    routing = value["routing"]
    _require(
        type(routing) is dict
        and routing.get("accessed_legacy_code_count") == call_count
        and routing.get("legacy_code_count") == call_count
        and routing.get("unobserved_fallback_code_count") == 5
        and routing.get("code_count") == call_count + 5,
        "analyze_legacy routing closure differs",
    )


def validate(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {
            "claim_boundary", "content_sha256", "exact_observation", "inputs",
            "production", "sample", "schema", "status",
        },
        "analyze_legacy opportunity keys differ",
    )
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["production"] is False
        and value["claim_boundary"] == _claim_boundary()
        and value["content_sha256"] == protocol.content_sha256(value),
        "analyze_legacy opportunity authority differs",
    )
    sample = value["sample"]
    _require(
        type(sample) is dict
        and sample.get("no_extrapolation") is True
        and type(sample.get("execution_profile")) is str
        and type(sample.get("clock_frame")) is str,
        "analyze_legacy sample differs",
    )
    for field in (
        "first_global_cycle", "first_segment_index", "retired_instructions",
        "sampled_cycles", "segment_count",
    ):
        _integer(sample.get(field), f"sample {field}")
    inputs = value["inputs"]
    _require(
        type(inputs) is dict
        and set(inputs) == {
            "authorities", "semantic_observation",
            "semantic_observation_content_sha256",
        }
        and type(inputs["authorities"]) is dict
        and tuple(inputs["authorities"]) == IDENTITY_FIELDS,
        "analyze_legacy opportunity inputs differ",
    )
    observation_identity = _validate_identity(
        inputs["semantic_observation"], "analyze_legacy semantic observation",
    )
    for name, identity in inputs["authorities"].items():
        _validate_identity(identity, f"analyze_legacy authority {name}")
    _sha(
        inputs["semantic_observation_content_sha256"],
        "semantic observation content seal",
    )
    _validate_summary(value["exact_observation"])
    expected = build(Path(observation_identity["path"]))
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "analyze_legacy opportunity differs from retained observation",
    )
    return value


def create(
    *, observation_path: Path, output_path: Path, staging_directory: Path,
) -> dict[str, Any]:
    value = build(observation_path)
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "analyze_legacy opportunity parent")
    store.require_directory(
        staging_directory, "analyze_legacy opportunity staging", create=True,
    )
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "analyze_legacy opportunity", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "analyze_legacy opportunity is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--semantic-observation", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--staging-directory", type=Path, required=True)
    replay_parser = commands.add_parser("replay")
    replay_parser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create":
            value = create(
                observation_path=arguments.semantic_observation,
                output_path=arguments.output,
                staging_directory=arguments.staging_directory,
            )
        else:
            value = load(arguments.evidence)
        exact = value["exact_observation"]
        print(json.dumps({
            "bitmap_bytes_sum": exact["metrics"]["bitmap_bytes"]["sum"],
            "call_count": exact["call_authority"]["call_count"],
            "content_sha256": value["content_sha256"],
            "input_length_bytes_sum": exact["metrics"]["input_length_bytes"]["sum"],
            "production": value["production"],
            "scan_iterations_sum": exact["metrics"]["scan_iterations"]["sum"],
            "schema": value["schema"],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (AnalyzeLegacyOpportunityError, ValueError,
            protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
