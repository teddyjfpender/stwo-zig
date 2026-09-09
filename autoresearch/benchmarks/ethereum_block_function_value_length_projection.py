#!/usr/bin/env python3
"""Project exact length-shape diagnostics from function-value observations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
import ethereum_block_function_value_contract as value_contract  # noqa: E402
import ethereum_block_function_value_evidence as value_evidence  # noqa: E402


SCHEMA = "stwo.riscv.function-load-value-length-projection.v1"
STATUS = "projected-diagnostic-only"
CLAIM_BOUNDARY = "observed-function-load-values-only-no-air-or-proof"
QUANTILE_METHOD = "nearest-rank-observed-values-v1"
QUANTILE_BASIS_POINTS = (0, 2500, 5000, 7500, 9000, 9500, 9900, 10000)
U64_MAX = (1 << 64) - 1


class FunctionValueLengthProjectionError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FunctionValueLengthProjectionError(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    _require(raw, f"{where} is empty")
    return {
        "bytes": len(raw),
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _quantiles(histogram: list[dict[str, Any]], count: int) -> list[dict[str, int]]:
    result = []
    for basis_points in QUANTILE_BASIS_POINTS:
        rank = max(1, (basis_points * count + 9999) // 10000)
        cumulative = 0
        selected = None
        for row in histogram:
            cumulative += row["count"]
            if cumulative >= rank:
                selected = row["value"]
                break
        _require(selected is not None,
                 "function-value quantile rank exceeds histogram")
        result.append({
            "basis_points": basis_points,
            "rank_one_based": rank,
            "value_bytes": selected,
        })
    return result


def _observed(observation: dict[str, Any]) -> dict[str, Any]:
    histogram = observation["histogram"]
    call_count = observation["value_count"]
    _require(
        observation["pending_entry_count"] == 0
        and observation["entry_count"] == call_count,
        "function-value source has an unclosed call",
    )
    padded_words = sum(
        row["count"] * ((row["value"] + 3) // 4) for row in histogram
    )
    bitmap_bytes = sum(
        row["count"] * ((row["value"] + 7) // 8) for row in histogram
    )
    output_words = sum(
        row["count"] * ((((row["value"] + 7) // 8) + 3) // 4)
        for row in histogram
    )
    _require(
        max(
            observation["value_sum"], padded_words, bitmap_bytes, output_words,
        ) <= U64_MAX,
        "function-value derived total overflows u64",
    )
    return {
        "call_count": call_count,
        "four_byte_lane_padded_input_word_count": padded_words,
        "jump_bitmap_byte_count": bitmap_bytes,
        "jump_bitmap_output_word_count": output_words,
        "length_histogram": histogram,
        "length_quantiles": _quantiles(histogram, call_count),
        "quantile_method": QUANTILE_METHOD,
        "total_input_bytes": observation["value_sum"],
    }


def _candidate_boundary() -> dict[str, Any]:
    return {
        "air_constraints": None,
        "air_interaction_columns": None,
        "air_main_columns": None,
        "candidate_schema": None,
        "cell_savings": None,
        "committed_cells": None,
        "end_to_end_wall_ns": None,
        "fresh_verification": None,
        "padded_domains": None,
        "proof_correctness": None,
    }


def _project(
    source: dict[str, Any], source_identity: dict[str, Any],
) -> dict[str, Any]:
    observation = source["observation"]
    return protocol.seal({
        "candidate_boundary": _candidate_boundary(),
        "claim_boundary": CLAIM_BOUNDARY,
        "derivation": {
            "four_byte_lane_padded_input_word_count": (
                "sum(count*ceil(length_bytes/4))"
            ),
            "jump_bitmap_byte_count": "sum(count*ceil(length_bytes/8))",
            "jump_bitmap_output_word_count": (
                "sum(count*ceil(ceil(length_bytes/8)/4))"
            ),
        },
        "function_authority": {
            "entry_instruction_word": observation["entry_instruction_word"],
            "entry_pc": observation["entry_pc"],
            "value_imm": observation["value_imm"],
            "value_instruction_word": observation["value_instruction_word"],
            "value_pc": observation["value_pc"],
            "value_rd": observation["value_rd"],
            "value_rs1": observation["value_rs1"],
            "value_source": observation["value_source"],
        },
        "no_extrapolation": True,
        "observed": _observed(observation),
        "performance_claim_eligible": False,
        "production": False,
        "sample": source["sample"],
        "schema": SCHEMA,
        "source_custody": {
            "elf": source["elf"],
            "execution_journal": source["execution_journal"],
            "input": source["input"],
            "observer_executable": source["observer_executable"],
            "observer_source": source["observer_source"],
            "raw_observation": source["raw_observation"],
        },
        "source_evidence": source_identity,
        "source_evidence_content_sha256": source["content_sha256"],
        "source_observation_content_sha256": observation["content_sha256"],
        "status": STATUS,
    })


def validate(value: Any) -> dict[str, Any]:
    expected_keys = {
        "candidate_boundary",
        "claim_boundary",
        "content_sha256",
        "derivation",
        "function_authority",
        "no_extrapolation",
        "observed",
        "performance_claim_eligible",
        "production",
        "sample",
        "schema",
        "source_custody",
        "source_evidence",
        "source_evidence_content_sha256",
        "source_observation_content_sha256",
        "status",
    }
    _require(type(value) is dict and set(value) == expected_keys,
             "function-value length projection keys differ")
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["claim_boundary"] == CLAIM_BOUNDARY
        and value["production"] is False
        and value["performance_claim_eligible"] is False
        and value["no_extrapolation"] is True
        and value["content_sha256"] == protocol.content_sha256(value),
        "function-value length projection authority differs",
    )
    source_identity = value["source_evidence"]
    _require(
        type(source_identity) is dict
        and set(source_identity) == {"bytes", "path", "sha256"}
        and type(source_identity["path"]) is str
        and Path(source_identity["path"]).is_absolute(),
        "function-value source evidence identity differs",
    )
    actual_identity = _identity(
        Path(source_identity["path"]), "function-value source evidence",
    )
    _require(source_identity == actual_identity,
             "function-value source evidence custody differs")
    try:
        source = value_evidence.load(Path(source_identity["path"]))
    except (value_contract.FunctionValueContractError,
            protocol.ProofProtocolError) as error:
        raise FunctionValueLengthProjectionError(
            "function-value source evidence replay failed"
        ) from error
    expected = _project(source, actual_identity)
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "function-value length projection differs from source",
    )
    return value


def create(
    *,
    source_evidence_path: Path,
    output_path: Path,
    staging_directory: Path,
) -> dict[str, Any]:
    source_evidence_path = source_evidence_path.absolute()
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    source_identity = _identity(
        source_evidence_path, "function-value source evidence",
    )
    source = value_evidence.load(source_evidence_path)
    value = _project(source, source_identity)
    validate(value)
    store.require_directory(output_path.parent, "function-value projection parent")
    store.require_directory(staging_directory, "function-value projection staging", create=True)
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(),
        "function-value length projection",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "function-value length projection is not canonical JSON",
    )
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or replay an exact function-value length projection",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--source-evidence", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--staging", type=Path, required=True)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create":
            value = create(
                source_evidence_path=arguments.source_evidence,
                output_path=arguments.output,
                staging_directory=arguments.staging,
            )
        else:
            value = load(arguments.evidence)
        print(json.dumps({
            "call_count": value["observed"]["call_count"],
            "content_sha256": value["content_sha256"],
            "performance_claim_eligible": value["performance_claim_eligible"],
            "production": value["production"],
            "schema": value["schema"],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (FunctionValueLengthProjectionError,
            value_contract.FunctionValueContractError,
            protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
