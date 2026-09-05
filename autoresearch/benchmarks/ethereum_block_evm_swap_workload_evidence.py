#!/usr/bin/env python3
"""Seal exact SWAP1..16 workload evidence from retained EVM PC custody."""

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

import ethereum_block_evm_micro_op_candidate_matrix_v8 as matrix_v8  # noqa: E402
import ethereum_block_evm_micro_op_census_v7 as census_v7  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.evm-swap-workload-evidence.v1"
STATUS = "exact-swap-workload-diagnostic-nonpromotable"
SWAP_PREFIX = "revm_interpreter::instructions::stack::swap::<"
ENTRY_SCOPE = (
    "retained-cross-symbol-basic-edge-entries;"
    "segment-boundary-transitions-omitted"
)
SWAP_INDICES = tuple(range(1, 17))


class EvmSwapWorkloadEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvmSwapWorkloadEvidenceError(message)


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
    path = path.absolute()
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
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
        f"{where} identity keys differ",
    )
    _integer(value["bytes"], f"{where}.bytes", minimum=1)
    _sha(value["sha256"], f"{where}.sha256")
    _require(value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _swap_index(symbol: Any) -> int:
    _require(type(symbol) is str and symbol.startswith(SWAP_PREFIX),
             "SWAP member symbol prefix differs")
    tail = symbol[len(SWAP_PREFIX):]
    ordinal, separator, remainder = tail.partition(",")
    _require(
        separator == ","
        and ordinal.isascii()
        and ordinal.isdigit()
        and remainder.startswith(" revm_interpreter::interpreter::"),
        "SWAP member instantiation differs",
    )
    index = int(ordinal, 10)
    _require(
        index in SWAP_INDICES and ordinal == str(index),
        "SWAP member index differs",
    )
    return index


def derive_swap(census: dict[str, Any]) -> dict[str, Any]:
    symbols = census.get("symbols") if type(census) is dict else None
    _require(type(symbols) is list and symbols,
             "SWAP source census symbols differ")
    by_index: dict[int, dict[str, Any]] = {}
    for row in symbols:
        symbol = row.get("symbol") if type(row) is dict else None
        if type(symbol) is not str or not symbol.startswith(SWAP_PREFIX):
            continue
        index = _swap_index(symbol)
        _require(index not in by_index, "duplicate SWAP member index")
        _require(
            row.get("category") == "stack"
            and row.get("opcode_group") == "swap",
            "SWAP member category differs",
        )
        rows = _integer(row.get("observed_rows"), "SWAP observed rows", minimum=1)
        entries = _integer(
            row.get("observed_cross_symbol_entries"),
            "SWAP observed entry count",
            minimum=1,
        )
        self_edges = _integer(
            row.get("observed_self_symbol_edges"),
            "SWAP self edges",
        )
        missing = _integer(
            row.get("rows_without_observed_incoming_edge"),
            "SWAP rows without incoming edge",
        )
        _require(rows == entries + self_edges + missing,
                 "SWAP retained edge closure differs")
        exact = rows % entries == 0
        by_index[index] = {
            "exact_integer_rows_per_call_closure": exact,
            "observed_call_count": entries,
            "observed_rows": rows,
            "observed_self_symbol_edges": self_edges,
            "rows_per_call": rows // entries if exact else None,
            "rows_without_observed_incoming_edge": missing,
            "swap_index": index,
            "symbol": symbol,
        }
    _require(tuple(sorted(by_index)) == SWAP_INDICES,
             "SWAP1..16 membership is incomplete")
    members = [by_index[index] for index in SWAP_INDICES]
    exact_members = all(
        member["exact_integer_rows_per_call_closure"] for member in members
    )
    ratios = {
        member["rows_per_call"] for member in members
        if member["rows_per_call"] is not None
    }
    uniform = exact_members and len(ratios) == 1
    uniform_rows = next(iter(ratios)) if uniform else None
    total_calls = sum(member["observed_call_count"] for member in members)
    total_rows = sum(member["observed_rows"] for member in members)
    aggregate = uniform and total_rows == total_calls * uniform_rows
    return {
        "entry_scope": ENTRY_SCOPE,
        "member_order": "swap-index-ascending",
        "members": members,
        "totals": {
            "aggregate_integer_closure": aggregate,
            "all_members_exact_integer_closure": exact_members,
            "member_count": len(members),
            "total_observed_call_count": total_calls,
            "total_observed_rows": total_rows,
            "total_rows_without_observed_incoming_edge": sum(
                member["rows_without_observed_incoming_edge"]
                for member in members
            ),
            "uniform_rows_per_call": uniform_rows,
        },
    }


def _candidate_boundary() -> dict[str, Any]:
    return {
        "candidate_abi": None,
        "candidate_air_geometry": None,
        "candidate_cells": None,
        "candidate_end_to_end_wall_ns": None,
        "candidate_padded_domains": None,
        "candidate_proof": None,
        "candidate_savings": None,
        "fresh_candidate_verification": None,
    }


def _load_observation(identity: dict[str, Any]) -> dict[str, Any]:
    raw = store.read_regular(
        Path(identity["path"]),
        "SWAP PC observation",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "SWAP PC observation is not canonical",
    )
    return value


def build(census_path: Path, matrix_path: Path) -> dict[str, Any]:
    census_path = census_path.absolute()
    matrix_path = matrix_path.absolute()
    census_identity = _identity(census_path, "SWAP census V7")
    matrix_identity = _identity(matrix_path, "SWAP matrix V8")
    census = census_v7.load(census_path)
    matrix = matrix_v8.load(matrix_path)
    _require(
        census["schema"] == census_v7.SCHEMA
        and matrix["schema"] == matrix_v8.SCHEMA
        and census["sample"]["complete_execution"] is True
        and census["sample"]["no_extrapolation"] is True
        and census["claim_boundary"]["production_active"] is False
        and matrix["claim_boundary"]["production_active"] is False,
        "SWAP upstream claim boundary differs",
    )
    pc_identity = census["inputs"]["pc_census_inputs"]["observation"]
    nm_identity = census["inputs"]["pc_census_inputs"]["nm_stdout"]
    _require(
        matrix["inputs"]["prior_census_v7"] == census_identity
        and matrix["inputs"]["pc_observation"] == pc_identity
        and matrix["inputs"]["symbol_map"] == nm_identity,
        "SWAP V7/V8/PC/nm join differs",
    )
    observation = _load_observation(pc_identity)
    recomputed = census_v7.derive(
        observation,
        Path(nm_identity["path"]),
        census["sample"]["segment_count"],
    )
    _require(
        protocol.canonical_bytes(recomputed)
        == protocol.canonical_bytes(census["census"]),
        "SWAP census does not replay from PC/nm authorities",
    )
    workload = derive_swap(recomputed)
    group = next(
        (row for row in recomputed["opcode_groups"]
         if row["category"] == "stack" and row["opcode_group"] == "swap"),
        None,
    )
    totals = workload["totals"]
    _require(
        type(group) is dict
        and group["executed_function_count"] == totals["member_count"]
        and group["observed_rows"] == totals["total_observed_rows"]
        and group["observed_outside_opcode_group_entries"]
        == totals["total_observed_call_count"],
        "SWAP opcode-group aggregate differs",
    )
    stack_candidate = next(
        (row for row in matrix["candidate_matrix"]
         if row["candidate_id"] == "stack-transform-v1"),
        None,
    )
    _require(
        type(stack_candidate) is dict
        and stack_candidate["production_active"] is False
        and stack_candidate["observed_rows"] >= totals["total_observed_rows"],
        "SWAP V8 stack-family authority differs",
    )
    return protocol.seal({
        "candidate_boundary": _candidate_boundary(),
        "no_extrapolation": True,
        "performance_claim_eligible": False,
        "production": False,
        "sample": copy.deepcopy(census["sample"]),
        "schema": SCHEMA,
        "status": STATUS,
        "upstream": {
            "census_v7": census_identity,
            "census_v7_content_sha256": census["content_sha256"],
            "census_v7_inputs": copy.deepcopy(census["inputs"]),
            "matrix_v8": matrix_identity,
            "matrix_v8_content_sha256": matrix["content_sha256"],
            "matrix_v8_inputs": copy.deepcopy(matrix["inputs"]),
            "nm_symbol_map": copy.deepcopy(nm_identity),
            "pc_observation": copy.deepcopy(pc_identity),
        },
        "v8_stack_family": copy.deepcopy(stack_candidate),
        "workload": workload,
    })


def _validate_workload(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {"entry_scope", "member_order", "members", "totals"}
        and value["entry_scope"] == ENTRY_SCOPE
        and value["member_order"] == "swap-index-ascending",
        "SWAP workload authority differs",
    )
    members = value["members"]
    _require(type(members) is list and len(members) == 16,
             "SWAP member count differs")
    for expected_index, member in zip(SWAP_INDICES, members, strict=True):
        _require(
            type(member) is dict
            and set(member) == {
                "exact_integer_rows_per_call_closure",
                "observed_call_count",
                "observed_rows",
                "observed_self_symbol_edges",
                "rows_per_call",
                "rows_without_observed_incoming_edge",
                "swap_index",
                "symbol",
            }
            and member["swap_index"] == expected_index
            and _swap_index(member["symbol"]) == expected_index,
            f"SWAP member {expected_index} differs",
        )
        calls = _integer(
            member["observed_call_count"],
            f"SWAP{expected_index} calls",
            minimum=1,
        )
        rows = _integer(
            member["observed_rows"], f"SWAP{expected_index} rows", minimum=1,
        )
        self_edges = _integer(
            member["observed_self_symbol_edges"],
            f"SWAP{expected_index} self edges",
        )
        missing = _integer(
            member["rows_without_observed_incoming_edge"],
            f"SWAP{expected_index} missing entries",
        )
        exact = rows % calls == 0
        _require(
            rows == calls + self_edges + missing
            and member["exact_integer_rows_per_call_closure"] is exact
            and member["rows_per_call"] == (rows // calls if exact else None),
            f"SWAP{expected_index} integer closure differs",
        )
    expected = derive_swap({"symbols": [
        {
            "category": "stack",
            "observed_cross_symbol_entries": member["observed_call_count"],
            "observed_rows": member["observed_rows"],
            "observed_self_symbol_edges": member[
                "observed_self_symbol_edges"
            ],
            "opcode_group": "swap",
            "rows_without_observed_incoming_edge": member[
                "rows_without_observed_incoming_edge"
            ],
            "symbol": member["symbol"],
        }
        for member in members
    ]})
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "SWAP aggregate workload closure differs",
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {
            "candidate_boundary",
            "content_sha256",
            "no_extrapolation",
            "performance_claim_eligible",
            "production",
            "sample",
            "schema",
            "status",
            "upstream",
            "v8_stack_family",
            "workload",
        },
        "SWAP evidence keys differ",
    )
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["production"] is False
        and value["performance_claim_eligible"] is False
        and value["no_extrapolation"] is True
        and value["content_sha256"] == protocol.content_sha256(value),
        "SWAP evidence authority differs",
    )
    _require(
        type(value["candidate_boundary"]) is dict
        and value["candidate_boundary"] == _candidate_boundary(),
        "SWAP candidate boundary differs",
    )
    upstream = value["upstream"]
    _require(
        type(upstream) is dict
        and set(upstream) == {
            "census_v7",
            "census_v7_content_sha256",
            "census_v7_inputs",
            "matrix_v8",
            "matrix_v8_content_sha256",
            "matrix_v8_inputs",
            "nm_symbol_map",
            "pc_observation",
        },
        "SWAP upstream keys differ",
    )
    census_identity = _validate_identity(upstream["census_v7"], "SWAP census V7")
    matrix_identity = _validate_identity(upstream["matrix_v8"], "SWAP matrix V8")
    _sha(upstream["census_v7_content_sha256"], "SWAP V7 content seal")
    _sha(upstream["matrix_v8_content_sha256"], "SWAP V8 content seal")
    _validate_workload(value["workload"])
    expected = build(
        Path(census_identity["path"]), Path(matrix_identity["path"]),
    )
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "SWAP evidence differs from retained authorities",
    )
    return value


def create(
    *,
    census_path: Path,
    matrix_path: Path,
    output_path: Path,
    staging_directory: Path,
) -> dict[str, Any]:
    value = build(census_path, matrix_path)
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "SWAP evidence parent")
    store.require_directory(staging_directory, "SWAP evidence staging", create=True)
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "SWAP evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "SWAP evidence is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--census-v7", type=Path, required=True)
    create_parser.add_argument("--matrix-v8", type=Path, required=True)
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
                census_path=arguments.census_v7,
                matrix_path=arguments.matrix_v8,
                output_path=arguments.output,
                staging_directory=arguments.staging_directory,
            )
        else:
            value = load(arguments.evidence)
        print(json.dumps({
            "content_sha256": value["content_sha256"],
            "production": value["production"],
            "schema": value["schema"],
            "status": value["status"],
            "total_observed_call_count": value["workload"]["totals"][
                "total_observed_call_count"
            ],
            "total_observed_rows": value["workload"]["totals"][
                "total_observed_rows"
            ],
            "uniform_rows_per_call": value["workload"]["totals"][
                "uniform_rows_per_call"
            ],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (EvmSwapWorkloadEvidenceError, ValueError,
            protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
