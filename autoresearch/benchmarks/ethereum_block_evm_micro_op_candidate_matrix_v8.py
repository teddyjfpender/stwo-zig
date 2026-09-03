"""Rank exact retained EVM micro-op opportunities without candidate estimates.

V8 reopens the sealed V7 function census and recomputes every candidate-group
boundary from the retained PC edge list.  In particular, arithmetic and
bitwise symbols form one word-ALU group, so edges between those categories are
internal rather than a sum of two independently counted boundaries.  The
matrix reports observed one-row-dispatch upper bounds only; no implementation,
cell saving, proof, fresh verification, or E2E estimate is admitted.
"""

from __future__ import annotations

import argparse
import bisect
import copy
from pathlib import Path
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_ecrecover_pc_census_evidence as recover_pc  # noqa: E402
import ethereum_block_evm_micro_op_census_v7 as census_v7  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.evm-micro-op-candidate-matrix.v8"
STATUS = "exact-dispatch-opportunity-matrix-diagnostic-nonpromotable"
MEMBERSHIP_DOMAIN = b"stwo-zig/evm-micro-op-candidate-membership/v1\x00"
SELECTED_COUNT = 3

# This is an explicit semantic partition, not a learned grouping.  The first
# tranche is chosen only after exact rows are recomputed for every disjoint row.
FAMILY_SPECS = (
    ("stack-transform-v1", ("stack",), "typed-air"),
    ("word-alu-v1", ("arithmetic", "bitwise"), "typed-air"),
    ("memory-word-and-copy-v1", ("memory",), "typed-air"),
    ("control-flow-v1", ("control",), "typed-air"),
    ("system-context-v1", ("system",), "typed-air-or-precompile-undecided"),
    ("host-state-v1", ("host",), "typed-air-or-precompile-undecided"),
    ("contract-call-v1", ("contract",), "typed-air-or-precompile-undecided"),
    ("transaction-context-v1", ("tx_info",), "typed-air"),
    ("block-context-v1", ("block_info",), "typed-air"),
)


class EvmMicroOpCandidateMatrixV8Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvmMicroOpCandidateMatrixV8Error(message)


def _integer(value: Any, where: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


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


def _ratio(numerator: int, denominator: int) -> dict[str, Any] | None:
    if denominator == 0:
        return None
    return {
        "numerator": numerator,
        "denominator": denominator,
        "scaled_million_floor": numerator * 1_000_000 // denominator,
    }


def _membership_identity(
    candidate_id: str, categories: tuple[str, ...], symbols: list[str],
) -> str:
    payload = {
        "candidate_id": candidate_id,
        "categories": list(categories),
        "symbols": symbols,
    }
    return protocol.sha256_bytes(
        MEMBERSHIP_DOMAIN + protocol.canonical_bytes(payload),
    )


def _required_semantics(candidate_id: str) -> dict[str, str]:
    common = {
        "program_counter": "exact-opcode-length-and-control-transition",
        "gas": "exact-base-dynamic-refund-and-out-of-gas-semantics",
        "stack": "exact-read-write-height-underflow-and-overflow",
        "exceptions": "exact-success-revert-halt-and-error-semantics",
    }
    if candidate_id == "memory-word-and-copy-v1":
        common["memory"] = "exact-address-size-expansion-copy-and-memory-bus"
    else:
        common["memory"] = "prove-no-memory-effect"
    if candidate_id in {
        "system-context-v1", "host-state-v1", "contract-call-v1",
        "transaction-context-v1", "block-context-v1",
    }:
        common["host_context"] = "exact-context-read-write-and-access-status"
    else:
        common["host_context"] = "prove-no-host-context-effect"
    return common


def _mapped_edges(
    observation: dict[str, Any], symbol_map_path: Path,
) -> list[tuple[str, str, int]]:
    symbols = recover_pc._parse_symbols(store.read_regular(
        symbol_map_path, "EVM candidate matrix symbol map",
        maximum=recover_pc.MAX_NM_BYTES,
    ))
    addresses = [address for address, _ in symbols]

    def name(pc: Any, where: str) -> str:
        value = _integer(pc, where)
        index = bisect.bisect_right(addresses, value) - 1
        _require(index >= 0, f"{where} has no preceding symbol")
        return symbols[index][1]

    return [
        (
            name(edge["from_pc"], "candidate edge source PC"),
            name(edge["to_pc"], "candidate edge target PC"),
            _integer(edge["count"], "candidate edge count", minimum=1),
        )
        for edge in observation["basic_edges"]
    ]


def _candidate(
    candidate_id: str, categories: tuple[str, ...], research_kind: str,
    symbols: list[dict[str, Any]], opcode_groups: list[dict[str, Any]],
    category_groups: list[dict[str, Any]], edges: list[tuple[str, str, int]],
    total_module_rows: int,
) -> dict[str, Any]:
    members = [row for row in symbols if row["category"] in categories]
    _require(members, f"candidate {candidate_id} has no member symbols")
    member_names = sorted(row["symbol"] for row in members)
    member_set = set(member_names)
    observed_rows = sum(row["observed_rows"] for row in members)
    self_edges = sum(
        count for source, target, count in edges
        if source == target and target in member_set
    )
    internal_cross_edges = sum(
        count for source, target, count in edges
        if source in member_set and target in member_set and source != target
    )
    outside_entries = sum(
        count for source, target, count in edges
        if target in member_set and source not in member_set
    )
    missing_incoming = (
        observed_rows - self_edges - internal_cross_edges - outside_entries
    )
    _require(
        0 <= missing_incoming <= 31,
        f"candidate {candidate_id} edge closure differs",
    )
    member_opcode_groups = [
        copy.deepcopy(row) for row in opcode_groups
        if row["category"] in categories
    ]
    member_category_groups = [
        copy.deepcopy(row) for row in category_groups
        if row["category"] in categories
    ]
    return {
        "candidate_id": candidate_id,
        "member_categories": list(categories),
        "member_symbol_count": len(members),
        "member_opcode_group_count": len(member_opcode_groups),
        "membership_identity_sha256": _membership_identity(
            candidate_id, categories, member_names,
        ),
        "member_category_breakdown": member_category_groups,
        "member_opcode_group_breakdown": member_opcode_groups,
        "research_family_kind": research_kind,
        "observed_rows": observed_rows,
        "observed_outside_candidate_entries": outside_entries,
        "observed_internal_cross_symbol_edges": internal_cross_edges,
        "observed_self_symbol_edges": self_edges,
        "rows_without_observed_incoming_edge": missing_incoming,
        "rows_per_observed_outside_entry": _ratio(
            observed_rows, outside_entries,
        ),
        "self_loop_concentration": _ratio(self_edges, observed_rows),
        "dispatch_share": _ratio(observed_rows, total_module_rows),
        "observed_one_row_dispatch_upper_bound_removable_rows": (
            observed_rows - outside_entries
        ),
        "upper_bound_scope": (
            "observed-rows-minus-recomputed-outside-group-entries;"
            "not-a-candidate-saving-estimate"
        ),
        "unobserved_boundary_entry_upper_bound": missing_incoming,
        "required_semantics": _required_semantics(candidate_id),
        "candidate_implementation_identity": None,
        "candidate_active_rows": None,
        "candidate_padded_rows": None,
        "candidate_main_columns": None,
        "candidate_main_cells": None,
        "candidate_saved_execution_rows": None,
        "candidate_saved_main_cells": None,
        "candidate_proof_identity": None,
        "fresh_candidate_verification": None,
        "candidate_end_to_end_wall_ns": None,
        "production_active": False,
    }


def build(prior_path: Path) -> dict[str, Any]:
    prior_path = prior_path.absolute()
    prior = census_v7.load(prior_path)
    _require(
        prior["schema"] == census_v7.SCHEMA
        and prior["sample"]["complete_execution"] is True
        and prior["sample"]["no_extrapolation"] is True
        and prior["claim_boundary"]["production_active"] is False,
        "EVM candidate matrix V7 boundary differs",
    )
    observation_identity = prior["inputs"]["pc_census_inputs"]["observation"]
    symbol_map_identity = prior["inputs"]["pc_census_inputs"]["nm_stdout"]
    observation_raw = store.read_regular(
        Path(observation_identity["path"]), "EVM candidate matrix observation",
        maximum=store.MAX_JSON_BYTES,
    )
    observation = store.decode_strict(observation_raw)
    _require(
        type(observation) is dict
        and observation_raw == protocol.canonical_bytes(observation),
        "EVM candidate matrix observation is not canonical",
    )
    edges = _mapped_edges(observation, Path(symbol_map_identity["path"]))
    census = prior["census"]
    total_rows = census["totals"]["observed_rows"]
    candidates = [
        _candidate(
            candidate_id, categories, research_kind,
            census["symbols"], census["opcode_groups"],
            census["category_groups"], edges, total_rows,
        )
        for candidate_id, categories, research_kind in FAMILY_SPECS
    ]
    candidates.sort(key=lambda row: (-row["observed_rows"], row["candidate_id"]))
    for rank, candidate in enumerate(candidates, start=1):
        candidate["priority_rank"] = rank
        candidate["selected_for_first_tranche"] = rank <= SELECTED_COUNT
    selected = candidates[:SELECTED_COUNT]
    selected_rows = sum(row["observed_rows"] for row in selected)
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "prior_census_v7": _identity(prior_path, "prior EVM census V7"),
            "prior_v7_inputs": copy.deepcopy(prior["inputs"]),
            "pc_observation": copy.deepcopy(observation_identity),
            "symbol_map": copy.deepcopy(symbol_map_identity),
        },
        "partition_authority": {
            "scope": "fixed-disjoint-semantic-partition-v1",
            "families": [
                {
                    "candidate_id": candidate_id,
                    "member_categories": list(categories),
                    "research_family_kind": research_kind,
                }
                for candidate_id, categories, research_kind in FAMILY_SPECS
            ],
            "categories_are_disjoint_and_complete": True,
            "word_alu_boundary_recomputed_from_edges": True,
        },
        "candidate_matrix": candidates,
        "ranking": {
            "objective": "maximum-exact-observed-rows-under-fixed-three-family-cap",
            "tie_break": "candidate-id-ascending",
            "selected_count": SELECTED_COUNT,
            "selected_candidate_ids": [row["candidate_id"] for row in selected],
            "selected_observed_rows": selected_rows,
            "module_observed_row_denominator": total_rows,
            "selected_dispatch_share": _ratio(selected_rows, total_rows),
            "residual_unselected_observed_rows": total_rows - selected_rows,
            "independent_gain_multiplication_used": False,
            "selected_candidate_saved_execution_rows": None,
            "selected_candidate_saved_main_cells": None,
            "selected_candidate_end_to_end_wall_ns": None,
        },
        "claim_boundary": {
            "candidate_implementations_available": False,
            "candidate_cells_available": False,
            "proof_correctness": None,
            "fresh_proof_verification": None,
            "measured_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_active": False,
        },
    })


def _validate_ratio(value: Any, numerator: int, denominator: int, where: str) -> None:
    _require(value == _ratio(numerator, denominator), f"{where} ratio differs")


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "partition_authority",
        "candidate_matrix", "ranking", "claim_boundary", "content_sha256",
    }, "EVM candidate matrix keys differ")
    _require(
        value["schema"] == SCHEMA and value["status"] == STATUS
        and value["content_sha256"] == protocol.content_sha256(value),
        "EVM candidate matrix authority differs",
    )
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "prior_census_v7", "prior_v7_inputs", "pc_observation", "symbol_map",
    }, "EVM candidate matrix inputs differ")
    _validate_identity(inputs["prior_census_v7"], "EVM matrix prior V7")
    _validate_identity(inputs["pc_observation"], "EVM matrix observation")
    _validate_identity(inputs["symbol_map"], "EVM matrix symbol map")

    candidates = value["candidate_matrix"]
    _require(type(candidates) is list and len(candidates) == len(FAMILY_SPECS),
             "EVM candidate matrix rows differ")
    for rank, candidate in enumerate(candidates, start=1):
        _require(
            type(candidate) is dict and candidate["priority_rank"] == rank
            and candidate["selected_for_first_tranche"]
            is (rank <= SELECTED_COUNT)
            and candidate["production_active"] is False,
            f"EVM candidate rank {rank} differs",
        )
        rows = _integer(
            candidate["observed_rows"], f"EVM candidate {rank} rows", minimum=1,
        )
        entries = _integer(
            candidate["observed_outside_candidate_entries"],
            f"EVM candidate {rank} entries", minimum=1,
        )
        self_edges = _integer(
            candidate["observed_self_symbol_edges"],
            f"EVM candidate {rank} self edges",
        )
        _validate_ratio(
            candidate["rows_per_observed_outside_entry"], rows, entries,
            f"EVM candidate {rank} rows/entry",
        )
        _validate_ratio(
            candidate["self_loop_concentration"], self_edges, rows,
            f"EVM candidate {rank} self concentration",
        )
        _require(
            candidate["observed_one_row_dispatch_upper_bound_removable_rows"]
            == rows - entries,
            f"EVM candidate {rank} removable-row bound differs",
        )
        for name in (
            "candidate_implementation_identity", "candidate_active_rows",
            "candidate_padded_rows", "candidate_main_columns",
            "candidate_main_cells", "candidate_saved_execution_rows",
            "candidate_saved_main_cells", "candidate_proof_identity",
            "fresh_candidate_verification", "candidate_end_to_end_wall_ns",
        ):
            _require(candidate[name] is None,
                     f"EVM candidate {rank} {name} is available")

    ranking = value["ranking"]
    _require(
        ranking["selected_count"] == SELECTED_COUNT
        and ranking["selected_candidate_ids"]
        == [row["candidate_id"] for row in candidates[:SELECTED_COUNT]]
        and ranking["independent_gain_multiplication_used"] is False
        and ranking["selected_candidate_saved_execution_rows"] is None
        and ranking["selected_candidate_saved_main_cells"] is None
        and ranking["selected_candidate_end_to_end_wall_ns"] is None,
        "EVM candidate matrix ranking boundary differs",
    )
    boundary = value["claim_boundary"]
    _require(
        boundary["candidate_implementations_available"] is False
        and boundary["candidate_cells_available"] is False
        and boundary["proof_correctness"] is None
        and boundary["fresh_proof_verification"] is None
        and boundary["measured_end_to_end_wall_ns"] is None
        and boundary["performance_claim_eligible"] is False
        and boundary["production_active"] is False,
        "EVM candidate matrix claim boundary differs",
    )
    expected = build(Path(inputs["prior_census_v7"]["path"]))
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "EVM candidate matrix replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "EVM candidate matrix", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "EVM candidate matrix is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--prior-census", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--matrix", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.matrix)
            return 0
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "EVM matrix parent")
        store.require_directory(staging, "EVM matrix staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(build(arguments.prior_census)),
            staging_directory=staging,
        )
        return 0
    except (ValueError, RuntimeError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
