"""Seal a complete retained EVM instruction-function census.

The census reopens V6, its PC observation, and its symbol map.  For every
executed `revm_interpreter::instructions::*` symbol it records exact rows and
incoming retained basic edges whose source maps to a different symbol.  The
rows/entry ratios are diagnostics only: segment-boundary transitions are not
observed, and no EVM micro-op AIR, cell saving, proof, or E2E estimate exists.
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
import ethereum_block_opportunity_ledger_v6 as ledger_v6  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.evm-micro-op-census.v7"
STATUS = "exact-instruction-function-census-diagnostic-nonpromotable"
MODULE_PREFIX = ledger_v6.INTERPRETER_PREFIX
RATIO_SCALE = 1_000_000


class EvmMicroOpCensusV7Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvmMicroOpCensusV7Error(message)


def _integer(value: Any, where: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _identity(
    path: Path, where: str, *, allow_empty: bool = False,
) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or raw, f"{where} is empty")
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": protocol.sha256_bytes(raw),
    }


def _validate_identity(
    value: Any, where: str, *, allow_empty: bool = False,
) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"path", "bytes", "sha256"},
             f"{where} keys differ")
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute()
             and value == _identity(
                 Path(value["path"]), where, allow_empty=allow_empty,
             ),
             f"{where} identity differs")
    return value


def _validate_identity_map(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and value, f"{where} differs")
    for name, identity in value.items():
        _require(type(name) is str and name, f"{where} name differs")
        _validate_identity(
            identity, f"{where} {name}", allow_empty=name == "nm_stderr",
        )
    return value


def _symbol_name(
    symbols: list[tuple[int, str]], addresses: list[int], pc: int,
) -> str:
    index = bisect.bisect_right(addresses, pc) - 1
    _require(index >= 0, "EVM micro-op census PC has no preceding symbol")
    return symbols[index][1]


def _category_opcode(name: str) -> tuple[str, str]:
    _require(name.startswith(MODULE_PREFIX),
             "EVM micro-op census symbol prefix differs")
    remainder = name[len(MODULE_PREFIX):]
    category, separator, tail = remainder.partition("::")
    _require(separator == "::" and category and tail,
             "EVM micro-op census category differs")
    opcode = tail.split("::", 1)[0].split("::<", 1)[0]
    _require(opcode != "", "EVM micro-op census opcode differs")
    return category, opcode


def _ratio(rows: int, entries: int) -> dict[str, Any] | None:
    if entries == 0:
        return None
    return {
        "numerator_rows": rows,
        "denominator_observed_entries": entries,
        "scaled_million_floor": rows * RATIO_SCALE // entries,
    }


def _group_rows(
    member_names: set[str], rows: dict[str, int],
    edges: list[tuple[str, str, int]],
) -> tuple[int, int]:
    observed_rows = sum(rows[name] for name in member_names)
    entries = sum(
        count for source, target, count in edges
        if target in member_names and source not in member_names
    )
    return observed_rows, entries


def derive(
    observation: dict[str, Any], symbol_map_path: Path, segment_count: int,
) -> dict[str, Any]:
    symbols = recover_pc._parse_symbols(store.read_regular(
        symbol_map_path.absolute(), "EVM micro-op census symbol map",
        maximum=recover_pc.MAX_NM_BYTES,
    ))
    addresses = [address for address, _ in symbols]
    all_rows: dict[str, int] = {}
    for row in observation["per_pc"]:
        name = _symbol_name(
            symbols, addresses, _integer(row["pc"], "EVM census PC"),
        )
        count = _integer(row["count"], "EVM census PC count", minimum=1)
        all_rows[name] = all_rows.get(name, 0) + count
    module_rows = {
        name: count for name, count in all_rows.items()
        if name.startswith(MODULE_PREFIX)
    }
    _require(module_rows, "EVM micro-op census module is empty")

    edges = []
    for edge in observation["basic_edges"]:
        edges.append((
            _symbol_name(
                symbols, addresses,
                _integer(edge["from_pc"], "EVM census edge source PC"),
            ),
            _symbol_name(
                symbols, addresses,
                _integer(edge["to_pc"], "EVM census edge target PC"),
            ),
            _integer(edge["count"], "EVM census edge count", minimum=1),
        ))

    symbol_rows = []
    total_cross_entries = total_self_edges = total_missing = 0
    outside_module_entries = inter_module_symbol_entries = 0
    categories: dict[str, set[str]] = {}
    opcodes: dict[tuple[str, str], set[str]] = {}
    for name, observed_rows in module_rows.items():
        category, opcode = _category_opcode(name)
        categories.setdefault(category, set()).add(name)
        opcodes.setdefault((category, opcode), set()).add(name)
        self_edges = sum(
            count for source, target, count in edges
            if source == name and target == name
        )
        cross_entries = sum(
            count for source, target, count in edges
            if target == name and source != name
        )
        outside_entries = sum(
            count for source, target, count in edges
            if target == name and not source.startswith(MODULE_PREFIX)
        )
        inter_entries = cross_entries - outside_entries
        missing = observed_rows - self_edges - cross_entries
        _require(
            0 <= missing <= segment_count and inter_entries >= 0,
            f"EVM micro-op census symbol {name} edge closure differs",
        )
        total_cross_entries += cross_entries
        total_self_edges += self_edges
        total_missing += missing
        outside_module_entries += outside_entries
        inter_module_symbol_entries += inter_entries
        symbol_rows.append({
            "symbol": name,
            "category": category,
            "opcode_group": opcode,
            "observed_rows": observed_rows,
            "observed_cross_symbol_entries": cross_entries,
            "observed_outside_module_entries": outside_entries,
            "observed_other_interpreter_symbol_entries": inter_entries,
            "observed_self_symbol_edges": self_edges,
            "rows_without_observed_incoming_edge": missing,
            "rows_per_observed_cross_symbol_entry": _ratio(
                observed_rows, cross_entries,
            ),
        })
    symbol_rows.sort(key=lambda row: (-row["observed_rows"], row["symbol"]))
    for rank, row in enumerate(symbol_rows, start=1):
        row["observed_row_rank"] = rank

    category_rows = []
    for category, members in sorted(categories.items()):
        observed_rows, entries = _group_rows(members, module_rows, edges)
        category_rows.append({
            "category": category,
            "executed_function_count": len(members),
            "opcode_group_count": sum(key[0] == category for key in opcodes),
            "observed_rows": observed_rows,
            "observed_outside_category_entries": entries,
            "rows_per_observed_outside_category_entry": _ratio(
                observed_rows, entries,
            ),
        })

    opcode_rows = []
    for (category, opcode), members in sorted(opcodes.items()):
        observed_rows, entries = _group_rows(members, module_rows, edges)
        opcode_rows.append({
            "category": category,
            "opcode_group": opcode,
            "executed_function_count": len(members),
            "observed_rows": observed_rows,
            "observed_outside_opcode_group_entries": entries,
            "rows_per_observed_outside_opcode_group_entry": _ratio(
                observed_rows, entries,
            ),
        })

    retired = _integer(
        observation["retired_instructions"],
        "EVM census retired instructions", minimum=1,
    )
    transition_count = _integer(
        observation["transition_count"], "EVM census transition count",
    )
    transition_omission = retired - transition_count
    _require(
        sum(module_rows.values()) == sum(row["observed_rows"] for row in symbol_rows)
        and total_cross_entries
        == outside_module_entries + inter_module_symbol_entries
        and total_missing <= segment_count
        and transition_omission == segment_count,
        "EVM micro-op census aggregate closure differs",
    )
    return {
        "module_prefix": MODULE_PREFIX,
        "symbol_order": "observed-rows-descending-then-symbol-ascending",
        "ratio_scope": "observed-rows/retained-cross-boundary-entry",
        "symbols": symbol_rows,
        "category_groups": category_rows,
        "opcode_groups": opcode_rows,
        "totals": {
            "executed_function_count": len(symbol_rows),
            "category_count": len(category_rows),
            "opcode_group_count": len(opcode_rows),
            "observed_rows": sum(module_rows.values()),
            "observed_cross_symbol_entries": total_cross_entries,
            "observed_outside_module_entries": outside_module_entries,
            "observed_other_interpreter_symbol_entries": (
                inter_module_symbol_entries
            ),
            "observed_self_symbol_edges": total_self_edges,
            "module_rows_without_observed_incoming_edge": total_missing,
            "all_execution_transition_omission_count": transition_omission,
            "segment_boundary_entry_omission_upper_bound": segment_count,
        },
    }


def build(prior_path: Path) -> dict[str, Any]:
    prior_path = prior_path.absolute()
    prior = ledger_v6.load(prior_path)
    _require(
        prior["schema"] == ledger_v6.SCHEMA
        and prior["evm_interpreter_residual"][
            "typed_evm_step_air_available"
        ] is False
        and prior["claims"]["production_promotion_eligible"] is False,
        "EVM micro-op census V6 boundary differs",
    )
    pc_identity = prior["inputs"]["ecrecover_pc_census_evidence"]
    pc = recover_pc.load(Path(pc_identity["path"]))
    _require(
        prior["inputs"]["pc_observation"] == pc["inputs"]["observation"]
        and prior["inputs"]["symbol_map"] == pc["inputs"]["nm_stdout"]
        and pc["sample"]["sample_is_complete_execution"] is True
        and pc["sample"]["no_extrapolation"] is True,
        "EVM micro-op census PC join differs",
    )
    observation = ledger_v6._load_observation(pc)
    census = derive(
        observation, Path(pc["inputs"]["nm_stdout"]["path"]),
        pc["sample"]["segment_count"],
    )
    residual = prior["evm_interpreter_residual"]
    totals = census["totals"]
    _require(
        totals["executed_function_count"] == residual["executed_function_count"]
        and totals["observed_rows"] == residual["observed_rows"]
        and totals["observed_outside_module_entries"]
        == residual["observed_outside_to_module_entries"]
        and totals["module_rows_without_observed_incoming_edge"]
        == residual["module_rows_without_observed_incoming_edge"]
        and totals["segment_boundary_entry_omission_upper_bound"]
        == residual["segment_boundary_transition_omission_upper_bound"],
        "EVM micro-op census V6 residual differs",
    )
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "prior_ledger_v6": _identity(prior_path, "prior ledger v6"),
            "prior_v6_inputs": copy.deepcopy(prior["inputs"]),
            "pc_census_inputs": copy.deepcopy(pc["inputs"]),
        },
        "sample": {
            "execution_profile": copy.deepcopy(pc["sample"]["execution_profile"]),
            "clock_frame": copy.deepcopy(pc["sample"]["clock_frame"]),
            "segment_count": pc["sample"]["segment_count"],
            "retired_instructions": pc["sample"]["retired_instructions"],
            "transition_scope": copy.deepcopy(pc["sample"]["transition_scope"]),
            "complete_execution": True,
            "no_extrapolation": True,
        },
        "census": census,
        "claim_boundary": {
            "candidate_micro_op_air_available": False,
            "candidate_active_rows": None,
            "candidate_padded_rows": None,
            "candidate_main_columns": None,
            "candidate_main_cells": None,
            "candidate_saved_main_cells": None,
            "candidate_execution_wall_ns": None,
            "candidate_proof_identity": None,
            "candidate_proof_wall_ns": None,
            "fresh_candidate_verification": None,
            "candidate_end_to_end_wall_ns": None,
            "performance_claim_eligible": False,
            "production_active": False,
        },
    })


def _validate_ratio(value: Any, rows: int, entries: int, where: str) -> None:
    if entries == 0:
        _require(value is None, f"{where} ratio differs")
        return
    _require(type(value) is dict and value == _ratio(rows, entries),
             f"{where} ratio differs")


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "sample", "census",
        "claim_boundary", "content_sha256",
    }, "EVM micro-op census keys differ")
    _require(
        value["schema"] == SCHEMA and value["status"] == STATUS
        and value["content_sha256"] == protocol.content_sha256(value),
        "EVM micro-op census authority differs",
    )
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "prior_ledger_v6", "prior_v6_inputs", "pc_census_inputs",
    }, "EVM micro-op census inputs differ")
    _validate_identity(inputs["prior_ledger_v6"], "EVM census prior V6")
    _validate_identity_map(inputs["prior_v6_inputs"], "EVM census V6 input")
    _validate_identity_map(inputs["pc_census_inputs"], "EVM census PC input")

    census = value["census"]
    totals = census["totals"]
    symbols = census["symbols"]
    _require(type(symbols) is list and symbols,
             "EVM micro-op census symbols differ")
    for index, row in enumerate(symbols, start=1):
        _require(
            type(row) is dict and row["observed_row_rank"] == index
            and type(row["symbol"]) is str
            and row["symbol"].startswith(MODULE_PREFIX)
            and type(row["category"]) is str and row["category"]
            and type(row["opcode_group"]) is str and row["opcode_group"],
            f"EVM micro-op census symbol {index} differs",
        )
        rows = _integer(row["observed_rows"], "EVM symbol rows", minimum=1)
        entries = _integer(
            row["observed_cross_symbol_entries"], "EVM symbol entries",
        )
        _validate_ratio(
            row["rows_per_observed_cross_symbol_entry"], rows, entries,
            f"EVM symbol {index}",
        )
    for name in (
        "executed_function_count", "category_count", "opcode_group_count",
        "observed_rows", "observed_cross_symbol_entries",
        "observed_outside_module_entries",
        "observed_other_interpreter_symbol_entries",
        "observed_self_symbol_edges",
        "module_rows_without_observed_incoming_edge",
        "all_execution_transition_omission_count",
        "segment_boundary_entry_omission_upper_bound",
    ):
        _integer(totals[name], f"EVM census total {name}")
    _require(
        totals["executed_function_count"] == len(symbols)
        and totals["all_execution_transition_omission_count"]
        <= totals["segment_boundary_entry_omission_upper_bound"],
        "EVM micro-op census totals differ",
    )

    sample = value["sample"]
    _require(
        sample["complete_execution"] is True
        and sample["no_extrapolation"] is True,
        "EVM micro-op census sample boundary differs",
    )
    boundary = value["claim_boundary"]
    _require(
        boundary["candidate_micro_op_air_available"] is False
        and boundary["performance_claim_eligible"] is False
        and boundary["production_active"] is False,
        "EVM micro-op census promotion boundary differs",
    )
    for name in (
        "candidate_active_rows", "candidate_padded_rows",
        "candidate_main_columns", "candidate_main_cells",
        "candidate_saved_main_cells", "candidate_execution_wall_ns",
        "candidate_proof_identity", "candidate_proof_wall_ns",
        "fresh_candidate_verification", "candidate_end_to_end_wall_ns",
    ):
        _require(boundary[name] is None,
                 f"EVM micro-op census {name} is available")

    expected = build(Path(inputs["prior_ledger_v6"]["path"]))
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "EVM micro-op census replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "EVM micro-op census", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "EVM micro-op census is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--prior-ledger", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--census", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.census)
            return 0
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "EVM census parent")
        store.require_directory(staging, "EVM census staging", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(build(arguments.prior_ledger)),
            staging_directory=staging,
        )
        return 0
    except (ValueError, RuntimeError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
