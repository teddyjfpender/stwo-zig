"""Seal the exact retained EVM-interpreter residual without estimating gains.

V6 preserves the sealed V5 scopes and derives two additional facts from their
reopened authorities: the executed `revm_interpreter::instructions` symbol and
edge census, and the current per-leaf opcode main-trace geometry.  No EVM-step
AIR exists, so candidate rows, cells, timings, proof claims, and savings remain
explicitly unavailable.
"""

from __future__ import annotations

import argparse
import bisect
import copy
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

import ethereum_block_ecrecover_pc_census_evidence as recover_pc  # noqa: E402
import ethereum_block_opportunity_ledger_v5 as ledger_v5  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v6"
STATUS = "exact-evm-interpreter-residual-diagnostic-nonpromotable"
INTERPRETER_PREFIX = "revm_interpreter::instructions::"
MIN_COMPONENT_LOG = 4
MAIN_COLUMN_DECLARATION = re.compile(
    rb"pub const MAIN_COLUMN_COUNT: usize = ([0-9]+);",
)

# Each row binds both the authority selected by the composition manifest and
# the physical layout declaration it imports.  The integer is checked against
# the declaration text before it is used in any geometry arithmetic.
OPCODE_COLUMN_AUTHORITIES = (
    ("auipc", 29, "typed_auipc_authority.zig", "typed_auipc.zig"),
    ("base_alu_imm", 35, "typed_base_alu_imm_authority.zig", "typed_addi.zig"),
    ("base_alu_reg", 35, "typed_base_alu_reg_authority.zig", "typed_base_alu_reg.zig"),
    ("branch_eq", 30, "typed_branch_eq_authority.zig", "typed_branch_eq.zig"),
    ("branch_lt", 37, "typed_branch_lt_authority.zig", "typed_branch_lt.zig"),
    ("div", 67, "typed_div_authority.zig", "typed_div.zig"),
    ("jal", 20, "typed_jal_authority.zig", "typed_jal.zig"),
    ("jalr", 41, "typed_jalr_authority.zig", "typed_jalr.zig"),
    ("load_store", 50, "typed_load_store_authority.zig", "typed_load_store.zig"),
    ("lt_imm", 37, "typed_lt_imm_authority.zig", "typed_lt_imm.zig"),
    ("lt_reg", 44, "typed_lt_reg_authority.zig", "typed_lt_reg.zig"),
    ("lui", 18, "typed_lui_authority.zig", "typed_lui.zig"),
    ("mul", 39, "typed_mul_authority.zig", "typed_mul.zig"),
    ("mulh", 47, "typed_mulh_authority.zig", "typed_mulh.zig"),
    ("shifts_imm", 51, "typed_shifts_imm_authority.zig", "typed_shifts_imm.zig"),
    ("shifts_reg", 60, "typed_shifts_reg_authority.zig", "typed_shifts_reg.zig"),
    ("fence", 6, "typed_fence_authority.zig", "typed_fence.zig"),
)
LANG_DIRECTORY = REPOSITORY / "src/frontends/riscv/air/lang"


class OpportunityLedgerV6Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerV6Error(message)


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


def _load_observation(pc: dict[str, Any]) -> dict[str, Any]:
    path = Path(pc["inputs"]["observation"]["path"])
    raw = store.read_regular(
        path, "opportunity ledger v6 PC observation",
        maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger v6 PC observation is not canonical")
    return value


def _symbol_name(
    symbols: list[tuple[int, str]], addresses: list[int], pc: int,
) -> str:
    index = bisect.bisect_right(addresses, pc) - 1
    _require(index >= 0, "opportunity ledger v6 PC has no preceding symbol")
    return symbols[index][1]


def _interpreter_residual(
    observation: dict[str, Any], symbol_map_path: Path, segment_count: int,
) -> dict[str, Any]:
    symbols = recover_pc._parse_symbols(store.read_regular(
        symbol_map_path, "opportunity ledger v6 symbol map",
        maximum=recover_pc.MAX_NM_BYTES,
    ))
    addresses = [address for address, _ in symbols]
    counts: dict[str, int] = {}
    for row in observation["per_pc"]:
        name = _symbol_name(symbols, addresses, _integer(row["pc"], "PC"))
        count = _integer(row["count"], "PC count", minimum=1)
        counts[name] = counts.get(name, 0) + count

    module_names = sorted(
        name for name in counts if name.startswith(INTERPRETER_PREFIX)
    )
    module_rows = sum(counts[name] for name in module_names)
    outside_entries = internal_edges = outside_exits = 0
    for edge in observation["basic_edges"]:
        count = _integer(edge["count"], "basic edge count", minimum=1)
        source_in = _symbol_name(
            symbols, addresses, _integer(edge["from_pc"], "edge source PC"),
        ).startswith(INTERPRETER_PREFIX)
        target_in = _symbol_name(
            symbols, addresses, _integer(edge["to_pc"], "edge target PC"),
        ).startswith(INTERPRETER_PREFIX)
        if source_in and target_in:
            internal_edges += count
        elif not source_in and target_in:
            outside_entries += count
        elif source_in and not target_in:
            outside_exits += count

    retired = _integer(
        observation["retired_instructions"], "retired instructions", minimum=1,
    )
    missing_incoming = module_rows - internal_edges - outside_entries
    _require(
        0 <= missing_incoming <= segment_count
        and sum(counts.values()) == retired,
        "opportunity ledger v6 interpreter edge closure differs",
    )
    handler = [
        (name, count) for name, count in counts.items()
        if "revm_handler::mainnet_handler::MainnetHandler" in name
        and name.endswith("::execution")
    ]
    _require(len(handler) == 1,
             "opportunity ledger v6 mainnet handler symbol differs")
    return {
        "module_prefix": INTERPRETER_PREFIX,
        "executed_function_count": len(module_names),
        "observed_rows": module_rows,
        "retired_instruction_denominator": retired,
        "observed_share_basis_points_rounded": (
            module_rows * 10_000 + retired // 2
        ) // retired,
        "observed_outside_to_module_entries": outside_entries,
        "observed_internal_module_edges": internal_edges,
        "observed_module_to_outside_exits": outside_exits,
        "module_rows_without_observed_incoming_edge": missing_incoming,
        "segment_boundary_transition_omission_upper_bound": segment_count,
        "mainnet_handler_symbol": handler[0][0],
        "mainnet_handler_observed_rows": handler[0][1],
        "no_extrapolation": True,
        "no_row_subtraction": True,
        "typed_evm_step_air_available": False,
        "candidate_active_rows": None,
        "candidate_padded_rows": None,
        "candidate_main_columns": None,
        "candidate_main_cells": None,
        "saved_main_cells": None,
        "measured_candidate_execution_wall_ns": None,
        "measured_candidate_proof_wall_ns": None,
        "measured_candidate_end_to_end_wall_ns": None,
    }


def _column_authorities(manifest_path: Path) -> dict[str, Any]:
    families = []
    for family, columns, authority_name, layout_name in OPCODE_COLUMN_AUTHORITIES:
        layout_path = LANG_DIRECTORY / layout_name
        raw = store.read_regular(layout_path, f"{family} physical layout source")
        matches = MAIN_COLUMN_DECLARATION.findall(raw)
        _require(len(matches) == 1 and int(matches[0]) == columns,
                 f"{family} physical main-column declaration differs")
        families.append({
            "family": family,
            "main_columns": columns,
            "authority_source": _identity(
                LANG_DIRECTORY / authority_name, f"{family} authority source",
            ),
            "layout_source": _identity(layout_path, f"{family} layout source"),
        })
    _require(
        tuple(row["family"] for row in families) == tuple(segmented.FAMILIES),
        "opcode column authority family order differs",
    )
    return {
        "composition_manifest_source": _identity(
            manifest_path, "opcode composition manifest source",
        ),
        "families": families,
    }


def _padded_rows(rows: int) -> int:
    return 1 << max(MIN_COMPONENT_LOG, (rows - 1).bit_length()) if rows else (
        1 << MIN_COMPONENT_LOG
    )


def _core_main_geometry(
    journal_path: Path, pc: dict[str, Any], prior: dict[str, Any],
    authorities: dict[str, Any],
) -> dict[str, Any]:
    raw = store.read_regular(
        journal_path, "opportunity ledger v6 V3 journal",
        maximum=segmented.MAX_JOURNAL_BYTES,
    )
    lines = raw.splitlines(keepends=True)
    try:
        summary = segmented.validate_records(lines, require_complete=True)
        payloads = [json.loads(line)["payload"] for line in lines]
    except (segmented.ContractError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise OpportunityLedgerV6Error(str(error)) from error
    _require(summary is not None and len(payloads) >= 3,
             "opportunity ledger v6 V3 journal is incomplete")
    segments = payloads[1:-1]
    candidate = prior["ecrecover_success_execution"]["candidate"]
    identity = _identity(journal_path, "opportunity ledger v6 V3 journal")
    _require(
        identity == pc["inputs"]["candidate_journal"]
        and summary["segment_count"] == len(segments)
        == pc["sample"]["segment_count"] == candidate["segment_count"]
        and summary["total_cycles"] == candidate["total_cycles"]
        and summary["total_core_trace_rows"]
        == candidate["total_core_trace_rows"]
        == pc["canonical_totals"]["retired_instructions"]
        and summary["total_external_trace_rows"]
        == candidate["total_external_trace_rows"],
        "opportunity ledger v6 V3 journal join differs",
    )

    columns = {
        row["family"]: row["main_columns"] for row in authorities["families"]
    }
    family_geometry = []
    for family in segmented.FAMILIES:
        active = padded = 0
        for index, segment in enumerate(segments):
            records = segment["opcode_family_rows"]
            matches = [row for row in records if row["family"] == family]
            _require(len(matches) == 1,
                     f"segment {index} {family} family row differs")
            rows = _integer(matches[0]["rows"], f"segment {index} {family} rows")
            active += rows
            padded += _padded_rows(rows)
        main_columns = columns[family]
        family_geometry.append({
            "family": family,
            "active_rows": active,
            "padded_rows": padded,
            "main_columns": main_columns,
            "padded_main_cells": padded * main_columns,
        })
    total = sum(row["padded_main_cells"] for row in family_geometry)
    load_store = next(
        row for row in family_geometry if row["family"] == "load_store"
    )
    return {
        "journal": identity,
        "segment_count": len(segments),
        "padding_policy": "per-segment-family-min-log4-including-empty",
        "component_sharding_applied": False,
        "family_geometry": family_geometry,
        "total_padded_main_cells": total,
        "load_store_padded_main_cells": load_store["padded_main_cells"],
        "candidate_geometry": None,
        "candidate_main_cells": None,
        "saved_main_cells": None,
    }


def _future_contract_map() -> dict[str, Any]:
    return {
        "proposed_schema": "stwo.ethereum.evm-micro-op-candidate-evidence.v1",
        "contract_frozen": False,
        "candidate_instance": None,
        "reduction_estimates": None,
        "required_typed_sections": [
            {
                "section": "source_and_workload_authority",
                "fields": [
                    "baseline_ledger_identity", "candidate_source_identities",
                    "toolchain_identity", "baseline_elf_identity",
                    "candidate_elf_identity", "input_identity",
                    "complete_baseline_v3_journal_identity",
                    "complete_candidate_v3_journal_identity",
                ],
            },
            {
                "section": "dispatch_and_boundary_authority",
                "fields": [
                    "ordered_interpreter_function_set_commitment",
                    "per_pc_census_identity", "basic_edge_census_identity",
                    "segment_boundary_transition_witness",
                    "dispatch_semantic_identity",
                ],
            },
            {
                "section": "air_and_geometry_authority",
                "fields": [
                    "air_program_identity", "profile_identity",
                    "verification_key_identity", "manifest_identity",
                    "per_leaf_active_rows", "per_leaf_padded_rows",
                    "main_columns", "interaction_columns",
                    "composition_geometry", "ordered_relation_claims",
                ],
            },
            {
                "section": "execution_and_proof_custody",
                "fields": [
                    "exact_output_equivalence", "external_row_equivalence",
                    "full_semantic_admission", "proof_identity",
                    "fresh_verifier_executable_identity",
                    "fresh_verifier_result_identity",
                    "verified_proof_capture_identity", "security_identity",
                ],
            },
            {
                "section": "scoped_measurement",
                "fields": [
                    "execution_wall_user_system_ns", "prove_stage_timings_ns",
                    "fresh_verify_wall_user_system_ns", "peak_rss_bytes",
                    "power_and_interference_envelope",
                ],
            },
        ],
        "promotion_requires_all_sections": True,
        "no_reduction_estimates": True,
    }


def build(prior_path: Path, manifest_path: Path) -> dict[str, Any]:
    prior_path, manifest_path = prior_path.absolute(), manifest_path.absolute()
    prior = ledger_v5.load(prior_path)
    _require(
        prior["schema"] == ledger_v5.SCHEMA
        and prior["scope_separation"][
            "independent_gain_multiplication_used"
        ] is False
        and prior["claims"]["production_promotion_eligible"] is False,
        "opportunity ledger v6 prior boundary differs",
    )
    pc_identity = prior["inputs"]["ecrecover_pc_census_evidence"]
    pc = recover_pc.load(Path(pc_identity["path"]))
    _require(
        prior["ecrecover_pc_census"]["source_evidence"] == pc_identity
        and prior["ecrecover_pc_census"]["no_extrapolation"] is True,
        "opportunity ledger v6 PC source differs",
    )
    observation = _load_observation(pc)
    authorities = _column_authorities(manifest_path)
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "prior_ledger_v5": _identity(prior_path, "prior ledger v5"),
            "ecrecover_pc_census_evidence": copy.deepcopy(pc_identity),
            "pc_observation": copy.deepcopy(pc["inputs"]["observation"]),
            "symbol_map": copy.deepcopy(pc["inputs"]["nm_stdout"]),
        },
        "retained_prior_ledger": {
            "source": _identity(prior_path, "prior ledger v5"),
            "scope_separation": copy.deepcopy(prior["scope_separation"]),
            "claims": copy.deepcopy(prior["claims"]),
        },
        "evm_interpreter_residual": _interpreter_residual(
            observation, Path(pc["inputs"]["nm_stdout"]["path"]),
            pc["sample"]["segment_count"],
        ),
        "current_cpu_main_geometry": _core_main_geometry(
            Path(pc["inputs"]["candidate_journal"]["path"]),
            pc, prior, authorities,
        ),
        "opcode_column_authorities": authorities,
        "future_evm_micro_op_evidence_contract": _future_contract_map(),
        "claims": {
            "candidate_air_complete": None,
            "candidate_execution_complete": None,
            "candidate_proof_complete": None,
            "fresh_candidate_verification": None,
            "measured_candidate_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "schema", "status", "inputs", "retained_prior_ledger",
        "evm_interpreter_residual", "current_cpu_main_geometry",
        "opcode_column_authorities", "future_evm_micro_op_evidence_contract",
        "claims", "content_sha256",
    }, "opportunity ledger v6 keys differ")
    _require(
        value["schema"] == SCHEMA and value["status"] == STATUS
        and value["content_sha256"] == protocol.content_sha256(value),
        "opportunity ledger v6 authority differs",
    )
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "prior_ledger_v5", "ecrecover_pc_census_evidence",
        "pc_observation", "symbol_map",
    }, "opportunity ledger v6 inputs differ")
    for name, identity in inputs.items():
        _validate_identity(identity, f"opportunity ledger v6 {name}")

    residual = value["evm_interpreter_residual"]
    for name in (
        "executed_function_count", "observed_rows",
        "retired_instruction_denominator", "observed_share_basis_points_rounded",
        "observed_outside_to_module_entries", "observed_internal_module_edges",
        "observed_module_to_outside_exits",
        "module_rows_without_observed_incoming_edge",
        "segment_boundary_transition_omission_upper_bound",
        "mainnet_handler_observed_rows",
    ):
        _integer(residual[name], f"opportunity ledger v6 residual {name}")
    _require(
        residual["no_extrapolation"] is True
        and residual["no_row_subtraction"] is True
        and residual["typed_evm_step_air_available"] is False,
        "opportunity ledger v6 residual boundary differs",
    )
    for name in (
        "candidate_active_rows", "candidate_padded_rows",
        "candidate_main_columns", "candidate_main_cells", "saved_main_cells",
        "measured_candidate_execution_wall_ns",
        "measured_candidate_proof_wall_ns",
        "measured_candidate_end_to_end_wall_ns",
    ):
        _require(residual[name] is None,
                 f"opportunity ledger v6 residual {name} is available")

    geometry = value["current_cpu_main_geometry"]
    _integer(geometry["segment_count"], "V6 geometry segment count", minimum=1)
    _integer(geometry["total_padded_main_cells"], "V6 total main cells", minimum=1)
    _integer(
        geometry["load_store_padded_main_cells"],
        "V6 load/store main cells", minimum=1,
    )
    _require(
        geometry["component_sharding_applied"] is False
        and geometry["candidate_geometry"] is None
        and geometry["candidate_main_cells"] is None
        and geometry["saved_main_cells"] is None,
        "opportunity ledger v6 geometry boundary differs",
    )
    future = value["future_evm_micro_op_evidence_contract"]
    _require(
        future["contract_frozen"] is False
        and future["candidate_instance"] is None
        and future["reduction_estimates"] is None
        and future["promotion_requires_all_sections"] is True
        and future["no_reduction_estimates"] is True,
        "opportunity ledger v6 future contract boundary differs",
    )
    claims = value["claims"]
    _require(
        all(claims[name] is None for name in (
            "candidate_air_complete", "candidate_execution_complete",
            "candidate_proof_complete", "fresh_candidate_verification",
            "measured_candidate_end_to_end_wall_ns",
        ))
        and claims["production_promotion_eligible"] is False,
        "opportunity ledger v6 claims differ",
    )
    manifest = value["opcode_column_authorities"][
        "composition_manifest_source"
    ]
    _validate_identity(manifest, "opportunity ledger v6 composition manifest")
    expected = build(
        Path(inputs["prior_ledger_v5"]["path"]), Path(manifest["path"]),
    )
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "opportunity ledger v6 replay differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger v6", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "opportunity ledger v6 is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--prior-ledger", type=Path, required=True)
    create.add_argument("--opcode-composition-manifest", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--staging-directory", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            load(arguments.ledger)
            return 0
        output, staging = arguments.output.absolute(), arguments.staging_directory.absolute()
        store.require_directory(output.parent, "opportunity ledger v6 parent")
        store.require_directory(staging, "opportunity ledger v6 staging", create=True)
        value = build(
            arguments.prior_ledger, arguments.opcode_composition_manifest,
        )
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (ValueError, RuntimeError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
