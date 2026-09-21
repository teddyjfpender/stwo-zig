#!/usr/bin/env python3
"""Seal a conservative, local SWAP AIR cell projection from retained custody."""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARKS = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARKS)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_ecrecover_pc_census_evidence as recover_pc  # noqa: E402
import ethereum_block_evm_swap_workload_evidence as swap_v1  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.evm-swap-conservative-cell-projection.v1"
STATUS = "exact-local-cell-projection-diagnostic-nonpromotable"
FAMILY_ORDER = (
    "base_alu_imm",
    "base_alu_reg",
    "branch_lt",
    "jalr",
    "load_store",
    "shifts_imm",
)
SECURE_COORDINATES_PER_CLAIM = 4
EXPECTED_CURRENT_CELLS = 507_261_888
EXPECTED_CANDIDATE_CELLS = 23_068_672
EXPECTED_REDUCTION_CELLS = 484_193_216

LANG = REPOSITORY / "src/frontends/riscv/air/lang"
PRODUCTION_MANIFEST = LANG / "opcode_composition_manifest.zig"
OPCODE_MANIFEST = REPOSITORY / "src/frontends/riscv/opcode_manifest.zig"
CANDIDATE_DIRECTORY = REPOSITORY / "src/frontends/riscv/air/guest_precompile"
CANDIDATE_ABI = REPOSITORY / "src/frontends/riscv/isa/stack_swap_candidate_v1.zig"
CANDIDATE_CALLER = CANDIDATE_DIRECTORY / "stack_swap_caller_candidate_v1.zig"
CANDIDATE_WORD = CANDIDATE_DIRECTORY / "stack_swap_word_candidate_v1.zig"
CANDIDATE_RELATIONS = CANDIDATE_DIRECTORY / "stack_swap_relations_v1.zig"

FAMILY_SOURCES = {
    "base_alu_imm": (
        LANG / "typed_base_alu_imm_authority.zig",
        LANG / "typed_addi.zig",
        "RELATION_EVENT_COUNT",
        "RELATION_BATCH_SIZE",
    ),
    "base_alu_reg": (
        LANG / "typed_base_alu_reg_authority.zig",
        LANG / "typed_base_alu_reg.zig",
        "RELATION_EVENT_COUNT",
        "RELATION_BATCH_SIZE",
    ),
    "branch_lt": (
        LANG / "typed_branch_lt_authority.zig",
        LANG / "typed_branch_lt.zig",
        "LOOKUP_COUNT",
        "LOOKUP_BATCH_SIZE",
    ),
    "jalr": (
        LANG / "typed_jalr_authority.zig",
        LANG / "typed_jalr.zig",
        "LOOKUP_COUNT",
        "LOOKUP_BATCH_SIZE",
    ),
    "load_store": (
        LANG / "typed_load_store_authority.zig",
        LANG / "typed_load_store.zig",
        "LOOKUP_COUNT",
        "LOOKUP_BATCH_SIZE",
    ),
    "shifts_imm": (
        LANG / "typed_shifts_imm_authority.zig",
        LANG / "typed_shifts_imm.zig",
        "RELATION_EVENT_COUNT",
        "RELATION_BATCH_SIZE",
    ),
}


class EvmSwapCellProjectionError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvmSwapCellProjectionError(message)


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


def _identity_map(paths: dict[str, Path], where: str) -> dict[str, Any]:
    return {
        name: _identity(path, f"{where} {name}")
        for name, path in sorted(paths.items())
    }


def _validate_identity_map(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and value, f"{where} differs")
    for name, identity in value.items():
        _require(type(name) is str and name, f"{where} name differs")
        _validate_identity(identity, f"{where} {name}")
    return value


def _source(path: Path, where: str) -> str:
    return store.read_regular(path.resolve(strict=True), where).decode("utf-8")


def _literal(source: str, name: str, where: str) -> int:
    match = re.search(
        rf"^pub const {re.escape(name)}(?:: [^=;]+)? = ([0-9][0-9_]*);$",
        source,
        re.MULTILINE,
    )
    _require(match is not None, f"{where} {name} is not a literal")
    return int(match.group(1).replace("_", ""), 10)


def _guard_literal(source: str, name: str, where: str) -> int:
    match = re.search(rf"\b{re.escape(name)} != ([0-9][0-9_]*)", source)
    _require(match is not None, f"{where} {name} guard differs")
    return int(match.group(1).replace("_", ""), 10)


def _next_power_of_two(value: int) -> int:
    _require(value > 0, "projection row count differs")
    return 1 << (value - 1).bit_length()


def _symbol_name(
    symbols: list[tuple[int, str]], addresses: list[int], pc: int,
) -> str:
    index = bisect.bisect_right(addresses, pc) - 1
    _require(index >= 0, "SWAP PC has no preceding symbol")
    return symbols[index][1]


def derive_family_rows(
    observation: dict[str, Any], nm_path: Path, workload: dict[str, Any],
) -> dict[str, int]:
    symbols = recover_pc._parse_symbols(store.read_regular(
        nm_path.resolve(strict=True),
        "SWAP projection symbol map",
        maximum=recover_pc.MAX_NM_BYTES,
    ))
    addresses = [address for address, _ in symbols]
    member_rows = {
        member["symbol"]: _integer(
            member["observed_rows"], "SWAP member observed rows", minimum=1,
        )
        for member in workload["members"]
    }
    _require(len(member_rows) == 16, "SWAP member authority differs")
    derived_members = {name: 0 for name in member_rows}
    family_rows = {family: 0 for family in FAMILY_ORDER}
    rows = observation.get("per_pc") if type(observation) is dict else None
    _require(type(rows) is list and rows, "SWAP per-PC rows differ")
    for row in rows:
        _require(
            type(row) is dict
            and set(row) == {"count", "opcode_family", "pc"}
            and type(row["opcode_family"]) is str,
            "SWAP per-PC row shape differs",
        )
        symbol = _symbol_name(
            symbols, addresses, _integer(row["pc"], "SWAP PC"),
        )
        if symbol not in derived_members:
            continue
        family = row["opcode_family"]
        _require(family in family_rows, "SWAP opcode family differs")
        count = _integer(row["count"], "SWAP PC count", minimum=1)
        derived_members[symbol] += count
        family_rows[family] += count
    _require(derived_members == member_rows,
             "SWAP per-PC/member row join differs")
    _require(
        sum(family_rows.values())
        == workload["totals"]["total_observed_rows"],
        "SWAP opcode-family row closure differs",
    )
    return family_rows


def _production_widths() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _source(PRODUCTION_MANIFEST, "opcode composition manifest")
    opcode_manifest = _source(OPCODE_MANIFEST, "opcode manifest")
    _require(
        "pub const SECURE_COORDINATES_PER_CLAIM: usize = 4;" in manifest
        and "const batches = (lookup_events + batch_size - 1) / batch_size;"
        in manifest
        and "const interaction_columns = batches * SECURE_COORDINATES_PER_CLAIM;"
        in manifest,
        "production interaction geometry formula differs",
    )
    paths = {
        "opcode_composition_manifest": PRODUCTION_MANIFEST,
        "opcode_manifest": OPCODE_MANIFEST,
    }
    result = {}
    for family in FAMILY_ORDER:
        authority_path, typed_path, lookup_name, batch_name = FAMILY_SOURCES[family]
        paths[f"{family}_authority"] = authority_path
        paths[f"{family}_typed"] = typed_path
        authority = _source(authority_path, f"{family} authority")
        typed = _source(typed_path, f"{family} typed component")
        _require(
            f'.{family} => typed_{family},' in manifest
            and f'const typed_{family} = @import("{authority_path.name}");'
            in manifest
            and f"    {family}," in opcode_manifest
            and "pub const MAIN_COLUMN_COUNT: usize = " in authority
            and "pub const LOOKUP_COUNT: usize = " in authority
            and "pub const LOOKUP_BATCH_SIZE: usize = " in authority
            and authority_path.name == f"typed_{family}_authority.zig",
            f"{family} production authority binding differs",
        )
        main = _literal(typed, "MAIN_COLUMN_COUNT", family)
        lookups = _literal(typed, lookup_name, family)
        batch = _literal(typed, batch_name, family)
        interaction = ((lookups + batch - 1) // batch) * SECURE_COORDINATES_PER_CLAIM
        result[family] = {
            "interaction_columns": interaction,
            "lookup_batch_size": batch,
            "lookup_events": lookups,
            "main_columns": main,
            "total_active_columns": main + interaction,
        }
    return result, _identity_map(paths, "production source")


def _retained_family_rows(source: str) -> dict[str, int]:
    marker = "pub const retained_software_family_rows = RetainedSoftwareFamilyRows{"
    start = source.find(marker)
    _require(start >= 0, "candidate retained family authority is absent")
    end = source.find("};", start)
    _require(end >= 0, "candidate retained family authority is truncated")
    block = source[start:end]
    result = {}
    for family in FAMILY_ORDER:
        match = re.search(rf"\.{family} = ([0-9][0-9_]*),", block)
        _require(match is not None, f"candidate retained {family} differs")
        result[family] = int(match.group(1).replace("_", ""), 10)
    return result


def _candidate_geometry() -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    caller = _source(CANDIDATE_CALLER, "SWAP caller candidate")
    word = _source(CANDIDATE_WORD, "SWAP word candidate")
    abi = _source(CANDIDATE_ABI, "SWAP ABI candidate")
    relations = _source(CANDIDATE_RELATIONS, "SWAP relation candidate")
    _require(
        "pub const production_active = false;" in caller
        and "pub const production_active = false;" in word
        and "pub const production_active = false;" in abi
        and 'const caller = @import("stack_swap_caller_candidate_v1.zig");'
        in relations
        and 'const words = @import("stack_swap_word_candidate_v1.zig");'
        in relations,
        "SWAP candidate production/relationship authority differs",
    )
    caller_geometry = {
        "interaction_columns": _literal(
            caller, "interaction_column_count", "SWAP caller",
        ),
        "main_columns": _guard_literal(
            caller, "main_column_count", "SWAP caller",
        ),
        "preprocessed_columns": _literal(
            caller, "preprocessed_column_count", "SWAP caller",
        ),
    }
    word_geometry = {
        "interaction_columns": _literal(
            word, "interaction_column_count", "SWAP word",
        ),
        "lane_count": _guard_literal(word, "lane_count", "SWAP word"),
        "main_columns": _guard_literal(
            word, "main_column_count", "SWAP word",
        ),
        "preprocessed_columns": _literal(
            word, "preprocessed_column_count", "SWAP word",
        ),
    }
    _require(
        caller_geometry == {
            "interaction_columns": 32,
            "main_columns": 37,
            "preprocessed_columns": 3,
        }
        and word_geometry == {
            "interaction_columns": 16,
            "lane_count": 8,
            "main_columns": 16,
            "preprocessed_columns": 3,
        },
        "SWAP candidate geometry differs",
    )
    identities = _identity_map({
        "abi": CANDIDATE_ABI,
        "caller": CANDIDATE_CALLER,
        "relations": CANDIDATE_RELATIONS,
        "word": CANDIDATE_WORD,
    }, "candidate source")
    return {
        "caller": caller_geometry,
        "word": word_geometry,
    }, identities, _retained_family_rows(abi)


def _load_canonical(identity: dict[str, Any], where: str) -> dict[str, Any]:
    raw = store.read_regular(
        Path(identity["path"]), where, maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        f"{where} is not canonical JSON",
    )
    return value


def _claim_boundary() -> dict[str, Any]:
    return {
        "candidate_end_to_end_wall_ns": None,
        "candidate_proof": None,
        "fresh_candidate_verification": None,
        "gain_multiplication_allowed": False,
        "local_projection_only": True,
        "performance_claim_eligible": False,
        "production_active": False,
        "proof_or_end_to_end_promotion": None,
    }


def build(workload_path: Path) -> dict[str, Any]:
    workload_path = workload_path.resolve(strict=True)
    workload_identity = _identity(workload_path, "SWAP workload evidence")
    workload_evidence = swap_v1.load(workload_path)
    _require(
        workload_evidence["production"] is False
        and workload_evidence["performance_claim_eligible"] is False
        and workload_evidence["no_extrapolation"] is True,
        "SWAP workload claim boundary differs",
    )
    pc_identity = copy.deepcopy(workload_evidence["upstream"]["pc_observation"])
    nm_identity = copy.deepcopy(workload_evidence["upstream"]["nm_symbol_map"])
    observation = _load_canonical(pc_identity, "SWAP PC observation")
    family_rows = derive_family_rows(
        observation,
        Path(nm_identity["path"]),
        workload_evidence["workload"],
    )
    calls = workload_evidence["workload"]["totals"][
        "total_observed_call_count"
    ]
    _require(calls > 0, "SWAP call count differs")
    production_widths, production_sources = _production_widths()
    candidate_geometry, candidate_sources, retained_per_call = _candidate_geometry()
    _require(
        all(family_rows[family] == retained_per_call[family] * calls
            for family in FAMILY_ORDER),
        "SWAP raw family mix/source manifest join differs",
    )
    current_families = []
    current_cells = 0
    for family in FAMILY_ORDER:
        widths = production_widths[family]
        cells = family_rows[family] * widths["total_active_columns"]
        current_cells += cells
        current_families.append({
            "active_cells": cells,
            "active_rows": family_rows[family],
            "family": family,
            **widths,
        })

    caller = candidate_geometry["caller"]
    word = candidate_geometry["word"]
    caller_padded = _next_power_of_two(calls)
    word_active = calls * word["lane_count"]
    word_padded = _next_power_of_two(word_active)
    caller_columns = sum(caller.values())
    word_columns = sum(
        word[name] for name in (
            "preprocessed_columns", "main_columns", "interaction_columns",
        )
    )
    candidate_components = [
        {
            "active_rows": calls,
            "all_committed_columns": caller_columns,
            "component": "caller",
            "padded_all_column_cells": caller_padded * caller_columns,
            "padded_rows": caller_padded,
            **caller,
        },
        {
            "active_rows": word_active,
            "all_committed_columns": word_columns,
            "component": "word-provider",
            "padded_all_column_cells": word_padded * word_columns,
            "padded_rows": word_padded,
            **word,
        },
    ]
    candidate_cells = sum(
        component["padded_all_column_cells"] for component in candidate_components
    )
    reduction = current_cells - candidate_cells
    _require(
        current_cells == EXPECTED_CURRENT_CELLS
        and candidate_cells == EXPECTED_CANDIDATE_CELLS
        and reduction == EXPECTED_REDUCTION_CELLS,
        "SWAP frozen projection totals differ",
    )
    return protocol.seal({
        "claim_boundary": _claim_boundary(),
        "comparison_scope": {
            "candidate_padding_included": True,
            "candidate_preprocessed_columns_included": True,
            "current_padding_included": False,
            "current_preprocessed_columns_included": False,
            "scope": (
                "retained-swap-software-active-main-plus-interaction-vs-"
                "candidate-padded-all-columns"
            ),
        },
        "inputs": {
            "candidate_sources": candidate_sources,
            "nm_symbol_map": nm_identity,
            "pc_observation": pc_identity,
            "production_sources": production_sources,
            "swap_workload": workload_identity,
            "swap_workload_content_sha256": workload_evidence["content_sha256"],
        },
        "production": False,
        "projection": {
            "candidate_components": candidate_components,
            "candidate_padded_all_column_cells": candidate_cells,
            "current_active_main_plus_interaction_cells": current_cells,
            "current_families": current_families,
            "reduction_m31_cells": reduction,
            "reduction_percent_floor_6dp": reduction * 100_000_000 // current_cells,
        },
        "sample": copy.deepcopy(workload_evidence["sample"]),
        "schema": SCHEMA,
        "status": STATUS,
    })


def _validate_projection(value: Any) -> None:
    projection = value.get("projection") if type(value) is dict else None
    _require(
        type(projection) is dict
        and set(projection) == {
            "candidate_components",
            "candidate_padded_all_column_cells",
            "current_active_main_plus_interaction_cells",
            "current_families",
            "reduction_m31_cells",
            "reduction_percent_floor_6dp",
        },
        "SWAP projection shape differs",
    )
    current = _integer(
        projection["current_active_main_plus_interaction_cells"],
        "SWAP current cells", minimum=1,
    )
    candidate = _integer(
        projection["candidate_padded_all_column_cells"],
        "SWAP candidate cells", minimum=1,
    )
    reduction = _integer(
        projection["reduction_m31_cells"], "SWAP reduction", minimum=1,
    )
    percent = _integer(
        projection["reduction_percent_floor_6dp"], "SWAP reduction percent",
    )
    _require(
        current == EXPECTED_CURRENT_CELLS
        and candidate == EXPECTED_CANDIDATE_CELLS
        and reduction == EXPECTED_REDUCTION_CELLS
        and reduction == current - candidate
        and percent == reduction * 100_000_000 // current,
        "SWAP projection arithmetic differs",
    )
    families = projection["current_families"]
    _require(
        type(families) is list
        and [row.get("family") for row in families] == list(FAMILY_ORDER),
        "SWAP projection family order differs",
    )
    family_cells = 0
    for row in families:
        _require(type(row) is dict, "SWAP projection family differs")
        active_rows = _integer(row.get("active_rows"), "SWAP family rows", minimum=1)
        main = _integer(row.get("main_columns"), "SWAP family main", minimum=1)
        interaction = _integer(
            row.get("interaction_columns"), "SWAP family interaction", minimum=1,
        )
        total = _integer(
            row.get("total_active_columns"), "SWAP family columns", minimum=1,
        )
        cells = _integer(row.get("active_cells"), "SWAP family cells", minimum=1)
        _require(total == main + interaction and cells == active_rows * total,
                 "SWAP family cell closure differs")
        family_cells += cells
    _require(family_cells == current, "SWAP current family cell sum differs")
    components = projection["candidate_components"]
    _require(
        type(components) is list
        and [row.get("component") for row in components]
        == ["caller", "word-provider"],
        "SWAP candidate component order differs",
    )
    component_cells = 0
    for component in components:
        active = _integer(component.get("active_rows"), "candidate active rows", minimum=1)
        padded = _integer(component.get("padded_rows"), "candidate padded rows", minimum=1)
        columns = _integer(
            component.get("all_committed_columns"), "candidate columns", minimum=1,
        )
        cells = _integer(
            component.get("padded_all_column_cells"), "candidate cells", minimum=1,
        )
        _require(
            padded >= active
            and padded & (padded - 1) == 0
            and cells == padded * columns,
            "SWAP candidate component closure differs",
        )
        component_cells += cells
    _require(component_cells == candidate, "SWAP candidate cell sum differs")


def validate(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {
            "claim_boundary", "comparison_scope", "content_sha256", "inputs",
            "production", "projection", "sample", "schema", "status",
        },
        "SWAP cell projection keys differ",
    )
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["production"] is False
        and value["claim_boundary"] == _claim_boundary()
        and value["content_sha256"] == protocol.content_sha256(value),
        "SWAP cell projection authority differs",
    )
    scope = value["comparison_scope"]
    _require(
        type(scope) is dict
        and scope.get("candidate_padding_included") is True
        and scope.get("candidate_preprocessed_columns_included") is True
        and scope.get("current_padding_included") is False
        and scope.get("current_preprocessed_columns_included") is False,
        "SWAP comparison scope differs",
    )
    inputs = value["inputs"]
    _require(
        type(inputs) is dict
        and set(inputs) == {
            "candidate_sources", "nm_symbol_map", "pc_observation",
            "production_sources", "swap_workload",
            "swap_workload_content_sha256",
        },
        "SWAP projection inputs differ",
    )
    workload_identity = _validate_identity(
        inputs["swap_workload"], "SWAP workload evidence",
    )
    _validate_identity(inputs["pc_observation"], "SWAP PC observation")
    _validate_identity(inputs["nm_symbol_map"], "SWAP symbol map")
    _validate_identity_map(inputs["production_sources"], "production sources")
    _validate_identity_map(inputs["candidate_sources"], "candidate sources")
    _sha(inputs["swap_workload_content_sha256"], "SWAP workload content seal")
    _validate_projection(value)
    expected = build(Path(workload_identity["path"]))
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "SWAP projection differs from retained authorities",
    )
    return value


def create(
    *, workload_path: Path, output_path: Path, staging_directory: Path,
) -> dict[str, Any]:
    value = build(workload_path)
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "SWAP projection parent")
    store.require_directory(staging_directory, "SWAP projection staging", create=True)
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "SWAP projection", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "SWAP projection is not canonical JSON")
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--swap-workload", type=Path, required=True)
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
                workload_path=arguments.swap_workload,
                output_path=arguments.output,
                staging_directory=arguments.staging_directory,
            )
        else:
            value = load(arguments.evidence)
        projection = value["projection"]
        print(json.dumps({
            "candidate_padded_all_column_cells": projection[
                "candidate_padded_all_column_cells"
            ],
            "content_sha256": value["content_sha256"],
            "current_active_main_plus_interaction_cells": projection[
                "current_active_main_plus_interaction_cells"
            ],
            "production": value["production"],
            "reduction_m31_cells": projection["reduction_m31_cells"],
            "reduction_percent_floor_6dp": projection[
                "reduction_percent_floor_6dp"
            ],
            "schema": value["schema"],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (EvmSwapCellProjectionError, ValueError,
            protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
