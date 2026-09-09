#!/usr/bin/env python3
"""Seal fail-closed economics for the nonproduction analyze_legacy AIR candidate."""

from __future__ import annotations

import argparse
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

import ethereum_block_analyze_legacy_semantic_evidence as semantic_v1  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.analyze-legacy-air-economics.v1"
STATUS = "conditional-go-diagnostic-pre-source-output-relations"
FUNCTION_START = 0x000B_D490
FUNCTION_END = 0x000B_D9E8
SOFTWARE_ACTIVE_CELLS = 480_147_895
CANDIDATE_LOWER_BOUND_CELLS = 101_518_336
SECURE_M31_COORDINATES = 4
LOGUP_BATCH_SIZE = 2

LANG = REPOSITORY / "src/frontends/riscv/air/lang"
GUEST = REPOSITORY / "src/frontends/riscv/air/guest_precompile"
COMPOSITION = LANG / "opcode_composition_manifest.zig"
OPCODE_MANIFEST = REPOSITORY / "src/frontends/riscv/opcode_manifest.zig"
CANDIDATE_AUTHORITY = GUEST / "analyze_legacy_candidate_v1.zig"
SCAN_SOURCE = GUEST / "analyze_legacy_scan_candidate_v1.zig"
BITMAP_SOURCE = GUEST / "analyze_legacy_bitmap_candidate_v1.zig"
RELATION_SOURCE = GUEST / "analyze_legacy_relations_candidate_v1.zig"

EXPECTED_FAMILY_ROWS = {
    "auipc": 255,
    "base_alu_imm": 1_680_912,
    "base_alu_reg": 333_172,
    "branch_eq": 798_415,
    "branch_lt": 1_553_769,
    "jal": 321,
    "jalr": 370,
    "load_store": 884_488,
    "lt_imm": 115,
    "lui": 1_124,
    "mul": 228,
    "shifts_imm": 1_552_772,
    "shifts_reg": 41_026,
}

# family: (implementation, main literal, lookup literal, batch literal source/name)
FAMILY_CONFIG = {
    "auipc": ("typed_auipc.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
              "typed_auipc_authority.zig", "LOOKUP_BATCH_SIZE"),
    "base_alu_imm": ("typed_addi.zig", "MAIN_COLUMN_COUNT", "RELATION_EVENT_COUNT",
                     "typed_addi.zig", "RELATION_BATCH_SIZE"),
    "base_alu_reg": ("typed_base_alu_reg.zig", "MAIN_COLUMN_COUNT",
                     "RELATION_EVENT_COUNT", "typed_base_alu_reg.zig",
                     "RELATION_BATCH_SIZE"),
    "branch_eq": ("typed_branch_eq.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
                  "typed_branch_eq.zig", "LOOKUP_BATCH_SIZE"),
    "branch_lt": ("typed_branch_lt.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
                  "typed_branch_lt.zig", "LOOKUP_BATCH_SIZE"),
    "jal": ("typed_jal.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
            "typed_jal.zig", "LOOKUP_BATCH_SIZE"),
    "jalr": ("typed_jalr.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
             "typed_jalr.zig", "LOOKUP_BATCH_SIZE"),
    "load_store": ("typed_load_store.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
                   "typed_load_store.zig", "LOOKUP_BATCH_SIZE"),
    "lt_imm": ("typed_lt_imm.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
               "typed_lt_imm_authority.zig", "LOOKUP_BATCH_SIZE"),
    "lui": ("typed_lui.zig", "MAIN_COLUMN_COUNT", "RELATION_EVENT_COUNT",
            "typed_lui_authority.zig", "LOOKUP_BATCH_SIZE"),
    "mul": ("typed_mul.zig", "MAIN_COLUMN_COUNT", "LOOKUP_COUNT",
            "typed_mul.zig", "LOOKUP_BATCH_SIZE"),
    "shifts_imm": ("typed_shifts_imm.zig", "MAIN_COLUMN_COUNT",
                   "RELATION_EVENT_COUNT", "typed_shifts_imm.zig",
                   "RELATION_BATCH_SIZE"),
    "shifts_reg": ("typed_shifts_reg.zig", "MAIN_COLUMN_COUNT",
                   "RELATION_EVENT_COUNT", "typed_shifts_reg.zig",
                   "RELATION_BATCH_SIZE"),
}


class AnalyzeLegacyAirEconomicsError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalyzeLegacyAirEconomicsError(message)


def _integer(value: Any, where: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{where} differs")
    return value


def _sha(value: Any, where: str) -> str:
    _require(
        type(value) is str and len(value) == 64
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
        type(value) is dict and set(value) == {"bytes", "path", "sha256"}
        and type(value["path"]) is str and Path(value["path"]).is_absolute(),
        f"{where} identity shape differs",
    )
    _integer(value["bytes"], f"{where}.bytes", minimum=1)
    _sha(value["sha256"], f"{where}.sha256")
    _require(value == _identity(Path(value["path"]), where),
             f"{where} identity differs")
    return value


def _source(path: Path, where: str) -> str:
    raw = store.read_regular(path.resolve(strict=True), where)
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AnalyzeLegacyAirEconomicsError(f"{where} is not UTF-8") from error


def _literal(source: str, name: str, where: str) -> int:
    matches = re.findall(
        rf"^pub const {re.escape(name)}:\s*(?:usize|u8|u16|u32|u64)\s*=\s*"
        rf"([0-9][0-9_]*)\s*;\s*$",
        source,
        flags=re.MULTILINE,
    )
    _require(len(matches) == 1, f"{where} {name} literal differs")
    return int(matches[0].replace("_", ""))


def _struct_fields(source: str, struct_name: str, where: str) -> list[tuple[str, str]]:
    marker = f"pub const {struct_name} = struct {{"
    start = source.find(marker)
    _require(start >= 0, f"{where} {struct_name} is absent")
    start += len(marker)
    end = source.find("\n};", start)
    _require(end >= 0, f"{where} {struct_name} is unterminated")
    declaration_end = source.find("\n\n    pub fn", start, end)
    if declaration_end >= 0:
        end = declaration_end
    fields: list[tuple[str, str]] = []
    for line in source[start:end].splitlines():
        match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*):\s*([^,]+),", line)
        if match is not None:
            fields.append((match.group(1), match.group(2).strip()))
    _require(fields, f"{where} {struct_name} has no fields")
    return fields


def _row_width(source: str, where: str) -> tuple[int, list[dict[str, Any]]]:
    constants = {
        match.group(1): int(match.group(2).replace("_", ""))
        for match in re.finditer(
            r"^pub const ([A-Za-z_][A-Za-z0-9_]*):\s*usize\s*=\s*"
            r"([0-9][0-9_]*)\s*;\s*$",
            source,
            flags=re.MULTILINE,
        )
    }
    marker = "pub fn Row(comptime S: type) type {\n    return struct {"
    start = source.find(marker)
    _require(start >= 0, f"{where} Row is absent")
    start += len(marker)
    end = source.find("\n    };", start)
    _require(end >= 0, f"{where} Row is unterminated")
    fields: list[dict[str, Any]] = []
    for line in source[start:end].splitlines():
        match = re.fullmatch(
            r"\s*([A-Za-z_][A-Za-z0-9_]*):\s*(?:\[([A-Za-z0-9_]+)\])?S,",
            line,
        )
        if match is None:
            continue
        extent_name = match.group(2)
        if extent_name is None:
            extent = 1
        elif extent_name.isdigit():
            extent = int(extent_name)
        else:
            _require(extent_name in constants,
                     f"{where} Row extent {extent_name} differs")
            extent = constants[extent_name]
        fields.append({"columns": extent, "field": match.group(1)})
    _require(fields, f"{where} Row fields are absent")
    return sum(field["columns"] for field in fields), fields


def _padded(active_rows: int) -> tuple[int, int]:
    _require(active_rows > 0, "active row count differs")
    log_size = (active_rows - 1).bit_length()
    return log_size, 1 << log_size


def _decode_pc_observation(raw: bytes) -> dict[str, Any]:
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value)
        and value.get("content_sha256") == protocol.content_sha256(value)
        and value.get("schema") == "stwo.riscv.retirement-pc-hotspot-observation.v1"
        and value.get("production") is False,
        "retained PC observation authority differs",
    )
    return value


def _family_rows(pc_observation: dict[str, Any]) -> dict[str, int]:
    rows = {family: 0 for family in EXPECTED_FAMILY_ROWS}
    previous_pc = -1
    total = 0
    for index, row in enumerate(pc_observation.get("per_pc", ())):
        _require(
            type(row) is dict and set(row) == {"count", "opcode_family", "pc"}
            and type(row["opcode_family"]) is str,
            f"PC row {index} differs",
        )
        pc = _integer(row["pc"], f"PC row {index}.pc")
        count = _integer(row["count"], f"PC row {index}.count", minimum=1)
        _require(pc > previous_pc, "PC row order differs")
        previous_pc = pc
        if FUNCTION_START <= pc < FUNCTION_END:
            _require(row["opcode_family"] in rows,
                     f"unexpected function opcode family {row['opcode_family']}")
            rows[row["opcode_family"]] += count
            total += count
    _require(rows == EXPECTED_FAMILY_ROWS and total == semantic_v1.FUNCTION_ROWS,
             "analyze_legacy function family rows differ")
    return rows


def _production_geometry(rows: dict[str, int]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    composition = _source(COMPOSITION, "opcode composition manifest")
    _require(
        _literal(composition, "SECURE_COORDINATES_PER_CLAIM", "composition")
        == SECURE_M31_COORDINATES
        and "const batches = (lookup_events + batch_size - 1) / batch_size;" in composition
        and "const interaction_columns = batches * SECURE_COORDINATES_PER_CLAIM;"
        in composition,
        "opcode composition interaction geometry differs",
    )
    opcode_manifest = _source(OPCODE_MANIFEST, "opcode manifest")
    result: list[dict[str, Any]] = []
    main_total = interaction_total = 0
    for family in sorted(rows):
        implementation_name, main_name, lookup_name, batch_name, batch_literal = (
            FAMILY_CONFIG[family]
        )
        implementation = _source(LANG / implementation_name, f"{family} implementation")
        batch_source = _source(LANG / batch_name, f"{family} batch authority")
        authority_name = f"typed_{family}_authority.zig"
        authority = _source(LANG / authority_name, f"{family} authority")
        _require(
            implementation_name in authority
            and f".{family} => typed_{family}" in composition
            and family in opcode_manifest,
            f"{family} production binding differs",
        )
        main_columns = _literal(implementation, main_name, family)
        lookup_events = _literal(implementation, lookup_name, family)
        batch_size = _literal(batch_source, batch_literal, family)
        _require(1 <= batch_size <= LOGUP_BATCH_SIZE,
                 f"{family} lookup batch size differs")
        lookup_batches = (lookup_events + batch_size - 1) // batch_size
        interaction_columns = lookup_batches * SECURE_M31_COORDINATES
        active_rows = rows[family]
        main_cells = active_rows * main_columns
        interaction_cells = active_rows * interaction_columns
        main_total += main_cells
        interaction_total += interaction_cells
        result.append({
            "active_rows": active_rows,
            "family": family,
            "interaction_cells": interaction_cells,
            "interaction_columns": interaction_columns,
            "lookup_batch_size": batch_size,
            "lookup_batches": lookup_batches,
            "lookup_events": lookup_events,
            "main_cells": main_cells,
            "main_columns": main_columns,
            "total_active_cells": main_cells + interaction_cells,
        })
    total = main_total + interaction_total
    _require(total == SOFTWARE_ACTIVE_CELLS,
             "canonical typed software active-cell authority differs")
    return result, {
        "active_rows": sum(rows.values()),
        "interaction_cells": interaction_total,
        "main_cells": main_total,
        "padded_cells": None,
        "preprocessed_cells": None,
        "total_active_cells": total,
    }


def _component(
    name: str, active_rows: int, main_columns: int,
    interaction_entries: int, preprocessed_columns: int,
    *, implemented: bool,
) -> dict[str, Any]:
    log_size, padded_rows = _padded(active_rows)
    interaction_columns = (
        (interaction_entries + LOGUP_BATCH_SIZE - 1) // LOGUP_BATCH_SIZE
        * SECURE_M31_COORDINATES
    )
    main_cells = main_columns * padded_rows
    interaction_cells = interaction_columns * padded_rows
    preprocessed_cells = preprocessed_columns * padded_rows
    return {
        "active_rows": active_rows,
        "air_implemented": implemented,
        "interaction_cells": interaction_cells,
        "interaction_columns": interaction_columns,
        "interaction_entries_per_row": interaction_entries,
        "log_size": log_size,
        "main_cells": main_cells,
        "main_columns": main_columns,
        "name": name,
        "padded_rows": padded_rows,
        "preprocessed_cells": preprocessed_cells,
        "preprocessed_columns": preprocessed_columns,
        "total_padded_cells": main_cells + interaction_cells + preprocessed_cells,
    }


def _candidate_geometry(observation: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    authority = _source(CANDIDATE_AUTHORITY, "candidate authority")
    scan_source = _source(SCAN_SOURCE, "scan candidate")
    bitmap_source = _source(BITMAP_SOURCE, "bitmap candidate")
    relation_source = _source(RELATION_SOURCE, "candidate relation")
    scan_columns, scan_fields = _row_width(scan_source, "scan candidate")
    bitmap_columns, bitmap_fields = _row_width(bitmap_source, "bitmap candidate")
    summary_fields = _struct_fields(authority, "SummaryV1", "candidate authority")
    descriptor_fields = _struct_fields(authority, "DescriptorV1", "candidate authority")
    caller_fields = _struct_fields(authority, "CallerV1", "candidate authority")
    _require(
        scan_columns == 82 and bitmap_columns == 75
        and [name for name, _ in summary_fields] == [
            "bitmap_bytes", "eof_immediate_padding", "jumpdest_count", "push_count",
            "push_overflow", "scan_iterations", "total_padding",
        ]
        and [name for name, _ in descriptor_fields] == [
            "call_index", "source_pointer", "source_length", "source_sha256", "summary",
        ]
        and [name for name, _ in caller_fields] == [
            "entry_clock", "entry_pc", "bytes_struct_pointer", "descriptor",
        ]
        and "pub fn scanInteraction(" in relation_source
        and "pub fn bitmapInteraction(" in relation_source
        and _literal(bitmap_source, "bits_per_word", "bitmap candidate") == 32
        and _literal(scan_source, "source_byte_relation_arity", "scan candidate") == 4
        and "pub const source_memory_relation_ready = false;" in authority
        and "pub const output_memory_relation_ready = false;" in authority,
        "candidate source geometry differs",
    )
    aggregate = observation["aggregate"]
    calls = observation["calls"]
    scan_rows = _integer(aggregate["scan_iterations_sum"], "scan rows", minimum=1)
    bitmap_rows = sum(
        (_integer(call["length"], "call length", minimum=1) + 31) // 32
        for call in calls
    )
    call_count = _integer(aggregate["call_count"], "call count", minimum=1)
    _require(
        scan_rows == _literal(authority, "retained_scan_rows", "candidate authority")
        and bitmap_rows == _literal(
            authority, "retained_bitmap_word_rows", "candidate authority",
        )
        and call_count == _literal(
            authority, "retained_call_count", "candidate authority",
        ),
        "candidate retained workload differs",
    )
    # Caller rows are a typed minimum model, not an implemented AIR. One active
    # selector + three CallerV1 scalars + three DescriptorV1 scalars + seven
    # SummaryV1 scalars; source_sha256 stays host custody only.
    caller_main_columns = 1 + 3 + 3 + len(summary_fields)
    components = [
        _component("scan", scan_rows, scan_columns, 1, 2, implemented=True),
        _component("bitmap", bitmap_rows, bitmap_columns, 32, 2, implemented=True),
        _component("caller-minimum-model", call_count, caller_main_columns, 3, 2,
                   implemented=False),
    ]
    totals = {
        "interaction_cells": sum(row["interaction_cells"] for row in components),
        "main_cells": sum(row["main_cells"] for row in components),
        "preprocessed_cells": sum(row["preprocessed_cells"] for row in components),
        "total_padded_cells": sum(row["total_padded_cells"] for row in components),
    }
    _require(totals == {
        "interaction_cells": 8_389_632,
        "main_cells": 90_900_224,
        "preprocessed_cells": 2_228_480,
        "total_padded_cells": CANDIDATE_LOWER_BOUND_CELLS,
    }, "candidate padded-cell lower bound differs")
    shape = {
        "bitmap_row_fields": bitmap_fields,
        "caller_host_only_fields": ["source_sha256"],
        "caller_main_column_derivation": "active1+caller3+descriptor3+summary7",
        "caller_relation_entries": [
            "scan-descriptor", "scan-terminal", "bitmap-descriptor",
        ],
        "logup_batch_size": LOGUP_BATCH_SIZE,
        "scan_row_fields": scan_fields,
        "secure_m31_coordinates": SECURE_M31_COORDINATES,
    }
    return {"components": components, "totals": totals}, shape


def _claim_boundary() -> dict[str, Any]:
    return {
        "candidate_compiler_artifact": None,
        "candidate_end_to_end_wall_ns": None,
        "candidate_proof": None,
        "candidate_savings_claim": None,
        "fresh_candidate_verification": None,
        "gain_multiplication_allowed": False,
        "performance_claim_eligible": False,
        "production_active": False,
        "software_comparator_padding_attributable": False,
        "software_comparator_preprocessed_attributable": False,
    }


def _soundness_seams() -> list[dict[str, Any]]:
    return [
        {
            "minimum_join": (
                "scan request (call_index,cursor,source_pointer,address,read_clock,source_byte) "
                "must cancel against committed RV32 load/memory authority"
            ),
            "name": "source-byte-read-clock",
            "ready": False,
            "required_fields": [
                "call_index", "cursor", "source_pointer", "address", "read_clock",
                "source_byte",
            ],
        },
        {
            "minimum_join": (
                "caller first/terminal/bitmap descriptors and derived bitmap/padding outputs "
                "must bind committed software entry and output memory writes or a typed output digest"
            ),
            "name": "caller-output-memory",
            "ready": False,
            "software_bytes_construction_retained": True,
        },
        {
            "minimum_join": (
                "register a transcript relation and materialize/fresh-verify LogUp columns for "
                "scan JUMPDEST requests and bitmap supplies"
            ),
            "name": "interaction-stark-registration",
            "ready": False,
        },
    ]


def _source_identities() -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_paths = {
        "authority": CANDIDATE_AUTHORITY,
        "bitmap": BITMAP_SOURCE,
        "relations": RELATION_SOURCE,
        "scan": SCAN_SOURCE,
    }
    production_paths = {
        "composition_manifest": COMPOSITION,
        "opcode_manifest": OPCODE_MANIFEST,
    }
    for family, config in FAMILY_CONFIG.items():
        implementation, _, _, batch_source, _ = config
        production_paths[f"{family}_authority"] = LANG / f"typed_{family}_authority.zig"
        production_paths[f"{family}_implementation"] = LANG / implementation
        production_paths[f"{family}_batch_source"] = LANG / batch_source
    return (
        {name: _identity(path, f"candidate source {name}")
         for name, path in sorted(candidate_paths.items())},
        {name: _identity(path, f"production source {name}")
         for name, path in sorted(production_paths.items())},
    )


def build(observation_path: Path) -> dict[str, Any]:
    observation_path = observation_path.resolve(strict=True)
    observation_identity = _identity(observation_path, "semantic observation")
    observation = semantic_v1.load(observation_path)
    _require(
        observation["production"] is False
        and observation["promotion"]["proof_correctness"] is None
        and observation["promotion"]["end_to_end_wall_ns"] is None,
        "semantic observation claim boundary differs",
    )
    pc_identity = copy.deepcopy(observation["pc_observation"])
    pc_raw = store.read_regular(Path(pc_identity["path"]), "retained PC observation")
    pc_observation = _decode_pc_observation(pc_raw)
    rows = _family_rows(pc_observation)
    families, software_totals = _production_geometry(rows)
    candidate, shape = _candidate_geometry(observation)
    candidate_sources, production_sources = _source_identities()
    delta = software_totals["total_active_cells"] - candidate["totals"]["total_padded_cells"]
    _require(delta > 0 and delta == 378_629_559, "candidate break-even headroom differs")
    return protocol.seal({
        "candidate_lower_bound": {
            **candidate,
            "excluded_unmodeled_cells": [
                "source-byte/read-clock relation",
                "caller/output-memory relation",
                "registered STARK wrapper and proof geometry",
            ],
            "scope": "padded-pre-source-output-relation-lower-bound",
            "shape_authority": shape,
        },
        "claim_boundary": _claim_boundary(),
        "comparison": {
            "asymmetric_conservative_candidate_is_padded_software_is_active_only": True,
            "break_even_unmodeled_relation_cell_budget": delta,
            "candidate_fraction_scaled_1e9_floor": (
                candidate["totals"]["total_padded_cells"] * 1_000_000_000
                // software_totals["total_active_cells"]
            ),
            "cell_delta_before_unmodeled_relations": delta,
            "reduction_percent_scaled_1e6_floor": (
                delta * 100_000_000 // software_totals["total_active_cells"]
            ),
        },
        "inputs": {
            "candidate_sources": candidate_sources,
            "pc_observation": pc_identity,
            "pc_observation_content_sha256": pc_observation["content_sha256"],
            "production_sources": production_sources,
            "semantic_observation": observation_identity,
            "semantic_observation_content_sha256": observation["content_sha256"],
        },
        "production": False,
        "recommendation": {
            "economics_headroom_meaningful": True,
            "next_authorized_scope": "source-output-relation-microproof-only",
            "result": "conditional-go-source-output-join-microproof",
            "stark_inclusion_ready": False,
        },
        "retained_workload": {
            "bitmap_word_rows": sum((call["length"] + 31) // 32
                                    for call in observation["calls"]),
            "call_count": observation["aggregate"]["call_count"],
            "function_end_exclusive": FUNCTION_END,
            "function_start": FUNCTION_START,
            "observed_function_rows": observation["function_authority"]["symbol_rows"],
            "scan_rows": observation["aggregate"]["scan_iterations_sum"],
            "semantic_observation_scope": "retained-prefix31-no-extrapolation",
        },
        "schema": SCHEMA,
        "software_comparator": {
            "families": families,
            "scope": "canonical-typed-software-active-main-plus-interaction-only",
            "totals": software_totals,
        },
        "soundness_seams": _soundness_seams(),
        "status": STATUS,
    })


def _validate_component(value: Any, where: str) -> None:
    _require(type(value) is dict and set(value) == {
        "active_rows", "air_implemented", "interaction_cells",
        "interaction_columns", "interaction_entries_per_row", "log_size",
        "main_cells", "main_columns", "name", "padded_rows",
        "preprocessed_cells", "preprocessed_columns", "total_padded_cells",
    }, f"{where} shape differs")
    _require(type(value["air_implemented"]) is bool and type(value["name"]) is str,
             f"{where} authority differs")
    for field in set(value) - {"air_implemented", "name"}:
        _integer(value[field], f"{where}.{field}")
    _require(
        value["padded_rows"] == 1 << value["log_size"]
        and value["active_rows"] <= value["padded_rows"]
        and value["main_cells"] == value["main_columns"] * value["padded_rows"]
        and value["interaction_cells"]
        == value["interaction_columns"] * value["padded_rows"]
        and value["preprocessed_cells"]
        == value["preprocessed_columns"] * value["padded_rows"]
        and value["total_padded_cells"] == value["main_cells"]
        + value["interaction_cells"] + value["preprocessed_cells"],
        f"{where} arithmetic differs",
    )


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {
        "candidate_lower_bound", "claim_boundary", "comparison", "content_sha256",
        "inputs", "production", "recommendation", "retained_workload", "schema",
        "software_comparator", "soundness_seams", "status",
    }, "analyze_legacy AIR economics keys differ")
    _require(
        value["schema"] == SCHEMA and value["status"] == STATUS
        and value["production"] is False and value["claim_boundary"] == _claim_boundary()
        and value["content_sha256"] == protocol.content_sha256(value),
        "analyze_legacy AIR economics authority differs",
    )
    inputs = value["inputs"]
    _require(type(inputs) is dict and set(inputs) == {
        "candidate_sources", "pc_observation", "pc_observation_content_sha256",
        "production_sources", "semantic_observation",
        "semantic_observation_content_sha256",
    }, "analyze_legacy AIR economics inputs differ")
    for group in ("candidate_sources", "production_sources"):
        _require(type(inputs[group]) is dict and inputs[group], f"{group} differs")
        for name, identity in inputs[group].items():
            _validate_identity(identity, f"{group} {name}")
    semantic_identity = _validate_identity(inputs["semantic_observation"],
                                           "semantic observation")
    _validate_identity(inputs["pc_observation"], "PC observation")
    _sha(inputs["semantic_observation_content_sha256"], "semantic observation seal")
    _sha(inputs["pc_observation_content_sha256"], "PC observation seal")
    candidate = value["candidate_lower_bound"]
    _require(type(candidate) is dict and type(candidate.get("components")) is list
             and len(candidate["components"]) == 3,
             "candidate lower-bound shape differs")
    for index, component in enumerate(candidate["components"]):
        _validate_component(component, f"candidate component {index}")
    totals = candidate.get("totals")
    _require(type(totals) is dict and totals == {
        "interaction_cells": 8_389_632,
        "main_cells": 90_900_224,
        "preprocessed_cells": 2_228_480,
        "total_padded_cells": CANDIDATE_LOWER_BOUND_CELLS,
    }, "candidate lower-bound totals differ")
    software = value["software_comparator"]
    _require(
        type(software) is dict and type(software.get("families")) is list
        and len(software["families"]) == len(EXPECTED_FAMILY_ROWS)
        and software.get("totals", {}).get("total_active_cells") == SOFTWARE_ACTIVE_CELLS
        and software.get("totals", {}).get("padded_cells") is None
        and software.get("totals", {}).get("preprocessed_cells") is None,
        "software comparator differs",
    )
    comparison = value["comparison"]
    _require(
        type(comparison) is dict
        and comparison.get("asymmetric_conservative_candidate_is_padded_software_is_active_only")
        is True
        and _integer(comparison.get("cell_delta_before_unmodeled_relations"),
                     "cell delta") == SOFTWARE_ACTIVE_CELLS - CANDIDATE_LOWER_BOUND_CELLS
        and comparison.get("break_even_unmodeled_relation_cell_budget")
        == comparison.get("cell_delta_before_unmodeled_relations"),
        "candidate comparison differs",
    )
    recommendation = value["recommendation"]
    _require(recommendation == {
        "economics_headroom_meaningful": True,
        "next_authorized_scope": "source-output-relation-microproof-only",
        "result": "conditional-go-source-output-join-microproof",
        "stark_inclusion_ready": False,
    }, "candidate recommendation differs")
    seams = value["soundness_seams"]
    _require(type(seams) is list and [row.get("name") for row in seams] == [
        "source-byte-read-clock", "caller-output-memory",
        "interaction-stark-registration",
    ] and all(row.get("ready") is False for row in seams),
             "candidate soundness seams differ")
    expected = build(Path(semantic_identity["path"]))
    _require(protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
             "analyze_legacy AIR economics differs from reopened authorities")
    return value


def create(*, observation_path: Path, output_path: Path,
           staging_directory: Path) -> dict[str, Any]:
    value = build(observation_path)
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "AIR economics output parent")
    store.require_directory(staging_directory, "AIR economics staging", create=True)
    store.publish_new_or_identical(
        output_path, protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "analyze_legacy AIR economics",
                             maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "analyze_legacy AIR economics is not canonical JSON")
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
        print(json.dumps({
            "candidate_padded_cells": value["candidate_lower_bound"]["totals"][
                "total_padded_cells"
            ],
            "conditional_go": value["recommendation"]["economics_headroom_meaningful"],
            "content_sha256": value["content_sha256"],
            "schema": value["schema"],
            "software_active_cells": value["software_comparator"]["totals"][
                "total_active_cells"
            ],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (AnalyzeLegacyAirEconomicsError, semantic_v1.AnalyzeLegacyEvidenceError,
            protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
