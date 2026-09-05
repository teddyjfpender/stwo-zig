"""Supersede the retained-corpus ledger with exact PC-symbol diagnostics."""

from __future__ import annotations

import argparse
from bisect import bisect_left
import copy
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = Path(__file__).resolve().parent
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_opportunity_ledger as ledger_v1  # noqa: E402
import ethereum_block_pc_hotspot_evidence as hotspot_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


SCHEMA = "stwo.ethereum.retained-corpus-opportunity-ledger.v2"
STATUS = "diagnostic-opportunities-with-pc-hotspots-nonpromotable"
EXPECTED_PREFIX_SEGMENTS = (1, 16, 64)
SYMBOL_PARSER = "elf32-little-endian-symtab-stt-func-v1"
TOP_SYMBOL_LIMIT = 32
ELF32_HEADER_BYTES = 52
ELF32_SECTION_HEADER_BYTES = 40
ELF32_SYMBOL_BYTES = 16
SHT_SYMTAB = 2
SHT_STRTAB = 3
STT_FUNC = 2
EM_RISCV = 243
SYMBOL_PROJECTION_DOMAIN = b"stwo.ethereum.pc-hotspot-elf-symbols.v1\0"
TWO_READ_ALIAS_SOURCE = (
    REPOSITORY
    / "src/frontends/riscv/air/lang/typed_two_read_register_alias_candidate_v1.zig"
)
TWO_READ_ALIAS_TEST_SOURCE = (
    REPOSITORY
    / "src/frontends/riscv/air/lang/typed_two_read_register_alias_candidate_v1_test.zig"
)
TWO_READ_ALIAS_SAVED_RAW_BYTES = 1_067_177_472
NAMED_RULES = (
    {
        "hotspot_id": "linked-list-allocator-first-fit",
        "display_name": "linked_list_allocator.allocate_first_fit",
        "required_substrings": ("linked_list_allocator", "Heap18allocate_first_fit"),
    },
    {
        "hotspot_id": "compiler-builtins-memcpy",
        "display_name": "memcpy",
        "required_substrings": ("compiler_builtins", "mem6memcpy"),
    },
    {
        "hotspot_id": "native-keccak256",
        "display_name": "native_keccak256",
        "required_substrings": ("native_keccak256",),
    },
    {
        "hotspot_id": "sha2-sha256-compress256",
        "display_name": "SHA256.compress256",
        "required_substrings": ("_4sha2", "6sha256", "11compress256"),
    },
    {
        "hotspot_id": "k256-field-10x26-mul",
        "display_name": "k256.field_10x26.mul",
        "required_substrings": ("_4k256", "field_10x26", "3mul"),
    },
)


class OpportunityLedgerV2Error(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpportunityLedgerV2Error(message)


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    _require(
        type(value) is dict and set(value) == {"path", "bytes", "sha256"},
        f"{where} keys differ",
    )
    path = Path(value["path"])
    _require(
        path.is_absolute() and value == _identity(path, where),
        f"{where} identity differs",
    )
    return value


def _u16(raw: bytes, offset: int, where: str) -> int:
    _require(offset + 2 <= len(raw), f"{where} exceeds ELF bytes")
    return struct.unpack_from("<H", raw, offset)[0]


def _u32(raw: bytes, offset: int, where: str) -> int:
    _require(offset + 4 <= len(raw), f"{where} exceeds ELF bytes")
    return struct.unpack_from("<I", raw, offset)[0]


def _string(raw: bytes, offset: int, where: str) -> str:
    _require(0 <= offset < len(raw), f"{where} offset differs")
    end = raw.find(b"\0", offset)
    _require(end >= offset, f"{where} is not terminated")
    try:
        value = raw[offset:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise OpportunityLedgerV2Error(f"{where} is not UTF-8") from error
    _require(value != "", f"{where} is empty")
    return value


def _elf_symbols(elf_identity: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    _validate_identity(elf_identity, "hotspot ELF")
    raw = store.read_regular(Path(elf_identity["path"]), "hotspot ELF")
    _require(
        len(raw) >= ELF32_HEADER_BYTES
        and raw[:7] == b"\x7fELF\x01\x01\x01"
        and _u16(raw, 18, "ELF machine") == EM_RISCV,
        "hotspot ELF class/data/machine differs",
    )
    section_offset = _u32(raw, 32, "ELF section offset")
    section_size = _u16(raw, 46, "ELF section-header size")
    section_count = _u16(raw, 48, "ELF section count")
    _require(
        section_size >= ELF32_SECTION_HEADER_BYTES
        and section_count > 0
        and section_offset + section_size * section_count <= len(raw),
        "hotspot ELF section table differs",
    )
    sections = []
    for index in range(section_count):
        offset = section_offset + index * section_size
        sections.append({
            "type": _u32(raw, offset + 4, "ELF section type"),
            "offset": _u32(raw, offset + 16, "ELF section file offset"),
            "bytes": _u32(raw, offset + 20, "ELF section bytes"),
            "link": _u32(raw, offset + 24, "ELF section link"),
            "entry_bytes": _u32(raw, offset + 36, "ELF section entry bytes"),
        })
    for section in sections:
        _require(
            section["offset"] + section["bytes"] <= len(raw),
            "hotspot ELF section exceeds file",
        )
    symbol_sections = [section for section in sections if section["type"] == SHT_SYMTAB]
    _require(len(symbol_sections) == 1, "hotspot ELF symbol table count differs")
    symbol_section = symbol_sections[0]
    _require(
        symbol_section["entry_bytes"] >= ELF32_SYMBOL_BYTES
        and symbol_section["bytes"] % symbol_section["entry_bytes"] == 0
        and symbol_section["link"] < len(sections),
        "hotspot ELF symbol table geometry differs",
    )
    strings = sections[symbol_section["link"]]
    _require(strings["type"] == SHT_STRTAB and strings["bytes"] > 0,
             "hotspot ELF symbol string table differs")
    string_table = raw[strings["offset"]:strings["offset"] + strings["bytes"]]
    symbols = []
    count = symbol_section["bytes"] // symbol_section["entry_bytes"]
    for index in range(count):
        offset = symbol_section["offset"] + index * symbol_section["entry_bytes"]
        name_offset = _u32(raw, offset, "ELF symbol name")
        address = _u32(raw, offset + 4, "ELF symbol address")
        size = _u32(raw, offset + 8, "ELF symbol size")
        symbol_type = raw[offset + 12] & 0x0F
        section_index = _u16(raw, offset + 14, "ELF symbol section")
        if symbol_type != STT_FUNC or section_index == 0 or size == 0:
            continue
        _require(
            address + size <= 1 << 32,
            "hotspot ELF symbol address range differs",
        )
        name = _string(string_table, name_offset, f"ELF symbol {index} name")
        symbols.append({"address": address, "bytes": size, "name": name})
    symbols.sort(key=lambda item: (item["address"], item["bytes"], item["name"]))
    _require(symbols, "hotspot ELF has no function symbols")
    projection_sha256 = hashlib.sha256(
        SYMBOL_PROJECTION_DOMAIN + protocol.canonical_bytes(symbols)
    ).hexdigest()
    return symbols, projection_sha256


def _symbol_assignments(
    symbols: list[dict[str, Any]], observed_pcs: list[int],
) -> dict[int, dict[str, Any]]:
    observed_pcs = sorted(set(observed_pcs))
    candidates: dict[int, tuple[tuple[Any, ...], dict[str, Any]]] = {}
    for symbol in symbols:
        start = symbol["address"]
        end = start + symbol["bytes"]
        index = bisect_left(observed_pcs, start)
        key = (symbol["bytes"], -start, symbol["name"])
        while index < len(observed_pcs) and observed_pcs[index] < end:
            pc = observed_pcs[index]
            current = candidates.get(pc)
            if current is None or key < current[0]:
                candidates[pc] = (key, symbol)
            index += 1
    return {pc: candidate[1] for pc, candidate in candidates.items()}


def _share(count: int, total: int) -> dict[str, Any]:
    _require(
        type(count) is int and type(total) is int and 0 <= count <= total and total > 0,
        "hotspot symbol share differs",
    )
    percent = Decimal(count) * Decimal(100) / Decimal(total)
    return {
        "numerator": count,
        "denominator": total,
        "millionths": count * 1_000_000 // total,
        "percent_rounded_3dp": format(
            percent.quantize(Decimal("0.001"), rounding=ROUND_HALF_UP), ".3f",
        ),
    }


def _matches_rule(name: str, rule: dict[str, Any]) -> bool:
    return all(token in name for token in rule["required_substrings"])


def _rank_sample(
    value: dict[str, Any],
    assignments: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    counts: dict[tuple[int, int, str], int] = {}
    unmatched = 0
    previous_counts: dict[int, int] = {}
    for row in value["per_pc"]:
        previous_counts[row["pc"]] = row["count"]
        symbol = assignments.get(row["pc"])
        if symbol is None:
            unmatched += row["count"]
            continue
        key = (symbol["address"], symbol["bytes"], symbol["name"])
        counts[key] = counts.get(key, 0) + row["count"]
    total = value["sample"]["retired_instructions"]
    _require(sum(counts.values()) + unmatched == total,
             "hotspot symbol counts do not close")
    ranked = sorted(
        ({
            "symbol": key[2],
            "address": key[0],
            "bytes": key[1],
            "count": count,
            "share": _share(count, total),
        } for key, count in counts.items()),
        key=lambda item: (-item["count"], item["symbol"], item["address"]),
    )
    for index, row in enumerate(ranked, 1):
        row["rank"] = index
    named = []
    for rule in NAMED_RULES:
        matches = [row for row in ranked if _matches_rule(row["symbol"], rule)]
        count = sum(row["count"] for row in matches)
        named.append({
            "hotspot_id": rule["hotspot_id"],
            "display_name": rule["display_name"],
            "matched_symbols": [row["symbol"] for row in matches],
            "count": count,
            "share": _share(count, total),
        })
    family_ranking = []
    for row in value["sample"]["opcode_family_rows"]:
        family_ranking.append({
            "family": row["family"],
            "count": row["rows"],
            "share": _share(row["rows"], total),
        })
    family_ranking.sort(key=lambda row: (-row["count"], row["family"]))
    for index, row in enumerate(family_ranking, 1):
        row["rank"] = index
    return {
        "coverage": {
            "kind": "canonical-contiguous-segment-zero-prefix",
            "first_segment_index": 0,
            "segment_count": value["sample"]["segment_count"],
            "retired_instructions": total,
            "no_extrapolation": True,
            "full_corpus": False,
        },
        "top_symbols": ranked[:TOP_SYMBOL_LIMIT],
        "named_hotspots": named,
        "opcode_family_ranking": family_ranking,
        "matched_retired_instructions": total - unmatched,
        "unmatched_retired_instructions": unmatched,
        "matched_plus_unmatched_closes": True,
        "production_active": False,
        "proof_correctness": None,
        "fresh_verification": None,
        "estimated_end_to_end_wall_ns": None,
    }


def _monotonic_prefixes(values: list[dict[str, Any]]) -> None:
    previous: dict[int, int] = {}
    for value in values:
        current = {row["pc"]: row["count"] for row in value["per_pc"]}
        _require(
            all(current.get(pc, 0) >= count for pc, count in previous.items()),
            "hotspot per-PC prefix counts are not monotonic",
        )
        previous = current


def _two_read_alias_projection(base: dict[str, Any]) -> dict[str, Any]:
    inventory = {
        row["family"]: row for row in base["corpus"]["family_inventory"]
    }
    rows = []
    total_saved_cells = 0
    for family in ("lt_reg", "mul", "mulh"):
        source = inventory[family]
        saved_cells = source["diagnostic_padded_rows"] * 8
        total_saved_cells += saved_cells
        rows.append({
            "family": family,
            "active_rows": source["active_rows"],
            "padded_rows": source["diagnostic_padded_rows"],
            "shard_count": source["diagnostic_shard_count"],
            "omitted_main_columns": 8,
            "saved_main_cells": saved_cells,
        })
    saved_raw_bytes = total_saved_cells * 4
    _require(saved_raw_bytes == TWO_READ_ALIAS_SAVED_RAW_BYTES,
             "LT/MUL/MULH retained projection differs")
    return {
        "opportunity_id": "lt-mul-mulh-two-read-register-alias-v1",
        "families": rows,
        "projection": {
            "saved_main_cells": total_saved_cells,
            "raw_m31_bytes_per_cell": 4,
            "saved_raw_bytes": saved_raw_bytes,
        },
        "source_authority": {
            "candidate": _identity(
                TWO_READ_ALIAS_SOURCE, "LT/MUL/MULH candidate source",
            ),
            "focused_tests": _identity(
                TWO_READ_ALIAS_TEST_SOURCE, "LT/MUL/MULH candidate tests",
            ),
            "production_active": False,
            "source_verified": True,
            "retained_standalone_gate_receipt": None,
        },
        "evidence_class": (
            "source-bound-focused-green-cost-projection-only;"
            "no-standalone-gate-receipt"
        ),
        "proof_correctness": None,
        "fresh_verification": None,
        "measured_stage_wall_ns": None,
        "estimated_end_to_end_wall_ns": None,
        "production_promotion_eligible": False,
    }


def _build_loaded(
    base: dict[str, Any],
    base_identity: dict[str, Any],
    values: list[dict[str, Any]],
    identities: list[dict[str, Any]],
) -> dict[str, Any]:
    _require(
        base["schema"] == ledger_v1.SCHEMA
        and base["status"] == ledger_v1.STATUS
        and len(values) == len(identities) == len(EXPECTED_PREFIX_SEGMENTS),
        "hotspot ledger input set differs",
    )
    _require(
        tuple(value["sample"]["segment_count"] for value in values)
        == EXPECTED_PREFIX_SEGMENTS,
        "hotspot sample ladder differs",
    )
    journal = base["inputs"]["journal"]
    elf = values[0]["elf"]
    for value in values:
        _require(
            value["execution_journal"] == journal
            and value["elf"] == elf
            and value["input"]["sha256"] == base["corpus"]["header"]["input_sha256"]
            and value["production"] is False
            and value["no_extrapolation"] is True,
            "hotspot sample corpus authority differs",
        )
    _require(
        elf["bytes"] == base["corpus"]["header"]["elf_bytes"]
        and elf["sha256"] == base["corpus"]["header"]["elf_sha256"],
        "hotspot ELF differs from retained corpus",
    )
    _monotonic_prefixes(values)
    symbols, symbol_projection = _elf_symbols(elf)
    observed_pcs = [row["pc"] for value in values for row in value["per_pc"]]
    assignments = _symbol_assignments(symbols, observed_pcs)
    rankings = [
        {
            "source_evidence": identity,
            "source_content_sha256": value["content_sha256"],
            "ranking": _rank_sample(value, assignments),
        }
        for value, identity in zip(values, identities, strict=True)
    ]
    rule_projection = [{
        "hotspot_id": rule["hotspot_id"],
        "display_name": rule["display_name"],
        "required_substrings": list(rule["required_substrings"]),
    } for rule in NAMED_RULES]
    return protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "inputs": {
            "base_ledger_v1": base_identity,
            "pc_hotspot_prefix_evidence": identities,
        },
        "base_ledger_v1": copy.deepcopy(base),
        "pc_hotspots": {
            "symbol_authority": {
                "elf": copy.deepcopy(elf),
                "parser": SYMBOL_PARSER,
                "function_symbol_count": len(symbols),
                "function_symbol_projection_sha256": symbol_projection,
                "overlap_resolution": "smallest-range-then-latest-start-then-name",
                "named_rule_projection": rule_projection,
                "named_rule_projection_sha256": protocol.sha256_bytes(
                    protocol.canonical_bytes(rule_projection)
                ),
            },
            "prefix_rankings": rankings,
            "interpretation": {
                "scope": "observed-retired-core-instructions-in-each-prefix-only",
                "external_retirements_omitted": True,
                "cross_prefix_monotonic_counts": True,
                "sample_to_full_corpus_extrapolation": None,
                "proof_or_end_to_end_timing_claim": None,
                "production_active": False,
            },
        },
        "source_verified_projections": {
            "lt_mul_mulh_two_read_alias": _two_read_alias_projection(base),
        },
        "next_experiments": [
            {
                "rank": 1,
                "experiment_id": "allocator-first-fit-retirement-microbenchmark-v1",
                "source_hotspot_id": "linked-list-allocator-first-fit",
                "maximum_wall_seconds": 60,
                "full_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-typed-semantics-preserving-candidate",
            },
            {
                "rank": 2,
                "experiment_id": "memcpy-retirement-microbenchmark-v1",
                "source_hotspot_id": "compiler-builtins-memcpy",
                "maximum_wall_seconds": 60,
                "full_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-typed-semantics-preserving-candidate",
            },
            {
                "rank": 3,
                "experiment_id": "native-keccak-retirement-microbenchmark-v1",
                "source_hotspot_id": "native-keccak256",
                "maximum_wall_seconds": 60,
                "full_proof_forbidden": True,
                "launch_ready": False,
                "unavailable_reason": "requires-typed-semantics-preserving-candidate",
            },
        ],
        "claims": {
            "base_ledger_claims_preserved": True,
            "hotspot_ranking_is_sample_observation_only": True,
            "sample_to_full_corpus_extrapolation": None,
            "cross_family_speedup": None,
            "measured_end_to_end_wall_ns": None,
            "full_block_proof_complete": None,
            "fresh_full_block_verification": None,
            "production_promotion_eligible": False,
        },
    })


def build(base_path: Path, hotspot_paths: list[Path]) -> dict[str, Any]:
    base_path = base_path.absolute()
    hotspot_paths = [path.absolute() for path in hotspot_paths]
    _require(
        len(hotspot_paths) == len(EXPECTED_PREFIX_SEGMENTS),
        "hotspot evidence path count differs",
    )
    base = ledger_v1.load(base_path)
    values = [hotspot_evidence.load(path) for path in hotspot_paths]
    return _build_loaded(
        base,
        _identity(base_path, "base opportunity ledger"),
        values,
        [_identity(path, f"PC hotspot evidence {index}")
         for index, path in enumerate(hotspot_paths)],
    )


def validate(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict and set(value) == {
            "schema",
            "status",
            "inputs",
            "base_ledger_v1",
            "pc_hotspots",
            "source_verified_projections",
            "next_experiments",
            "claims",
            "content_sha256",
        },
        "opportunity ledger v2 keys differ",
    )
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["content_sha256"] == protocol.content_sha256(value),
        "opportunity ledger v2 authority differs",
    )
    inputs = value["inputs"]
    _require(
        type(inputs) is dict
        and set(inputs) == {"base_ledger_v1", "pc_hotspot_prefix_evidence"}
        and type(inputs["pc_hotspot_prefix_evidence"]) is list
        and len(inputs["pc_hotspot_prefix_evidence"]) == len(EXPECTED_PREFIX_SEGMENTS),
        "opportunity ledger v2 inputs differ",
    )
    _validate_identity(inputs["base_ledger_v1"], "base opportunity ledger")
    for index, identity in enumerate(inputs["pc_hotspot_prefix_evidence"]):
        _validate_identity(identity, f"PC hotspot evidence {index}")
    expected = build(
        Path(inputs["base_ledger_v1"]["path"]),
        [Path(identity["path"]) for identity in inputs["pc_hotspot_prefix_evidence"]],
    )
    _require(
        protocol.canonical_bytes(value) == protocol.canonical_bytes(expected),
        "opportunity ledger v2 replay differs",
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "opportunity ledger v2", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "opportunity ledger v2 is not canonical JSON",
    )
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--base-ledger", type=Path, required=True)
    create.add_argument("--hotspot-evidence", type=Path, action="append", required=True)
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
        output = arguments.output.absolute()
        staging = arguments.staging_directory.absolute()
        store.require_directory(output.parent, "opportunity ledger v2 parent")
        store.require_directory(staging, "opportunity ledger v2 staging", create=True)
        value = build(arguments.base_ledger, arguments.hotspot_evidence)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value), staging_directory=staging,
        )
        return 0
    except (
        OpportunityLedgerV2Error,
        ledger_v1.OpportunityLedgerError,
        hotspot_evidence.PcHotspotEvidenceError,
        protocol.ProofProtocolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
