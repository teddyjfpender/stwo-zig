from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_opportunity_ledger as ledger_v1  # noqa: E402
import ethereum_block_opportunity_ledger_v2 as ledger_v2  # noqa: E402


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": str(path.absolute()),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def write_elf(path: Path) -> None:
    names = [
        "broad",
        "native_keccak256",
        "_RNvMs_fixture_21linked_list_allocator_Heap18allocate_first_fit",
        "_RNv_fixture_17compiler_builtins3mem6memcpy",
        "_RNv_fixture_4sha26sha25611compress256",
        "_RNv_fixture_4k256_field_10x26_3mul",
    ]
    strings = bytearray(b"\0")
    offsets = {}
    for name in names:
        offsets[name] = len(strings)
        strings.extend(name.encode("ascii") + b"\0")
    functions = [
        ("broad", 0x1000, 0x100),
        ("native_keccak256", 0x1000, 0x10),
        (names[2], 0x1010, 0x10),
        (names[3], 0x1020, 0x10),
        (names[4], 0x1030, 0x10),
        (names[5], 0x1040, 0x10),
    ]
    symbols = bytearray(ledger_v2.ELF32_SYMBOL_BYTES)
    for name, address, size in functions:
        symbols.extend(struct.pack(
            "<IIIBBH", offsets[name], address, size, ledger_v2.STT_FUNC, 0, 1,
        ))
    string_offset = ledger_v2.ELF32_HEADER_BYTES
    symbol_offset = (string_offset + len(strings) + 3) & ~3
    section_offset = symbol_offset + len(symbols)
    raw = bytearray(section_offset + 3 * ledger_v2.ELF32_SECTION_HEADER_BYTES)
    raw[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", raw, 16, 2)
    struct.pack_into("<H", raw, 18, ledger_v2.EM_RISCV)
    struct.pack_into("<I", raw, 32, section_offset)
    struct.pack_into("<H", raw, 40, ledger_v2.ELF32_HEADER_BYTES)
    struct.pack_into("<H", raw, 46, ledger_v2.ELF32_SECTION_HEADER_BYTES)
    struct.pack_into("<H", raw, 48, 3)
    raw[string_offset:string_offset + len(strings)] = strings
    raw[symbol_offset:symbol_offset + len(symbols)] = symbols
    section1 = section_offset + ledger_v2.ELF32_SECTION_HEADER_BYTES
    struct.pack_into("<I", raw, section1 + 4, ledger_v2.SHT_STRTAB)
    struct.pack_into("<I", raw, section1 + 16, string_offset)
    struct.pack_into("<I", raw, section1 + 20, len(strings))
    struct.pack_into("<I", raw, section1 + 32, 1)
    section2 = section1 + ledger_v2.ELF32_SECTION_HEADER_BYTES
    struct.pack_into("<I", raw, section2 + 4, ledger_v2.SHT_SYMTAB)
    struct.pack_into("<I", raw, section2 + 16, symbol_offset)
    struct.pack_into("<I", raw, section2 + 20, len(symbols))
    struct.pack_into("<I", raw, section2 + 24, 1)
    struct.pack_into("<I", raw, section2 + 32, 4)
    struct.pack_into("<I", raw, section2 + 36, ledger_v2.ELF32_SYMBOL_BYTES)
    path.write_bytes(raw)


class OpportunityLedgerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "fixture.elf"
        write_elf(self.elf)
        self.journal = self._placeholder("execution.ndjson")
        self.input = self._placeholder("input.bin")
        self.base_path = self._placeholder("base-ledger.json")
        self.hotspot_paths = [
            self._placeholder(f"hotspot-{count}.json")
            for count in ledger_v2.EXPECTED_PREFIX_SEGMENTS
        ]
        self.elf_identity = identity(self.elf)
        self.journal_identity = identity(self.journal)
        self.input_identity = identity(self.input)
        inventory = []
        for family, active, padded, shards in (
            ("lt_reg", 12_323_520, 13_218_896, 326),
            ("mul", 9_755_116, 10_266_688, 310),
            ("mulh", 9_300_216, 9_863_712, 290),
        ):
            inventory.append({
                "family": family,
                "active_rows": active,
                "diagnostic_padded_rows": padded,
                "diagnostic_shard_count": shards,
            })
        self.base = {
            "schema": ledger_v1.SCHEMA,
            "status": ledger_v1.STATUS,
            "inputs": {"journal": self.journal_identity},
            "corpus": {
                "header": {
                    "elf_bytes": self.elf_identity["bytes"],
                    "elf_sha256": self.elf_identity["sha256"],
                    "input_sha256": self.input_identity["sha256"],
                },
                "family_inventory": inventory,
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _placeholder(self, name: str) -> Path:
        path = self.root / name
        path.write_bytes(name.encode("ascii"))
        return path

    def value(self, segment_count: int, scale: int) -> dict:
        per_pc = [
            {"pc": 0x1000, "opcode_family": "base_alu_imm", "count": 5 * scale},
            {"pc": 0x1010, "opcode_family": "load_store", "count": 4 * scale},
            {"pc": 0x1020, "opcode_family": "load_store", "count": 3 * scale},
            {"pc": 0x1030, "opcode_family": "base_alu_reg", "count": 2 * scale},
            {"pc": 0x1040, "opcode_family": "mul", "count": scale},
        ]
        retired = sum(row["count"] for row in per_pc)
        return {
            "sample": {
                "segment_count": segment_count,
                "retired_instructions": retired,
                "opcode_family_rows": [
                    {"family": "base_alu_imm", "rows": 5 * scale},
                    {"family": "load_store", "rows": 7 * scale},
                    {"family": "base_alu_reg", "rows": 2 * scale},
                    {"family": "mul", "rows": scale},
                ],
            },
            "per_pc": per_pc,
            "execution_journal": self.journal_identity,
            "elf": self.elf_identity,
            "input": self.input_identity,
            "production": False,
            "no_extrapolation": True,
            "content_sha256": hashlib.sha256(str(segment_count).encode()).hexdigest(),
        }

    def loaded(self) -> tuple[list[dict], list[dict]]:
        values = [
            self.value(segment_count, index + 1)
            for index, segment_count in enumerate(ledger_v2.EXPECTED_PREFIX_SEGMENTS)
        ]
        identities = [identity(path) for path in self.hotspot_paths]
        return values, identities

    def test_symbol_parser_overlap_and_named_rankings(self) -> None:
        symbols, projection = ledger_v2._elf_symbols(self.elf_identity)
        self.assertEqual(len(projection), 64)
        assignments = ledger_v2._symbol_assignments(
            symbols, [0x1000, 0x1010, 0x1020, 0x1030, 0x1040],
        )
        self.assertEqual(assignments[0x1000]["name"], "native_keccak256")
        ranking = ledger_v2._rank_sample(self.value(1, 1), assignments)
        named = {
            row["hotspot_id"]: row for row in ranking["named_hotspots"]
        }
        self.assertEqual(named["native-keccak256"]["count"], 5)
        self.assertEqual(named["compiler-builtins-memcpy"]["count"], 3)
        self.assertEqual(ranking["opcode_family_ranking"][0]["family"], "load_store")
        self.assertTrue(ranking["coverage"]["no_extrapolation"])

    def test_superseding_projection_and_lt_mul_mulh_cost_close(self) -> None:
        values, identities = self.loaded()
        result = ledger_v2._build_loaded(
            self.base, identity(self.base_path), values, identities,
        )
        projection = result["source_verified_projections"][
            "lt_mul_mulh_two_read_alias"
        ]
        self.assertEqual(
            projection["projection"]["saved_raw_bytes"], 1_067_177_472,
        )
        self.assertFalse(projection["production_promotion_eligible"])
        self.assertIsNone(result["claims"]["sample_to_full_corpus_extrapolation"])
        self.assertEqual(
            [row["ranking"]["coverage"]["segment_count"]
             for row in result["pc_hotspots"]["prefix_rankings"]],
            [1, 16, 64],
        )

    def test_nonmonotonic_prefix_and_identity_mutations_reject(self) -> None:
        values, identities = self.loaded()
        values[1]["per_pc"][0]["count"] = 1
        with self.assertRaises(ledger_v2.OpportunityLedgerV2Error):
            ledger_v2._build_loaded(
                self.base, identity(self.base_path), values, identities,
            )

        values, identities = self.loaded()
        values[2]["no_extrapolation"] = False
        with self.assertRaises(ledger_v2.OpportunityLedgerV2Error):
            ledger_v2._build_loaded(
                self.base, identity(self.base_path), values, identities,
            )

        malformed = bytearray(self.elf.read_bytes())
        malformed[18:20] = struct.pack("<H", 62)
        self.elf.write_bytes(malformed)
        with self.assertRaises(ledger_v2.OpportunityLedgerV2Error):
            ledger_v2._elf_symbols(identity(self.elf))


if __name__ == "__main__":
    unittest.main()
