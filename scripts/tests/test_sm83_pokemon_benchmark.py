from __future__ import annotations

import unittest
from pathlib import Path

from scripts import sm83_pokemon_benchmark as benchmark


class Sm83PokemonBenchmarkTests(unittest.TestCase):
    def test_power_source_keeps_only_non_sensitive_supply_identity(self) -> None:
        self.assertEqual(
            "AC Power",
            benchmark.power_source(
                "Now drawing from 'AC Power'\n"
                " -InternalBattery-0 (id=123) 100%; charged"
            ),
        )

    def test_full_battle_target_rejects_marker_drift(self) -> None:
        manifest = {
            "schema": "pe-agi-sameboy-battle-trace-v1",
            "proof_ready": False,
            "battle_rows": 447_516,
            "battle_mcycles": 4_899_537,
            "battle_end_row": 447_516,
            "trace_rows": 1_048_576,
            "padding_rows_after_battle": 601_060,
            "markers": {
                "start": {"bank": 1, "pc": 20_094},
                "end": {"bank": 1, "pc": 20_099},
            },
            "chunks": [{"contains_battle_end": True}],
        }
        self.assertEqual(
            20_099,
            benchmark.validate_full_battle_manifest(manifest)["end_pc"],
        )
        manifest["markers"]["end"]["pc"] ^= 1
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_full_battle_manifest(manifest)

    def test_commands_use_exact_long_and_verified_profiles(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        self.assertEqual(
            [
                "zig",
                "build",
                "benchmark-pokemon-prepare",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
                "--proof-fast-turn",
            ],
            benchmark.command_for_prepare("zig", corpus),
        )
        self.assertEqual(
            [
                "zig",
                "build",
                "test-pokemon-checkpoint",
                "--build-file",
                "src/integrations/sm83_metal/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
                "--proof-fast-turn",
            ],
            benchmark.command_for_proof("zig", corpus, "metal"),
        )

    def test_receipts_fail_closed_on_count_drift(self) -> None:
        prepared = (
            "SM83 Pokemon fixture: PREPARED rows=262144 callbacks=54602 "
            "mcycles=330527 lookahead_rows=3684 oracle_records=200480 "
            "party_count=1 first_species=0x84 dma_sources=3040"
        )
        self.assertEqual(
            262_144,
            benchmark.parse_counts(
                benchmark.PREPARED_PATTERN,
                prepared,
                benchmark.LONG_RECEIPT_EXPECTED,
            )["rows"],
        )
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.parse_counts(
                benchmark.PREPARED_PATTERN,
                prepared.replace("callbacks=54602", "callbacks=54601"),
                benchmark.LONG_RECEIPT_EXPECTED,
            )


if __name__ == "__main__":
    unittest.main()
