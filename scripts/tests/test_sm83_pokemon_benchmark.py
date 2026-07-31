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
            "scenario": "proof-benchmark",
            "battle_rows": 594_575,
            "battle_mcycles": 1_436_786,
            "battle_end_row": 594_575,
            "trace_rows": 1_048_576,
            "padding_rows_after_battle": 454_001,
            "markers": {
                "start": {"bank": 1, "pc": 20_153},
                "end": {"bank": 1, "pc": 20_167},
            },
            "input": {"count": 33},
            "battle_logic": {"count": 16},
            "chunks": [{"contains_battle_end": True}],
        }
        self.assertEqual(
            20_167,
            benchmark.validate_full_battle_manifest(manifest)["end_pc"],
        )
        manifest["markers"]["end"]["pc"] ^= 1
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_full_battle_manifest(manifest)

    def test_commands_use_exact_audit_and_battle_profiles(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        self.assertEqual(
            [
                "zig",
                "build",
                "test-pokemon-hardware-surface",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                f"-Dpokemon-corpus={corpus}",
            ],
            benchmark.command_for_hardware_audit("zig", corpus),
        )
        self.assertEqual(
            [
                "zig",
                "build",
                "test-pokemon-battle-chain",
                "--build-file",
                "src/integrations/sm83_metal/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
            ],
            benchmark.command_for_proof("zig", corpus, "metal"),
        )

    def test_receipts_fail_closed_on_count_drift(self) -> None:
        receipt = (
            "SM83 Pokemon CPU battle proof: PASS proof_ready=true "
            "security_bits=96 chunks=12 rows=786432 mcycles=1505332 "
            "callbacks=601239 actions=33 dma_sources=13600 "
            "initial_mcycle=5967321 final_mcycle=7472653 "
            f"action_digest={benchmark.EXPECTED_ACTION_DIGEST} "
            f"final_system_digest={benchmark.EXPECTED_FINAL_SYSTEM_DIGEST} "
            "battle_result=0 enemy_hp=0 battle_hp=180 party_hp=430 "
            "in_battle=0 stage=1 "
            f"rom_digest={'00' * 32} initial_system_digest={'01' * 32} "
            f"initial_sram_digest={'02' * 32} final_sram_digest={'03' * 32} "
            f"first_statement_digest={'04' * 32} last_statement_digest={'05' * 32}"
        )
        self.assertEqual(
            786_432,
            benchmark.parse_proof_receipt(receipt)["rows"],
        )
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.parse_proof_receipt(
                receipt.replace("callbacks=601239", "callbacks=601238")
            )


if __name__ == "__main__":
    unittest.main()
