from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import sm83_frontend_gate


class Sm83FrontendGateTests(unittest.TestCase):
    def test_mooneye_release_url_names_the_pinned_directory_asset(self) -> None:
        release = sm83_frontend_gate.MOONEYE_RELEASE
        self.assertTrue(
            sm83_frontend_gate.MOONEYE_RELEASE_URL.endswith(
                f"/{release}/{release}.tar.xz"
            )
        )

    def test_mooneye_gate_appends_one_rom_after_the_release_directory(self) -> None:
        release = Path("/pinned/mooneye-release")
        relative_rom = "acceptance/timer/div_write.gb"
        with mock.patch.object(sm83_frontend_gate, "run") as run:
            sm83_frontend_gate.mooneye_gate(release, relative_rom)
        run.assert_called_once_with(
            "Mooneye focused machine",
            [
                "zig",
                "build",
                "test-mooneye-focused",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(release),
                "--rom",
                relative_rom,
            ],
        )

    def test_live_ppu_gate_is_a_distinct_short_command(self) -> None:
        release = Path("/pinned/mooneye-release")
        with mock.patch.object(sm83_frontend_gate, "run") as run:
            sm83_frontend_gate.mooneye_ppu_gate(release)
        run.assert_called_once_with(
            "Mooneye live PPU machine (2 ROMs, 2 detached controls)",
            [
                "zig",
                "build",
                "test-mooneye-ppu-live",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(release),
            ],
        )

    def test_live_dma_gate_is_a_distinct_short_command(self) -> None:
        release = Path("/pinned/mooneye-release")
        with mock.patch.object(sm83_frontend_gate, "run") as run:
            sm83_frontend_gate.mooneye_dma_gate(release)
        run.assert_called_once_with(
            "Mooneye live DMA machine (1 ROM, 2 negative controls)",
            [
                "zig",
                "build",
                "test-mooneye-dma-live",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(release),
            ],
        )

    def test_pokemon_fixture_is_a_distinct_external_gate(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(sm83_frontend_gate, "run") as run,
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_hardware_surface_gate",
            ) as hardware_surface,
        ):
            sm83_frontend_gate.pokemon_gate(corpus, prove=False)
        hardware_surface.assert_called_once_with(corpus)
        run.assert_called_once_with(
            "Pokemon checkpoint fixture",
            [
                "zig",
                "build",
                "test-pokemon-fixture",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
            ],
        )

    def test_pokemon_hardware_surface_is_a_distinct_short_gate(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with mock.patch.object(sm83_frontend_gate, "run") as run:
            sm83_frontend_gate.pokemon_hardware_surface_gate(corpus)
        run.assert_called_once_with(
            "Pokemon hardware surface",
            [
                "zig",
                "build",
                "test-pokemon-hardware-surface",
                "--build-file",
                "src/frontends/sm83/build.zig",
                "-Doptimize=ReleaseFast",
                f"-Dpokemon-corpus={corpus}",
                "-j2",
            ],
        )

    def test_pokemon_proof_defaults_secure_on_each_backend_without_fallback(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        cases = (
            ("CPU/SIMD", False, "src/integrations/sm83_cpu/build.zig"),
            ("Metal", True, "src/integrations/sm83_metal/build.zig"),
        )
        for backend, metal, build_file in cases:
            with (
                self.subTest(backend=backend),
                mock.patch.object(sm83_frontend_gate, "run") as run,
                mock.patch.object(
                    sm83_frontend_gate,
                    "pokemon_hardware_surface_gate",
                ) as hardware_surface,
            ):
                sm83_frontend_gate.pokemon_gate(
                    corpus,
                    prove=True,
                    metal=metal,
                )
            hardware_surface.assert_called_once_with(corpus)
            run.assert_called_once_with(
                f"{backend} Pokemon checkpoint proof (secure)",
                [
                    "zig",
                    "build",
                    "test-pokemon-checkpoint",
                    "--build-file",
                    build_file,
                    "-Doptimize=ReleaseFast",
                    "--",
                    str(corpus),
                ],
            )

    def test_pokemon_battle_chain_defaults_secure(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(sm83_frontend_gate, "run") as run,
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_hardware_surface_gate",
            ) as hardware_surface,
        ):
            sm83_frontend_gate.pokemon_chain_gate(corpus)
        hardware_surface.assert_called_once_with(corpus)
        run.assert_called_once_with(
            "CPU/SIMD Pokemon battle chain (secure)",
            [
                "zig",
                "build",
                "test-pokemon-battle-chain",
                "--build-file",
                "src/integrations/sm83_cpu/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
            ],
        )

    def test_pokemon_battle_chain_forwards_a_bounded_chunk_count(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(sm83_frontend_gate, "run") as run,
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_hardware_surface_gate",
            ) as hardware_surface,
        ):
            sm83_frontend_gate.pokemon_chain_gate(
                corpus,
                smoke=True,
                chunks=17,
            )
        hardware_surface.assert_called_once_with(corpus)
        run.assert_called_once_with(
            "CPU/SIMD Pokemon battle chain (smoke)",
            [
                "zig",
                "build",
                "test-pokemon-battle-chain",
                "--build-file",
                "src/integrations/sm83_cpu/build.zig",
                "-Doptimize=ReleaseFast",
                "--",
                str(corpus),
                "--smoke",
                "--chunks",
                "17",
            ],
        )
        for chunks in (0, 257):
            with self.assertRaises(ValueError):
                sm83_frontend_gate.pokemon_chain_gate(corpus, chunks=chunks)

    def test_pokemon_start_release_follows_corpus_for_every_gate(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        cases = (
            (
                False,
                False,
                False,
                "Pokemon checkpoint START-release fixture",
                "src/frontends/sm83/build.zig",
                "test-pokemon-fixture",
                [],
            ),
            (
                True,
                False,
                False,
                "CPU/SIMD Pokemon checkpoint START-release proof (secure)",
                "src/integrations/sm83_cpu/build.zig",
                "test-pokemon-checkpoint",
                [],
            ),
            (
                True,
                True,
                True,
                "Metal Pokemon checkpoint START-release proof (smoke)",
                "src/integrations/sm83_metal/build.zig",
                "test-pokemon-checkpoint",
                ["--smoke"],
            ),
        )
        for prove, metal, smoke, label, build_file, step, trailing in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(sm83_frontend_gate, "run") as run,
                mock.patch.object(
                    sm83_frontend_gate,
                    "pokemon_hardware_surface_gate",
                ) as hardware_surface,
            ):
                sm83_frontend_gate.pokemon_gate(
                    corpus,
                    prove=prove,
                    metal=metal,
                    smoke=smoke,
                    start_release=True,
                )
            hardware_surface.assert_called_once_with(corpus)
            run.assert_called_once_with(
                label,
                [
                    "zig",
                    "build",
                    step,
                    "--build-file",
                    build_file,
                    "-Doptimize=ReleaseFast",
                    "--",
                    str(corpus),
                    "--start-release",
                    *trailing,
                ],
            )

    def test_pokemon_proof_fast_routes_exactly_to_fixture_and_each_backend(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        cases = (
            (
                False,
                False,
                "Pokemon checkpoint proof-fast fixture",
                "src/frontends/sm83/build.zig",
                "test-pokemon-fixture",
            ),
            (
                True,
                False,
                "CPU/SIMD Pokemon checkpoint proof-fast proof (secure)",
                "src/integrations/sm83_cpu/build.zig",
                "test-pokemon-checkpoint",
            ),
            (
                True,
                True,
                "Metal Pokemon checkpoint proof-fast proof (secure)",
                "src/integrations/sm83_metal/build.zig",
                "test-pokemon-checkpoint",
            ),
        )
        for prove, metal, label, build_file, step in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(sm83_frontend_gate, "run") as run,
                mock.patch.object(
                    sm83_frontend_gate,
                    "pokemon_hardware_surface_gate",
                ) as hardware_surface,
            ):
                sm83_frontend_gate.pokemon_gate(
                    corpus,
                    prove=prove,
                    metal=metal,
                    proof_fast=True,
                )
            hardware_surface.assert_not_called()
            run.assert_called_once_with(
                label,
                [
                    "zig",
                    "build",
                    step,
                    "--build-file",
                    build_file,
                    "-Doptimize=ReleaseFast",
                    "--",
                    str(corpus),
                    "--proof-fast",
                ],
            )

    def test_pokemon_proof_fast_chunks_route_exactly_without_visual_audit(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        gates = (
            (
                False,
                False,
                "Pokemon checkpoint proof-fast-chunk-{chunk} fixture",
                "src/frontends/sm83/build.zig",
                "test-pokemon-fixture",
            ),
            (
                True,
                False,
                "CPU/SIMD Pokemon checkpoint proof-fast-chunk-{chunk} proof (secure)",
                "src/integrations/sm83_cpu/build.zig",
                "test-pokemon-checkpoint",
            ),
            (
                True,
                True,
                "Metal Pokemon checkpoint proof-fast-chunk-{chunk} proof (secure)",
                "src/integrations/sm83_metal/build.zig",
                "test-pokemon-checkpoint",
            ),
        )
        for chunk in (1, 2):
            for prove, metal, label, build_file, step in gates:
                with (
                    self.subTest(chunk=chunk, backend=label),
                    mock.patch.object(sm83_frontend_gate, "run") as run,
                    mock.patch.object(
                        sm83_frontend_gate,
                        "pokemon_hardware_surface_gate",
                    ) as hardware_surface,
                ):
                    sm83_frontend_gate.pokemon_gate(
                        corpus,
                        prove=prove,
                        metal=metal,
                        proof_fast_chunk=chunk,
                    )
                hardware_surface.assert_not_called()
                run.assert_called_once_with(
                    label.format(chunk=chunk),
                    [
                        "zig",
                        "build",
                        step,
                        "--build-file",
                        build_file,
                        "-Doptimize=ReleaseFast",
                        "--",
                        str(corpus),
                        f"--proof-fast-chunk-{chunk}",
                    ],
                )

    def test_pokemon_smoke_parser_routes_without_running_the_opcode_corpus(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--pokemon-proof",
                    "--pokemon-dir",
                    str(corpus),
                    "--smoke",
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_root",
                return_value=corpus,
            ),
            mock.patch.object(sm83_frontend_gate, "pokemon_gate") as gate,
            mock.patch.object(sm83_frontend_gate, "gate") as corpus_gate,
        ):
            sm83_frontend_gate.main()
        gate.assert_called_once_with(
            corpus,
            prove=True,
            metal=False,
            smoke=True,
            start_release=False,
            battle_chunk=None,
            proof_fast=False,
            proof_fast_chunk=None,
        )
        corpus_gate.assert_not_called()

    def test_pokemon_hardware_surface_parser_routes_only_to_the_audit(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--pokemon-hardware-surface",
                    "--pokemon-dir",
                    str(corpus),
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_root",
                return_value=corpus,
            ) as pokemon_root,
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_hardware_surface_gate",
            ) as hardware_surface,
            mock.patch.object(sm83_frontend_gate, "gate") as corpus_gate,
        ):
            sm83_frontend_gate.main()
        pokemon_root.assert_called_once_with(corpus)
        hardware_surface.assert_called_once_with(corpus)
        corpus_gate.assert_not_called()

    def test_pokemon_chain_parser_routes_security_and_chunk_count(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--pokemon-battle-chain",
                    "--pokemon-dir",
                    str(corpus),
                    "--smoke",
                    "--chain-chunks",
                    "17",
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_root",
                return_value=corpus,
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_chain_gate",
            ) as chain,
        ):
            sm83_frontend_gate.main()
        chain.assert_called_once_with(corpus, smoke=True, chunks=17)

    def test_pokemon_start_release_parser_routes_to_fixture(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--pokemon-fixture",
                    "--pokemon-dir",
                    str(corpus),
                    "--start-release",
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "pokemon_root",
                return_value=corpus,
            ),
            mock.patch.object(sm83_frontend_gate, "pokemon_gate") as gate,
        ):
            sm83_frontend_gate.main()
        gate.assert_called_once_with(
            corpus,
            prove=False,
            start_release=True,
            battle_chunk=None,
            proof_fast=False,
            proof_fast_chunk=None,
        )

    def test_missing_pokemon_root_and_action_flags_fail_closed_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaisesRegex(
                SystemExit,
                "missing pinned Pokemon corpus directory",
            ):
                sm83_frontend_gate.pokemon_root(missing)
        for flag in (
            "--smoke",
            "--start-release",
            "--battle-chunk",
            "--proof-fast",
            "--chain-chunks",
        ):
            with (
                self.subTest(flag=flag),
                mock.patch.object(
                    sys,
                    "argv",
                    ["sm83_frontend_gate.py", flag],
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                sm83_frontend_gate.main()
            self.assertEqual(2, raised.exception.code)

        with (
            mock.patch.object(
                sys,
                "argv",
                ["sm83_frontend_gate.py", "--proof-fast-chunk", "1"],
            ),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            sm83_frontend_gate.main()
        self.assertEqual(2, raised.exception.code)

    def test_pokemon_proof_fast_chunk_rejects_unpinned_indices(self) -> None:
        for chunk in (0, 3):
            with (
                self.subTest(chunk=chunk),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "sm83_frontend_gate.py",
                        "--pokemon-fixture",
                        "--proof-fast-chunk",
                        str(chunk),
                    ],
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                sm83_frontend_gate.main()
            self.assertEqual(2, raised.exception.code)

    def test_pokemon_proof_fast_chunk_rejects_other_fixture_profiles(self) -> None:
        cases = (
            ["--start-release"],
            ["--battle-chunk", "1"],
            ["--proof-fast"],
        )
        for profile in cases:
            with (
                self.subTest(profile=profile[0]),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "sm83_frontend_gate.py",
                        "--pokemon-fixture",
                        "--proof-fast-chunk",
                        "1",
                        *profile,
                    ],
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                sm83_frontend_gate.main()
            self.assertEqual(2, raised.exception.code)

    def test_pokemon_proof_fast_rejects_other_fixture_profiles(self) -> None:
        for profile in ("--start-release", "--battle-chunk"):
            arguments = ["--pokemon-fixture", "--proof-fast", profile]
            if profile == "--battle-chunk":
                arguments.append("1")
            with (
                self.subTest(profile=profile),
                mock.patch.object(
                    sys,
                    "argv",
                    ["sm83_frontend_gate.py", *arguments],
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                sm83_frontend_gate.main()
            self.assertEqual(2, raised.exception.code)

    def test_pokemon_battle_chunk_routes_to_each_backend(self) -> None:
        corpus = Path("/pinned/PE-AGI/v1")
        cases = (
            (
                False,
                False,
                "Pokemon checkpoint battle-chunk-1 fixture",
                "src/frontends/sm83/build.zig",
                "test-pokemon-fixture",
            ),
            (
                True,
                False,
                "CPU/SIMD Pokemon checkpoint battle-chunk-1 proof (secure)",
                "src/integrations/sm83_cpu/build.zig",
                "test-pokemon-checkpoint",
            ),
            (
                True,
                True,
                "Metal Pokemon checkpoint battle-chunk-1 proof (secure)",
                "src/integrations/sm83_metal/build.zig",
                "test-pokemon-checkpoint",
            ),
        )
        for prove, metal, label, build_file, step in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(sm83_frontend_gate, "run") as run,
                mock.patch.object(
                    sm83_frontend_gate,
                    "pokemon_hardware_surface_gate",
                ) as hardware_surface,
            ):
                sm83_frontend_gate.pokemon_gate(
                    corpus,
                    prove=prove,
                    metal=metal,
                    battle_chunk=1,
                )
            hardware_surface.assert_called_once_with(corpus)
            run.assert_called_once_with(
                label,
                [
                    "zig",
                    "build",
                    step,
                    "--build-file",
                    build_file,
                    "-Doptimize=ReleaseFast",
                    "--",
                    str(corpus),
                    "--battle-chunk-1",
                ],
            )

    def test_live_ppu_parser_forwards_only_to_its_gate(self) -> None:
        release = Path("/pinned/mooneye-release")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--mooneye-ppu-live",
                    "--mooneye-dir",
                    str(release),
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "run_mooneye_ppu",
            ) as run_mooneye_ppu,
        ):
            sm83_frontend_gate.main()
        run_mooneye_ppu.assert_called_once_with(release)

    def test_live_dma_parser_forwards_only_to_its_gate(self) -> None:
        release = Path("/pinned/mooneye-release")
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--mooneye-dma-live",
                    "--mooneye-dir",
                    str(release),
                ],
            ),
            mock.patch.object(
                sm83_frontend_gate,
                "run_mooneye_dma",
            ) as run_mooneye_dma,
        ):
            sm83_frontend_gate.main()
        run_mooneye_dma.assert_called_once_with(release)

    def test_mooneye_rom_parser_forwards_only_to_the_focused_gate(self) -> None:
        release = Path("/pinned/mooneye-release")
        relative_rom = "acceptance/timer/div_write.gb"
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sm83_frontend_gate.py",
                    "--mooneye-focused",
                    "--mooneye-dir",
                    str(release),
                    "--mooneye-rom",
                    relative_rom,
                ],
            ),
            mock.patch.object(sm83_frontend_gate, "run_mooneye") as run_mooneye,
        ):
            sm83_frontend_gate.main()
        run_mooneye.assert_called_once_with(release, relative_rom)

    def test_mooneye_rom_rejects_every_other_scope(self) -> None:
        cases = (
            ("missing focused gate", []),
            ("precommit", ["--mooneye-focused", "--precommit"]),
            ("opcode", ["--mooneye-focused", "--opcode", "00"]),
            ("proof", ["--mooneye-focused", "--proof"]),
            ("Blargg", ["--mooneye-focused", "--blargg-flat"]),
        )
        for label, arguments in cases:
            with (
                self.subTest(scope=label),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "sm83_frontend_gate.py",
                        *arguments,
                        "--mooneye-rom",
                        "acceptance/timer/div_write.gb",
                    ],
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                sm83_frontend_gate.main()
            self.assertEqual(2, raised.exception.code)

    def test_missing_mooneye_release_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-release"
            with (
                mock.patch.object(sm83_frontend_gate, "mooneye_gate") as gate,
                self.assertRaisesRegex(
                    SystemExit,
                    "missing pinned Mooneye release directory",
                ),
            ):
                sm83_frontend_gate.run_mooneye(
                    missing,
                    "acceptance/timer/div_write.gb",
                )
        gate.assert_not_called()

    def test_missing_explicit_live_ppu_release_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-release"
            with (
                mock.patch.object(
                    sm83_frontend_gate,
                    "mooneye_ppu_gate",
                ) as gate,
                self.assertRaisesRegex(
                    SystemExit,
                    "missing pinned Mooneye release directory",
                ),
            ):
                sm83_frontend_gate.run_mooneye_ppu(missing)
        gate.assert_not_called()

    def test_missing_explicit_live_dma_release_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-release"
            with (
                mock.patch.object(
                    sm83_frontend_gate,
                    "mooneye_dma_gate",
                ) as gate,
                self.assertRaisesRegex(
                    SystemExit,
                    "missing pinned Mooneye release directory",
                ),
            ):
                sm83_frontend_gate.run_mooneye_dma(missing)
        gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
