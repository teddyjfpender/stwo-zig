"""Command-line surface for the local SM83 frontend gate."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path


def parse_args(
    argv: Sequence[str] | None = None,
) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(
        description="Pinned SM83 differential, proof, and local pre-commit gate"
    )
    parser.add_argument("--corpus-dir", type=Path)
    parser.add_argument("--blargg-dir", type=Path)
    parser.add_argument("--mooneye-dir", type=Path)
    parser.add_argument("--pokemon-dir", type=Path)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--opcode", metavar="HEX", help="run one opcode: 80 or cb:11")
    scope.add_argument(
        "--cartridge",
        action="store_true",
        help="run only the cartridge runner and AIR feedback slice",
    )
    scope.add_argument(
        "--cartridge-proof",
        action="store_true",
        help="run only cartridge statement and proof-component geometry",
    )
    scope.add_argument(
        "--joypad",
        action="store_true",
        help="run only the joypad runner and AIR feedback slice",
    )
    scope.add_argument(
        "--environment",
        action="store_true",
        help="run only the environment statement and replay feedback slice",
    )
    scope.add_argument(
        "--intermediate-ram-observation",
        action="store_true",
        help="run only the intermediate RAM observation lookup slice",
    )
    scope.add_argument(
        "--scheduler",
        action="store_true",
        help="run only the scheduler semantics and IE/IF lookup slice",
    )
    scope.add_argument(
        "--ppu",
        action="store_true",
        help="run only the PPU timing, binding, and MMIO lookup slice",
    )
    scope.add_argument(
        "--dma",
        action="store_true",
        help="run only the DMA semantics, binding, and execution lookup slice",
    )
    scope.add_argument(
        "--pokemon-hardware-surface",
        action="store_true",
        help="audit exact MMIO, VRAM, DMA, and safety counts for the pinned replay",
    )
    scope.add_argument(
        "--pokemon-fixture",
        action="store_true",
        help="prepare and validate the pinned Pokemon checkpoint proof input",
    )
    scope.add_argument(
        "--pokemon-proof",
        action="store_true",
        help="prove and verify the pinned Pokemon checkpoint slice on CPU/SIMD",
    )
    scope.add_argument(
        "--pokemon-battle-chain",
        action="store_true",
        help="prove, verify, and join contiguous pinned battle chunks (default three)",
    )
    scope.add_argument(
        "--family",
        choices=(
            "misc",
            "load8",
            "load16",
            "increment_decrement8",
            "increment_decrement16",
            "alu8",
            "alu16",
            "rotate_accumulator",
            "branch",
            "stack",
            "interrupt",
            "rotate_shift",
            "bit",
            "reset_set",
        ),
    )
    parser.add_argument(
        "--proof",
        action="store_true",
        help="also run the current CPU/SIMD execution proof and mutation checks",
    )
    parser.add_argument(
        "--metal",
        action="store_true",
        help="also prove and verify through the Metal adapter",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="use the three-query development profile for a Pokemon proof or battle chain",
    )
    pokemon_profile = parser.add_mutually_exclusive_group()
    pokemon_profile.add_argument(
        "--start-release",
        action="store_true",
        help=(
            "run the pinned START-release action profile; requires "
            "--pokemon-fixture or --pokemon-proof"
        ),
    )
    pokemon_profile.add_argument(
        "--battle-chunk",
        type=int,
        metavar="INDEX",
        help=(
            "run one pinned 2^17-row battle chunk by positive index; requires "
            "--pokemon-fixture or --pokemon-proof"
        ),
    )
    pokemon_profile.add_argument(
        "--proof-fast",
        action="store_true",
        help=(
            "run the pinned _ROGUE_FAST ROM profile; requires "
            "--pokemon-fixture or --pokemon-proof"
        ),
    )
    pokemon_profile.add_argument(
        "--proof-fast-chunk",
        type=int,
        metavar="INDEX",
        help=(
            "run pinned _ROGUE_FAST chunk 1 or 2; requires "
            "--pokemon-fixture or --pokemon-proof"
        ),
    )
    parser.add_argument(
        "--chain-chunks",
        type=int,
        metavar="COUNT",
        help="prove this many contiguous battle chunks; requires --pokemon-battle-chain",
    )
    parser.add_argument(
        "--blargg-flat",
        action="store_true",
        help="run the pinned 11-ROM Blargg cpu_instrs gate only",
    )
    parser.add_argument(
        "--mooneye-focused",
        action="store_true",
        help="run the 25 pinned PPU-independent Mooneye ROMs only",
    )
    parser.add_argument(
        "--mooneye-ppu-live",
        action="store_true",
        help="run the 2 pinned live-PPU Mooneye ROMs and detached controls only",
    )
    parser.add_argument(
        "--mooneye-dma-live",
        action="store_true",
        help="run the pinned live-DMA Mooneye ROM and negative controls only",
    )
    parser.add_argument(
        "--mooneye-rom",
        metavar="RELEASE_RELATIVE_PATH",
        help="run one pinned Mooneye ROM; requires --mooneye-focused",
    )
    parser.add_argument(
        "--precommit",
        action="store_true",
        help="run the complete local SM83 gate; cannot be scoped",
    )
    return parser, parser.parse_args(argv)
