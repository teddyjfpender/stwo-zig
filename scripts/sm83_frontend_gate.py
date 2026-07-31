#!/usr/bin/env python3
"""Fail-closed SM83 corpus, ROM, checkpoint, and proof gates."""

from __future__ import annotations

import hashlib
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

try:
    from . import sm83_frontend_gate_args, sm83_pokemon_gate
except ImportError:
    import sm83_frontend_gate_args
    import sm83_pokemon_gate


ROOT = Path(__file__).resolve().parents[1]
CORPUS_REPOSITORY = "https://github.com/SingleStepTests/sm83"
CORPUS_REVISION = "f9c30210245dd691661db39f5ace022c465ecc2f"
BLARGG_REPOSITORY = "https://github.com/retrio/gb-test-roms"
BLARGG_REVISION = "c240dd7d700e5c0b00a7bbba52b53e4ee67b5f15"
MOONEYE_RELEASE = "mts-20260714-0944-31510e1"
MOONEYE_RELEASE_SHA256 = "6d4fdda2f1d8d2f5f51b0ff3f6f3cc2fbae047aa395a39c82bda3a0e7cbd2641"
MOONEYE_RELEASE_SIZE = 51_248
MOONEYE_RELEASE_URL = (
    f"https://gekkio.fi/files/mooneye-test-suite/{MOONEYE_RELEASE}.tar.xz"
)


def run(label: str, command: list[str]) -> None:
    started = time.perf_counter()
    print(f"[sm83] START {label}: {shlex.join(command)}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)
    print(f"[sm83] PASS  {label} ({time.perf_counter() - started:.2f}s)", flush=True)


def gate(corpus_v1: Path, *, opcode: str | None, family: str | None) -> None:
    command = [
        "zig",
        "build",
        "test-corpus",
        "--build-file",
        "src/frontends/sm83/build.zig",
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus_v1),
    ]
    if opcode is not None:
        command.extend(["--opcode", opcode])
    elif family is not None:
        command.extend(["--family", family])
    scope = (
        f"opcode {opcode}"
        if opcode
        else f"family {family}"
        if family
        else "full corpus"
    )
    run(scope, command)


def integration_proof_gate(
    backend: str,
    build_file: str,
    optimize: str,
) -> None:
    for step, scope in (
        ("test", "package proof suite"),
        (
            "test-machine-environment",
            "machine-environment proof and adversarial mutations",
        ),
    ):
        run(
            f"{backend} {scope}",
            [
                "zig",
                "build",
                step,
                "--build-file",
                build_file,
                f"-Doptimize={optimize}",
                "-j2",
            ],
        )


def proof_gate() -> None:
    integration_proof_gate(
        "CPU/SIMD",
        "src/integrations/sm83_cpu/build.zig",
        "ReleaseFast",
    )


def metal_gate() -> None:
    integration_proof_gate(
        "Metal",
        "src/integrations/sm83_metal/build.zig",
        "ReleaseSafe",
    )


def pokemon_gate(
    corpus_root: Path,
    *,
    prove: bool,
    metal: bool = False,
    smoke: bool = False,
    start_release: bool = False,
    battle_chunk: int | None = None,
    proof_fast: bool = False,
    proof_fast_chunk: int | None = None,
) -> None:
    if not proof_fast and proof_fast_chunk is None:
        pokemon_hardware_surface_gate(corpus_root)
    sm83_pokemon_gate.gate(
        corpus_root,
        prove=prove,
        run=run,
        metal=metal,
        smoke=smoke,
        start_release=start_release,
        battle_chunk=battle_chunk,
        proof_fast=proof_fast,
        proof_fast_chunk=proof_fast_chunk,
    )


def pokemon_root(explicit: Path | None) -> Path:
    return sm83_pokemon_gate.root(explicit, ROOT.parent / "PE-AGI" / "v1")


def pokemon_hardware_surface_gate(corpus_root: Path) -> None:
    run(
        "Pokemon hardware surface",
        [
            "zig",
            "build",
            "test-pokemon-hardware-surface",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            f"-Dpokemon-corpus={corpus_root}",
            "-j2",
        ],
    )


def pokemon_chain_gate(
    corpus_root: Path,
    *,
    smoke: bool = False,
    chunks: int | None = None,
) -> None:
    if chunks is not None and not 1 <= chunks <= 256:
        raise ValueError("Pokemon chain chunk count must be in 1...256")
    pokemon_hardware_surface_gate(corpus_root)
    sm83_pokemon_gate.chain(
        corpus_root,
        run=run,
        smoke=smoke,
        chunks=chunks,
    )


def frontend_leaf_gate(name: str) -> None:
    run(
        f"{name} runner and AIR",
        [
            "zig",
            "build",
            f"test-{name}",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            "-j2",
        ],
    )


def blargg_gate(rom_directory: Path) -> None:
    run(
        "Blargg flat cpu_instrs",
        [
            "zig",
            "build",
            "test-blargg-flat",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            "--",
            str(rom_directory),
        ],
    )


def run_blargg(explicit: Path | None) -> None:
    if explicit is not None:
        blargg_gate(explicit.resolve())
        return
    sibling = ROOT.parent / "gb-test-roms" / "cpu_instrs" / "individual"
    if sibling.is_dir():
        blargg_gate(sibling)
        return
    with tempfile.TemporaryDirectory(prefix="stwo-sm83-blargg-") as temporary:
        checkout = Path(temporary) / "gb-test-roms"
        run("Blargg checkout init", ["git", "init", str(checkout)])
        run(
            "Blargg checkout fetch",
            [
                "git",
                "-C",
                str(checkout),
                "fetch",
                "--depth=1",
                BLARGG_REPOSITORY,
                BLARGG_REVISION,
            ],
        )
        run(
            "Blargg checkout pin",
            ["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"],
        )
        blargg_gate(checkout / "cpu_instrs" / "individual")


def mooneye_gate(
    rom_directory: Path,
    release_relative_rom: str | None = None,
) -> None:
    command = [
        "zig",
        "build",
        "test-mooneye-focused",
        "--build-file",
        "src/frontends/sm83/build.zig",
        "-Doptimize=ReleaseFast",
        "--",
        str(rom_directory),
    ]
    if release_relative_rom is not None:
        command.extend(["--rom", release_relative_rom])
    run(
        "Mooneye focused machine",
        command,
    )


def mooneye_ppu_gate(rom_directory: Path) -> None:
    run(
        "Mooneye live PPU machine (2 ROMs, 2 detached controls)",
        [
            "zig",
            "build",
            "test-mooneye-ppu-live",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            "--",
            str(rom_directory),
        ],
    )


def mooneye_dma_gate(rom_directory: Path) -> None:
    run(
        "Mooneye live DMA machine (1 ROM, 2 negative controls)",
        [
            "zig",
            "build",
            "test-mooneye-dma-live",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            "--",
            str(rom_directory),
        ],
    )


def download_mooneye_release(destination: Path) -> Path:
    archive = destination / f"{MOONEYE_RELEASE}.tar.xz"
    try:
        with urllib.request.urlopen(MOONEYE_RELEASE_URL) as response:
            payload = response.read(MOONEYE_RELEASE_SIZE + 1)
    except OSError as error:
        raise SystemExit(f"failed to download pinned Mooneye release: {error}")
    if len(payload) != MOONEYE_RELEASE_SIZE:
        raise SystemExit(
            "pinned Mooneye release size mismatch: "
            f"expected {MOONEYE_RELEASE_SIZE}, got {len(payload)}"
        )
    actual = hashlib.sha256(payload).hexdigest()
    if actual != MOONEYE_RELEASE_SHA256:
        raise SystemExit(
            "pinned Mooneye release digest mismatch: "
            f"expected {MOONEYE_RELEASE_SHA256}, got {actual}"
        )
    archive.write_bytes(payload)
    try:
        with tarfile.open(archive, mode="r:xz") as bundle:
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as error:
        raise SystemExit(f"failed to extract pinned Mooneye release: {error}")
    directory = destination / MOONEYE_RELEASE
    if not directory.is_dir():
        raise SystemExit(
            f"pinned Mooneye release omitted expected directory: {directory}"
        )
    return directory


def with_mooneye_release(
    explicit: Path | None,
    action: Callable[[Path], None],
) -> None:
    if explicit is not None:
        directory = explicit.resolve()
        if not directory.is_dir():
            raise SystemExit(
                f"missing pinned Mooneye release directory: {directory}"
            )
        action(directory)
        return
    sibling = ROOT.parent / "mooneye-test-suite-bin" / MOONEYE_RELEASE
    if sibling.is_dir():
        action(sibling)
        return
    with tempfile.TemporaryDirectory(prefix="stwo-sm83-mooneye-") as temporary:
        action(download_mooneye_release(Path(temporary)))


def run_mooneye(
    explicit: Path | None,
    release_relative_rom: str | None = None,
) -> None:
    with_mooneye_release(
        explicit,
        lambda directory: mooneye_gate(directory, release_relative_rom),
    )


def run_mooneye_ppu(explicit: Path | None) -> None:
    with_mooneye_release(explicit, mooneye_ppu_gate)


def run_mooneye_dma(explicit: Path | None) -> None:
    with_mooneye_release(explicit, mooneye_dma_gate)


def run_all_mooneye(explicit: Path | None) -> None:
    def gates(directory: Path) -> None:
        mooneye_gate(directory)
        mooneye_ppu_gate(directory)
        mooneye_dma_gate(directory)

    with_mooneye_release(explicit, gates)


def precommit(
    corpus_v1: Path,
    blargg_directory: Path | None,
    mooneye_directory: Path | None,
) -> None:
    run(
        "frontend unit tests",
        [
            "zig",
            "build",
            "test",
            "--build-file",
            "src/frontends/sm83/build.zig",
            "-Doptimize=ReleaseFast",
            "-j2",
        ],
    )
    gate(corpus_v1, opcode=None, family=None)
    run_blargg(blargg_directory)
    run_all_mooneye(mooneye_directory)
    proof_gate()
    if sys.platform == "darwin":
        metal_gate()
    else:
        print(
            "[sm83] NOT SELECTED Metal package and machine-environment proofs "
            "(requires macOS)",
            flush=True,
        )
    run(
        "format",
        ["zig", "fmt", "--check", "build.zig", "build_support", "src", "tools"],
    )
    run("package contracts", ["python3", "scripts/check_package_workspace.py"])
    run("authority pins", ["python3", "scripts/check_upstream_pins.py"])
    run("source conformance", ["python3", "scripts/check_source_conformance.py"])
    run(
        "CI package contracts",
        [
            "python3",
            "-m",
            "unittest",
            "scripts.tests.test_ci_package_graph",
            "scripts.tests.test_integration_package_ci_contract",
            "scripts.tests.test_sm83_frontend_gate",
            "scripts.tests.test_sm83_frontend_gate_contract",
        ],
    )
    run("clean patch", ["git", "diff", "--check"])


def main() -> None:
    parser, args = sm83_frontend_gate_args.parse_args()
    if args.precommit and (
        args.opcode
        or args.family
        or args.cartridge
        or args.cartridge_proof
        or args.joypad
        or args.environment
        or args.intermediate_ram_observation
        or args.scheduler
        or args.ppu
        or args.dma
        or args.pokemon_hardware_surface
        or args.pokemon_fixture
        or args.pokemon_proof
        or args.pokemon_battle_chain
        or args.proof
        or args.metal
        or args.smoke
        or args.start_release
        or args.battle_chunk is not None
        or args.proof_fast
        or args.proof_fast_chunk is not None
        or args.chain_chunks is not None
        or args.blargg_flat
        or args.mooneye_focused
        or args.mooneye_ppu_live
        or args.mooneye_dma_live
    ):
        parser.error(
            "--precommit cannot be combined with --opcode, --family, --proof, "
            "--metal, --cartridge, --cartridge-proof, --joypad, --environment, "
            "--intermediate-ram-observation, --scheduler, --ppu, --dma, "
            "--pokemon-hardware-surface, --pokemon-fixture, --pokemon-proof, "
            "--pokemon-battle-chain, "
            "--smoke, --blargg-flat, "
            "--start-release, --battle-chunk, --proof-fast, "
            "--proof-fast-chunk, --mooneye-focused, "
            "--chain-chunks, "
            "--mooneye-ppu-live, or "
            "--mooneye-dma-live"
        )
    if (
        args.cartridge
        or args.cartridge_proof
        or args.joypad
        or args.environment
        or args.intermediate_ram_observation
        or args.scheduler
        or args.ppu
        or args.dma
    ) and (
        args.proof
        or args.metal
        or args.smoke
        or args.blargg_flat
        or args.mooneye_focused
        or args.mooneye_ppu_live
        or args.mooneye_dma_live
    ):
        parser.error(
            "--cartridge, --cartridge-proof, --joypad, --environment, "
            "--intermediate-ram-observation, --scheduler, --ppu, and --dma are "
            "focused gates and cannot be combined with proof or ROM gates"
        )
    if args.pokemon_fixture and (args.proof or args.metal or args.smoke):
        parser.error(
            "--pokemon-fixture cannot be combined with --proof, --metal, or --smoke"
        )
    if args.pokemon_proof and (
        args.proof
        or args.blargg_flat
        or args.mooneye_focused
        or args.mooneye_ppu_live
        or args.mooneye_dma_live
    ):
        parser.error("--pokemon-proof cannot be combined with another proof or ROM gate")
    if args.pokemon_battle_chain and (
        args.proof
        or args.blargg_flat
        or args.mooneye_focused
        or args.mooneye_ppu_live
        or args.mooneye_dma_live
    ):
        parser.error(
            "--pokemon-battle-chain cannot be combined with another proof or ROM gate"
        )
    if args.smoke and not (args.pokemon_proof or args.pokemon_battle_chain):
        parser.error("--smoke requires --pokemon-proof or --pokemon-battle-chain")
    if args.pokemon_battle_chain and args.metal:
        parser.error("--pokemon-battle-chain currently verifies on CPU/SIMD")
    if args.start_release and not (args.pokemon_fixture or args.pokemon_proof):
        parser.error("--start-release requires --pokemon-fixture or --pokemon-proof")
    if args.battle_chunk is not None and not (
        args.pokemon_fixture or args.pokemon_proof
    ):
        parser.error(
            "--battle-chunk requires --pokemon-fixture or --pokemon-proof"
        )
    if args.proof_fast and not (args.pokemon_fixture or args.pokemon_proof):
        parser.error("--proof-fast requires --pokemon-fixture or --pokemon-proof")
    if args.proof_fast_chunk is not None and not (
        args.pokemon_fixture or args.pokemon_proof
    ):
        parser.error(
            "--proof-fast-chunk requires --pokemon-fixture or --pokemon-proof"
        )
    if args.chain_chunks is not None and not args.pokemon_battle_chain:
        parser.error("--chain-chunks requires --pokemon-battle-chain")
    if args.chain_chunks is not None and not 1 <= args.chain_chunks <= 256:
        parser.error("--chain-chunks COUNT must be in 1...256")
    if args.battle_chunk is not None and args.battle_chunk < 1:
        parser.error("--battle-chunk INDEX must be positive")
    if args.proof_fast_chunk is not None and args.proof_fast_chunk not in (1, 2):
        parser.error("--proof-fast-chunk INDEX must be 1 or 2")
    if args.pokemon_dir and not (
        args.pokemon_hardware_surface or
        args.pokemon_fixture or
        args.pokemon_proof or
        args.pokemon_battle_chain
    ):
        parser.error(
            "--pokemon-dir requires a Pokemon hardware audit, fixture, proof, "
            "or battle chain"
        )
    if (
        args.pokemon_hardware_surface or
        args.pokemon_fixture or
        args.pokemon_proof or
        args.pokemon_battle_chain
    ) and (
        args.corpus_dir or args.blargg_dir or args.mooneye_dir
    ):
        parser.error(
            "Pokemon gates cannot be combined with corpus, Blargg, or Mooneye directories"
        )
    if args.blargg_dir and not (args.blargg_flat or args.precommit):
        parser.error("--blargg-dir requires --blargg-flat or --precommit")
    if args.mooneye_dir and not (
        args.mooneye_focused
        or args.mooneye_ppu_live
        or args.mooneye_dma_live
        or args.precommit
    ):
        parser.error(
            "--mooneye-dir requires --mooneye-focused, "
            "--mooneye-ppu-live, --mooneye-dma-live, or --precommit"
        )
    if args.mooneye_ppu_live and (
        args.mooneye_focused
        or args.mooneye_dma_live
        or args.blargg_flat
        or args.opcode
        or args.family
        or args.proof
        or args.metal
    ):
        parser.error("--mooneye-ppu-live cannot be combined with another scope")
    if args.mooneye_dma_live and (
        args.mooneye_focused
        or args.mooneye_ppu_live
        or args.blargg_flat
        or args.opcode
        or args.family
        or args.proof
        or args.metal
    ):
        parser.error("--mooneye-dma-live cannot be combined with another scope")
    if args.mooneye_rom is not None:
        if not args.mooneye_focused:
            parser.error("--mooneye-rom requires --mooneye-focused")
        if (
            args.precommit
            or args.opcode
            or args.family
            or args.cartridge
            or args.cartridge_proof
            or args.joypad
            or args.environment
            or args.intermediate_ram_observation
            or args.scheduler
            or args.ppu
            or args.dma
            or args.proof
            or args.metal
            or args.blargg_flat
            or args.mooneye_ppu_live
            or args.mooneye_dma_live
        ):
            parser.error(
                "--mooneye-rom cannot be combined with precommit or another scope"
            )
    if args.proof and (
        args.opcode
        or (
            args.family
            and args.family
            not in (
                "alu8",
                "bit",
                "branch",
                "increment_decrement8",
                "increment_decrement16",
                "load8",
                "load16",
                "misc",
                "reset_set",
                "rotate_accumulator",
                "rotate_shift",
                "stack",
                "interrupt",
            )
        )
    ):
        parser.error(
            "--proof requires the full corpus or a family with a live proof component"
        )
    if args.metal and sys.platform != "darwin":
        parser.error("--metal requires macOS and the Apple Metal SDK")
    if args.pokemon_battle_chain:
        pokemon_chain_gate(
            pokemon_root(args.pokemon_dir),
            smoke=args.smoke,
            chunks=args.chain_chunks,
        )
        return
    if args.pokemon_hardware_surface:
        pokemon_hardware_surface_gate(pokemon_root(args.pokemon_dir))
        return
    if args.pokemon_fixture:
        pokemon_gate(
            pokemon_root(args.pokemon_dir),
            prove=False,
            start_release=args.start_release,
            battle_chunk=args.battle_chunk,
            proof_fast=args.proof_fast,
            proof_fast_chunk=args.proof_fast_chunk,
        )
        return
    if args.pokemon_proof:
        pokemon_gate(
            pokemon_root(args.pokemon_dir),
            prove=True,
            metal=args.metal,
            smoke=args.smoke,
            start_release=args.start_release,
            battle_chunk=args.battle_chunk,
            proof_fast=args.proof_fast,
            proof_fast_chunk=args.proof_fast_chunk,
        )
        return
    if args.blargg_flat:
        run_blargg(args.blargg_dir)
        return
    if args.mooneye_focused:
        run_mooneye(args.mooneye_dir, args.mooneye_rom)
        return
    if args.mooneye_ppu_live:
        run_mooneye_ppu(args.mooneye_dir)
        return
    if args.mooneye_dma_live:
        run_mooneye_dma(args.mooneye_dir)
        return
    if args.cartridge:
        frontend_leaf_gate("cartridge")
        return
    if args.cartridge_proof:
        frontend_leaf_gate("cartridge-proof")
        return
    if args.joypad:
        frontend_leaf_gate("joypad")
        return
    if args.environment:
        frontend_leaf_gate("environment")
        return
    if args.intermediate_ram_observation:
        frontend_leaf_gate("intermediate-ram-observation")
        return
    if args.scheduler:
        frontend_leaf_gate("scheduler")
        return
    if args.ppu:
        frontend_leaf_gate("ppu")
        return
    if args.dma:
        frontend_leaf_gate("dma")
        return

    def execute(corpus_v1: Path) -> None:
        if args.precommit:
            precommit(corpus_v1, args.blargg_dir, args.mooneye_dir)
            return
        gate(corpus_v1, opcode=args.opcode, family=args.family)
        if args.proof:
            proof_gate()
        if args.metal:
            metal_gate()

    if args.corpus_dir is not None:
        execute(args.corpus_dir.resolve())
        return

    sibling = ROOT.parent / "sm83-tests" / "v1"
    if sibling.is_dir():
        execute(sibling)
        return

    with tempfile.TemporaryDirectory(prefix="stwo-sm83-corpus-") as temporary:
        checkout = Path(temporary) / "sm83"
        run("corpus checkout init", ["git", "init", str(checkout)])
        run(
            "corpus checkout fetch",
            [
                "git",
                "-C",
                str(checkout),
                "fetch",
                "--depth=1",
                CORPUS_REPOSITORY,
                CORPUS_REVISION,
            ]
        )
        run(
            "corpus checkout pin",
            ["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"],
        )
        execute(checkout / "v1")
if __name__ == "__main__":
    main()
