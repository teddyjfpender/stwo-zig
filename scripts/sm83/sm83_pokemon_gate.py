"""Focused command construction for pinned PE-AGI Pokémon gates."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

Run = Callable[[str, list[str]], None]


def gate(
    corpus_root: Path,
    *,
    prove: bool,
    run: Run,
    metal: bool = False,
    smoke: bool = False,
    start_release: bool = False,
    battle_chunk: int | None = None,
    proof_fast: bool = False,
    proof_fast_chunk: int | None = None,
) -> None:
    if sum(
        (
            start_release,
            battle_chunk is not None,
            proof_fast,
            proof_fast_chunk is not None,
        )
    ) > 1:
        raise ValueError("Pokemon fixture profiles are mutually exclusive")
    if battle_chunk is not None and battle_chunk < 1:
        raise ValueError("Pokemon battle chunk index must be positive")
    if proof_fast_chunk is not None and proof_fast_chunk not in (1, 2):
        raise ValueError("Pokemon proof-fast chunk index must be 1 or 2")
    profile = (
        " START-release"
        if start_release
        else f" battle-chunk-{battle_chunk}"
        if battle_chunk is not None
        else " proof-fast"
        if proof_fast
        else f" proof-fast-chunk-{proof_fast_chunk}"
        if proof_fast_chunk is not None
        else ""
    )
    if prove:
        backend = "Metal" if metal else "CPU/SIMD"
        build_file = (
            "src/integrations/sm83_metal/build.zig"
            if metal
            else "src/integrations/sm83_cpu/build.zig"
        )
        command = [
            "zig",
            "build",
            "test-pokemon-checkpoint",
            "--build-file",
            build_file,
            "-Doptimize=ReleaseFast",
            "--",
            str(corpus_root),
        ]
        if start_release:
            command.append("--start-release")
        if battle_chunk is not None:
            command.append(f"--battle-chunk-{battle_chunk}")
        if proof_fast:
            command.append("--proof-fast")
        if proof_fast_chunk is not None:
            command.append(f"--proof-fast-chunk-{proof_fast_chunk}")
        if smoke:
            command.append("--smoke")
        run(
            f"{backend} Pokemon checkpoint{profile} proof "
            f"({'smoke' if smoke else 'secure'})",
            command,
        )
        return

    command = [
        "zig",
        "build",
        "test-pokemon-fixture",
        "--build-file",
        "src/frontends/sm83/build.zig",
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus_root),
    ]
    if start_release:
        command.append("--start-release")
    if battle_chunk is not None:
        command.append(f"--battle-chunk-{battle_chunk}")
    if proof_fast:
        command.append("--proof-fast")
    if proof_fast_chunk is not None:
        command.append(f"--proof-fast-chunk-{proof_fast_chunk}")
    run(f"Pokemon checkpoint{profile} fixture", command)


def root(explicit: Path | None, sibling_root: Path) -> Path:
    directory = explicit.resolve() if explicit is not None else sibling_root
    if not directory.is_dir():
        raise SystemExit(f"missing pinned Pokemon corpus directory: {directory}")
    return directory


def chain(
    corpus_root: Path,
    *,
    run: Run,
    smoke: bool = False,
    chunks: int | None = None,
) -> None:
    if chunks is not None and not 1 <= chunks <= 256:
        raise ValueError("Pokemon battle chain chunk count must be in 1...256")
    command = [
        "zig",
        "build",
        "test-pokemon-battle-chain",
        "--build-file",
        "src/integrations/sm83_cpu/build.zig",
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus_root),
    ]
    if smoke:
        command.append("--smoke")
    if chunks is not None:
        command.extend(["--chunks", str(chunks)])
    run(
        "CPU/SIMD Pokemon battle chain "
        f"({'smoke' if smoke else 'secure'})",
        command,
    )
