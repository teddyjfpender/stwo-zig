#!/usr/bin/env python3
"""Emit one honest local benchmark receipt for the pinned _ROGUE_FAST ROM."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT.parent / "PE-AGI" / "v1"
DEFAULT_REPORT = ROOT / "zig-out" / "sm83-pokemon-benchmark.json"
TRACE_DIRECTORY = Path("build/traces/battle-seed-1-fast")

LONG_EXPECTED = {
    "rows": 262_144,
    "callbacks": 54_602,
    "mcycles": 330_527,
    "lookahead_rows": 3_684,
    "oracle_records": 200_480,
    "dma_sources": 3_040,
    "actions": 2,
}
LONG_RECEIPT_EXPECTED = {
    key: value for key, value in LONG_EXPECTED.items() if key != "actions"
}
PROOF_EXPECTED = {
    "security_bits": 96,
    "rows": 262_144,
    "callbacks": 54_602,
    "mcycles": 330_527,
    "actions": 2,
    "dma_sources": 3_040,
    "apu_events": 0,
    "observations": 2,
}
TURN_MILESTONES = {
    "execute_player_move": 212_538,
    "apply_damage_to_enemy_pokemon": 226_037,
    "handle_enemy_mon_fainted": 245_787,
}
FULL_BATTLE_EXPECTED = {
    "callback_rows": 447_516,
    "callbacks": 447_516,
    "mcycles": 4_899_537,
    "captured_trace_rows": 1_048_576,
    "padding_rows": 601_060,
}

PREPARED_PATTERN = re.compile(
    r"SM83 Pokemon fixture: PREPARED "
    r"rows=(?P<rows>\d+) callbacks=(?P<callbacks>\d+) "
    r"mcycles=(?P<mcycles>\d+) lookahead_rows=(?P<lookahead_rows>\d+) "
    r"oracle_records=(?P<oracle_records>\d+).*?"
    r"dma_sources=(?P<dma_sources>\d+)"
)
PROOF_PATTERN = re.compile(
    r"SM83 Pokemon (?P<backend>CPU|Metal) proof: PASS "
    r"profile=secure fixture_profile=proof_fast_turn "
    r"security_bits=(?P<security_bits>\d+) rows=(?P<rows>\d+) "
    r"mcycles=(?P<mcycles>\d+) callbacks=(?P<callbacks>\d+) "
    r"actions=(?P<actions>\d+) dma_sources=(?P<dma_sources>\d+) "
    r"apu_events=(?P<apu_events>\d+) observations=(?P<observations>\d+)"
)


class BenchmarkError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_for_prepare(zig: str, corpus: Path) -> list[str]:
    return [
        zig,
        "build",
        "benchmark-pokemon-prepare",
        "--build-file",
        "src/frontends/sm83/build.zig",
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus),
        "--proof-fast-turn",
    ]


def command_for_proof(zig: str, corpus: Path, backend: str) -> list[str]:
    build_file = f"src/integrations/sm83_{backend}/build.zig"
    return [
        zig,
        "build",
        "test-pokemon-checkpoint",
        "--build-file",
        build_file,
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus),
        "--proof-fast-turn",
    ]


def parse_counts(pattern: re.Pattern[str], output: str, expected: dict[str, int]) -> dict[str, int]:
    match = pattern.search(output)
    if match is None:
        raise BenchmarkError("benchmark command omitted its exact positive receipt")
    counts = {
        key: int(value)
        for key, value in match.groupdict().items()
        if key != "backend" and value is not None
    }
    for key, value in expected.items():
        if counts.get(key) != value:
            raise BenchmarkError(
                f"benchmark receipt drifted for {key}: expected {value}, got {counts.get(key)}"
            )
    return counts


def run_timed(command: Sequence[str]) -> tuple[str, float]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise BenchmarkError(
            f"command exited {completed.returncode}: {' '.join(command)}\n{output[-4000:]}"
        )
    return output, elapsed


def validate_full_battle_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "schema": "pe-agi-sameboy-battle-trace-v1",
        "proof_ready": False,
        "battle_rows": FULL_BATTLE_EXPECTED["callback_rows"],
        "battle_mcycles": FULL_BATTLE_EXPECTED["mcycles"],
        "battle_end_row": FULL_BATTLE_EXPECTED["callbacks"],
        "trace_rows": FULL_BATTLE_EXPECTED["captured_trace_rows"],
        "padding_rows_after_battle": FULL_BATTLE_EXPECTED["padding_rows"],
    }
    for key, expected in checks.items():
        if manifest.get(key) != expected:
            raise BenchmarkError(
                f"full-battle manifest drifted for {key}: expected {expected!r}, "
                f"got {manifest.get(key)!r}"
            )
    try:
        chunks = manifest["chunks"]
        identity = {
            "start_bank": manifest["markers"]["start"]["bank"],
            "start_pc": manifest["markers"]["start"]["pc"],
            "end_bank": manifest["markers"]["end"]["bank"],
            "end_pc": manifest["markers"]["end"]["pc"],
            "contains_battle_end": chunks[0]["contains_battle_end"],
        }
    except (IndexError, KeyError, TypeError) as error:
        raise BenchmarkError("full-battle manifest identity is incomplete") from error
    expected_identity = {
        "start_bank": 1,
        "start_pc": 20_094,
        "end_bank": 1,
        "end_pc": 20_099,
        "contains_battle_end": True,
    }
    if len(chunks) != 1 or identity != expected_identity:
        raise BenchmarkError(
            "full-battle marker or terminal-chunk identity drifted: "
            f"expected {expected_identity!r}, got {identity!r}"
        )
    return identity


def validate_full_battle_target(corpus: Path) -> dict[str, Any]:
    directory = corpus / TRACE_DIRECTORY
    manifest_path = directory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read proof-fast battle manifest: {error}") from error
    identity = validate_full_battle_manifest(manifest)
    chunks = manifest["chunks"]
    files = {
        "rom": (corpus / manifest["rom"]["file"], manifest["rom"]["sha256"]),
        "trace": (directory / "instructions.bin", manifest["trace_sha256"]),
    }
    for boundary in ("initial_state", "final_state"):
        entry = manifest["chunks"][0][boundary]
        files[boundary] = (directory / entry["file"], entry["sha256"])
    identities: dict[str, dict[str, Any]] = {}
    for name, (path, expected_digest) in files.items():
        if not path.is_file():
            raise BenchmarkError(f"missing full-battle artifact: {path}")
        actual = sha256_file(path)
        if actual != expected_digest:
            raise BenchmarkError(
                f"full-battle {name} hash mismatch: expected {expected_digest}, got {actual}"
            )
        identities[name] = {
            "path": os.path.relpath(path, corpus),
            "sha256": actual,
            "bytes": path.stat().st_size,
        }
    return {
        **FULL_BATTLE_EXPECTED,
        "actions": None,
        "actions_authenticated": False,
        "proof_rows": None,
        "proof_available": False,
        "proof_ready": False,
        "markers": identity,
        "stage": "authenticated SameBoy reference target; not timed or proved",
        "artifacts": identities,
    }


def git_value(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def optional_command_text(command: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def power_source(pmset_output: str | None) -> str | None:
    if pmset_output is None:
        return None
    match = re.search(r"Now drawing from '([^']+)'", pmset_output)
    return None if match is None else match.group(1)


def host_identity(zig: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "zig": optional_command_text([zig, "version"]),
        "model": None,
        "cpu": None,
        "memory_bytes": None,
        "power_source": None,
    }
    if result["system"] == "Darwin":
        result["model"] = optional_command_text(["sysctl", "-n", "hw.model"])
        result["cpu"] = optional_command_text(
            ["sysctl", "-n", "machdep.cpu.brand_string"]
        )
        memory = optional_command_text(["sysctl", "-n", "hw.memsize"])
        if memory is not None and memory.isdecimal():
            result["memory_bytes"] = int(memory)
        result["power_source"] = power_source(
            optional_command_text(["pmset", "-g", "batt"])
        )
    return result


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(encoded)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark an exact long Pokemon replay slice and verified proof baseline"
    )
    parser.add_argument("--pokemon-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    corpus = args.pokemon_dir.resolve()
    if not corpus.is_dir():
        parser.error(f"missing pinned Pokemon corpus directory: {corpus}")
    if args.backend == "metal" and sys.platform != "darwin":
        parser.error("Metal benchmark requires macOS")

    full_target = validate_full_battle_target(corpus)
    prepare_command = command_for_prepare(args.zig, corpus)
    prepare_output, prepare_seconds = run_timed(prepare_command)
    prepare_counts = parse_counts(
        PREPARED_PATTERN,
        prepare_output,
        LONG_RECEIPT_EXPECTED,
    )
    prepare_counts["actions"] = LONG_EXPECTED["actions"]

    proof_command = command_for_proof(args.zig, corpus, args.backend)
    proof_output, proof_seconds = run_timed(proof_command)
    proof_counts = parse_counts(PROOF_PATTERN, proof_output, PROOF_EXPECTED)

    report = {
        "schema": "sm83_pokemon_benchmark_v2",
        "status": "verified_battle_turn_baseline",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {
            "git_commit": git_value("rev-parse", "HEAD"),
            "dirty": bool(git_value("status", "--porcelain")),
        },
        "host": host_identity(args.zig),
        "full_battle_target": full_target,
        "battle_turn_workload": {
            "label": "proof_fast_turn exact replay from command handling through opponent faint",
            "terminal_battle": False,
            "backend": "frontend CPU runner and backend-generic witness preparation",
            "build_mode": "ReleaseFast",
            "command": prepare_command,
            "counts": prepare_counts,
            "milestone_rows": TURN_MILESTONES,
            "elapsed_seconds": prepare_seconds,
            "verified_proof": False,
        },
        "verified_proof_baseline": {
            "label": "proof_fast_turn",
            "backend": args.backend,
            "build_mode": "ReleaseFast",
            "command": proof_command,
            "counts": proof_counts,
            "elapsed_seconds": proof_seconds,
            "verified_proof": True,
        },
        "measurement": {
            "samples": 1,
            "warmups": 0,
            "timing_scope": "whole command wall clock including ambient Zig build-cache orchestration",
            "evidence_class": "one-shot local release diagnostic; not a headline benchmark",
        },
        "limitations": [
            "the proved workload begins after battle setup and ends shortly after the opponent-faint handler, not at the marker-to-marker battle return",
            "the full-battle target has callback and M-cycle counts but no measured proof-row count",
            "no cross-language Rust verifier receipt is available for the SM83 extension",
        ],
    }
    atomic_write_json(args.report_out.resolve(), report)
    print(
        "SM83 Pokemon benchmark: PASS "
        f"turn_rows={prepare_counts['rows']} turn_callbacks={prepare_counts['callbacks']} "
        f"turn_mcycles={prepare_counts['mcycles']} turn_actions={prepare_counts['actions']} "
        f"turn_dma={prepare_counts['dma_sources']} turn_seconds={prepare_seconds:.6f} "
        f"proof_backend={args.backend} proof_rows={proof_counts['rows']} "
        f"proof_callbacks={proof_counts['callbacks']} proof_mcycles={proof_counts['mcycles']} "
        f"proof_seconds={proof_seconds:.6f} report={args.report_out.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
