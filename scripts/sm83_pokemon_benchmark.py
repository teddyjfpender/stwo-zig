#!/usr/bin/env python3
"""Prove the pinned proof-fast Pokemon battle and emit an honest receipt."""

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
TRACE_DIRECTORY = Path("build/traces/battle-benchmark-fast")

PROOF_EXPECTED = {
    "security_bits": 96,
    "chunks": 12,
    "rows": 786_432,
    "mcycles": 1_505_332,
    "callbacks": 601_239,
    "actions": 33,
    "dma_sources": 13_600,
    "initial_mcycle": 5_967_321,
    "final_mcycle": 7_472_653,
    "battle_result": 0,
    "enemy_hp": 0,
    "battle_hp": 180,
    "party_hp": 430,
    "in_battle": 0,
    "stage": 1,
}
EXPECTED_ACTION_DIGEST = (
    "89be37761cdef991ee299f16adfde19fad405be3a5c1adf50b925ee1a4b914ba"
)
EXPECTED_FINAL_SYSTEM_DIGEST = (
    "bd371af12b911647f1e6f175ddf5ef587cc57abf18f3bbe4001cbb8679275780"
)
FULL_BATTLE_EXPECTED = {
    "callback_rows": 594_575,
    "callbacks": 594_575,
    "mcycles": 1_436_786,
    "captured_trace_rows": 1_048_576,
    "padding_rows": 454_001,
    "actions": 33,
    "logic_events": 16,
}

PROOF_PATTERN = re.compile(
    r"SM83 Pokemon (?P<backend>CPU|Metal) battle proof: PASS "
    r"proof_ready=true security_bits=(?P<security_bits>\d+) "
    r"chunks=(?P<chunks>\d+) rows=(?P<rows>\d+) "
    r"mcycles=(?P<mcycles>\d+) callbacks=(?P<callbacks>\d+) "
    r"actions=(?P<actions>\d+) dma_sources=(?P<dma_sources>\d+) "
    r"initial_mcycle=(?P<initial_mcycle>\d+) "
    r"final_mcycle=(?P<final_mcycle>\d+) "
    r"action_digest=(?P<action_digest>[0-9a-f]{64}) "
    r"final_system_digest=(?P<final_system_digest>[0-9a-f]{64}) "
    r"battle_result=(?P<battle_result>\d+) enemy_hp=(?P<enemy_hp>\d+) "
    r"battle_hp=(?P<battle_hp>\d+) party_hp=(?P<party_hp>\d+) "
    r"in_battle=(?P<in_battle>\d+) stage=(?P<stage>\d+) "
    r"rom_digest=(?P<rom_digest>[0-9a-f]{64}) "
    r"initial_system_digest=(?P<initial_system_digest>[0-9a-f]{64}) "
    r"initial_sram_digest=(?P<initial_sram_digest>[0-9a-f]{64}) "
    r"final_sram_digest=(?P<final_sram_digest>[0-9a-f]{64}) "
    r"first_statement_digest=(?P<first_statement_digest>[0-9a-f]{64}) "
    r"last_statement_digest=(?P<last_statement_digest>[0-9a-f]{64})"
)


class BenchmarkError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_for_hardware_audit(zig: str, corpus: Path) -> list[str]:
    return [
        zig,
        "build",
        "test-pokemon-hardware-surface",
        "--build-file",
        "src/frontends/sm83/build.zig",
        "-Doptimize=ReleaseFast",
        f"-Dpokemon-corpus={corpus}",
    ]


def command_for_proof(zig: str, corpus: Path, backend: str) -> list[str]:
    build_file = f"src/integrations/sm83_{backend}/build.zig"
    command = [
        zig,
        "build",
        "test-pokemon-battle-chain",
        "--build-file",
        build_file,
        "-Doptimize=ReleaseFast",
        "--",
        str(corpus),
    ]
    if backend == "cpu":
        command.append("--benchmark")
    return command


def parse_proof_receipt(output: str) -> dict[str, Any]:
    match = PROOF_PATTERN.search(output)
    if match is None:
        raise BenchmarkError("proof command omitted its exact positive receipt")
    counts = {
        key: int(value)
        for key, value in match.groupdict().items()
        if key
        not in {
            "backend",
            "action_digest",
            "final_system_digest",
            "rom_digest",
            "initial_system_digest",
            "initial_sram_digest",
            "final_sram_digest",
            "first_statement_digest",
            "last_statement_digest",
        }
        and value is not None
    }
    for key, value in PROOF_EXPECTED.items():
        if counts.get(key) != value:
            raise BenchmarkError(
                f"proof receipt drifted for {key}: expected {value}, got {counts.get(key)}"
            )
    strings = {
        "backend": match.group("backend"),
        "action_digest": match.group("action_digest"),
        "final_system_digest": match.group("final_system_digest"),
        "rom_digest": match.group("rom_digest"),
        "initial_system_digest": match.group("initial_system_digest"),
        "initial_sram_digest": match.group("initial_sram_digest"),
        "final_sram_digest": match.group("final_sram_digest"),
        "first_statement_digest": match.group("first_statement_digest"),
        "last_statement_digest": match.group("last_statement_digest"),
    }
    if strings["action_digest"] != EXPECTED_ACTION_DIGEST:
        raise BenchmarkError("proof action digest drifted")
    if strings["final_system_digest"] != EXPECTED_FINAL_SYSTEM_DIGEST:
        raise BenchmarkError("proof final-system digest drifted")
    counts.update(strings)
    return counts


def run_timed(
    command: Sequence[str], environment: dict[str, str] | None = None
) -> tuple[str, float]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=None if environment is None else {**os.environ, **environment},
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
        "scenario": "proof-benchmark",
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
            "action_count": manifest["input"]["count"],
            "logic_count": manifest["battle_logic"]["count"],
        }
    except (IndexError, KeyError, TypeError) as error:
        raise BenchmarkError("full-battle manifest identity is incomplete") from error
    expected_identity = {
        "start_bank": 1,
        "start_pc": 20_153,
        "end_bank": 1,
        "end_pc": 20_167,
        "contains_battle_end": True,
        "action_count": FULL_BATTLE_EXPECTED["actions"],
        "logic_count": FULL_BATTLE_EXPECTED["logic_events"],
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
        "actions": (
            directory / manifest["input"]["file"],
            manifest["input"]["sha256"],
        ),
        "battle_logic": (
            directory / manifest["battle_logic"]["file"],
            manifest["battle_logic"]["sha256"],
        ),
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
        "actions_authenticated": True,
        "reference_manifest_proof_ready": False,
        "markers": identity,
        "stage": "authenticated SameBoy reference imported by the Stwo replay gate",
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
        description="Prove the complete pinned proof-fast Pokemon battle"
    )
    parser.add_argument("--pokemon-dir", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument(
        "--allow-high-memory-metal",
        action="store_true",
        help="allow the experimental full-battle Metal path",
    )
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    corpus = args.pokemon_dir.resolve()
    if not corpus.is_dir():
        parser.error(f"missing pinned Pokemon corpus directory: {corpus}")
    if args.backend == "metal" and sys.platform != "darwin":
        parser.error("Metal benchmark requires macOS")
    if args.backend == "metal" and not args.allow_high_memory_metal:
        parser.error(
            "Metal full-battle proving currently exceeds 25 GiB unified memory; "
            "pass --allow-high-memory-metal only on a suitable host"
        )

    full_target = validate_full_battle_target(corpus)
    audit_command = command_for_hardware_audit(args.zig, corpus)
    _, audit_seconds = run_timed(audit_command)

    proof_command = command_for_proof(args.zig, corpus, args.backend)
    proof_environment = (
        {"STWO_ZIG_WORKERS": "1", "STWO_ZIG_MERKLE_WORKERS": "1"}
        if args.backend == "cpu"
        else None
    )
    proof_output, proof_seconds = run_timed(proof_command, proof_environment)
    proof_counts = parse_proof_receipt(proof_output)
    expected_backend = "CPU" if args.backend == "cpu" else "Metal"
    if proof_counts["backend"] != expected_backend:
        raise BenchmarkError(
            f"proof backend drifted: expected {expected_backend}, "
            f"got {proof_counts['backend']}"
        )
    if proof_counts["rom_digest"] != full_target["artifacts"]["rom"]["sha256"]:
        raise BenchmarkError("proof ROM digest differs from the pinned artifact")

    report = {
        "schema": "sm83_pokemon_benchmark_v3",
        "status": "full_battle_proof_ready",
        "proof_ready": True,
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {
            "git_commit": git_value("rev-parse", "HEAD"),
            "dirty": bool(git_value("status", "--porcelain")),
        },
        "host": host_identity(args.zig),
        "full_battle_target": full_target,
        "hardware_audit": {
            "status": "passed_exact_pinned_report",
            "build_mode": "ReleaseFast",
            "command": audit_command,
            "elapsed_seconds": audit_seconds,
        },
        "verified_proof": {
            "label": "proof-fast complete benchmark battle",
            "backend": args.backend,
            "build_mode": "ReleaseFast",
            "command": proof_command,
            "environment": proof_environment,
            "counts": proof_counts,
            "elapsed_seconds": proof_seconds,
            "proof_ready": True,
        },
        "measurement": {
            "samples": 1,
            "warmups": 0,
            "timing_scope": "whole command wall clock including ambient Zig build-cache orchestration",
            "evidence_class": "one-shot local release diagnostic; not a headline benchmark",
        },
        "limitations": [
            "the claim is the documented headless SM83 machine model; it does not claim rendered pixels or audio samples",
            "the PE-AGI manifest remains a SameBoy reference manifest with proof_ready=false; this receipt is the downstream Stwo proof",
            "no cross-language Rust verifier receipt is available for the SM83 extension",
        ],
    }
    atomic_write_json(args.report_out.resolve(), report)
    print(
        "SM83 Pokemon benchmark: PASS "
        "proof_ready=true "
        f"proof_backend={args.backend} proof_rows={proof_counts['rows']} "
        f"proof_callbacks={proof_counts['callbacks']} proof_mcycles={proof_counts['mcycles']} "
        f"proof_seconds={proof_seconds:.6f} report={args.report_out.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
