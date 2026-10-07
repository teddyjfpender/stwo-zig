#!/usr/bin/env python3
"""Matched direct-M31 gate/chip proof measurements with both PoW stages."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import platform

import benchmark_profiles_v2 as base
import s31


def source(rounds: int) -> dict:
    return {
        "version": 1,
        "name": f"step{rounds}",
        "inputs": [{"name": "x", "kind": "m31", "length": 4, "visibility": "public"}],
        "nodes": [{
            "name": "result", "op": "repeat", "lhs": "x", "rounds": rounds,
            "body": [{"op": "square"}, {"op": "add_const", "constant": 7}],
        }],
        "assertions": [],
        "public_outputs": ["result"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, nargs="+", default=[16, 256, 4096, 32768])
    parser.add_argument("--trials", type=int, default=9)
    args = parser.parse_args()
    if args.trials < 1:
        raise ValueError("trials must be positive")
    for rounds in args.rounds:
        if rounds < 16 or rounds > 32768 or rounds & (rounds - 1):
            raise ValueError("rounds must be powers of two in [16, 32768]")
    fingerprint = s31.compiler_fingerprint()
    work = s31.ROOT / "zig-out" / "s31" / "benchmark-direct-v4" / fingerprint[:16]
    work.mkdir(parents=True, exist_ok=True)
    for rounds in args.rounds:
        s31.write_json(work / f"step{rounds}.s31.json", source(rounds))
        for trial in range(args.trials):
            valid = base.assignment(rounds, trial)
            s31.write_json(work / f"step{rounds}.trial-{trial}.valid.json", valid)
            s31.write_json(work / f"step{rounds}.trial-{trial}.statement.json", {
                "public_inputs": valid["public_inputs"],
                "public_outputs": valid["public_outputs"],
            })
    results = []
    for rounds in args.rounds:
        for lowering in ("sparse-gate", "sparse-chip", "direct-gate", "direct-chip"):
            print(f"measuring {rounds} {lowering}", flush=True)
            item = base.run_case(work, rounds, lowering, args.trials)
            results.append(item)
            print(
                f"  setup={item['median_setup_s']:.6f}s "
                f"prove={item['median_prove_s']:.6f}s "
                f"excluding-pow={item['median_prove_excluding_pow_s']:.6f}s "
                f"proof={item['proof_bytes']} bytes",
                flush=True,
            )
    record = {
        "schema": "s31-direct-profile-benchmark-v4",
        "compiler_sha256": fingerprint,
        "zig_version": s31.invoke("zig", "version").strip(),
        "machine": platform.platform(),
        "trials_per_case": args.trials,
        "timing_note": "Each process builds a cold preprocessed commitment in setup_s. prove_s leases it. Both interaction and FRI/PCS PoW are measured separately. Distinct valid public inputs are used for each trial.",
        "results": results,
    }
    output = s31.ROOT / "design" / "s31" / "measurements" / "profiles-direct-v4-2026-10-06.json"
    s31.write_json(output, record)
    print(output)


if __name__ == "__main__":
    main()
