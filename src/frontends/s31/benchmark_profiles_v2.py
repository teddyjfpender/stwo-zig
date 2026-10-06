#!/usr/bin/env python3
"""Reproducible S31 sparse gate/chip crossover measurement."""

import argparse
import json
import platform
import re
import statistics
import subprocess
import time
from pathlib import Path

import s31

ROOT = s31.ROOT
HERE = Path(__file__).resolve().parent
INPUT = [1, 2, 3, 65535]
MODULUS = (1 << 31) - 1


def invoke(*args: str) -> tuple[str, float]:
    start = time.perf_counter()
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    elapsed = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed ({result.returncode})\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr, elapsed


def source(rounds: int) -> dict:
    return {
        "version": 1,
        "name": f"step{rounds}",
        "inputs": [{"name": "x", "kind": "u16", "length": 4, "visibility": "public"}],
        "nodes": [
            {"name": "field", "op": "cast_m31", "lhs": "x"},
            {"name": "result", "op": "repeat", "lhs": "field", "rounds": rounds,
             "body": [{"op": "square"}, {"op": "add_const", "constant": 7}]},
        ],
        "assertions": [],
        "public_outputs": ["result"],
    }


def assignment(rounds: int, trial: int) -> dict:
    inputs = INPUT if trial == 0 else [
        (1 + 97 * trial) % 65536,
        (2 + 193 * trial) % 65536,
        (3 + 389 * trial) % 65536,
        (65535 - 53 * trial) % 65536,
    ]
    result = inputs.copy()
    for _ in range(rounds):
        result = [(value * value + 7) % MODULUS for value in result]
    return {"public_inputs": {"x": inputs}, "private_inputs": {},
            "public_outputs": {"result": result}}


def timing(output: str, name: str) -> float:
    matched = re.search(rf"\b{name}=([0-9.]+)s\b", output)
    if matched is None:
        raise ValueError(f"missing {name} timing: {output}")
    return float(matched.group(1))


def run_case(work: Path, rounds: int, lowering: str, trials: int) -> dict:
    case = work / f"{rounds}-{lowering}"
    package = s31.build(work / f"step{rounds}.s31.json", case / "package", lowering)
    report = json.loads((package / "cost-report.json").read_text())
    prover = package / "bin" / f"s31-step{rounds}-prover"
    verifier = package / "bin" / f"s31-step{rounds}-native-verifier"
    measurements = []
    for trial in range(trials):
        proof = case / f"trial-{trial}.proof"
        proof.parent.mkdir(parents=True, exist_ok=True)
        valid = work / f"step{rounds}.trial-{trial}.valid.json"
        statement = work / f"step{rounds}.trial-{trial}.statement.json"
        stdout, prove_wall = invoke(str(prover), "prove", str(valid), str(proof))
        _, verify_wall = invoke(str(verifier), str(proof), str(statement), str(package / "verification-key.json"))
        interaction_pow_s = timing(stdout, "interaction_pow")
        fri_pow_s = timing(stdout, "fri_pow")
        prove_s = timing(stdout, "prove")
        measurements.append({
            "trial": trial,
            "public_inputs": assignment(rounds, trial)["public_inputs"],
            "witness_s": timing(stdout, "witness"),
            "setup_s": timing(stdout, "setup"),
            "prove_s": prove_s,
            "interaction_pow_s": interaction_pow_s,
            "fri_pow_s": fri_pow_s,
            "prove_excluding_pow_s": prove_s - interaction_pow_s - fri_pow_s,
            "total_through_self_verify_s": timing(stdout, "total through verification"),
            "prover_process_wall_s": prove_wall,
            "native_verifier_process_wall_s": verify_wall,
            "proof_bytes": proof.stat().st_size,
            "proof_sha256": s31.file_hash(proof),
        })
    return {
        "rounds": rounds,
        "lowering": lowering,
        "program_sha256": report["program_sha256"],
        "canonical_ir_sha256": report["canonical_ir_sha256"],
        "preprocessed_root": report["preprocessed_root"],
        "circuit_hash": report["circuit_hash"],
        "raw": report["raw"],
        "padded": report["padded"],
        "preprocessed_columns": report["preprocessed_columns"],
        "preprocessed_cells": report["preprocessed_cells"],
        "chip": report["chip"],
        "proof_bytes": measurements[0]["proof_bytes"],
        "median_prove_s": statistics.median(item["prove_s"] for item in measurements),
        "median_setup_s": statistics.median(item["setup_s"] for item in measurements),
        "median_interaction_pow_s": statistics.median(item["interaction_pow_s"] for item in measurements),
        "median_fri_pow_s": statistics.median(item["fri_pow_s"] for item in measurements),
        "median_prove_excluding_pow_s": statistics.median(item["prove_excluding_pow_s"] for item in measurements),
        "median_verify_process_s": statistics.median(item["native_verifier_process_wall_s"] for item in measurements),
        "trials": measurements,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, nargs="+", default=[16, 256, 4096, 32768])
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if args.trials < 1:
        raise ValueError("trials must be positive")
    for rounds in args.rounds:
        if rounds < 16 or rounds > 32768 or rounds & (rounds - 1):
            raise ValueError("rounds must be powers of two in [16, 32768]")
    fingerprint = s31.compiler_fingerprint()
    work = ROOT / "zig-out" / "s31" / "benchmark-profiles-v2" / fingerprint[:16]
    work.mkdir(parents=True, exist_ok=True)
    for rounds in args.rounds:
        s31.write_json(work / f"step{rounds}.s31.json", source(rounds))
        for trial in range(args.trials):
            valid = assignment(rounds, trial)
            s31.write_json(work / f"step{rounds}.trial-{trial}.valid.json", valid)
            s31.write_json(work / f"step{rounds}.trial-{trial}.statement.json", {
                "public_inputs": valid["public_inputs"], "public_outputs": valid["public_outputs"],
            })
    results = []
    for rounds in args.rounds:
        for lowering in ("sparse-gate", "sparse-chip"):
            print(f"measuring {rounds} {lowering}", flush=True)
            item = run_case(work, rounds, lowering, args.trials)
            results.append(item)
            print(
                f"  prove={item['median_prove_s']:.6f}s "
                f"excluding-pow={item['median_prove_excluding_pow_s']:.6f}s "
                f"proof={item['proof_bytes']} bytes",
                flush=True,
            )
    record = {
        "schema": "s31-profile-benchmark-v3",
        "compiler_sha256": fingerprint,
        "zig_version": s31.invoke("zig", "version").strip(),
        "machine": platform.platform(),
        "trials_per_case": args.trials,
        "timing_note": "setup_s includes topology construction and a cold preprocessed commitment. prove_s leases that commitment; interaction and FRI/PCS PoW are timed separately inside prove_s. Each trial launches a fresh prover process, so cached proving is measured from a same-process tree built during setup, not an across-process cache.",
        "results": results,
    }
    output = ROOT / "design" / "s31" / "measurements" / "profiles-cached-v3-2026-10-06.json"
    s31.write_json(output, record)
    print(output)


if __name__ == "__main__":
    main()
