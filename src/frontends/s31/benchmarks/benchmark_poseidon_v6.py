#!/usr/bin/env python3
"""Matched tree shapes: native-verified Poseidon2 direct circuits and BLAKE2s gates."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))
from example_paths import example_path

import argparse
import hashlib
import json
import re
import statistics
import struct
import subprocess
import tempfile
import time
from pathlib import Path

import poseidon2_oracle as poseidon
import s31


HERE = S31_SOURCE_ROOT
P = (1 << 31) - 1
STAGES = re.compile(r"witness=([0-9.]+)s, setup=([0-9.]+)s, prove=([0-9.]+)s")


def blake(words: list[int], domain: bytes) -> list[int]:
    raw = hashlib.blake2s(b"".join(struct.pack("<I", word) for word in words), person=domain).digest()
    return [word % P for word in struct.unpack("<8I", raw)]


def assignment_for(shape: str, algorithm: str, trial: int) -> dict:
    leaf_hash = poseidon.leaf if algorithm == "poseidon2" else lambda words: blake(words, b"S31LEAF1")
    pair_hash = poseidon.pair if algorithm == "poseidon2" else lambda left, right: blake(left + right, b"S31PAIR1")
    if shape == "merkle2":
        left = [1 + trial * 17 + i for i in range(8)]
        right = [9 + trial * 17 + i for i in range(8)]
        root = pair_hash(leaf_hash(left), leaf_hash(right))
        private = {"left": left, "right": right}
    else:
        leaf = [1 + trial * 17 + i for i in range(8)]
        sibling = [100 * (i + 1) + trial * 17 for i in range(8)]
        direction = trial % 2
        digest = leaf_hash(leaf)
        root = pair_hash(digest, sibling) if direction == 0 else pair_hash(sibling, digest)
        private = {"leaf": leaf, "sibling": sibling, "direction": [direction]}
    return {"public_inputs": {}, "private_inputs": private, "public_outputs": {"root": root}}


def measured(*args: str) -> tuple[float, str]:
    started = time.perf_counter()
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    wall = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return wall, result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("trials must be positive")
    poseidon.self_check()
    record = {
        "schema": "s31-poseidon-comparison-v6",
        "compiler_sha256": s31.compiler_fingerprint(),
        "poseidon_constants_sha256": poseidon.CONSTANTS_SHA256,
        "trials_per_case": args.trials,
        "comparison_note": "same private input arrays and tree topology; distinct hash outputs and security assumptions; each proof independently checked by its generated native verifier",
        "timing_note": "distinct valid inputs per trial; cold setup in each prover process; proof-of-work included and stochastic",
        "cases": {},
        "ratios_blake_over_poseidon": {},
    }
    with tempfile.TemporaryDirectory(prefix="s31-poseidon-bench-") as temporary:
        work = Path(temporary)
        for shape in ("merkle2", "merkle_path1"):
            for algorithm, suffix, lowering in (("blake2s", "", "gate"), ("poseidon2", "_poseidon", "direct-gate")):
                name = shape + suffix
                source = example_path(f"{name}.s31.json")
                package = s31.build(source, work / f"{name}-package", lowering)
                s31.verify_package(package)
                cost = json.loads((package / "cost-report.json").read_text())
                prover = package / "bin" / f"s31-{name}-prover"
                verifier = package / "bin" / f"s31-{name}-native-verifier"
                key = package / "verification-key.json"
                trials = []
                for trial in range(args.trials):
                    assignment = assignment_for(shape, algorithm, trial)
                    assignment_path = work / f"{name}-{trial}.assignment.json"
                    statement_path = work / f"{name}-{trial}.statement.json"
                    proof_path = work / f"{name}-{trial}.proof"
                    s31.write_json(assignment_path, assignment)
                    s31.write_json(statement_path, {"public_inputs": {}, "public_outputs": assignment["public_outputs"]})
                    prove_wall, output = measured(str(prover), "prove", str(assignment_path), str(proof_path))
                    match = STAGES.search(output)
                    if not match:
                        raise AssertionError(f"missing prover stage timings: {output}")
                    verify_wall, _ = measured(str(verifier), str(proof_path), str(statement_path), str(key))
                    trials.append({
                        "witness_seconds": float(match.group(1)),
                        "cold_setup_seconds": float(match.group(2)),
                        "prove_seconds": float(match.group(3)),
                        "prove_process_wall_seconds": prove_wall,
                        "native_verify_process_wall_seconds": verify_wall,
                        "proof_bytes": proof_path.stat().st_size,
                        "proof_sha256": s31.file_hash(proof_path),
                    })
                record["cases"][name] = {
                    "algorithm": algorithm,
                    "lowering": lowering,
                    "program_sha256": s31.file_hash(source),
                    "profile": cost["profile"],
                    "preprocessed_cells": cost["preprocessed_cells"],
                    "preprocessed_columns": cost["preprocessed_columns"],
                    "raw_rows": cost["raw"],
                    "trials": trials,
                    "median": {key: statistics.median(sample[key] for sample in trials) for key in (
                        "witness_seconds", "cold_setup_seconds", "prove_seconds", "prove_process_wall_seconds", "native_verify_process_wall_seconds", "proof_bytes"
                    )},
                }
                print(f"{name}: median prove {record['cases'][name]['median']['prove_seconds']:.3f}s, proof {record['cases'][name]['median']['proof_bytes']} bytes", flush=True)
            old = record["cases"][shape]
            new = record["cases"][shape + "_poseidon"]
            record["ratios_blake_over_poseidon"][shape] = {
                "preprocessed_cells": old["preprocessed_cells"] / new["preprocessed_cells"],
                "proof_bytes": old["median"]["proof_bytes"] / new["median"]["proof_bytes"],
                "median_prove_seconds": old["median"]["prove_seconds"] / new["median"]["prove_seconds"],
            }
    output = s31.ROOT / "design/s31/measurements/hash/poseidon-comparison-v6-2026-10-06.json"
    s31.write_json(output, record)
    print(output)


if __name__ == "__main__":
    main()
