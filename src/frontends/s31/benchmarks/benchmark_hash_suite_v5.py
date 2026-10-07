#!/usr/bin/env python3
"""Verified native timing for the personalized BLAKE2s tree examples."""

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

import s31


HERE = S31_SOURCE_ROOT
P = (1 << 31) - 1
STAGES = re.compile(r"witness=([0-9.]+)s, setup=([0-9.]+)s, prove=([0-9.]+)s")


def digest(words: list[int], domain: bytes) -> list[int]:
    raw = hashlib.blake2s(b"".join(struct.pack("<I", word) for word in words), person=domain).digest()
    return [word % P for word in struct.unpack("<8I", raw)]


def assignment_for(name: str, trial: int) -> dict:
    if name == "merkle2":
        left = [1 + trial * 17 + i for i in range(8)]
        right = [9 + trial * 17 + i for i in range(8)]
        root = digest(digest(left, b"S31LEAF1") + digest(right, b"S31LEAF1"), b"S31PAIR1")
        private = {"left": left, "right": right}
    else:
        leaf = [1 + trial * 17 + i for i in range(8)]
        sibling = [100 * (i + 1) + trial * 17 for i in range(8)]
        direction = trial % 2
        leaf_digest = digest(leaf, b"S31LEAF1")
        ordered = leaf_digest + sibling if direction == 0 else sibling + leaf_digest
        root = digest(ordered, b"S31PAIR1")
        private = {"leaf": leaf, "sibling": sibling, "direction": [direction]}
    return {"public_inputs": {}, "private_inputs": private, "public_outputs": {"root": root}}


def measured(*args: str) -> tuple[float, str]:
    start = time.perf_counter()
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    wall = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return wall, result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("trials must be positive")
    record = {
        "schema": "s31-hash-suite-benchmark-v5",
        "compiler_sha256": s31.compiler_fingerprint(),
        "trials_per_case": args.trials,
        "timing_note": "distinct valid inputs per trial; cold setup included in each proof process; native verifier run separately; full-gate PoW not isolated",
        "cases": {},
    }
    with tempfile.TemporaryDirectory(prefix="s31-hash-bench-") as temporary:
        work = Path(temporary)
        for name in ("merkle2", "merkle_path1"):
            source = example_path(f"{name}.s31.json")
            package = s31.build(source, work / f"{name}-package", "gate")
            cost = json.loads((package / "cost-report.json").read_text())
            prover = package / "bin" / f"s31-{name}-prover"
            verifier = package / "bin" / f"s31-{name}-native-verifier"
            key = package / "verification-key.json"
            trials = []
            for trial in range(args.trials):
                assignment = assignment_for(name, trial)
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
                "program_sha256": s31.file_hash(source),
                "preprocessed_cells": cost["preprocessed_cells"],
                "raw_rows": cost["raw"],
                "trials": trials,
                "median": {key: statistics.median(sample[key] for sample in trials) for key in (
                    "witness_seconds", "cold_setup_seconds", "prove_seconds", "prove_process_wall_seconds", "native_verify_process_wall_seconds", "proof_bytes"
                )},
            }
            print(f"{name}: median prove {record['cases'][name]['median']['prove_seconds']:.3f}s, proof {trials[0]['proof_bytes']} bytes", flush=True)
    output = s31.ROOT / "design/s31/measurements/hash/hash-suite-benchmark-v5-2026-10-06.json"
    s31.write_json(output, record)
    print(output)


if __name__ == "__main__":
    main()
