#!/usr/bin/env python3
"""Match an independently verified Cairo proof's ordered public output to the oracle."""

import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_PROGRAM_ROOT = "a9e2a56aa041c583b124df4455f94085ee76426e8f13b287484ef117dd799b75"

def check(proof_path: Path, expected_path: Path, verdict_path: Path,
          statement_path: Path) -> None:
    proof_bytes = proof_path.read_bytes()
    proof = json.loads(proof_bytes)
    expected = json.loads(expected_path.read_text())
    verdict = json.loads(verdict_path.read_text())
    statement = json.loads(statement_path.read_text())
    if verdict.get("verified") is not True:
        raise ValueError("official Rust verifier did not accept the proof")
    if verdict.get("proof_sha256") != hashlib.sha256(proof_bytes).hexdigest():
        raise ValueError("verdict belongs to a different proof")
    config = proof["stark_proof"]["config"]
    if config["pow_bits"] != 26 or config["fri_config"]["n_queries"] != 70:
        raise ValueError("proof is not at the canonical security profile")
    if statement.get("program_root_blake2s") != EXPECTED_PROGRAM_ROOT:
        raise ValueError("proof did not use the pinned generated Cairo program")
    cells = proof["claim"]["public_data"]["public_memory"]["output"]
    words = [sum(int(limb) << (32 * i) for i, limb in enumerate(value))
             for _, value in cells]
    if len(expected) != 512 or words != [512, *expected]:
        raise ValueError("verified public output does not match the independent gate oracle")
    print("officially verified q70/PoW26 proof has all 512 expected output words")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    args = parser.parse_args()
    check(args.proof, args.expected, args.verdict, args.statement)


if __name__ == "__main__":
    main()
