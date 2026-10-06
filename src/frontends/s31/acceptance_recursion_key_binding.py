#!/usr/bin/env python3
"""A same-AIR child key must produce a distinct recursive circuit and claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "examples/arith4_m31.s31"
ASSIGNMENT = HERE / "examples/arith4.valid.json"


def run(*args: str, accept: bool = True) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse the original gate package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-recursion-key-binding-") as temporary:
        work = Path(temporary)
        original = args.package.resolve() if args.package else s31.build(SOURCE, work / "original", "gate")
        s31.verify_package(original)
        clone_source = work / "arith4_clone.s31"
        clone_source.write_text(SOURCE.read_text().replace("circuit arith4_m31(",
                                                           "circuit arith4_clone("))
        clone = s31.build(clone_source, work / "clone", "gate")
        original_key = json.loads((original / "verification-key.json").read_text())
        clone_key = json.loads((clone / "verification-key.json").read_text())
        if original_key["preprocessed_root"] != clone_key["preprocessed_root"]:
            raise AssertionError("same arithmetic unexpectedly changed child AIR root")
        if original_key["circuit_hash"] != clone_key["circuit_hash"]:
            raise AssertionError("same arithmetic unexpectedly changed child circuit hash")
        original_recursive = json.loads((original / "recursive-verification-key.json").read_text())
        clone_recursive = json.loads((clone / "recursive-verification-key.json").read_text())
        if original_recursive["outer_preprocessed_root"] == clone_recursive["outer_preprocessed_root"]:
            raise AssertionError("different child key did not change the recursive AIR")

        child = work / "child.proof"
        outer = work / "outer.proof"
        original_prover = original / "bin/s31-arith4_m31-prover"
        original_verifier = original / "bin/s31-arith4_m31-native-verifier"
        clone_verifier = clone / "bin/s31-arith4_clone-native-verifier"
        run(str(original_prover), "recurse-prove", str(ASSIGNMENT), str(child),
            str(outer), str(original / "verification-key.json"))
        assignment = json.loads(ASSIGNMENT.read_text())
        child_statement = work / "child.statement.json"
        s31.write_json(child_statement, {"public_inputs": assignment["public_inputs"],
                                         "public_outputs": assignment["public_outputs"]})
        # The child STARK is portable across these keys because their AIRs
        # are identical. The outer proof must bind the stronger program key.
        run(str(clone_verifier), str(child), str(child_statement),
            str(clone / "verification-key.json"))
        statement = json.loads(Path(f"{outer}.statement.json").read_text())
        run(str(original_verifier), "recurse-verify", str(outer), f"{outer}.statement.json")
        original_outer_words = statement["outer_public_words"]
        clone_digest = hashlib.sha256((clone / "verification-key.json").read_bytes()).digest()
        statement["child_key_sha256"] = clone_digest.hex()
        statement["outer_public_words"] = list(struct.unpack(
            "<8I", hashlib.blake2s(clone_digest + struct.pack("<8I", *statement["child_public_words"]),
                                    person=b"S31RCV2!").digest()))
        if statement["outer_public_words"] == original_outer_words:
            raise AssertionError("different child keys produced the same recursive claim")
        statement["outer_preprocessed_root"] = clone_recursive["outer_preprocessed_root"]
        statement["outer_circuit_hash"] = clone_recursive["outer_circuit_hash"]
        replay_statement = work / "replay.statement.json"
        s31.write_json(replay_statement, statement)
        run(str(clone_verifier), "recurse-verify", str(outer), str(replay_statement), accept=False)
        print(json.dumps({"schema": "s31-recursion-key-binding-acceptance-v1",
                          "same_child_air": True,
                          "distinct_outer_air": True,
                          "child_proof_accepted_under_clone_key": True,
                          "outer_proof_rejected_under_clone_key": True}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
