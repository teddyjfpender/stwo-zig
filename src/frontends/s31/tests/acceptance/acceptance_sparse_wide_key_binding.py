#!/usr/bin/env python3
"""Sparse-wide leaf and outer replay fail across source or FRI key changes."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import s31

HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples" / "wide" / "wide_order.s31"
ASSIGNMENT = HERE / "examples" / "wide" / "wide_order.valid.json"


def call(*args: str, accepted: bool = True) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{output}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse the original wide_order package")
    parser.add_argument("--compare-fri-schedules", action="store_true",
                        help="compare the same source under child fold steps 1 and 4")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-wide-key-binding-") as temporary:
        work = Path(temporary)
        original = args.package.resolve() if args.package else s31.build(SOURCE, work / "original", "sparse-wide-gate")
        s31.verify_package(original)
        if args.compare_fri_schedules:
            clone_source = SOURCE
            clone_name = "wide_order"
            clone = s31.build(clone_source, work / "clone", "sparse-wide-gate", 4)
        else:
            clone_source = work / "wide_order_clone.s31"
            clone_source.write_text(SOURCE.read_text().replace("circuit wide_order(", "circuit wide_order_clone("))
            clone_name = "wide_order_clone"
            clone = s31.build(clone_source, work / "clone", "sparse-wide-gate")
        original_key = json.loads((original / "verification-key.json").read_text())
        clone_key = json.loads((clone / "verification-key.json").read_text())
        if original_key["preprocessed_root"] != clone_key["preprocessed_root"]:
            raise AssertionError("same arithmetic changed the preprocessed AIR root")
        if args.compare_fri_schedules:
            if original_key["circuit_hash"] != clone_key["circuit_hash"]:
                raise AssertionError("FRI-only change changed the source/AIR identity")
            if (original_key["fri"]["fold_step"], clone_key["fri"]["fold_step"]) != (1, 4):
                raise AssertionError("comparison did not build both child FRI schedules")
        elif original_key["circuit_hash"] == clone_key["circuit_hash"]:
            raise AssertionError("different source did not change sparse-wide circuit identity")
        original_recursive = json.loads((original / "recursive-verification-key.json").read_text())
        clone_recursive = json.loads((clone / "recursive-verification-key.json").read_text())
        if original_recursive["outer_preprocessed_root"] == clone_recursive["outer_preprocessed_root"]:
            raise AssertionError("different keys did not change the outer verifier AIR")

        original_prover = original / "bin" / "s31-wide_order-prover"
        original_verifier = original / "bin" / "s31-wide_order-native-verifier"
        clone_prover = clone / "bin" / f"s31-{clone_name}-prover"
        clone_verifier = clone / "bin" / f"s31-{clone_name}-native-verifier"
        original_leaf = work / "original-leaf.proof"
        original_outer = work / "original-outer.proof"
        clone_leaf = work / "clone-leaf.proof"
        call(str(original_prover), "prove", str(ASSIGNMENT), str(original_leaf))
        call(str(clone_prover), "prove", str(ASSIGNMENT), str(clone_leaf))
        assignment = json.loads(ASSIGNMENT.read_text())
        statement = work / "statement.json"
        s31.write_json(statement, {"public_inputs": assignment["public_inputs"], "public_outputs": assignment["public_outputs"]})
        call(str(original_verifier), str(original_leaf), str(statement), str(original / "verification-key.json"))
        call(str(clone_verifier), str(clone_leaf), str(statement), str(clone / "verification-key.json"))
        call(str(clone_verifier), str(original_leaf), str(statement), str(clone / "verification-key.json"), accepted=False)
        call(str(original_verifier), str(clone_leaf), str(statement), str(original / "verification-key.json"), accepted=False)

        call(str(original_prover), "recurse-wide-wrap", str(original_leaf), str(statement), str(original_outer), str(original / "verification-key.json"), "--low-memory")
        original_outer_statement = Path(str(original_outer) + ".statement.json")
        call(str(original_verifier), "recurse-verify", str(original_outer), str(original_outer_statement))
        repaired = json.loads(original_outer_statement.read_text())
        clone_digest = hashlib.sha256((clone / "verification-key.json").read_bytes()).digest()
        repaired["child_key_sha256"] = clone_digest.hex()
        repaired["outer_public_words"] = list(struct.unpack(
            "<8I", hashlib.blake2s(clone_digest + struct.pack("<8I", *repaired["child_public_words"]), person=b"S31RCV2!").digest()
        ))
        repaired["outer_preprocessed_root"] = clone_recursive["outer_preprocessed_root"]
        repaired["outer_circuit_hash"] = clone_recursive["outer_circuit_hash"]
        repaired_path = work / "repaired-clone-statement.json"
        s31.write_json(repaired_path, repaired)
        rejection = call(str(clone_verifier), "recurse-verify", str(original_outer), str(repaired_path), accepted=False)
        if "InvalidRecursiveStatement" in rejection or "InvalidRecursiveVerificationKey" in rejection:
            raise AssertionError("repaired clone statement failed before outer proof verification")
        print(json.dumps({
            "schema": "s31-sparse-wide-key-binding-v2",
            "comparison": "fri-schedules" if args.compare_fri_schedules else "source-names",
            "same_preprocessed_air_root": True,
            "same_profile_identity": args.compare_fri_schedules,
            "cross_key_leaf_replay_rejected": True,
            "different_outer_air_root": True,
            "cross_key_outer_replay_rejected_after_statement_repair": True,
        }, indent=2))


if __name__ == "__main__":
    main()
