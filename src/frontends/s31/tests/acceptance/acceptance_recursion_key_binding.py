#!/usr/bin/env python3
"""A same-AIR child key must produce a distinct recursive circuit and claim."""

from __future__ import annotations

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
SOURCE = HERE / "examples/arithmetic/arith4_m31.s31"
ASSIGNMENT = HERE / "examples/arithmetic/arith4.valid.json"


def run(*args: str, accept: bool = True) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{output}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse the original gate package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-recursion-key-binding-") as temporary:
        work = Path(temporary)
        original = args.package.resolve() if args.package else s31.package_for(SOURCE)
        s31.verify_package(original)
        original_key = json.loads((original / "verification-key.json").read_text())
        clone_source = work / "arith4_clone.s31"
        clone_source.write_text(SOURCE.read_text().replace("circuit arith4_m31(",
                                                           "circuit arith4_clone("))
        clone = s31.build(clone_source, work / "clone", fri_fold_step=original_key["fri"]["fold_step"])
        clone_key = json.loads((clone / "verification-key.json").read_text())
        if original_key["preprocessed_root"] != clone_key["preprocessed_root"]:
            raise AssertionError("same arithmetic unexpectedly changed child AIR root")
        if original_key["circuit_hash"] != clone_key["circuit_hash"]:
            raise AssertionError("same arithmetic unexpectedly changed child circuit hash")
        original_recursive = json.loads((original / "recursive-verification-key.json").read_text())
        clone_recursive = json.loads((clone / "recursive-verification-key.json").read_text())
        if original_recursive["outer_preprocessed_root"] == clone_recursive["outer_preprocessed_root"]:
            raise AssertionError("different child key did not change the recursive AIR")
        original_fold = json.loads((original / "fixed-fold-verification-key.json").read_text())
        clone_fold = json.loads((clone / "fixed-fold-verification-key.json").read_text())
        if original_fold["fold_preprocessed_root"] == clone_fold["fold_preprocessed_root"]:
            raise AssertionError("different base keys did not change the fixed-fold AIR")
        original_state = json.loads((original / "state-fold-verification-key.json").read_text())
        clone_state = json.loads((clone / "state-fold-verification-key.json").read_text())
        if original_state["fold_preprocessed_root"] == clone_state["fold_preprocessed_root"]:
            raise AssertionError("different base keys did not change the state-fold AIR")

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
        fold0 = work / "fold0.proof"
        run("python3", str(HERE / "python/s31.py"), "fold-base", str(original), str(outer), str(fold0))
        run(str(original_verifier), "fold-verify", str(fold0), f"{fold0}.statement.json")
        fold_statement = json.loads(Path(f"{fold0}.statement.json").read_text())
        run(str(clone_verifier), "fold-verify", str(fold0), f"{fold0}.statement.json", accept=False)
        fold_statement["fold_key_sha256"] = hashlib.sha256(
            (clone / "fixed-fold-verification-key.json").read_bytes()).hexdigest()
        fold_statement["base_public_words"] = statement["outer_public_words"]
        fold_statement["fold_preprocessed_root"] = clone_fold["fold_preprocessed_root"]
        fold_statement["fold_circuit_hash"] = clone_fold["fold_circuit_hash"]
        message = bytes.fromhex(clone_fold["fold_preprocessed_root"]) + struct.pack(
            "<I8I", 0, *fold_statement["base_public_words"])
        fold_statement["fold_public_words"] = list(struct.unpack(
            "<8I", hashlib.blake2s(message, person=b"S31FOL2!").digest()))
        replay_fold_statement = work / "replay-fold.statement.json"
        s31.write_json(replay_fold_statement, fold_statement)
        run(str(clone_verifier), "fold-verify", str(fold0), str(replay_fold_statement), accept=False)
        state0 = work / "state0.proof"
        run("python3", str(HERE / "python/s31.py"), "state-fold-base", str(original), str(outer), str(state0))
        run(str(original_verifier), "state-fold-verify", str(state0), f"{state0}.statement.json")
        state_statement = json.loads(Path(f"{state0}.statement.json").read_text())
        original_state_words = state_statement["fold_public_words"]
        state_statement["state_fold_key_sha256"] = hashlib.sha256(
            (clone / "state-fold-verification-key.json").read_bytes()).hexdigest()
        state_statement["base_public_words"] = statement["outer_public_words"]
        state_statement["fold_preprocessed_root"] = clone_state["fold_preprocessed_root"]
        state_statement["fold_circuit_hash"] = clone_state["fold_circuit_hash"]
        state_message = bytes.fromhex(clone_state["fold_preprocessed_root"]) + struct.pack(
            "<I8I4I4I", 0, *state_statement["base_public_words"],
            *state_statement["initial_state"], *state_statement["current_state"])
        state_domain = {
            "s31-state-fold-verification-key-v1": b"S31STF1!",
            "s31-state-fold-verification-key-v2": b"S31STF1!",
            "s31-state-fold-verification-key-v3": b"S31STF2!",
        }[clone_state["schema"]]
        if len(state_message) != 100:
            raise AssertionError("wrong cloned state-fold digest preimage length")
        state_statement["fold_public_words"] = list(struct.unpack(
            "<8I", hashlib.blake2s(state_message, person=state_domain).digest()))
        if state_statement["fold_public_words"] == original_state_words:
            raise AssertionError("different state-fold keys produced the same public claim")
        replay_state_statement = work / "replay-state.statement.json"
        s31.write_json(replay_state_statement, state_statement)
        rejection = run(str(clone_verifier), "state-fold-verify", str(state0),
                        str(replay_state_statement), accept=False)
        if "InvalidStateFoldStatement" in rejection:
            raise AssertionError("cloned statement was rejected before proof verification")
        print(json.dumps({"schema": "s31-recursion-key-binding-acceptance-v1",
                          "same_child_air": True,
                          "distinct_outer_air": True,
                          "child_proof_accepted_under_clone_key": True,
                          "outer_proof_rejected_under_clone_key": True,
                          "distinct_fold_air": True,
                          "fold_proof_rejected_under_clone_key_after_digest_repair": True,
                          "distinct_state_fold_air": True,
                          "state_fold_proof_rejected_under_clone_key_after_digest_repair": True}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
