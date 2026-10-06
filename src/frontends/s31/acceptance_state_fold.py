#!/usr/bin/env python3
"""Verify that one fixed AIR proves successive S31 recurrence steps."""

from __future__ import annotations

import argparse
import copy
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
P = (1 << 31) - 1


def run(*args: str, accept: bool = True) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def statement(path: Path) -> dict:
    return json.loads(Path(f"{path}.statement.json").read_text())


def digest(root: str, step: int, base: list[int], initial: list[int], current: list[int]) -> list[int]:
    message = bytes.fromhex(root) + struct.pack("<I8I4I4I", step, *base, *initial, *current)
    if len(message) != 100:
        raise AssertionError("wrong state-fold digest preimage length")
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31STF2!").digest()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a built arith4 package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-state-fold-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.package_for(SOURCE)
        s31.verify_package(package)
        key = package / "state-fold-verification-key.json"
        sealed = json.loads(key.read_text())
        if sealed["schema"] != "s31-state-fold-verification-key-v3" or sealed["counter_bits"] != 32:
            raise AssertionError("state-fold key missing")
        step_body = sealed["step_body"]
        rounds = sealed["source_rounds"]
        if (step_body, rounds) != ([{"op": "square", "constant": None},
                                   {"op": "add_const", "constant": 7}], 256):
            raise AssertionError("source recurrence mismatch")
        child_key = package / "verification-key.json"
        first_key = package / "recursive-verification-key.json"
        prover = package / "bin/s31-arith4_m31-prover"
        verifier = package / "bin/s31-arith4_m31-native-verifier"
        reproduced = work / "reproduced-key.json"
        run(str(prover), "state-fold-keygen", str(child_key), str(first_key), str(reproduced))
        if reproduced.read_bytes() != key.read_bytes():
            raise AssertionError("state-fold key is not reproducible")

        leaf = work / "leaf.proof"
        first = work / "first.proof"
        run("python3", str(HERE / "s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf), str(first))
        run("python3", str(HERE / "s31.py"), "audit-state-fold-base", str(package), str(first))
        folds = [work / f"state{step}.proof" for step in range(4)]
        run("python3", str(HERE / "s31.py"), "state-fold-base", str(package), str(first), str(folds[0]))
        for step in range(1, 4):
            run("python3", str(HERE / "s31.py"), "audit-state-fold-next", str(package),
                str(folds[step - 1]))
            run("python3", str(HERE / "s31.py"), "state-fold-next", str(package),
                str(folds[step - 1]), str(folds[step]))
        root = sealed["fold_preprocessed_root"]
        original = statement(first)
        expected = original["child_public_words"][4:8]
        for step, path in enumerate(folds):
            item = statement(path)
            if item["step"] != step or item["fold_preprocessed_root"] != root:
                raise AssertionError("state fold changed its key or step")
            if item["leaf_public_words"] != original["child_public_words"] or item["base_public_words"] != original["outer_public_words"]:
                raise AssertionError("state fold changed its base claim")
            if item["initial_state"] != original["child_public_words"][4:8]:
                raise AssertionError("initial state is not the leaf's public output")
            if step:
                expected = [(word * word + 7) % P for word in expected]
            if item["current_state"] != expected:
                raise AssertionError(f"wrong independently computed state at step {step}")
            if item["fold_public_words"] != digest(root, step, item["base_public_words"],
                                                   item["initial_state"], item["current_state"]):
                raise AssertionError("wrong state-fold public digest")
            run(str(verifier), "state-fold-verify", str(path), f"{path}.statement.json")

        low_memory = work / "state3-low-memory.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-next", str(package),
            str(folds[2]), str(low_memory), "--low-memory")
        if low_memory.read_bytes() != folds[3].read_bytes():
            raise AssertionError("low-memory policy changed state-fold proof bytes")

        top = folds[3]
        top_statement = statement(top)
        def rejected(changed: dict, label: str) -> None:
            path = work / f"{label}.json"
            s31.write_json(path, changed)
            run(str(verifier), "state-fold-verify", str(top), str(path), accept=False)

        changed = copy.deepcopy(top_statement)
        changed["current_state"][0] = (changed["current_state"][0] + 1) % P
        changed["fold_public_words"] = digest(root, changed["step"], changed["base_public_words"],
                                               changed["initial_state"], changed["current_state"])
        rejected(changed, "wrong-current-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["step"] = 2
        changed["fold_public_words"] = digest(root, 2, changed["base_public_words"],
                                               changed["initial_state"], changed["current_state"])
        rejected(changed, "wrong-step-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["initial_state"][0] ^= 1
        changed["fold_public_words"] = digest(root, changed["step"], changed["base_public_words"],
                                               changed["initial_state"], changed["current_state"])
        rejected(changed, "wrong-initial-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["leaf_public_words"][0] ^= 1
        child_digest = hashlib.sha256(child_key.read_bytes()).digest()
        changed["base_public_words"] = list(struct.unpack("<8I", hashlib.blake2s(
            child_digest + struct.pack("<8I", *changed["leaf_public_words"]),
            person=b"S31RCV2!").digest()))
        changed["fold_public_words"] = digest(root, changed["step"], changed["base_public_words"],
                                               changed["initial_state"], changed["current_state"])
        rejected(changed, "wrong-leaf-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["current_state"][0] = P
        rejected(changed, "noncanonical-state")

        corrupt = bytearray(top.read_bytes())
        corrupt[-1] ^= 1
        bad_top = work / "corrupt-top.proof"
        bad_top.write_bytes(corrupt)
        run(str(verifier), "state-fold-verify", str(bad_top), f"{top}.statement.json", accept=False)
        corrupt = bytearray(folds[2].read_bytes())
        corrupt[-1] ^= 1
        bad_child = work / "corrupt-child.proof"
        bad_child.write_bytes(corrupt)
        run(str(prover), "state-fold-wrap-next", str(bad_child), f"{folds[2]}.statement.json",
            str(work / "invalid.proof"), str(child_key), str(first_key), str(key), accept=False)
        tampered_key = json.loads(key.read_text())
        tampered_key["step_body"][1]["constant"] ^= 1
        bad_key = work / "wrong-step-key.json"
        s31.write_json(bad_key, tampered_key)
        run(str(prover), "state-fold-wrap-next", str(folds[2]), f"{folds[2]}.statement.json",
            str(work / "invalid.proof"), str(child_key), str(first_key), str(bad_key), accept=False)

        for path in (leaf, first, *folds[:-1], low_memory):
            path.unlink()
            Path(f"{path}.statement.json").unlink()
        run(str(verifier), "state-fold-verify", str(top), f"{top}.statement.json")
        print("S31 state-fold acceptance: four states, one key, independent M31 recurrence, "
              "isolated top proof, low-memory equality, repaired hostile claims and corrupt proofs")


if __name__ == "__main__":
    main()
