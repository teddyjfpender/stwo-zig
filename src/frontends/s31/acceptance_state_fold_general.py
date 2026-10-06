#!/usr/bin/env python3
"""Exercise a non-chip recurrence with a source-bound recursive transition."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

import s31
from acceptance_state_fold import digest, run, statement


HERE = Path(__file__).resolve().parent
P = (1 << 31) - 1
SOURCE = HERE / "examples/affine_square4.s31"
ASSIGNMENT = HERE / "examples/affine_square4.valid.json"
BODY = [{"op": "square", "constant": None},
        {"op": "mul_const", "constant": 3},
        {"op": "add_const", "constant": 5}]


def step(values: list[int]) -> list[int]:
    return [(3 * value * value + 5) % P for value in values]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a built affine_square4 package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-general-state-fold-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.package_for(SOURCE)
        s31.verify_package(package)
        key_path = package / "state-fold-verification-key.json"
        key = json.loads(key_path.read_text())
        if (key["schema"] != "s31-state-fold-verification-key-v2" or
                key["source_rounds"] != 3 or key["step_body"] != BODY):
            raise AssertionError("source step was not bound into the recursive key")
        cost = json.loads((package / "cost-report.json").read_text())
        if cost["repeated_step"] is not None or cost["state_fold_step"] != {"rounds": 3, "body": BODY}:
            raise AssertionError("general fold accidentally selected the narrow chip")
        prover = package / "bin/s31-affine_square4-prover"
        verifier = package / "bin/s31-affine_square4-native-verifier"
        leaf, first = work / "leaf.proof", work / "first.proof"
        run("python3", str(HERE / "s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf), str(first))
        expected = [1, 2, 3, 4]
        for _ in range(3):
            expected = step(expected)
        if statement(first)["child_public_words"][4:8] != expected:
            raise AssertionError("source base proof computed the wrong three rounds")
        run("python3", str(HERE / "s31.py"), "audit-state-fold-base", str(package), str(first))
        checkpoints = work / "checkpoints"
        top = work / "top.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package), str(first),
            str(top), "--steps", "3", "--checkpoint-dir", str(checkpoints))
        folds = [checkpoints / "state-00000.proof", checkpoints / "state-00001.proof", top]
        for proof in folds[:2]:
            run("python3", str(HERE / "s31.py"), "audit-state-fold-next", str(package), str(proof))
        resumed = work / "resumed.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
            str(folds[1]), str(resumed), "--steps", "1")
        if resumed.read_bytes() != top.read_bytes():
            raise AssertionError("checkpoint resume changed proof bytes")
        low_memory = work / "low-memory.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
            str(folds[1]), str(low_memory), "--steps", "1", "--low-memory")
        if low_memory.read_bytes() != top.read_bytes():
            raise AssertionError("low-memory resume changed proof bytes")
        overflow = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                       str(top), str(work / "overflow.proof"), "--steps", "65535", accept=False)
        zero = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                   str(top), str(work / "zero.proof"), "--steps", "0", accept=False)
        if "counter would overflow" not in overflow or "at least one step" not in zero:
            raise AssertionError("state-fold advance rejected bounds for the wrong reason")
        root = key["fold_preprocessed_root"]
        for i, proof in enumerate(folds):
            item = statement(proof)
            if i:
                expected = step(expected)
            if item["step"] != i or item["current_state"] != expected:
                raise AssertionError(f"incorrect state at fold step {i}")
            if item["fold_public_words"] != digest(root, i, item["base_public_words"],
                                                   item["initial_state"], expected):
                raise AssertionError("state fold public digest mismatch")
            run(str(verifier), "state-fold-verify", str(proof), f"{proof}.statement.json")

        hostile = copy.deepcopy(statement(folds[-1]))
        hostile["current_state"][0] = (hostile["current_state"][0] + 1) % P
        hostile["fold_public_words"] = digest(root, hostile["step"], hostile["base_public_words"],
                                               hostile["initial_state"], hostile["current_state"])
        hostile_path = work / "false-state-rehashed.json"
        s31.write_json(hostile_path, hostile)
        run(str(verifier), "state-fold-verify", str(folds[-1]), str(hostile_path), accept=False)

        altered = copy.deepcopy(key)
        altered["step_body"][1]["constant"] = 4
        altered_key_path = work / "false-body-key.json"
        s31.write_json(altered_key_path, altered)
        run(str(prover), "state-fold-wrap-next", str(folds[-1]), f"{folds[-1]}.statement.json",
            str(work / "invalid.proof"), str(package / "verification-key.json"),
            str(package / "recursive-verification-key.json"), str(altered_key_path), accept=False)

        for path in (leaf, first, *folds[:-1]):
            path.unlink()
            Path(f"{path}.statement.json").unlink()
        run(str(verifier), "state-fold-verify", str(folds[-1]), f"{folds[-1]}.statement.json")
        print("S31 general state-fold acceptance: three base rounds, square/multiply/add step, "
              "independent M31 arithmetic, checkpoint and low-memory resume, hostile claims and key, isolated top proof")


if __name__ == "__main__":
    main()
