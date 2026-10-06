#!/usr/bin/env python3
"""End-to-end fixed-key recursive fold with hostile public statements."""

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
SOURCE = HERE / "examples/preimage4.s31"
ASSIGNMENT = HERE / "examples/preimage4.valid.json"
M31_MODULUS = (1 << 31) - 1


def run(*args: str, accept: bool = True) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def recursive_digest(key_bytes: bytes, words: list[int]) -> list[int]:
    message = hashlib.sha256(key_bytes).digest() + struct.pack("<8I", *words)
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31RCV2!").digest()))


def fold_digest(root: str, step: int, words: list[int]) -> list[int]:
    message = bytes.fromhex(root) + struct.pack("<I8I", step, *words)
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31FOL2!").digest()))


def statement(path: Path) -> dict:
    return json.loads(Path(f"{path}.statement.json").read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a built preimage4 package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-fixed-fold-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.package_for(SOURCE)
        s31.verify_package(package)
        child_key = package / "verification-key.json"
        first_key = package / "recursive-verification-key.json"
        fold_key = package / "fixed-fold-verification-key.json"
        prover = package / "bin/s31-preimage4-prover"
        verifier = package / "bin/s31-preimage4-native-verifier"
        reproduced = work / "fold-key.json"
        run(str(prover), "fold-keygen", str(child_key), str(first_key), str(reproduced))
        if reproduced.read_bytes() != fold_key.read_bytes():
            raise AssertionError("fixed-fold key is not reproducible")

        leaf = work / "leaf.proof"
        first = work / "first.proof"
        run("python3", str(HERE / "s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf), str(first))
        run(str(prover), "fold-audit", str(first), f"{first}.statement.json",
            str(child_key), str(first_key), str(fold_key))

        folds = [work / f"fold{step}.proof" for step in range(4)]
        run("python3", str(HERE / "s31.py"), "fold-base", str(package), str(first), str(folds[0]))
        for step in range(1, 4):
            run("python3", str(HERE / "s31.py"), "fold-next", str(package),
                str(folds[step - 1]), str(folds[step]))
            run("python3", str(HERE / "s31.py"), "audit-fold-next", str(package),
                str(folds[step - 1]))
        root = json.loads(fold_key.read_text())["fold_preprocessed_root"]
        first_statement = statement(first)
        # The discarded v1 preimage aliased (root, step) with
        # (root.word0 XOR step, 0). Their v2 digests must differ.
        shifted_root = bytearray.fromhex(root)
        shifted_root[:4] = (int.from_bytes(shifted_root[:4], "little") ^ 3).to_bytes(4, "little")
        if fold_digest(root, 3, first_statement["outer_public_words"]) == fold_digest(
                shifted_root.hex(), 0, first_statement["outer_public_words"]):
            raise AssertionError("fold root/step encoding aliases")
        for step, path in enumerate(folds):
            item = statement(path)
            if item["step"] != step or item["fold_preprocessed_root"] != root:
                raise AssertionError("fixed key or counter changed")
            if item["leaf_public_words"] != first_statement["child_public_words"]:
                raise AssertionError("leaf claim changed across folds")
            if item["base_public_words"] != first_statement["outer_public_words"]:
                raise AssertionError("base digest changed across folds")
            if item["fold_public_words"] != fold_digest(root, step, item["base_public_words"]):
                raise AssertionError("fold digest mismatch")
            run(str(verifier), "fold-verify", str(path), f"{path}.statement.json")
        if not any(word >= M31_MODULUS for word in statement(folds[3])["base_public_words"]):
            raise AssertionError("recursive digest does not exercise raw u32 words")

        low_memory = work / "fold2-low-memory.proof"
        run("python3", str(HERE / "s31.py"), "fold-next", str(package),
            str(folds[1]), str(low_memory), "--low-memory")
        if low_memory.read_bytes() != folds[2].read_bytes():
            raise AssertionError("low-memory policy changed fold proof bytes")

        top = folds[3]
        top_statement = statement(top)
        def rejected(changed: dict, label: str) -> None:
            path = work / f"{label}.json"
            s31.write_json(path, changed)
            run(str(verifier), "fold-verify", str(top), str(path), accept=False)

        changed = copy.deepcopy(top_statement)
        changed["step"] = 2
        changed["fold_public_words"] = fold_digest(root, 2, changed["base_public_words"])
        rejected(changed, "wrong-step-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["leaf_public_words"][0] += 1
        changed["base_public_words"] = recursive_digest(child_key.read_bytes(), changed["leaf_public_words"])
        changed["fold_public_words"] = fold_digest(root, 3, changed["base_public_words"])
        rejected(changed, "wrong-leaf-rehashed")
        changed = copy.deepcopy(top_statement)
        changed["fold_preprocessed_root"] = "0" * 64
        rejected(changed, "wrong-fold-root")
        changed = copy.deepcopy(top_statement)
        changed["fold_key_sha256"] = "0" * 64
        rejected(changed, "wrong-fold-key")
        changed = copy.deepcopy(top_statement)
        changed["leaf_public_words"][0] = M31_MODULUS
        rejected(changed, "noncanonical-leaf")

        corrupt = bytearray(top.read_bytes())
        corrupt[-1] ^= 1
        bad_proof = work / "corrupt-top.proof"
        bad_proof.write_bytes(corrupt)
        run(str(verifier), "fold-verify", str(bad_proof), f"{top}.statement.json", accept=False)
        corrupt = bytearray(folds[2].read_bytes())
        corrupt[-1] ^= 1
        bad_child = work / "corrupt-child.proof"
        bad_child.write_bytes(corrupt)
        run(str(prover), "fold-wrap-next", str(bad_child), f"{folds[2]}.statement.json",
            str(work / "should-not-exist.proof"), str(child_key), str(first_key), str(fold_key),
            accept=False)
        bad_fold_key = json.loads(fold_key.read_text())
        bad_fold_key["fold_preprocessed_root"] = "0" * 64
        bad_fold_path = work / "bad-fold-key.json"
        s31.write_json(bad_fold_path, bad_fold_key)
        run(str(prover), "fold-wrap-next", str(folds[2]), f"{folds[2]}.statement.json",
            str(work / "should-not-exist.proof"), str(child_key), str(first_key),
            str(bad_fold_path), accept=False)

        # The final native verifier receives only the top proof and statement.
        for path in (leaf, first, *folds[:-1], low_memory):
            path.unlink()
            Path(f"{path}.statement.json").unlink()
        run(str(verifier), "fold-verify", str(top), f"{top}.statement.json")
        print("S31 fixed-fold acceptance: four steps, one key, isolated top verifier, "
              "private leaf, raw u32 digest, low-memory equality, hostile statements and proof bytes")


if __name__ == "__main__":
    main()
