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
        manifest = s31.verify_package(package)
        if "state-fold-verification-key.json" in manifest["artifacts"]:
            raise AssertionError("non-recurrence source unexpectedly received a state-fold key")
        child_key = package / "verification-key.json"
        first_key = package / "recursive-verification-key.json"
        fold_key = package / "fixed-fold-verification-key.json"
        prover = package / "bin/s31-preimage4-prover"
        verifier = package / "bin/s31-preimage4-native-verifier"
        geometry = json.loads(run("python3", str(HERE / "s31.py"), "inspect-fold", str(package)))
        sealed_fold = json.loads(fold_key.read_text())
        if geometry["fold_preprocessed_root"] != sealed_fold["fold_preprocessed_root"]:
            raise AssertionError("inspected fold topology did not match the sealed root")
        for component, padded in geometry["padded_rows"].items():
            if geometry["raw_rows"][component] + geometry["headroom_rows"][component] != padded:
                raise AssertionError(f"incorrect fold headroom for {component}")
        stages = geometry["verifier_stages"]
        if (not isinstance(stages, list) or len(stages) < 20 or
                stages[0]["name"] != "proof_witness" or
                stages[-1]["name"] != "finalize" or
                stages[-1]["raw_vars"] != geometry["raw_vars"]):
            raise AssertionError("gate fold stage capture is incomplete")
        reproduced = work / "fold-key.json"
        run(str(prover), "fold-keygen", str(child_key), str(first_key), str(reproduced))
        if reproduced.read_bytes() != fold_key.read_bytes():
            raise AssertionError("fixed-fold key is not reproducible")

        leaf = work / "leaf.proof"
        first = work / "first.proof"
        run("python3", str(HERE / "s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf), str(first))
        run("python3", str(HERE / "s31.py"), "state-fold-base", str(package),
            str(first), str(work / "unsupported-state.proof"), accept=False)
        base_audit = run("python3", str(HERE / "s31.py"), "audit-fold-base", str(package), str(first))
        if "valid=true rejected=23" not in base_audit:
            raise AssertionError(base_audit)

        folds = [work / f"fold{step}.proof" for step in range(4)]
        run("python3", str(HERE / "s31.py"), "fold-base", str(package), str(first), str(folds[0]))
        for step in range(1, 4):
            run("python3", str(HERE / "s31.py"), "fold-next", str(package),
                str(folds[step - 1]), str(folds[step]))
            next_audit = run("python3", str(HERE / "s31.py"), "audit-fold-next", str(package),
                             str(folds[step - 1]))
            if "valid=true rejected=23" not in next_audit:
                raise AssertionError(next_audit)
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
        if "s31-fixed-fold-batch-v1" not in manifest.get("capabilities", []):
            raise AssertionError("fixed-fold batch capability was not sealed")
        batch_top = work / "batch-top.proof"
        checkpoints = work / "batch-checkpoints"
        run("python3", str(HERE / "s31.py"), "fold-advance", str(package), str(first),
            str(batch_top), "--steps", "4", "--checkpoint-dir", str(checkpoints), "--low-memory")
        batch_paths = [*(checkpoints / f"fold-{step:05d}.proof" for step in range(3)), batch_top]
        for one, batched in zip(folds, batch_paths, strict=True):
            if one.read_bytes() != batched.read_bytes() or Path(f"{one}.statement.json").read_bytes() != Path(f"{batched}.statement.json").read_bytes():
                raise AssertionError("fixed-fold batch changed proof or statement bytes")
        run(str(verifier), "fold-verify", str(batch_top), f"{batch_top}.statement.json")

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
        inspected = json.loads(run("python3", str(HERE / "inspect_recursive_claim.py"),
                                   str(package), str(top)))
        if (inspected["native_top_verification"] != "accepted" or
                inspected["first_wrapper_public_words_d1"] != first_statement["outer_public_words"] or
                inspected["base_public_words"] != top_statement["base_public_words"] or
                inspected["top_public_words"] != top_statement["fold_public_words"] or
                inspected["step"] != 3 or inspected["lower_proof_files_required"] is not False):
            raise AssertionError("claim inspector did not explain the isolated gate fold")
        print("S31 fixed-fold acceptance: four steps, one key, isolated top verifier, "
              "private leaf, raw u32 digest, byte-identical batch, inspected claim, low-memory equality, hostile statements and proof bytes")


if __name__ == "__main__":
    main()
