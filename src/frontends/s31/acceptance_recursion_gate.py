#!/usr/bin/env python3
"""End-to-end and adversarial checks for the one-level S31 gate wrapper."""

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
ROOT = HERE.parents[2]
SOURCE = HERE / "examples/arith4_m31.s31"
ASSIGNMENT = HERE / "examples/arith4.valid.json"


def run(*args: str, accept: bool) -> None:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(
            f"unexpected exit {result.returncode} for {args!r}:\n"
            f"{result.stdout}{result.stderr}"
        )


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a built gate-profile S31 package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-recursion-") as tmp:
        work = Path(tmp)
        package = args.package.resolve() if args.package else work / "package"
        if args.package is None:
            run("python3", str(HERE / "s31.py"), "build", str(SOURCE),
                "--lowering", "gate", "--out", str(package), accept=True)
        manifest = s31.verify_package(package)
        child_profile = json.loads((package / "verification-key.json").read_text())["profile"]
        if manifest["lowering"] != "gate" or child_profile != "circuit-v1":
            raise AssertionError("recursive gate acceptance requires circuit-v1")
        prover = package / "bin/s31-arith4_m31-prover"
        verifier = package / "bin/s31-arith4_m31-native-verifier"
        key = package / "verification-key.json"
        reproduced_recursive_key = work / "reproduced-recursive-key.json"
        run(str(prover), "recurse-keygen", str(key), str(reproduced_recursive_key),
            accept=True)
        if json.loads(reproduced_recursive_key.read_text()) != json.loads(
                (package / "recursive-verification-key.json").read_text()):
            raise AssertionError("sealed recursive key is not reproducible")
        leaf = work / "leaf.proof"
        outer = work / "outer.proof"
        run(str(prover), "recurse-check", str(ASSIGNMENT),
            str(work / "audit-leaf.proof"), accept=True)
        run(str(prover), "recurse-prove", str(ASSIGNMENT), str(leaf),
            str(outer), str(key), accept=True)
        statement_path = Path(f"{outer}.statement.json")
        statement = json.loads(statement_path.read_text())
        run(str(verifier), "recurse-verify", str(outer), str(statement_path), accept=True)

        leaf_assignment = json.loads(ASSIGNMENT.read_text())
        leaf_statement = work / "leaf.statement.json"
        write_json(leaf_statement, {
            "public_inputs": leaf_assignment["public_inputs"],
            "public_outputs": leaf_assignment["public_outputs"],
        })
        run(str(verifier), str(leaf), str(leaf_statement), str(key), accept=True)
        run("python3", str(HERE / "s31.py"), "audit-recursive", str(package),
            str(leaf), "--statement", str(leaf_statement), accept=True)

        # A separately loaded S31NAT1 proof is verified natively, expanded
        # from the verifier's authenticated capture, then verified in-circuit.
        saved_outer = work / "saved-outer.proof"
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf),
            str(saved_outer), "--statement", str(leaf_statement), accept=True)
        saved_statement_path = Path(f"{saved_outer}.statement.json")
        saved_statement = json.loads(saved_statement_path.read_text())
        if saved_statement != statement:
            raise AssertionError("saved-proof wrapper changed the outer public statement")
        run("python3", str(HERE / "s31.py"), "verify-recursive", str(package),
            str(saved_outer), accept=True)
        low_memory_outer = work / "low-memory-outer.proof"
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf),
            str(low_memory_outer), "--statement", str(leaf_statement),
            "--low-memory", accept=True)
        if low_memory_outer.read_bytes() != saved_outer.read_bytes():
            raise AssertionError("low-memory policy changed recursive proof bytes")
        run("python3", str(HERE / "s31.py"), "verify-recursive", str(package),
            str(low_memory_outer), accept=True)

        wrong_leaf_statement = copy.deepcopy(json.loads(leaf_statement.read_text()))
        wrong_leaf_statement["public_outputs"]["result"][0] += 1
        wrong_leaf_statement_path = work / "wrong-leaf-statement.json"
        write_json(wrong_leaf_statement_path, wrong_leaf_statement)
        run(str(prover), "recurse-wrap", str(leaf), str(wrong_leaf_statement_path),
            str(work / "bad-saved-statement.proof"), str(key), accept=False)
        corrupted_leaf = bytearray(leaf.read_bytes())
        corrupted_leaf[-1] ^= 1
        corrupted_leaf_path = work / "corrupted-leaf.proof"
        corrupted_leaf_path.write_bytes(corrupted_leaf)
        run(str(prover), "recurse-wrap", str(corrupted_leaf_path), str(leaf_statement),
            str(work / "bad-saved-proof.proof"), str(key), accept=False)

        # Change the child claim and recompute the public wrapper digest.
        # The outer proof must still reject, establishing that its output
        # binds the original child words rather than a caller's replacement.
        changed = copy.deepcopy(statement)
        changed["child_public_words"][0] += 1
        root = bytes.fromhex(json.loads(key.read_text())["preprocessed_root"])
        digest = hashlib.blake2s(root + struct.pack("<8I", *changed["child_public_words"])).digest()
        changed["outer_public_words"] = list(struct.unpack("<8I", digest))
        wrong_child = work / "wrong-child.json"
        write_json(wrong_child, changed)
        run(str(verifier), "recurse-verify", str(outer), str(wrong_child), accept=False)

        for label, field in (("key", "child_key_sha256"),
                             ("root", "outer_preprocessed_root"),
                             ("hash", "outer_circuit_hash")):
            changed = copy.deepcopy(statement)
            changed[field] = ("0" if changed[field][0] != "0" else "1") + changed[field][1:]
            path = work / f"wrong-{label}.json"
            write_json(path, changed)
            run(str(verifier), "recurse-verify", str(outer), str(path), accept=False)

        changed = copy.deepcopy(statement)
        changed["outer_public_words"][0] ^= 1
        wrong_output = work / "wrong-output.json"
        write_json(wrong_output, changed)
        run(str(verifier), "recurse-verify", str(outer), str(wrong_output), accept=False)

        corrupted = bytearray(outer.read_bytes())
        corrupted[-1] ^= 1
        corrupted_path = work / "corrupted.proof"
        corrupted_path.write_bytes(corrupted)
        run(str(verifier), "recurse-verify", str(corrupted_path), str(statement_path), accept=False)

        wrong_key = json.loads(key.read_text())
        wrong_key["circuit_hash"] = "0" * 64
        wrong_key_path = work / "wrong-key.json"
        write_json(wrong_key_path, wrong_key)
        run(str(prover), "recurse-keygen", str(wrong_key_path),
            str(work / "wrong-recursive-key.json"), accept=False)
        run(str(prover), "recurse-prove", str(ASSIGNMENT), str(work / "bad-leaf.proof"),
            str(work / "bad-outer.proof"), str(wrong_key_path), accept=False)
        run(str(prover), "recurse-wrap", str(leaf), str(leaf_statement),
            str(work / "bad-saved-key.proof"), str(wrong_key_path), accept=False)

        tampered_package = work / "tampered-package"
        tampered_package.mkdir()
        copied_key = tampered_package / "verification-key.json"
        copied_key.write_bytes(key.read_bytes())
        bad_recursive_key = json.loads((package / "recursive-verification-key.json").read_text())
        bad_recursive_key["outer_preprocessed_root"] = "0" * 64
        write_json(tampered_package / "recursive-verification-key.json", bad_recursive_key)
        run(str(prover), "recurse-wrap", str(leaf), str(leaf_statement),
            str(work / "bad-outer-key.proof"), str(copied_key), accept=False)

        print(json.dumps({
            "schema": "s31-recursive-gate-acceptance-v1",
            "child_profile": child_profile,
            "leaf_proof_bytes": leaf.stat().st_size,
            "outer_proof_bytes": outer.stat().st_size,
            "outer_statement_sha256": hashlib.sha256(statement_path.read_bytes()).hexdigest(),
            "accepted": 4,
            "rejected": 12,
            "in_circuit_rejections": [
                "changed_public_word", "trace_root", "claimed_sum",
                "channel_salt", "fri_witness", "fri_last_layer",
            ],
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
