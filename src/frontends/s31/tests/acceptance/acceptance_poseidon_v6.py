#!/usr/bin/env python3
"""Pinned M31 Poseidon2 oracle, real proofs, and native-verifier rejection checks."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import json
import subprocess
import tempfile
from pathlib import Path

import poseidon2_oracle as oracle
import s31


HERE = S31_SOURCE_ROOT
EXAMPLES = HERE / "examples"


def call(*args: str, accept: bool = True) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{result.stdout}{result.stderr}")


def fixture(name: str) -> tuple[Path, dict]:
    source = EXAMPLES / f"{name}.s31.json"
    assignment = json.loads((EXAMPLES / f"{name}.valid.json").read_text())
    return source, assignment


def main() -> None:
    oracle.self_check()
    if oracle.leaf(list(range(1, 17))) == oracle.pair(list(range(1, 9)), list(range(9, 17))):
        raise AssertionError("leaf and parent domains were not separated")
    tree_source, tree = fixture("merkle2_poseidon")
    left = oracle.leaf(tree["private_inputs"]["left"])
    right = oracle.leaf(tree["private_inputs"]["right"])
    root = oracle.pair(left, right)
    if root != tree["public_outputs"]["root"] or root == oracle.pair(right, left):
        raise AssertionError("two-leaf fixture disagrees with independent arithmetic oracle")
    path_source, path = fixture("merkle_path1_poseidon")
    leaf = oracle.leaf(path["private_inputs"]["leaf"])
    sibling = path["private_inputs"]["sibling"]
    path_root = oracle.pair(sibling, leaf)
    if path["private_inputs"]["direction"] != [1] or path_root != path["public_outputs"]["root"]:
        raise AssertionError("path fixture disagrees with independent arithmetic oracle")

    with tempfile.TemporaryDirectory(prefix="s31-poseidon-acceptance-") as temporary:
        work = Path(temporary)
        for label, source, edit in (
            ("invalid_leaf", tree_source, lambda data: data["inputs"][0].update(length=5)),
            ("invalid_pair", tree_source, lambda data: (data["inputs"][1].update(length=4), data["nodes"][2].update(rhs="right"))),
            ("invalid_selector", path_source, lambda data: data["inputs"][2].update(length=2)),
        ):
            malformed = json.loads(source.read_text())
            edit(malformed)
            target = work / f"{label}.json"
            s31.write_json(target, malformed)
            call("python3", str(HERE / "python/s31.py"), "check", str(target), accept=False)

        cases = {}
        artifacts = {}
        for length in (4, 12, 16):
            name = f"poseidon_leaf{length}"
            words = list(range(1, length + 1))
            source = work / f"{name}.s31.json"
            assignment_file = work / f"{name}.assignment.json"
            statement = work / f"{name}.statement.json"
            s31.write_json(source, {
                "version": 1, "name": name,
                "inputs": [{"name": "words", "kind": "m31", "length": length, "visibility": "private"}],
                "nodes": [{"name": "root", "op": "hash_poseidon2_leaf", "lhs": "words"}],
                "assertions": [], "public_outputs": ["root"],
            })
            expected = oracle.leaf(words)
            s31.write_json(assignment_file, {"public_inputs": {}, "private_inputs": {"words": words}, "public_outputs": {"root": expected}})
            s31.write_json(statement, {"public_inputs": {}, "public_outputs": {"root": expected}})
            package = s31.build(source, work / f"{name}-package", "direct-gate")
            s31.verify_package(package)
            proof = work / f"{name}.proof"
            call(str(package / "bin" / f"s31-{name}-prover"), "prove", str(assignment_file), str(proof))
            call(str(package / "bin" / f"s31-{name}-native-verifier"), str(proof), str(statement), str(package / "verification-key.json"))
            cost = json.loads((package / "cost-report.json").read_text())
            cases[name] = {"program_sha256": s31.file_hash(source), "proof_bytes": proof.stat().st_size,
                           "preprocessed_cells": cost["preprocessed_cells"], "raw_qm31_rows": cost["raw"]["qm31_ops"], "native_verified": True}
        for name, source, assignment in (
            ("merkle2_poseidon", tree_source, tree),
            ("merkle_path1_poseidon", path_source, path),
        ):
            package = s31.build(source, work / f"{name}-package", "direct-gate")
            s31.verify_package(package)
            cost = json.loads((package / "cost-report.json").read_text())
            if cost["profile"] != "direct-m31-v4" or cost["preprocessed_columns"] != 8:
                raise AssertionError("Poseidon2 did not select direct-M31 arithmetic AIR")
            if any(cost["raw"][kind] for kind in ("eq", "blake_g", "triple_xor", "m31_to_u32")):
                raise AssertionError("Poseidon2 path unexpectedly requires a bitwise or conversion component")
            prover = package / "bin" / f"s31-{name}-prover"
            verifier = package / "bin" / f"s31-{name}-native-verifier"
            key = package / "verification-key.json"
            proof = work / f"{name}.proof"
            assignment_file = work / f"{name}.assignment.json"
            statement = work / f"{name}.statement.json"
            s31.write_json(assignment_file, assignment)
            s31.write_json(statement, {"public_inputs": {}, "public_outputs": assignment["public_outputs"]})
            call(str(prover), "prove", str(assignment_file), str(proof))
            call(str(verifier), str(proof), str(statement), str(key))
            artifacts[name] = (prover, verifier, key, proof, statement)
            cases[name] = {
                "program_sha256": s31.file_hash(source),
                "proof_bytes": proof.stat().st_size,
                "preprocessed_cells": cost["preprocessed_cells"],
                "raw_qm31_rows": cost["raw"]["qm31_ops"],
                "native_verified": True,
            }

        tree_prover, tree_verifier, tree_key, tree_proof, tree_statement = artifacts["merkle2_poseidon"]
        path_prover, path_verifier, path_key, path_proof, path_statement = artifacts["merkle_path1_poseidon"]
        wrong_statement = json.loads(tree_statement.read_text())
        wrong_statement["public_outputs"]["root"][0] = (root[0] + 1) % oracle.P
        wrong_statement_file = work / "wrong-statement.json"
        s31.write_json(wrong_statement_file, wrong_statement)
        call(str(tree_verifier), str(tree_proof), str(wrong_statement_file), str(tree_key), accept=False)
        wrong_private = json.loads(json.dumps(tree))
        wrong_private["private_inputs"]["left"][0] += 1
        wrong_private_file = work / "wrong-private.json"
        s31.write_json(wrong_private_file, wrong_private)
        call(str(tree_prover), "prove", str(wrong_private_file), str(work / "wrong-private.proof"), accept=False)
        damaged = bytearray(tree_proof.read_bytes())
        damaged[len(damaged) // 2] ^= 1
        damaged_file = work / "damaged.proof"
        damaged_file.write_bytes(damaged)
        call(str(tree_verifier), str(damaged_file), str(tree_statement), str(tree_key), accept=False)
        call(str(path_verifier), str(tree_proof), str(path_statement), str(path_key), accept=False)

        other = json.loads(json.dumps(path))
        other["private_inputs"]["direction"] = [0]
        other_root = oracle.pair(leaf, sibling)
        other["public_outputs"]["root"] = other_root
        other_file = work / "direction-zero.json"
        other_statement = work / "direction-zero-statement.json"
        other_proof = work / "direction-zero.proof"
        s31.write_json(other_file, other)
        s31.write_json(other_statement, {"public_inputs": {}, "public_outputs": {"root": other_root}})
        call(str(path_prover), "prove", str(other_file), str(other_proof))
        call(str(path_verifier), str(other_proof), str(other_statement), str(path_key))
        call(str(path_verifier), str(other_proof), str(path_statement), str(path_key), accept=False)
        non_bit = json.loads(json.dumps(path))
        non_bit["private_inputs"]["direction"] = [2]
        non_bit_file = work / "non-bit.json"
        s31.write_json(non_bit_file, non_bit)
        call(str(path_prover), "prove", str(non_bit_file), str(work / "non-bit.proof"), accept=False)
        cases["merkle_path1_poseidon"]["native_verified_both_directions"] = True
        cases["merkle_path1_poseidon"]["selector_gate"] = "b*b=b, sole producer of direct selector wire"

        record = {
            "schema": "s31-poseidon-acceptance-v6",
            "compiler_sha256": s31.compiler_fingerprint(),
            "constants_sha256": oracle.CONSTANTS_SHA256,
            "reference_vector": {"hash_pair_1_2": 1975699496},
            "cases": cases,
            "independent_oracle": "Python M31 arithmetic and sponge implementation reading pinned Stark-V constants",
            "negative_checks": ["invalid_leaf_shape", "invalid_pair_shape", "invalid_selector_shape", "changed_public_root", "changed_private_leaf", "damaged_proof", "cross_program_replay", "changed_direction_root", "non_bit_direction"],
        }
        output = s31.ROOT / "design/s31/measurements/hash/poseidon-acceptance-v6-2026-10-06.json"
        s31.write_json(output, record)
        print(f"accepted Poseidon2 leaf lengths 4/8/12/16, tree {tree_proof.stat().st_size} B and path {path_proof.stat().st_size} B; rejected nine invalid cases", flush=True)
        print(output)


if __name__ == "__main__":
    main()
