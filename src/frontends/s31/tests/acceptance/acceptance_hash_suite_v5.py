#!/usr/bin/env python3
"""Independent BLAKE2s oracle and sealed-proof checks for the tree hash nodes."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/merkle2.s31.json"
ASSIGNMENT = HERE / "examples/merkle2.valid.json"
P = (1 << 31) - 1


def digest(words: list[int], domain: bytes) -> list[int]:
    message = b"".join(struct.pack("<I", word) for word in words)
    raw = hashlib.blake2s(message, person=domain).digest()
    return [word % P for word in struct.unpack("<8I", raw)]


def call(*args: str, accept: bool = True) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{result.stdout}{result.stderr}")


def main() -> None:
    assignment = json.loads(ASSIGNMENT.read_text())
    left = digest(assignment["private_inputs"]["left"], b"S31LEAF1")
    right = digest(assignment["private_inputs"]["right"], b"S31LEAF1")
    root = digest(left + right, b"S31PAIR1")
    if root != assignment["public_outputs"]["root"]:
        raise AssertionError("fixture disagrees with independent BLAKE2s oracle")
    if root == digest(right + left, b"S31PAIR1"):
        raise AssertionError("ordered parent hash collided after swapping children")
    if left == digest(assignment["private_inputs"]["left"], b""):
        raise AssertionError("leaf domain does not separate raw hashing")

    with tempfile.TemporaryDirectory(prefix="s31-hash-suite-") as temporary:
        work = Path(temporary)
        invalid_leaf = json.loads(SOURCE.read_text())
        invalid_leaf["inputs"][0]["length"] = 5
        invalid_leaf_path = work / "invalid-leaf.s31.json"
        s31.write_json(invalid_leaf_path, invalid_leaf)
        call("python3", str(HERE / "python/s31.py"), "check", str(invalid_leaf_path), accept=False)
        invalid_pair = json.loads(SOURCE.read_text())
        invalid_pair["inputs"][1]["length"] = 4
        invalid_pair["nodes"][2]["rhs"] = "right"
        invalid_pair_path = work / "invalid-pair.s31.json"
        s31.write_json(invalid_pair_path, invalid_pair)
        call("python3", str(HERE / "python/s31.py"), "check", str(invalid_pair_path), accept=False)
        invalid_selector = json.loads((HERE / "examples/merkle_path1.s31.json").read_text())
        invalid_selector["inputs"][2]["length"] = 2
        invalid_selector_path = work / "invalid-selector.s31.json"
        s31.write_json(invalid_selector_path, invalid_selector)
        call("python3", str(HERE / "python/s31.py"), "check", str(invalid_selector_path), accept=False)
        package = s31.build(SOURCE, work / "package", "gate")
        s31.verify_package(package)
        cost = json.loads((package / "cost-report.json").read_text())
        by_name = {span["name"]: span for span in cost["source_map"]}
        for name in ("left_digest", "right_digest", "root"):
            span = by_name[name]
            if span["blake_g_end"] - span["blake_g_start"] != 80:
                raise AssertionError(f"expected one constrained BLAKE2s block for {name}")
        prover = package / "bin/s31-merkle2-prover"
        verifier = package / "bin/s31-merkle2-native-verifier"
        key = package / "verification-key.json"
        proof = work / "merkle2.proof"
        statement = work / "statement.json"
        s31.write_json(statement, {"public_inputs": {}, "public_outputs": {"root": root}})
        call(str(prover), "prove", str(ASSIGNMENT), str(proof))
        call(str(verifier), str(proof), str(statement), str(key))

        wrong = json.loads(statement.read_text())
        wrong["public_outputs"]["root"][0] = (wrong["public_outputs"]["root"][0] + 1) % P
        wrong_path = work / "wrong-statement.json"
        s31.write_json(wrong_path, wrong)
        call(str(verifier), str(proof), str(wrong_path), str(key), accept=False)

        changed_assignment = json.loads(ASSIGNMENT.read_text())
        changed_assignment["private_inputs"]["left"][0] += 1
        changed_path = work / "wrong-private.json"
        s31.write_json(changed_path, changed_assignment)
        call(str(prover), "prove", str(changed_path), str(work / "wrong-private.proof"), accept=False)

        damaged = bytearray(proof.read_bytes())
        damaged[len(damaged) // 2] ^= 1
        damaged_path = work / "damaged.proof"
        damaged_path.write_bytes(damaged)
        call(str(verifier), str(damaged_path), str(statement), str(key), accept=False)

        path_source = HERE / "examples/merkle_path1.s31.json"
        path_assignment_path = HERE / "examples/merkle_path1.valid.json"
        path_assignment = json.loads(path_assignment_path.read_text())
        path_inputs = path_assignment["private_inputs"]
        path_leaf = digest(path_inputs["leaf"], b"S31LEAF1")
        expected_path_root = digest(path_inputs["sibling"] + path_leaf, b"S31PAIR1")
        if path_inputs["direction"] != [1] or expected_path_root != path_assignment["public_outputs"]["root"]:
            raise AssertionError("path fixture disagrees with independent BLAKE2s oracle")
        path_package = s31.build(path_source, work / "path-package", "gate")
        s31.verify_package(path_package)
        path_cost = json.loads((path_package / "cost-report.json").read_text())
        path_spans = {span["name"]: span for span in path_cost["source_map"]}
        if any(path_spans[name]["eq_end"] <= path_spans[name]["eq_start"] for name in ("ordered_left", "ordered_right")):
            raise AssertionError("selector has no boolean AIR constraint")
        path_prover = path_package / "bin/s31-merkle_path1-prover"
        path_verifier = path_package / "bin/s31-merkle_path1-native-verifier"
        path_key = path_package / "verification-key.json"
        path_proof = work / "path.proof"
        path_statement = work / "path-statement.json"
        s31.write_json(path_statement, {"public_inputs": {}, "public_outputs": {"root": expected_path_root}})
        call(str(path_prover), "prove", str(path_assignment_path), str(path_proof))
        call(str(path_verifier), str(path_proof), str(path_statement), str(path_key))
        other_valid = json.loads(path_assignment_path.read_text())
        other_valid["private_inputs"]["direction"] = [0]
        other_valid_root = digest(path_leaf + path_inputs["sibling"], b"S31PAIR1")
        other_valid["public_outputs"]["root"] = other_valid_root
        other_valid_path = work / "path-direction0.json"
        s31.write_json(other_valid_path, other_valid)
        other_statement = work / "path-direction0-statement.json"
        s31.write_json(other_statement, {"public_inputs": {}, "public_outputs": {"root": other_valid_root}})
        other_proof = work / "path-direction0.proof"
        call(str(path_prover), "prove", str(other_valid_path), str(other_proof))
        call(str(path_verifier), str(other_proof), str(other_statement), str(path_key))
        call(str(path_verifier), str(proof), str(path_statement), str(path_key), accept=False)
        for label, value in (("other-direction", 0), ("non-bit", 2)):
            changed_path_assignment = json.loads(path_assignment_path.read_text())
            changed_path_assignment["private_inputs"]["direction"] = [value]
            altered = work / f"{label}.json"
            s31.write_json(altered, changed_path_assignment)
            call(str(path_prover), "prove", str(altered), str(work / f"{label}.proof"), accept=False)

        record = {
            "schema": "s31-hash-suite-acceptance-v5",
            "compiler_sha256": s31.compiler_fingerprint(),
            "cases": {
                "merkle2": {
                    "program_sha256": s31.file_hash(SOURCE),
                    "proof_bytes": proof.stat().st_size,
                    "preprocessed_cells": cost["preprocessed_cells"],
                    "blake_g_rows": {name: by_name[name]["blake_g_end"] - by_name[name]["blake_g_start"] for name in ("left_digest", "right_digest", "root")},
                    "native_verified": True,
                },
                "merkle_path1": {
                    "program_sha256": s31.file_hash(path_source),
                    "proof_bytes": path_proof.stat().st_size,
                    "preprocessed_cells": path_cost["preprocessed_cells"],
                    "boolean_selector_constrained": True,
                    "native_verified_both_directions": True,
                },
            },
            "independent_oracle": "Python hashlib.blake2s(person=...), little-endian M31 words, digest words mod p",
            "negative_checks": ["invalid_leaf_shape", "invalid_pair_shape", "invalid_selector_shape", "changed_public_root", "changed_private_leaf", "damaged_proof", "cross_program_replay", "other_direction", "non_bit_direction"],
        }
        output = s31.ROOT / "design/s31/measurements/hash/hash-suite-acceptance-v5-2026-10-06.json"
        s31.write_json(output, record)
        print(f"accepted merkle2: {proof.stat().st_size} bytes; merkle_path1: {path_proof.stat().st_size} bytes; rejected nine invalid cases", flush=True)
        print(output)


if __name__ == "__main__":
    main()
