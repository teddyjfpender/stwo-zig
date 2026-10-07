#!/usr/bin/env python3
"""Sealed source-to-chip private endpoint package acceptance."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

S31_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_ROOT / "python"))
import s31

SOURCE = S31_ROOT / "examples" / "boundary" / "private_step16.s31"
PINNED_RELATION = SOURCE.with_suffix(".s31.json")
ASSIGNMENT = S31_ROOT / "examples" / "boundary" / "private_step16.valid.json"


def call(*args: str, accepted: bool) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def main() -> None:
    _, lowered_bytes, _ = s31.lower_text(SOURCE)
    if lowered_bytes != PINNED_RELATION.read_bytes():
        raise AssertionError("text lowering differs from the pinned relation bytes")
    with tempfile.TemporaryDirectory(prefix="s31-private-boundary-") as temporary:
        work = Path(temporary)
        package = s31.build(SOURCE, work / "package", "direct-chip")
        s31.verify_package(package)
        key_path = package / "verification-key.json"
        key = json.loads(key_path.read_text())
        report = json.loads((package / "cost-report.json").read_text())
        if (key["schema"] != "s31-verification-key-v5p" or
                key["profile"] != "direct-m31-private-v5" or
                key["private_boundary"] != report["private_boundary"]):
            raise AssertionError("private source boundary was not sealed into the key")
        if len(set(key["private_boundary"]["input"] + key["private_boundary"]["output"])) != 8:
            raise AssertionError("private endpoint addresses are not disjoint")

        prover = package / "bin" / "s31-private_step16-prover"
        verifier = package / "bin" / "s31-private_step16-native-verifier"
        proof = work / "proof.bin"
        call(str(prover), "prove", str(ASSIGNMENT), str(proof), accepted=True)
        assignment = json.loads(ASSIGNMENT.read_text())
        statement = {
            "public_inputs": assignment["public_inputs"],
            "public_outputs": assignment["public_outputs"],
        }
        statement_path = work / "statement.json"
        s31.write_json(statement_path, statement)
        if statement["public_inputs"] or list(statement["public_outputs"]) != ["total"]:
            raise AssertionError("private endpoints entered the public statement")
        call(str(verifier), str(proof), str(statement_path), str(key_path), accepted=True)

        changed_statement = copy.deepcopy(statement)
        changed_statement["public_outputs"]["total"][0] += 1
        changed_statement_path = work / "changed-statement.json"
        s31.write_json(changed_statement_path, changed_statement)
        call(str(verifier), str(proof), str(changed_statement_path), str(key_path), accepted=False)

        leaked_statement = copy.deepcopy(statement)
        leaked_statement["private_inputs"] = assignment["private_inputs"]
        leaked_statement_path = work / "leaked-statement.json"
        s31.write_json(leaked_statement_path, leaked_statement)
        call(str(verifier), str(proof), str(leaked_statement_path), str(key_path), accepted=False)

        changed_key = copy.deepcopy(key)
        changed_key["private_boundary"]["input"][0] += 1
        changed_key_path = work / "changed-key.json"
        s31.write_json(changed_key_path, changed_key)
        call(str(verifier), str(proof), str(statement_path), str(changed_key_path), accepted=False)

        changed_assignment = copy.deepcopy(assignment)
        changed_assignment["private_inputs"]["secret"][0] += 1
        changed_assignment_path = work / "changed-assignment.json"
        s31.write_json(changed_assignment_path, changed_assignment)
        call(str(prover), "prove", str(changed_assignment_path), str(work / "bad-proof.bin"), accepted=False)

        changed_proof = bytearray(proof.read_bytes())
        changed_proof[-1] ^= 1
        changed_proof_path = work / "changed-proof.bin"
        changed_proof_path.write_bytes(changed_proof)
        call(str(verifier), str(changed_proof_path), str(statement_path), str(key_path), accepted=False)

        changed_source_package = work / "changed-source-package"
        shutil.copytree(package, changed_source_package)
        changed_source = changed_source_package / "source.s31.json"
        changed_source.write_bytes(changed_source.read_bytes() + b"\n")
        try:
            s31.verify_package(changed_source_package)
        except ValueError:
            pass
        else:
            raise AssertionError("changed source was accepted under the sealed package")
        print(f"private source/chip proof accepted ({proof.stat().st_size} bytes); six mutations rejected")


if __name__ == "__main__":
    main()
