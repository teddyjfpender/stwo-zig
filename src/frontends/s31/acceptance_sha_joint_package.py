#!/usr/bin/env python3
"""Build the sealed single-header SHA package and compare its proof to generic."""

import copy
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import s31

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "examples/bitcoin_header_pow.s31.json"
ASSIGNMENT = HERE / "examples/bitcoin_header_pow.valid.json"


def command(*args: object, accepted: bool = True) -> str:
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {args}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--joint-package", type=Path, help="reuse a sealed sha-joint package")
    parser.add_argument("--generic-package", type=Path, help="reuse a sealed sparse-wide-gate package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-sha-package-") as directory:
        root = Path(directory)
        joint = args.joint_package.resolve() if args.joint_package else s31.build(SOURCE, root / "joint", "sha-joint")
        generic = args.generic_package.resolve() if args.generic_package else s31.build(SOURCE, root / "generic", "sparse-wide-gate")
        if s31.verify_package(joint)["lowering"] != "sha-joint" or s31.verify_package(generic)["lowering"] != "sparse-wide-gate":
            raise AssertionError("acceptance requires sha-joint and sparse-wide-gate packages")
        assignment = json.loads(ASSIGNMENT.read_text())
        statement = {"public_inputs": assignment["public_inputs"], "public_outputs": assignment["public_outputs"]}
        statement_path = root / "statement.json"
        s31.write_json(statement_path, statement)
        joint_proof = root / "joint.proof"
        generic_proof = root / "generic.proof"
        for package, proof in ((joint, joint_proof), (generic, generic_proof)):
            name = s31.verify_package(package)["name"]
            command(package / "bin" / f"s31-{name}-prover", "prove", ASSIGNMENT, proof)
            command(package / "bin" / f"s31-{name}-native-verifier", proof, statement_path,
                    package / "verification-key.json")
        joint_verifier = joint / "bin/s31-bitcoin_header_pow-native-verifier"
        joint_key = joint / "verification-key.json"
        changed = copy.deepcopy(statement)
        changed["public_outputs"]["root"][0] += 1
        changed_path = root / "changed.json"
        s31.write_json(changed_path, changed)
        command(joint_verifier, joint_proof, changed_path, joint_key, accepted=False)
        command(joint_verifier, generic_proof, statement_path, joint_key, accepted=False)
        command(joint_verifier, joint_proof, statement_path, generic / "verification-key.json", accepted=False)
        corrupt = root / "corrupt.proof"
        bytes_ = bytearray(joint_proof.read_bytes())
        bytes_[-1] ^= 1
        corrupt.write_bytes(bytes_)
        command(joint_verifier, corrupt, statement_path, joint_key, accepted=False)
        altered_key = json.loads(joint_key.read_text())
        altered_key["sha_joint"]["gate_addresses"][0] += 1
        altered_key_path = root / "altered-key.json"
        s31.write_json(altered_key_path, altered_key)
        command(joint_verifier, joint_proof, statement_path, altered_key_path, accepted=False)
        report = {
            "schema": "s31-sha-joint-package-acceptance-v1",
            "source_sha256": s31.file_hash(SOURCE),
            "assignment_sha256": s31.file_hash(ASSIGNMENT),
            "joint_profile": json.loads((joint / "cost-report.json").read_text())["profile"],
            "generic_profile": json.loads((generic / "cost-report.json").read_text())["profile"],
            "joint_proof_bytes": joint_proof.stat().st_size,
            "generic_proof_bytes": generic_proof.stat().st_size,
            "same_public_statement": True,
            "native_verifiers_accepted": True,
            "negative_cases_rejected": ["changed public root", "generic proof replay", "generic key",
                                        "corrupt proof", "altered SHA boundary key"],
        }
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
