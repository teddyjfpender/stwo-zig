#!/usr/bin/env python3
"""The native verifier's sealed key must describe its embedded S31 source."""

import copy
import json
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "examples" / "affine4_v1.s31.json"
ASSIGNMENT = HERE / "examples" / "affine4_v1.valid.json"


def run(*args: str, accepted: bool) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{output}")
    return output


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="s31-key-binding-") as temporary:
        work = Path(temporary)
        source_b = json.loads(SOURCE.read_text())
        source_b["nodes"][1]["constant"] = 9
        variant = work / "variant.s31.json"
        s31.write_json(variant, source_b)
        package_a = s31.build(SOURCE, work / "source-a", "gate")
        package_b = s31.build(variant, work / "source-b", "gate")

        assignment_b = copy.deepcopy(json.loads(ASSIGNMENT.read_text()))
        assignment_b["public_outputs"]["y"] = [20, 29, 38, 589826]
        assignment_path = work / "assignment-b.json"
        s31.write_json(assignment_path, assignment_b)
        statement_path = work / "statement-b.json"
        s31.write_json(statement_path, {
            "public_inputs": assignment_b["public_inputs"],
            "public_outputs": assignment_b["public_outputs"],
        })
        proof = work / "source-b.proof"
        run(str(package_b / "bin/s31-affine4_v1-prover"), "prove",
            str(assignment_path), str(proof), accepted=True)
        run(str(package_b / "bin/s31-affine4_v1-native-verifier"),
            str(proof), str(statement_path),
            str(package_b / "verification-key.json"), accepted=True)

        # Keep source A's name, source digest, and canonical IR digest, but
        # substitute source B's committed circuit and geometry. The old
        # verifier checked these fields only for format and accepted B's proof.
        forged_key = json.loads((package_a / "verification-key.json").read_text())
        key_b = json.loads((package_b / "verification-key.json").read_text())
        if forged_key["preprocessed_root"] == key_b["preprocessed_root"]:
            raise AssertionError("the altered relation must produce a different fixed circuit")
        for field in ("preprocessed_root", "circuit_hash", "padded", "trace_log_size"):
            forged_key[field] = key_b[field]
        forged_path = work / "forged-verification-key.json"
        s31.write_json(forged_path, forged_key)
        prefix = work / "forged-binary"
        run("zig", "build", "--build-file", str(s31.BUILD_FILE), "install",
            "-Doptimize=ReleaseFast", "-Ds31-version=1", "-Ds31-lowering=gate",
            f"-Ds31-source={SOURCE}", "-Ds31-name=affine4_v1",
            f"-Ds31-key={forged_path}", "--prefix", str(prefix), accepted=True)
        rejection = run(str(prefix / "bin/s31-affine4_v1-native-verifier"),
                        str(proof), str(statement_path), str(forged_path), accepted=False)
        if "InvalidVerificationKey" not in rejection:
            raise AssertionError(f"forged key failed for the wrong reason:\n{rejection}")
        print("forged source/circuit binding rejected by native verifier", flush=True)


if __name__ == "__main__":
    main()
