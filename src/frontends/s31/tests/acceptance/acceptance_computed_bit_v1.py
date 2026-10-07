#!/usr/bin/env python3
"""Proof-level checks for the computed is_zero bit and direct selector."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import s31
from oracle import P, OracleError, evaluate_relation
from text_frontend import compile_file


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/computed_choice.s31"


def run(*args: str, accept: bool) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-computed-bit-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.build(SOURCE, work / "package", "direct-gate")
        manifest = s31.verify_package(package)
        if manifest["lowering"] != "direct-gate":
            raise AssertionError("computed-bit acceptance requires direct-gate")
        relation, _ = compile_file(SOURCE)
        prover = package / "bin/s31-computed_choice-prover"
        verifier = package / "bin/s31-computed_choice-native-verifier"
        key = package / "verification-key.json"
        accepted = 0
        rejected = 0
        for x, expected in ((0, 23), (1, 17), (P - 1, 17)):
            assignment = {
                "public_inputs": {"x": [x], "left": [17], "right": [23]},
                "private_inputs": {}, "public_outputs": {"result": [expected]},
            }
            if evaluate_relation(relation, assignment) != assignment["public_outputs"]:
                raise AssertionError("independent oracle disagrees")
            input_path = work / f"input-{x}.json"
            proof_path = work / f"proof-{x}.bin"
            statement_path = work / f"statement-{x}.json"
            s31.write_json(input_path, assignment)
            s31.write_json(statement_path, {
                "public_inputs": assignment["public_inputs"],
                "public_outputs": assignment["public_outputs"],
            })
            run(str(prover), "prove", str(input_path), str(proof_path), accept=True)
            run(str(verifier), str(proof_path), str(statement_path), str(key), accept=True)
            accepted += 1
            changed = json.loads(statement_path.read_text())
            changed["public_outputs"]["result"] = [23 if expected == 17 else 17]
            wrong_path = work / f"wrong-{x}.json"
            s31.write_json(wrong_path, changed)
            run(str(verifier), str(proof_path), str(wrong_path), str(key), accept=False)
            rejected += 1
        bad = {
            "public_inputs": {"x": [0], "left": [17], "right": [23]},
            "private_inputs": {}, "public_outputs": {"result": [17]},
        }
        try:
            evaluate_relation(relation, bad)
        except OracleError:
            pass
        else:
            raise AssertionError("oracle accepted the wrong zero branch")
        bad_path = work / "wrong-branch.json"
        s31.write_json(bad_path, bad)
        run(str(prover), "prove", str(bad_path), str(work / "bad.proof"), accept=False)
        rejected += 1
        report = json.loads((package / "cost-report.json").read_text())
        if report["raw"]["eq"] != 0:
            raise AssertionError("computed bit escaped the direct arithmetic profile")
        print(json.dumps({"schema": "s31-computed-bit-acceptance-v1",
                          "accepted": accepted, "rejected": rejected,
                          "raw_qm31_ops": report["raw"]["qm31_ops"],
                          "padded_qm31_ops": report["padded"]["qm31_ops"]},
                         indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
