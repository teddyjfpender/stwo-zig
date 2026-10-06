#!/usr/bin/env python3
"""Second recursive geometry: private witness stays out of the outer claim."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path

import s31
from oracle import OracleError, evaluate_relation
from text_frontend import compile_file


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "examples/preimage4.s31"
VALID = HERE / "examples/preimage4.valid.json"


def run(*args: str, accept: bool) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-recursion-private-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.build(SOURCE, work / "package", "gate")
        manifest = s31.verify_package(package)
        if manifest["lowering"] != "gate":
            raise AssertionError("private recursive fixture requires gate profile")
        relation, _ = compile_file(SOURCE)
        assignment = json.loads(VALID.read_text())
        if evaluate_relation(relation, assignment) != assignment["public_outputs"]:
            raise AssertionError("independent value oracle disagrees")
        prover = package / "bin/s31-preimage4-prover"
        verifier = package / "bin/s31-preimage4-native-verifier"
        key = package / "verification-key.json"
        child = work / "child.proof"
        outer = work / "outer.proof"
        statement = work / "child.statement.json"
        s31.write_json(statement, {"public_inputs": assignment["public_inputs"],
                                   "public_outputs": assignment["public_outputs"]})
        run(str(prover), "prove", str(VALID), str(child), accept=True)
        run(str(verifier), str(child), str(statement), str(key), accept=True)
        run(str(prover), "recurse-audit", str(child), str(statement), str(key), accept=True)
        run(str(prover), "recurse-wrap", str(child), str(statement), str(outer), str(key), accept=True)
        outer_statement_path = Path(f"{outer}.statement.json")
        outer_statement = json.loads(outer_statement_path.read_text())
        if outer_statement["child_public_words"] != [8, 11, 16, 1771, 1, 4, 9, 1764]:
            raise AssertionError("outer statement lost the child public ABI")
        if "secret" in json.dumps(outer_statement):
            raise AssertionError("outer statement contains the private witness name")
        run(str(verifier), "recurse-verify", str(outer), str(outer_statement_path), accept=True)

        changed = copy.deepcopy(outer_statement)
        changed["child_public_words"][4] += 1
        wrong_outer = work / "wrong-outer.json"
        s31.write_json(wrong_outer, changed)
        run(str(verifier), "recurse-verify", str(outer), str(wrong_outer), accept=False)
        changed_child = json.loads(statement.read_text())
        changed_child["public_outputs"]["square"][0] += 1
        wrong_child = work / "wrong-child.json"
        s31.write_json(wrong_child, changed_child)
        run(str(prover), "recurse-wrap", str(child), str(wrong_child),
            str(work / "wrong-child-outer.proof"), str(key), accept=False)
        bad_assignment = copy.deepcopy(assignment)
        bad_assignment["private_inputs"]["secret"][3] += 1
        try:
            evaluate_relation(relation, bad_assignment)
        except OracleError:
            pass
        else:
            raise AssertionError("oracle accepted an incorrect secret")
        bad_path = work / "wrong-secret.json"
        s31.write_json(bad_path, bad_assignment)
        run(str(prover), "prove", str(bad_path), str(work / "wrong-secret.proof"), accept=False)
        print(json.dumps({"schema": "s31-recursion-private-acceptance-v1",
                          "accepted": 3, "rejected": 3,
                          "child_proof_bytes": child.stat().st_size,
                          "outer_proof_bytes": outer.stat().st_size,
                          "outer_statement_has_private_witness": False},
                         indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
