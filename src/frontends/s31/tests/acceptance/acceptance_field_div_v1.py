#!/usr/bin/env python3
"""Native proof and adversarial checks for checked M31 inverse/division."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import json
import random
import subprocess
import tempfile
from pathlib import Path

import s31
from oracle import P, OracleError, evaluate_relation
from text_frontend import compile_file


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/field_div4.s31"
ASSIGNMENT = HERE / "examples/field_div4.valid.json"


def run(*args: str, accept: bool) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(
            f"unexpected exit {result.returncode} for {args!r}:\n"
            f"{result.stdout}{result.stderr}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-field-div-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.build(SOURCE, work / "package", "direct-gate")
        manifest = s31.verify_package(package)
        if manifest["lowering"] != "direct-gate":
            raise AssertionError("field division acceptance requires direct-gate")
        relation, _ = compile_file(SOURCE)
        assignment = json.loads(ASSIGNMENT.read_text())
        if evaluate_relation(relation, assignment) != assignment["public_outputs"]:
            raise AssertionError("independent field oracle disagrees")
        prover = package / "bin/s31-field_div4-prover"
        verifier = package / "bin/s31-field_div4-native-verifier"
        key = package / "verification-key.json"
        proof = work / "field-div.proof"
        statement = work / "statement.json"
        s31.write_json(statement, {
            "public_inputs": assignment["public_inputs"],
            "public_outputs": assignment["public_outputs"],
        })
        run(str(prover), "prove", str(ASSIGNMENT), str(proof), accept=True)
        run(str(verifier), str(proof), str(statement), str(key), accept=True)

        rng = random.Random(0x31D1)
        vectors = [([0, 1, P - 1, P - 2], [1, P - 1, 2, 3])]
        vectors.extend((
            [rng.randrange(P) for _ in range(4)],
            [rng.randrange(1, P) for _ in range(4)],
        ) for _ in range(7))
        for index, (numerator, denominator) in enumerate(vectors):
            candidate = {
                "public_inputs": {"numerator": numerator},
                "private_inputs": {"denominator": denominator},
                "public_outputs": {"result": [
                    ((a + 1) * pow(b, P - 2, P)) % P
                    for a, b in zip(numerator, denominator)
                ]},
            }
            if evaluate_relation(relation, candidate) != candidate["public_outputs"]:
                raise AssertionError(f"oracle disagrees on vector {index}")
            candidate_path = work / f"vector-{index}.json"
            candidate_proof = work / f"vector-{index}.proof"
            candidate_statement = work / f"vector-{index}.statement.json"
            s31.write_json(candidate_path, candidate)
            s31.write_json(candidate_statement, {
                "public_inputs": candidate["public_inputs"],
                "public_outputs": candidate["public_outputs"],
            })
            run(str(prover), "prove", str(candidate_path), str(candidate_proof), accept=True)
            run(str(verifier), str(candidate_proof), str(candidate_statement), str(key), accept=True)

        for lane in (0, 3):
            bad = copy.deepcopy(assignment)
            bad["private_inputs"]["denominator"][lane] = 0
            try:
                evaluate_relation(relation, bad)
            except OracleError:
                pass
            else:
                raise AssertionError(f"oracle accepted zero denominator lane {lane}")
            path = work / f"zero-lane-{lane}.json"
            s31.write_json(path, bad)
            run(str(prover), "prove", str(path), str(work / f"zero-{lane}.proof"), accept=False)

        for group, name in (("public_inputs", "numerator"), ("public_outputs", "result")):
            bad = json.loads(statement.read_text())
            bad[group][name][0] = (bad[group][name][0] + 1) % P
            path = work / f"wrong-{name}.json"
            s31.write_json(path, bad)
            run(str(verifier), str(proof), str(path), str(key), accept=False)

        corrupted = bytearray(proof.read_bytes())
        corrupted[-1] ^= 1
        corrupted_path = work / "corrupted.proof"
        corrupted_path.write_bytes(corrupted)
        run(str(verifier), str(corrupted_path), str(statement), str(key), accept=False)
        report = json.loads((package / "cost-report.json").read_text())
        if report["raw"]["eq"] != 0 or report["raw"]["qm31_ops"] != 327:
            raise AssertionError("checked inverse escaped the direct arithmetic profile")
        print(json.dumps({
            "schema": "s31-field-division-acceptance-v1",
            "profile": manifest["lowering"],
            "proof_bytes": proof.stat().st_size,
            "raw_qm31_ops": report["raw"]["qm31_ops"],
            "padded_qm31_ops": report["padded"]["qm31_ops"],
            "accepted": 9,
            "rejected": 5,
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
