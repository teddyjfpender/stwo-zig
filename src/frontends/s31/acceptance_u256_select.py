#!/usr/bin/env python3
"""Native-proof acceptance for range-preserving UInt256 selection.

Run the u256_order_select trial shown in docs/wide-values.md first. This
script reuses its sealed package for both selector branches and equality.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile

from oracle import OracleError, evaluate_relation
from poseidon2_oracle import leaf
from text_frontend import compile_file


S31 = Path(__file__).resolve().parent
ROOT = S31.parents[2]
TRIAL = ROOT / "zig-out/s31/u256-order-select-trial"
SOURCE = S31 / "examples/u256_order_select.s31"


def run(*args: object, accept: bool) -> None:
    process = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                             capture_output=True, text=True)
    if (process.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {process.returncode}: {args!r}\n"
                             f"{process.stdout}{process.stderr}")


def limbs(number: int) -> list[int]:
    return [(number >> (16 * index)) & 0xffff for index in range(16)]


def assignment(relation: dict, a: int, b: int) -> dict:
    return {"public_inputs": {},
            "private_inputs": {"a": limbs(a), "b": limbs(b)},
            "public_outputs": {relation["public_outputs"][0]: leaf(limbs(abs(a - b)))}}


def main() -> None:
    report = json.loads((TRIAL / "trial-report.json").read_text())
    assert report["native_verifier_accepted"] is True
    assert report["independent_value_oracle"]["status"] == "passed"
    assert report["changed_public_statement_rejected"] == "public_outputs._s31_12[0]"
    package = TRIAL / "package"
    prover = package / "bin/s31-u256_order_select-prover"
    verifier = package / "bin/s31-u256_order_select-native-verifier"
    key = package / "verification-key.json"
    relation, _ = compile_file(SOURCE)
    assert relation == json.loads((S31 / "examples/u256_order_select.s31.json").read_text())
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        for label, a, b in (
            ("a_lt_b", 2**128 - 1, 2**128 + 7),
            ("a_gt_b", 2**128 + 7, 2**128 - 1),
            ("equal", 2**256 - 1, 2**256 - 1),
        ):
            claim = assignment(relation, a, b)
            assert evaluate_relation(relation, claim) == claim["public_outputs"]
            assignment_path = temp / f"{label}.assignment.json"
            statement_path = temp / f"{label}.statement.json"
            proof_path = temp / f"{label}.proof"
            assignment_path.write_text(json.dumps(claim))
            statement_path.write_text(json.dumps({"public_inputs": claim["public_inputs"],
                                                  "public_outputs": claim["public_outputs"]}))
            run(prover, "prove", assignment_path, proof_path, accept=True)
            run(verifier, proof_path, statement_path, key, accept=True)

            changed_statement = copy.deepcopy(json.loads(statement_path.read_text()))
            changed_statement["public_outputs"]["_s31_12"][0] += 1
            changed_path = temp / f"{label}.changed.statement.json"
            changed_path.write_text(json.dumps(changed_statement))
            run(verifier, proof_path, changed_path, key, accept=False)

            damaged = bytearray(proof_path.read_bytes())
            damaged[len(damaged) // 2] ^= 1
            damaged_path = temp / f"{label}.damaged.proof"
            damaged_path.write_bytes(damaged)
            run(verifier, damaged_path, statement_path, key, accept=False)

            false_claim = copy.deepcopy(claim)
            false_claim["private_inputs"]["a"][0] ^= 1
            bad_path = temp / f"{label}.bad.assignment.json"
            bad_path.write_text(json.dumps(false_claim))
            try:
                evaluate_relation(relation, false_claim)
            except OracleError:
                pass
            else:
                raise AssertionError("independent oracle accepted a false fixed public claim")
            run(prover, "prove", bad_path, temp / f"{label}.bad.proof", accept=False)

    print("UInt256 select: three native proofs accepted; false claims, changed statements, and damaged proofs rejected")


if __name__ == "__main__":
    main()
