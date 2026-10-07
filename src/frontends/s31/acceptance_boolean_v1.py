#!/usr/bin/env python3
"""Native-proof acceptance for computed Boolean algebra and typed bit inputs."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import s31
from oracle import OracleError, evaluate_relation
from text_frontend import compile_file


HERE = Path(__file__).resolve().parent


def run(*args: str, accept: bool) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")


def proof_case(package: Path, work: Path, assignment: dict, name: str) -> int:
    program = json.loads((package / "source.s31.json").read_text())
    if evaluate_relation(program, assignment) != assignment["public_outputs"]:
        raise AssertionError("independent Boolean oracle disagrees")
    prover = package / f"bin/s31-{name}-prover"
    verifier = package / f"bin/s31-{name}-native-verifier"
    input_path = work / f"{name}.assignment.json"
    proof_path = work / f"{name}.proof"
    statement_path = work / f"{name}.statement.json"
    s31.write_json(input_path, assignment)
    s31.write_json(statement_path, {"public_inputs": assignment["public_inputs"],
                                    "public_outputs": assignment["public_outputs"]})
    run(str(prover), "prove", str(input_path), str(proof_path), accept=True)
    run(str(verifier), str(proof_path), str(statement_path),
        str(package / "verification-key.json"), accept=True)
    wrong = json.loads(statement_path.read_text())
    output_name = next(iter(wrong["public_outputs"]))
    wrong["public_outputs"][output_name][0] ^= 1
    wrong_path = work / f"{name}.wrong-statement.json"
    s31.write_json(wrong_path, wrong)
    run(str(verifier), str(proof_path), str(wrong_path),
        str(package / "verification-key.json"), accept=False)
    return proof_path.stat().st_size


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="s31-boolean-") as temporary:
        work = Path(temporary)
        computed_source = HERE / "examples/bool_computed_choice.s31"
        relation, _ = compile_file(computed_source)
        handwritten = json.loads((HERE / "examples/bool_computed_choice.s31.json").read_text())
        if relation != handwritten:
            raise AssertionError("handwritten Boolean relation differs from text lowering")
        computed = s31.build(computed_source, work / "computed", "direct-gate")
        if s31.verify_package(computed)["lowering"] != "direct-gate":
            raise AssertionError("Boolean package needs direct-gate")
        accepted = rejected = 0
        proof_sizes: list[int] = []
        for x, y, expected in ((0, 0, 23), (0, 5, 17), (9, 0, 17), (9, 5, 17)):
            assignment = {"public_inputs": {"x": [x], "y": [y],
                                            "left": [17], "right": [23]},
                          "private_inputs": {}, "public_outputs": {"_s31_0": [expected]}}
            proof_sizes.append(proof_case(computed, work, assignment,
                                          "bool_computed_choice"))
            accepted += 1
            rejected += 1
        input_source = HERE / "examples/bool_input_and.s31"
        input_package = s31.build(input_source, work / "input", "direct-gate")
        good = json.loads((HERE / "examples/bool_input_and.valid.json").read_text())
        proof_sizes.append(proof_case(input_package, work, good, "bool_input_and"))
        accepted += 1
        rejected += 1
        input_relation, _ = compile_file(input_source)
        bad = json.loads(json.dumps(good))
        bad["private_inputs"]["b"] = [2]
        try:
            evaluate_relation(input_relation, bad)
        except OracleError:
            pass
        else:
            raise AssertionError("oracle accepted a non-Boolean private input")
        bad_path = work / "non-boolean.json"
        s31.write_json(bad_path, bad)
        run(str(input_package / "bin/s31-bool_input_and-prover"), "prove",
            str(bad_path), str(work / "bad.proof"), accept=False)
        rejected += 1
        computed_cost = json.loads((computed / "cost-report.json").read_text())
        input_cost = json.loads((input_package / "cost-report.json").read_text())
        print(json.dumps({"schema": "s31-boolean-acceptance-v1",
                          "accepted": accepted, "rejected": rejected,
                          "computed_raw_qm31_rows": computed_cost["raw"]["qm31_ops"],
                          "computed_raw_eq_rows": computed_cost["raw"]["eq"],
                          "input_raw_qm31_rows": input_cost["raw"]["qm31_ops"],
                          "input_raw_eq_rows": input_cost["raw"]["eq"],
                          "proof_bytes": proof_sizes}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
