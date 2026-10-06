#!/usr/bin/env python3
"""Prove that text and handwritten relations retain the same S31 cost shape."""

import json
import sys
import tempfile
from pathlib import Path

import s31
from s31_stdlib import P


CASES = (
    ("arith4_m31", "arith4", "direct-chip"),
    ("merkle_path1_poseidon", "merkle_path1_poseidon", "direct-gate"),
)
EQUAL_FIELDS = (
    "canonical_ir_sha256", "profile", "chip", "raw", "padded",
    "preprocessed_cells", "preprocessed_columns", "preprocessed_root",
    "source_map", "input_packing", "public_binding", "finalization", "fri",
)


def prove_and_verify(package: Path, assignment_path: Path, proof: Path) -> int:
    manifest = s31.verify_package(package)
    executable = package / "bin" / f"s31-{manifest['name']}-prover"
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    assignment = json.loads(assignment_path.read_text())
    statement = proof.with_suffix(".statement.json")
    s31.write_json(statement, {
        "public_inputs": assignment["public_inputs"],
        "public_outputs": assignment["public_outputs"],
    })
    s31.invoke(str(executable), "prove", str(assignment_path), str(proof))
    s31.invoke(str(verifier), str(proof), str(statement), str(package / "verification-key.json"))
    return proof.stat().st_size


def reject_bad_text_claims(package: Path, assignment_path: Path, proof: Path,
                           work: Path, name: str) -> None:
    manifest = s31.verify_package(package)
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    statement = json.loads(proof.with_suffix(".statement.json").read_text())
    output_name = next(iter(statement["public_outputs"]))
    statement["public_outputs"][output_name][0] = (statement["public_outputs"][output_name][0] + 1) % P
    wrong_statement = work / f"{name}-wrong-statement.json"
    s31.write_json(wrong_statement, statement)
    try:
        s31.invoke(str(verifier), str(proof), str(wrong_statement),
                   str(package / "verification-key.json"))
    except RuntimeError:
        pass
    else:
        raise AssertionError(f"{name}: native verifier accepted a changed public output")

    if name == "merkle_path1_poseidon":
        bad = json.loads(assignment_path.read_text())
        bad["private_inputs"]["direction"] = [2]
        bad_assignment = work / "invalid-direction.json"
        s31.write_json(bad_assignment, bad)
        prover = package / "bin" / f"s31-{manifest['name']}-prover"
        try:
            s31.invoke(str(prover), "prove", str(bad_assignment),
                       str(work / "invalid-direction.proof"))
        except RuntimeError:
            pass
        else:
            raise AssertionError("text bit selector accepted witness value 2")


def main() -> None:
    result = []
    with tempfile.TemporaryDirectory(prefix="s31-text-acceptance-") as directory:
        work = Path(directory)
        for name, assignment_name, lowering in CASES:
            text_source = s31.S31_DIR / "examples" / f"{name}.s31"
            json_source = s31.S31_DIR / "examples" / f"{name}.s31.json"
            assignment = s31.S31_DIR / "examples" / f"{assignment_name}.valid.json"
            text_package = s31.build(text_source, work / f"{name}-text", lowering)
            json_package = s31.build(json_source, work / f"{name}-json", lowering)
            text_report = json.loads((text_package / "cost-report.json").read_text())
            json_report = json.loads((json_package / "cost-report.json").read_text())
            mismatches = [field for field in EQUAL_FIELDS if text_report[field] != json_report[field]]
            if mismatches:
                raise AssertionError(f"{name}: text and JSON cost structures differ: {mismatches}")
            text_proof = work / f"{name}-text.proof"
            text_bytes = prove_and_verify(text_package, assignment, text_proof)
            reject_bad_text_claims(text_package, assignment, text_proof, work, name)
            json_bytes = prove_and_verify(json_package, assignment, work / f"{name}-json.proof")
            result.append({"name": name, "lowering": lowering,
                           "canonical_ir_sha256": text_report["canonical_ir_sha256"],
                           "raw": text_report["raw"], "padded": text_report["padded"],
                           "preprocessed_cells": text_report["preprocessed_cells"],
                           "text_proof_bytes": text_bytes, "json_proof_bytes": json_bytes,
                           "native_verifiers_accepted": True})
    print(json.dumps({"schema": "s31-text-acceptance-v1", "cases": result}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f"s31 text acceptance: {exc}", file=sys.stderr)
        raise SystemExit(1)
