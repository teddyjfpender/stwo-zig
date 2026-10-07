#!/usr/bin/env python3
"""Native proof acceptance for fixed-array views of public and private lanes."""

import argparse
import copy
import json
import tempfile
from pathlib import Path

import s31
from oracle import OracleError, evaluate_relation
from text_frontend import compile_file


CASES = (
    ("array_views", "direct-gate", [18]),
    ("array_views_private", "direct-gate", [14]),
    ("array_views_u16", "gate", [65535]),
    ("array_slice_aligned", "direct-gate", [11, 13, 17, 19]),
    ("array_slice_shifted", "direct-gate", [3, 5, 7, 11]),
    ("array_matrix_runtime", "direct-gate", [17]),
    ("array_slice_u16", "gate", [65535, 7]),
)
NEW_VIEWS = {"array_slice_aligned", "array_slice_shifted", "array_matrix_runtime", "array_slice_u16"}
MUTATION = {
    "array_slice_aligned": ("x", 4),
    "array_slice_shifted": ("x", 1),
    "array_matrix_runtime": ("x", 6),
    "array_slice_u16": ("x", 1),
}
BASELINE = s31.ROOT / "design/s31/measurements/array-view-cost-v1-2026-10-07.json"
MATCHED_COST = (
    "canonical_ir_sha256", "profile", "chip", "raw", "padded",
    "preprocessed_cells", "preprocessed_columns", "preprocessed_root",
    "input_packing", "public_binding", "finalization", "fri",
)


def reference(relation: dict, assignment: dict) -> dict[str, list[int]]:
    """List arithmetic independent of the S31 oracle and circuit compiler."""
    values = {**assignment["public_inputs"], **assignment["private_inputs"]}
    modulus = (1 << 31) - 1
    for node in relation["nodes"]:
        op = node["op"]
        if op == "array_concat":
            result = values[node["lhs"]] + values[node["rhs"]]
        elif op == "array_slice":
            start = node["index"]
            result = values[node["lhs"]][start:start + node["length"]]
            assert len(result) == node["length"]
        elif op == "array_get":
            result = [values[node["lhs"]][node["index"]]]
        elif op == "add":
            result = [(a + b) % modulus for a, b in
                      zip(values[node["lhs"]], values[node["rhs"]], strict=True)]
        else:
            raise AssertionError(f"missing independent array reference for {op}")
        values[node["name"]] = result
    return {name: values[name] for name in relation["public_outputs"]}


def rejects(action, description: str) -> None:
    try:
        action()
    except (RuntimeError, OracleError):
        return
    raise AssertionError(f"accepted {description}")


def prove_and_check(package: Path, assignment_path: Path, proof_path: Path,
                    statement_path: Path) -> None:
    name = s31.verify_package(package)["name"]
    prover = package / "bin" / f"s31-{name}-prover"
    verifier = package / "bin" / f"s31-{name}-native-verifier"
    s31.invoke(str(prover), "prove", str(assignment_path), str(proof_path))
    s31.invoke(str(verifier), str(proof_path), str(statement_path),
               str(package / "verification-key.json"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-baseline", action="store_true",
                        help="record inspected rows and a proof-size ceiling after native acceptance")
    args = parser.parse_args()
    baseline = None if args.record_baseline else json.loads(BASELINE.read_text())
    if baseline is not None and baseline.get("schema") != "s31-array-view-cost-v1":
        raise AssertionError("invalid array view cost baseline")
    reports = []
    with tempfile.TemporaryDirectory(prefix="s31-array-views-") as directory:
        work = Path(directory)
        for name, profile, expected in CASES:
            example = s31.S31_DIR / "examples" / name
            source = example.with_suffix(".s31")
            relation_path = source.with_suffix(".s31.json")
            assignment_path = example.with_suffix(".valid.json")
            relation, _ = compile_file(source)
            handwritten = json.loads(relation_path.read_text())
            assignment = json.loads(assignment_path.read_text())
            assert relation == handwritten, f"{name}: text and handwritten relations differ"
            output_name = relation["public_outputs"][0]
            assert assignment["public_outputs"] == {output_name: expected}
            assert reference(relation, assignment) == assignment["public_outputs"]
            assert evaluate_relation(relation, assignment) == assignment["public_outputs"]

            text_package = s31.build(source, work / f"{name}-text", profile)
            json_package = s31.build(relation_path, work / f"{name}-json", profile)
            text_report = json.loads((text_package / "cost-report.json").read_text())
            json_report = json.loads((json_package / "cost-report.json").read_text())
            mismatch = [field for field in MATCHED_COST
                        if text_report[field] != json_report[field]]
            assert not mismatch, f"{name}: text/JSON circuit cost differs: {mismatch}"
            spans = {item["name"]: item for item in text_report["source_map"]}
            slices = [{"name": node["name"],
                       "qm31_rows": spans[node["name"]]["qm31_end"] - spans[node["name"]]["qm31_start"]}
                      for node in relation["nodes"] if node["op"] == "array_slice"]
            if name in {"array_slice_aligned", "array_matrix_runtime"}:
                assert all(item["qm31_rows"] == 0 for item in slices)
            if name in {"array_slice_shifted", "array_slice_u16"}:
                assert slices[0]["qm31_rows"] > 0

            statement = {"public_inputs": assignment["public_inputs"],
                         "public_outputs": assignment["public_outputs"]}
            statement_path = work / f"{name}-statement.json"
            s31.write_json(statement_path, statement)
            text_proof = work / f"{name}-text.proof"
            json_proof = work / f"{name}-json.proof"
            prove_and_check(text_package, assignment_path, text_proof, statement_path)
            prove_and_check(json_package, assignment_path, json_proof, statement_path)

            if name in NEW_VIEWS:
                changed_witness = copy.deepcopy(assignment)
                input_name, index = MUTATION[name]
                input_kind = relation["inputs"][0]["kind"]
                old_value = changed_witness["private_inputs"][input_name][index]
                changed_witness["private_inputs"][input_name][index] = (
                    old_value - 1 if input_kind == "u16" and old_value == 65535 else old_value + 1)
                changed_output = reference(relation, changed_witness)
                assert changed_output != assignment["public_outputs"], f"{name}: insensitive mutation"
                rejects(lambda: evaluate_relation(relation, changed_witness),
                        f"{name} changed oracle witness with stale claim")
                assert evaluate_relation(relation, {**changed_witness,
                                                    "public_outputs": changed_output}) == changed_output
                stale_path = work / f"{name}-stale-witness.json"
                s31.write_json(stale_path, changed_witness)
                prover = text_package / "bin" / f"s31-{name}-prover"
                rejects(lambda: s31.invoke(str(prover), "prove", str(stale_path),
                                           str(work / f"{name}-stale.proof")),
                        f"{name} changed witness with stale claim")
                changed_witness["public_outputs"] = changed_output
                changed_assignment_path = work / f"{name}-changed-witness.json"
                changed_statement_path = work / f"{name}-changed-statement.json"
                changed_proof = work / f"{name}-changed.proof"
                s31.write_json(changed_assignment_path, changed_witness)
                s31.write_json(changed_statement_path, {
                    "public_inputs": changed_witness["public_inputs"],
                    "public_outputs": changed_output,
                })
                prove_and_check(text_package, changed_assignment_path,
                                changed_proof, changed_statement_path)

            verifier = text_package / "bin" / f"s31-{name}-native-verifier"
            key = text_package / "verification-key.json"
            changed_statement = copy.deepcopy(statement)
            changed_statement["public_outputs"][output_name][0] = expected[0] - 1
            bad_statement_path = work / f"{name}-wrong-statement.json"
            s31.write_json(bad_statement_path, changed_statement)
            rejects(lambda: s31.invoke(str(verifier), str(text_proof),
                                       str(bad_statement_path), str(key)),
                    f"{name} wrong public claim")
            if name in NEW_VIEWS:
                corrupt = work / f"{name}-corrupt.proof"
                damaged = bytearray(text_proof.read_bytes())
                damaged[-1] ^= 1
                corrupt.write_bytes(damaged)
                rejects(lambda: s31.invoke(str(verifier), str(corrupt),
                                           str(statement_path), str(key)),
                        f"{name} damaged proof")
                altered_key = json.loads(key.read_text())
                altered_key["program_sha256"] = "00" * 32
                altered_key_path = work / f"{name}-altered-key.json"
                s31.write_json(altered_key_path, altered_key)
                rejects(lambda: s31.invoke(str(verifier), str(text_proof),
                                           str(statement_path), str(altered_key_path)),
                        f"{name} altered sealed key")

            wrong_assignment = copy.deepcopy(assignment)
            wrong_assignment["public_outputs"][output_name][0] = expected[0] - 1
            bad_assignment_path = work / f"{name}-wrong-assignment.json"
            s31.write_json(bad_assignment_path, wrong_assignment)
            rejects(lambda: evaluate_relation(relation, wrong_assignment),
                    f"{name} wrong oracle claim")
            prover = text_package / "bin" / f"s31-{name}-prover"
            rejects(lambda: s31.invoke(str(prover), "prove", str(bad_assignment_path),
                                       str(work / f"{name}-wrong.proof")),
                    f"{name} wrong prover claim")

            cost = {"raw": text_report["raw"], "padded": text_report["padded"],
                    "preprocessed_columns": text_report["preprocessed_columns"],
                    "preprocessed_cells": text_report["preprocessed_cells"],
                    "slice_gate_rows": slices}
            largest_proof = max(text_proof.stat().st_size, json_proof.stat().st_size)
            if baseline is not None:
                reference_cost = baseline["cases"][name]
                for field in cost:
                    assert cost[field] == reference_cost[field], f"{name}: {field} cost regression"
                assert largest_proof <= reference_cost["proof_bytes_ceiling"], f"{name}: proof-size regression"
            reports.append({"name": name, "profile": profile,
                            "canonical_ir_sha256": text_report["canonical_ir_sha256"],
                            **cost,
                            "text_proof_bytes": text_proof.stat().st_size,
                            "json_proof_bytes": json_proof.stat().st_size,
                            "native_verifier_accepted_both": True,
                            "wrong_claim_rejected": True,
                            "bad_proof_and_key_rejected": name in NEW_VIEWS,
                            "changed_witness_proved_and_verified": name in NEW_VIEWS})
    if args.record_baseline:
        s31.write_json(BASELINE, {
            "schema": "s31-array-view-cost-v1",
            "measurement": "ReleaseFast native proof acceptance; proof ceilings allow 10% size variance",
            "cases": {report["name"]: {
                **{field: report[field] for field in
                   ("raw", "padded", "preprocessed_columns", "preprocessed_cells", "slice_gate_rows")},
                "observed_text_proof_bytes": report["text_proof_bytes"],
                "observed_json_proof_bytes": report["json_proof_bytes"],
                "proof_bytes_ceiling": (max(report["text_proof_bytes"], report["json_proof_bytes"]) * 11 + 9) // 10,
            } for report in reports},
        })
    print(json.dumps({"schema": "s31-array-view-acceptance-v1", "cases": reports}, indent=2))


if __name__ == "__main__":
    main()
