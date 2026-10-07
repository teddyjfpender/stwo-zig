#!/usr/bin/env python3
"""Native proof acceptance for fixed-array views of public and private lanes."""

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
MATCHED_COST = (
    "canonical_ir_sha256", "profile", "chip", "raw", "padded",
    "preprocessed_cells", "preprocessed_columns", "preprocessed_root",
    "input_packing", "public_binding", "finalization", "fri",
)


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

            verifier = text_package / "bin" / f"s31-{name}-native-verifier"
            key = text_package / "verification-key.json"
            changed_statement = copy.deepcopy(statement)
            changed_statement["public_outputs"][output_name][0] = expected[0] - 1
            bad_statement_path = work / f"{name}-wrong-statement.json"
            s31.write_json(bad_statement_path, changed_statement)
            rejects(lambda: s31.invoke(str(verifier), str(text_proof),
                                       str(bad_statement_path), str(key)),
                    f"{name} wrong public claim")

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

            reports.append({"name": name, "profile": profile,
                            "canonical_ir_sha256": text_report["canonical_ir_sha256"],
                            "raw": text_report["raw"], "padded": text_report["padded"],
                            "slice_gate_rows": slices,
                            "text_proof_bytes": text_proof.stat().st_size,
                            "json_proof_bytes": json_proof.stat().st_size,
                            "native_verifier_accepted_both": True,
                            "wrong_claim_rejected": True})
    print(json.dumps({"schema": "s31-array-view-acceptance-v1", "cases": reports}, indent=2))


if __name__ == "__main__":
    main()
