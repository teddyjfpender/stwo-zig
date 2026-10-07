#!/usr/bin/env python3
"""Prove that text and handwritten relations retain the same S31 cost shape."""

import json
import shutil
import sys
import tempfile
from pathlib import Path

import s31
from s31_stdlib import P


CASES = (
    ("arith4_m31", "arith4", "direct-chip"),
    ("merkle_path1_poseidon", "merkle_path1_poseidon", "direct-gate"),
    ("math_polynomial4", "math_polynomial4", "direct-gate"),
    ("mathlib4", "mathlib4", "direct-gate"),
    ("static_matvec", "static_matvec", "direct-gate"),
    ("lane_stats4", "lane_stats4", "direct-gate"),
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


def reject_forged_text_source(package: Path, work: Path) -> None:
    """A package manifest cannot authorize text that lowers to a different AIR."""
    forged = work / "mathlib4-forged-text-package"
    shutil.copytree(package, forged)
    manifest_path = forged / "manifest.json"
    original_manifest = json.loads(manifest_path.read_text())
    missing_artifact = json.loads(json.dumps(original_manifest))
    del missing_artifact["artifacts"]["bin/s31-mathlib4-native-verifier"]
    s31.write_json(manifest_path, missing_artifact)
    try:
        s31.verify_package(forged)
    except ValueError as exc:
        if "missing required artifacts" not in str(exc):
            raise AssertionError(f"omitted verifier was rejected for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("manifest omitted the verifier artifact without rejection")
    s31.write_json(manifest_path, original_manifest)

    key_path = forged / "verification-key.json"
    original_key = json.loads(key_path.read_text())
    changed_key = {**original_key, "name": "forged-program"}
    s31.write_json(key_path, changed_key)
    mismatched_key = json.loads(json.dumps(original_manifest))
    mismatched_key["artifacts"]["verification-key.json"] = s31.file_hash(key_path)
    s31.write_json(manifest_path, mismatched_key)
    try:
        s31.verify_package(forged)
    except ValueError as exc:
        if "key does not match manifest" not in str(exc):
            raise AssertionError(f"mismatched key was rejected for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("manifest accepted a rehashed key for another program")
    s31.write_json(key_path, original_key)
    s31.write_json(manifest_path, original_manifest)

    source = forged / "source.s31"
    original = source.read_text()
    changed = original.replace("11_m31", "12_m31")
    if changed == original or changed.count("12_m31") != 1:
        raise AssertionError("mathlib4 tamper fixture no longer identifies one constant")
    source.write_text(changed)
    source_digest = s31.file_hash(source)
    source_map_path = forged / "source-map.json"
    source_map = json.loads(source_map_path.read_text())
    source_map["source_sha256"] = source_digest
    s31.write_json(source_map_path, source_map)
    manifest = json.loads(manifest_path.read_text())
    manifest["source_text_sha256"] = source_digest
    for name in ("source.s31", "source-map.json"):
        manifest["artifacts"][name] = s31.file_hash(forged / name)
    s31.write_json(manifest_path, manifest)
    try:
        s31.verify_package(forged)
    except ValueError as exc:
        if "text source does not lower to the sealed relation" not in str(exc):
            raise AssertionError(f"forged text was rejected for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("text package accepted source computing +12 with sealed relation computing +11")


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
            lock = json.loads((text_package / "stdlib-lock.json").read_text())
            if lock["package"] != "std" or lock["version"] != 1 or lock["explicit_import"] != (name in {"mathlib4", "static_matvec", "lane_stats4"}):
                raise AssertionError(f"{name}: unexpected standard library lock")
            s31.verify_package(text_package)
            if name == "mathlib4":
                reject_forged_text_source(text_package, work)
            equation_report = s31.equations(text_package)
            relation = json.loads((text_package / "source.s31.json").read_text())
            if ([node["name"] for node in equation_report["nodes"]] !=
                    [node["name"] for node in relation["nodes"]]):
                raise AssertionError(f"{name}: equation report omitted or reordered a relation node")
            if name == "mathlib4":
                last = equation_report["nodes"][-1]
                if last["field_equations"] != ["result[j] - weighted[j] - 11 = 0"]:
                    raise AssertionError("mathlib4: equation inspector misstated the output gate")
            text_report = json.loads((text_package / "cost-report.json").read_text())
            json_report = json.loads((json_package / "cost-report.json").read_text())
            # The handwritten math fixtures give relation nodes descriptive
            # names, so their name-bearing source maps differ.
            compared = (field for field in EQUAL_FIELDS
                        if name not in {"mathlib4", "lane_stats4"} or field != "source_map")
            mismatches = [field for field in compared if text_report[field] != json_report[field]]
            if mismatches:
                raise AssertionError(f"{name}: text and JSON cost structures differ: {mismatches}")
            text_proof = work / f"{name}-text.proof"
            text_bytes = prove_and_verify(text_package, assignment, text_proof)
            reject_bad_text_claims(text_package, assignment, text_proof, work, name)
            if name == "lane_stats4":
                trial_report = s31.trial(text_package, assignment, work / "lane_stats4-trial")
                if (trial_report["canonical_ir_sha256"] != text_report["canonical_ir_sha256"] or
                        trial_report["raw"] != text_report["raw"] or
                        trial_report["changed_public_statement_rejected"] != "public_outputs.result[0]" or
                        trial_report["independent_value_oracle"] != {
                            "status": "passed", "computed_public_outputs": {"result": [296]}}):
                    raise AssertionError("lane_stats4: trial report does not match the verified package")
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
