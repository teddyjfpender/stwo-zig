#!/usr/bin/env python3
"""Reproducible native-proof release gate for the supported S31 library MVP.

The default command runs the core examples and the Bitcoin chain-work
acceptance. Use --core while iterating on the six smaller library examples.
The checked-in cost baseline is deliberately not refreshed by this command.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))

import s31
from oracle import P, OracleError, evaluate_relation
from poseidon2_oracle import leaf as poseidon_leaf
from text_frontend import compile_file

BASELINE = Path(__file__).with_name("library_mvp_cost_baseline.json")
CHAINWORK_ACCEPTANCE = Path(__file__).with_name("acceptance_bitcoin_chainwork_step.py")
U256 = 1 << 256


@dataclass(frozen=True)
class Case:
    name: str
    source: str
    assignment: str
    lowering: str
    proof_ceiling: int


CASES = (
    Case("mathlib4", "arithmetic/mathlib4.s31", "arithmetic/mathlib4.valid.json", "direct-gate", 1_000_000),
    Case("field_div4", "arithmetic/field_div4.s31", "arithmetic/field_div4.valid.json", "direct-gate", 1_000_000),
    Case("u256_sum_checked", "wide/u256_sum_checked.s31", "wide/u256_sum_checked.valid.json", "sparse-wide-gate", 1_000_000),
    Case("merkle2", "hashes/merkle2.s31.json", "hashes/merkle2.valid.json", "gate", 1_000_000),
    Case("array_slice_aligned", "arrays/array_slice_aligned.s31", "arrays/array_slice_aligned.valid.json", "direct-gate", 1_000_000),
    Case("bool_computed_choice", "control/bool_computed_choice.s31", "control/bool_computed_choice.valid.json", "direct-gate", 1_000_000),
)


def source_path(relative: str) -> Path:
    return S31 / "examples" / relative


def wide_value(limbs: list[int]) -> int:
    if len(limbs) != 16 or any(type(value) is not int or not 0 <= value < 65536 for value in limbs):
        raise AssertionError("UInt256 fixture has invalid limbs")
    return sum(value << (16 * index) for index, value in enumerate(limbs))


def blake2s_words(words: list[int], person: bytes) -> list[int]:
    message = b"".join(struct.pack("<I", word) for word in words)
    return [word % P for word in struct.unpack("<8I", hashlib.blake2s(message, person=person).digest())]


def structural_relation(relation: dict) -> dict:
    """Compare every edge while allowing descriptive handwritten node names."""
    names = {item["name"]: f"input{index}" for index, item in enumerate(relation["inputs"])}
    nodes = []
    for index, node in enumerate(relation["nodes"]):
        nodes.append({key: names[value] if key in {"lhs", "rhs", "selector"} else value
                      for key, value in node.items() if key != "name"})
        names[node["name"]] = f"node{index}"
    return {
        "inputs": [{key: value for key, value in item.items() if key != "name"}
                   for item in relation["inputs"]],
        "nodes": nodes,
        "assertions": [{key: names[value] for key, value in item.items()}
                       for item in relation["assertions"]],
        "public_outputs": [names[name] for name in relation["public_outputs"]],
    }


def check_independent_value(case: Case, assignment: dict) -> None:
    public, private = assignment["public_inputs"], assignment.get("private_inputs", {})
    if case.name == "mathlib4":
        expected = [
            (2 * x + 3 * (7 + 5 * x + 3 * x * x + 2 * x * x * x) + 11) % P
            for x in public["x"]
        ]
    elif case.name == "field_div4":
        expected = [
            ((numerator + 1) * pow(denominator, P - 2, P)) % P
            for numerator, denominator in zip(public["numerator"], private["denominator"], strict=True)
        ]
    elif case.name == "u256_sum_checked":
        total = sum(wide_value(private[name]) for name in ("a", "b", "c"))
        if total >= U256:
            raise AssertionError("checked wide-sum fixture overflows")
        limbs = [(total >> (16 * index)) & 65535 for index in range(16)]
        expected = poseidon_leaf(limbs)
    elif case.name == "merkle2":
        left = blake2s_words(private["left"], b"S31LEAF1")
        right = blake2s_words(private["right"], b"S31LEAF1")
        expected = blake2s_words(left + right, b"S31PAIR1")
        if expected == blake2s_words(right + left, b"S31PAIR1"):
            raise AssertionError("ordered Merkle fixture is not order sensitive")
    elif case.name == "array_slice_aligned":
        expected = private["x"][4:8]
    elif case.name == "bool_computed_choice":
        expected = [public["right"][0] if public["x"][0] == 0 and public["y"][0] == 0
                    else public["left"][0]]
    else:
        raise AssertionError(f"unknown library gate case {case.name}")
    output = next(iter(assignment["public_outputs"].values()))
    if expected != output:
        raise AssertionError(f"{case.name}: fixture differs from independent Python calculation")


def check_source_and_equations(case: Case, package: Path, source: Path) -> dict:
    manifest = s31.verify_package(package)
    relation = json.loads((package / "source.s31.json").read_text())
    if source.suffix == ".s31":
        compiled, _ = compile_file(source)
        pinned = json.loads(source.with_suffix(".s31.json").read_text())
        if relation != compiled or structural_relation(compiled) != structural_relation(pinned):
            raise AssertionError(f"{case.name}: text source, handwritten relation, and package disagree")
        if "source_text_sha256" not in manifest:
            raise AssertionError(f"{case.name}: package did not bind the source text")
        lock = json.loads((package / "stdlib-lock.json").read_text())
        if (lock["package"], lock["version"], lock["explicit_import"]) != ("std", 1, True):
            raise AssertionError(f"{case.name}: unexpected standard-library lock")
    elif relation != json.loads(source.read_text()):
        raise AssertionError(f"{case.name}: packaged relation differs from source")
    equations = s31.equations(package)
    relation_names = [node["name"] for node in relation["nodes"]]
    if [node["name"] for node in equations["nodes"]] != relation_names:
        raise AssertionError(f"{case.name}: equation report omitted or reordered relation nodes")
    if any(not (node["field_equations"] or node["functional_spec"]) for node in equations["nodes"]):
        raise AssertionError(f"{case.name}: equation report has an unexplained node")
    cost = json.loads((package / "cost-report.json").read_text())
    spans = {span["name"] for span in cost["source_map"]}
    if not set(relation_names).issubset(spans):
        raise AssertionError(f"{case.name}: some relation nodes have no AIR source-map span")
    return cost


def must_reject(*args: Path | str) -> None:
    try:
        s31.invoke(*(str(value) for value in args))
    except RuntimeError:
        return
    raise AssertionError(f"invalid witness or proof was accepted: {args}")


def check_negative_witness(case: Case, report: dict, assignment: dict, work: Path) -> None:
    if case.name not in {"field_div4", "u256_sum_checked", "array_slice_aligned", "bool_computed_choice"}:
        return
    package = Path(report["package"])
    prover = package / "bin" / f"s31-{case.name}-prover"
    forged = copy.deepcopy(assignment)
    if case.name == "field_div4":
        forged["private_inputs"]["denominator"][0] = 0
    elif case.name == "u256_sum_checked":
        forged["private_inputs"]["a"] = [65535] * 16
    elif case.name == "array_slice_aligned":
        forged["private_inputs"]["x"][4] += 1
    else:
        forged["public_inputs"]["x"] = [1]
    relation = json.loads((package / "source.s31.json").read_text())
    try:
        evaluate_relation(relation, forged)
    except OracleError:
        pass
    else:
        raise AssertionError(f"{case.name}: independent oracle accepted an invalid witness")
    forged_path = work / f"{case.name}-invalid-witness.json"
    s31.write_json(forged_path, forged)
    must_reject(prover, "prove", forged_path, work / f"{case.name}-invalid.proof")


def run_core(baseline: dict | None, work: Path) -> tuple[dict, dict]:
    if baseline is not None and baseline.get("schema") != "s31-library-mvp-cost-baseline-v1":
        raise AssertionError("missing or invalid library MVP cost baseline")
    outcomes, costs = {}, {}
    for case in CASES:
        source = source_path(case.source)
        fixture = source_path(case.assignment)
        assignment = json.loads(fixture.read_text())
        check_independent_value(case, assignment)
        report = s31.trial(source, fixture, work / case.name, case.lowering)
        if report["independent_value_oracle"]["status"] != "passed":
            raise AssertionError(f"{case.name}: independent relation oracle failed")
        if report["native_verifier_accepted"] is not True or not report["changed_public_statement_rejected"]:
            raise AssertionError(f"{case.name}: native acceptance or statement rejection missing")
        if report["proof_bytes"] > case.proof_ceiling:
            raise AssertionError(f"{case.name}: proof grew beyond {case.proof_ceiling} bytes")
        package = Path(report["package"])
        cost = check_source_and_equations(case, package, source)
        measured = {
            "source_sha256": s31.file_hash(source),
            "lowering": case.lowering,
            "profile": cost["profile"],
            "canonical_ir_sha256": cost["canonical_ir_sha256"],
            "raw": cost["raw"],
            "padded": cost["padded"],
            "preprocessed_cells": cost["preprocessed_cells"],
            "preprocessed_columns": cost["preprocessed_columns"],
        }
        if baseline is not None:
            if measured != baseline["cases"].get(case.name):
                changed = [field for field in measured if measured[field] != baseline["cases"].get(case.name, {}).get(field)]
                raise AssertionError(f"{case.name}: pinned AIR cost/source changed: {changed}; review before updating baseline")
        costs[case.name] = measured
        proof = work / case.name / "proof.bin"
        damaged = bytearray(proof.read_bytes())
        damaged[len(damaged) // 2] ^= 1
        damaged_path = work / f"{case.name}-damaged.proof"
        damaged_path.write_bytes(damaged)
        verifier = package / "bin" / f"s31-{case.name}-native-verifier"
        must_reject(verifier, damaged_path, work / case.name / "statement.json", package / "verification-key.json")
        check_negative_witness(case, report, assignment, work)
        outcomes[case.name] = {"proof_bytes": report["proof_bytes"], "raw": report["raw"], "padded": report["padded"]}
        print(f"{case.name}: independent value, source equations, cost, native proof and rejections passed", flush=True)
    return outcomes, costs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", action="store_true", help="Run only the six focused library examples")
    parser.add_argument("--record-baseline", action="store_true",
                        help="Write cost geometry only after successful native acceptance; review the diff")
    args = parser.parse_args()
    if args.record_baseline and not args.core:
        parser.error("--record-baseline requires --core")
    baseline = None if args.record_baseline else json.loads(BASELINE.read_text())
    with tempfile.TemporaryDirectory(prefix="s31-library-mvp-") as temporary:
        outcomes, costs = run_core(baseline, Path(temporary))
    if args.record_baseline:
        s31.write_json(BASELINE, {"schema": "s31-library-mvp-cost-baseline-v1", "cases": costs,
                                  "policy": "Exact source digest and AIR geometry; proof-size ceiling is in the gate script."})
    if not args.core:
        if not CHAINWORK_ACCEPTANCE.is_file():
            raise AssertionError(f"required full-MVP acceptance is missing: {CHAINWORK_ACCEPTANCE}")
        subprocess.run([sys.executable, str(CHAINWORK_ACCEPTANCE)], cwd=s31.ROOT, check=True)
    print(json.dumps({"schema": "s31-library-mvp-gate-v1", "mode": "core" if args.core else "full",
                      "core_cases": outcomes, "chainwork_accepted": not args.core}, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.CalledProcessError) as error:
        print(f"S31 library MVP gate: {error}", file=sys.stderr)
        raise SystemExit(1)
