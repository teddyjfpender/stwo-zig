#!/usr/bin/env python3
"""Differential and native-proof acceptance for fixed UInt256 reductions."""

from __future__ import annotations

import copy
import json
import random
import sys
import tempfile
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))
from example_paths import example_path

import s31
from oracle import OracleError, evaluate_relation
from poseidon2_oracle import leaf
from text_frontend import compile_file

EXAMPLES = S31 / "examples"
LIMIT = 1 << 256


def limbs(number: int) -> list[int]:
    return [(number >> (16 * index)) & 0xffff for index in range(16)]


def structural_relation(relation: dict) -> dict:
    """Compare every normalized edge despite source-local temporary names."""
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


def assignment(a: int, b: int, c: int) -> dict:
    return {"public_inputs": {}, "private_inputs": {
        "a": limbs(a), "b": limbs(b), "c": limbs(c)},
        "public_outputs": {"root": leaf(limbs((a + b + c) % LIMIT))}}


def must_reject(command: tuple[object, ...]) -> None:
    try:
        s31.invoke(*(str(item) for item in command))
    except RuntimeError:
        return
    raise AssertionError(f"command accepted an invalid proof or witness: {command}")


def main() -> None:
    sources = {name: example_path(f"{name}.s31") for name in
               ("u256_sum_checked", "u256_sum_wrap", "u256_sum_checked_manual")}
    relations = {name: compile_file(path)[0] for name, path in sources.items()}
    if structural_relation(relations["u256_sum_checked"]) != structural_relation(relations["u256_sum_checked_manual"]):
        raise AssertionError("checked helper differs from explicit checked-add chain")
    for name, relation in relations.items():
        saved = json.loads((example_path(f"{name}.s31.json")).read_text())
        if relation != saved:
            raise AssertionError(f"{name}: checked-in normalized relation changed")
        fixture = json.loads((example_path(f"{name}.valid.json")).read_text())
        if evaluate_relation(relation, fixture) != fixture["public_outputs"]:
            raise AssertionError(f"{name}: independent oracle rejected fixture")

    rng = random.Random(0x531256)
    for _ in range(32):
        a, b, c = (rng.randrange(LIMIT) for _ in range(3))
        wrap_claim = assignment(a, b, c)
        evaluate_relation(relations["u256_sum_wrap"], wrap_claim)
        if a + b + c < LIMIT:
            evaluate_relation(relations["u256_sum_checked"], wrap_claim)
        else:
            try:
                evaluate_relation(relations["u256_sum_checked"], wrap_claim)
            except OracleError as error:
                if "overflow" not in str(error):
                    raise
            else:
                raise AssertionError("checked reduction accepted overflowing random sum")

    with tempfile.TemporaryDirectory(prefix="s31-u256-sum-") as temporary:
        work = Path(temporary)
        reports = {}
        for name, source in sources.items():
            fixture = example_path(f"{name}.valid.json")
            reports[name] = s31.trial(source, fixture, work / name, "sparse-wide-gate")
            if reports[name]["native_verifier_accepted"] is not True or reports[name]["independent_value_oracle"]["status"] != "passed":
                raise AssertionError(f"{name}: native proof or oracle failed")
            if reports[name]["changed_public_statement_rejected"] != "public_outputs.root[0]":
                raise AssertionError(f"{name}: changed public root was accepted")
        checked = reports["u256_sum_checked"]
        manual = reports["u256_sum_checked_manual"]
        for field in ("raw", "padded", "preprocessed_cells"):
            if checked[field] != manual[field]:
                raise AssertionError(f"checked helper changed {field} relative to manual chain")

        checked_package = work / "u256_sum_checked/package"
        wrap_package = work / "u256_sum_wrap/package"
        checked_prover = checked_package / "bin/s31-u256_sum_checked-prover"
        checked_verifier = checked_package / "bin/s31-u256_sum_checked-native-verifier"
        wrap_prover = wrap_package / "bin/s31-u256_sum_wrap-prover"
        checked_key = checked_package / "verification-key.json"

        overflow = json.loads((EXAMPLES / "wide" / "u256_sum_wrap.valid.json").read_text())
        overflow_path = work / "overflow.json"
        s31.write_json(overflow_path, overflow)
        must_reject((checked_prover, "prove", overflow_path, work / "overflow.proof"))

        same_claim = json.loads((EXAMPLES / "wide" / "u256_sum_checked.valid.json").read_text())
        same_claim_path = work / "same-claim.json"
        same_statement_path = work / "same-claim.statement.json"
        same_proof_path = work / "same-claim-wrap.proof"
        s31.write_json(same_claim_path, same_claim)
        s31.write_json(same_statement_path, {"public_inputs": {},
                                            "public_outputs": same_claim["public_outputs"]})
        s31.invoke(str(wrap_prover), "prove", str(same_claim_path), str(same_proof_path))
        must_reject((checked_verifier, same_proof_path, same_statement_path, checked_key))

        false_claim = copy.deepcopy(same_claim)
        false_claim["public_outputs"]["root"][0] += 1
        false_path = work / "false-claim.json"
        s31.write_json(false_path, false_claim)
        try:
            evaluate_relation(relations["u256_sum_checked"], false_claim)
        except OracleError:
            pass
        else:
            raise AssertionError("independent oracle accepted altered root")
        must_reject((checked_prover, "prove", false_path, work / "false.proof"))

        damaged = bytearray((work / "u256_sum_checked/proof.bin").read_bytes())
        damaged[len(damaged) // 2] ^= 1
        damaged_path = work / "damaged.proof"
        damaged_path.write_bytes(damaged)
        must_reject((checked_verifier, damaged_path,
                     work / "u256_sum_checked/statement.json", checked_key))

        print(json.dumps({
            "schema": "s31-u256-static-sum-acceptance-v1",
            "checked_manual_structural_match": True,
            "checked_manual_cost_match": True,
            "independent_random_cases": 32,
            "native_proofs": 3,
            "checked_overflow_rejected": True,
            "same_claim_cross_key_replay_rejected": True,
            "changed_public_root_rejected": True,
            "damaged_proof_rejected": True,
            "checked_proof_bytes": checked["proof_bytes"],
            "wrapping_proof_bytes": reports["u256_sum_wrap"]["proof_bytes"],
            "manual_proof_bytes": manual["proof_bytes"],
            "checked_prove_seconds": checked["prove_seconds"],
            "manual_prove_seconds": manual["prove_seconds"],
            "raw": checked["raw"],
            "padded": checked["padded"],
        }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, AssertionError) as error:
        print(f"S31 UInt256 static-sum acceptance: {error}", file=sys.stderr)
        raise SystemExit(1)
