#!/usr/bin/env python3
"""Prove a source-defined four-lane coupled recurrence under one fold key."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import json
import tempfile
from pathlib import Path

import s31
from acceptance_state_fold import digest, run, statement
from s31_stdlib import reference_iterate
from text_frontend import SourceError, compile_text

HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/mix4_square4.s31"
ASSIGNMENT = HERE / "examples/mix4_square4.valid.json"
P = (1 << 31) - 1
BODY = [{"op": "square", "constant": None},
        {"op": "add_const", "constant": 7},
        {"op": "mix4", "constant": None}]


def step(values: list[int]) -> list[int]:
    squared = [(value * value + 7) % P for value in values]
    total = sum(squared) % P
    return [(value + total) % P for value in squared]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, help="reuse a sealed mix4 package")
    parser.add_argument("--record", type=Path, help="write the verified proof geometry and public claim")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-mix4-state-fold-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.build(SOURCE, work / "package", "gate", 4)
        manifest = s31.verify_package(package)
        if manifest["lowering"] != "gate" or manifest["fri_fold_step"] != 4:
            raise AssertionError("mix4 fixture needs the fourfold gate profile")
        key = json.loads((package / "state-fold-verification-key.json").read_text())
        if key["source_rounds"] != 3 or key["step_body"] != BODY or key["counter_bits"] != 32:
            raise AssertionError("sealed key did not bind the coupled transition")
        cost = json.loads((package / "cost-report.json").read_text())
        if cost["repeated_step"] is not None or cost["state_fold_step"] != {"rounds": 3, "body": BODY}:
            raise AssertionError("coupled recurrence selected an unrelated chip")
        if any(left == right for left, right in zip(step([1, 2, 3, 4]), step([2, 2, 3, 4]))):
            raise AssertionError("mix4 test did not couple all four lanes")
        bad_shape = """fn step(v: [m31; 3]) -> [m31; 3] { std::math::mix4(v) }
circuit bad(public x: [m31; 3]) -> public [m31; 3] { iterate<1>(step, x) }
"""
        try:
            compile_text(bad_shape)
        except SourceError:
            pass
        else:
            raise AssertionError("text frontend accepted mix4 on three lanes")

        leaf, first = work / "leaf.proof", work / "first.proof"
        run("python3", str(HERE / "python/s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "python/s31.py"), "wrap", str(package), str(leaf), str(first), "--low-memory")
        initial = [1, 2, 3, 4]
        for _ in range(3):
            initial = step(initial)
        if reference_iterate([1, 2, 3, 4], 3, tuple(BODY)) != initial:
            raise AssertionError("standard-library recurrence disagrees with independent mix4 arithmetic")
        if statement(first)["child_public_words"][4:8] != initial:
            raise AssertionError("base leaf computed the wrong mixed state")
        if "rejected=27" not in run("python3", str(HERE / "python/s31.py"), "audit-state-fold-base", str(package), str(first)):
            raise AssertionError("coupled fold base audit missed a challenge")

        checkpoints = work / "checkpoints"
        top = work / "top.proof"
        run("python3", str(HERE / "python/s31.py"), "state-fold-advance", str(package), str(first),
            str(top), "--steps", "3", "--checkpoint-dir", str(checkpoints), "--low-memory")
        folds = [checkpoints / "state-00000.proof", checkpoints / "state-00001.proof", top]
        chain_audit = s31.audit_fold_chain(package, manifest, folds, True, 2)
        if chain_audit["proofs_verified"] != 3 or chain_audit["top_step"] != 2:
            raise AssertionError("coupled checkpoint audit did not cover all source steps")
        proof_sizes = [proof.stat().st_size for proof in (leaf, first, *folds)]
        if "rejected=28" not in run("python3", str(HERE / "python/s31.py"), "audit-state-fold-next", str(package), str(folds[0])):
            raise AssertionError("coupled fold recursive audit missed a challenge")
        expected = initial.copy()
        root = key["fold_preprocessed_root"]
        for index, proof in enumerate(folds):
            if index:
                expected = step(expected)
            item = statement(proof)
            if (item["step"] != index or item["initial_state"] != initial or
                    item["current_state"] != expected or
                    item["fold_public_words"] != digest(root, index, item["base_public_words"], initial, expected)):
                raise AssertionError(f"coupled state fold step {index} is incorrect")
            run("python3", str(HERE / "python/s31.py"), "verify-state-fold", str(package), str(proof))

        false_claim = copy.deepcopy(statement(top))
        false_claim["current_state"][0] = (false_claim["current_state"][0] + 1) % P
        false_claim["fold_public_words"] = digest(root, 2, false_claim["base_public_words"],
                                                   initial, false_claim["current_state"])
        altered = work / "false-state.json"
        s31.write_json(altered, false_claim)
        run("python3", str(HERE / "python/s31.py"), "verify-state-fold", str(package), str(top),
            "--statement", str(altered), accept=False)

        for proof in (leaf, first, *folds[:-1]):
            proof.unlink()
            Path(f"{proof}.statement.json").unlink()
        inspected = json.loads(run("python3", str(HERE / "tools/inspect/inspect_state_fold_claim.py"), str(package), str(top)))
        if (inspected["native_top_verification"] != "accepted" or
                inspected["independent_state_replay"] != "matched" or
                inspected["expected_current_state"] != expected or
                inspected["initial_state"] != initial or inspected["step_body"] != BODY or
                inspected["lower_proof_files_required"] is not False):
            raise AssertionError("isolated coupled-fold inspector disagreed with source semantics")
        if args.record:
            geometry = json.loads(run("python3", str(HERE / "python/s31.py"), "inspect-state-fold", str(package)))
            output = args.record.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            s31.write_json(output, {
                "schema": "s31-mix4-state-fold-acceptance-v1",
                "source_sha256": s31.file_hash(SOURCE),
                "compiler_sha256": manifest["compiler_sha256"],
                "fri_fold_step": 4,
                "step_body": BODY,
                "source_rounds": 3,
                "proof_bytes_leaf_first_fold0_fold1_fold2": proof_sizes,
                "fold_geometry": {name: geometry[name] for name in
                                  ("fold_preprocessed_root", "raw_vars", "padded_vars", "raw_rows", "padded_rows")},
                "base_and_recursive_audit_rejections": [27, 28],
                "top_claim": inspected,
            })
            print(output)
        print("S31 mix4 state fold: coupled lanes, three source rounds, three recursive proofs, "
              "27/28 circuit challenges, repaired false state rejected, isolated top replayed")


if __name__ == "__main__":
    main()
