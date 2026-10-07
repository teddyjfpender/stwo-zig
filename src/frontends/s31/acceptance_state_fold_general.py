#!/usr/bin/env python3
"""Exercise a non-chip recurrence with a source-bound recursive transition."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

import s31
from acceptance_state_fold import digest, run, statement


HERE = Path(__file__).resolve().parent
P = (1 << 31) - 1
SOURCE = HERE / "examples/affine_square4.s31"
ASSIGNMENT = HERE / "examples/affine_square4.valid.json"
BODY = [{"op": "square", "constant": None},
        {"op": "mul_const", "constant": 3},
        {"op": "add_const", "constant": 5}]


def step(values: list[int]) -> list[int]:
    return [(3 * value * value + 5) % P for value in values]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a built affine_square4 package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-general-state-fold-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.package_for(SOURCE)
        manifest = s31.verify_package(package)
        if "s31-state-fold-batch-v2" not in manifest.get("capabilities", []):
            raise AssertionError("general state-fold package did not enable cached native batching")
        key_path = package / "state-fold-verification-key.json"
        key = json.loads(key_path.read_text())
        if (key["schema"] != "s31-state-fold-verification-key-v3" or key["counter_bits"] != 32 or
                key["source_rounds"] != 3 or key["step_body"] != BODY):
            raise AssertionError("source step was not bound into the recursive key")
        geometry = json.loads(run("python3", str(HERE / "s31.py"), "inspect-state-fold", str(package)))
        stages = geometry["verifier_stages"]
        if (geometry["schema"] != "s31-state-fold-geometry-v2" or len(stages) != 24 or
                stages[0]["name"] != "proof_witness" or stages[-1]["name"] != "finalize" or
                stages[-1]["raw_vars"] != geometry["raw_vars"] or
                any(stages[-1][field] != geometry["raw_rows"][field]
                    for field in ("eq", "qm31_ops", "triple_xor", "m31_to_u32", "blake_g"))):
            raise AssertionError("stage profiler changed or omitted AIR rows")
        for previous, current in zip(stages, stages[1:]):
            if any(previous[field] > current[field] for field in
                   ("raw_vars", "eq", "qm31_ops", "triple_xor", "m31_to_u32", "blake_g")):
                raise AssertionError("stage profiler has nonmonotonic gate counts")
        cost = json.loads((package / "cost-report.json").read_text())
        if cost["repeated_step"] is not None or cost["state_fold_step"] != {"rounds": 3, "body": BODY}:
            raise AssertionError("general fold accidentally selected the narrow chip")
        prover = package / "bin/s31-affine_square4-prover"
        verifier = package / "bin/s31-affine_square4-native-verifier"
        leaf, first = work / "leaf.proof", work / "first.proof"
        run("python3", str(HERE / "s31.py"), "prove", str(package), str(ASSIGNMENT), str(leaf))
        run("python3", str(HERE / "s31.py"), "wrap", str(package), str(leaf), str(first))
        expected = [1, 2, 3, 4]
        for _ in range(3):
            expected = step(expected)
        if statement(first)["child_public_words"][4:8] != expected:
            raise AssertionError("source base proof computed the wrong three rounds")
        base_audit = run("python3", str(HERE / "s31.py"), "audit-state-fold-base", str(package), str(first))
        if "rejected=27" not in base_audit:
            raise AssertionError("base audit did not challenge all child proof fields")
        checkpoints = work / "checkpoints"
        top = work / "top.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package), str(first),
            str(top), "--steps", "3", "--checkpoint-dir", str(checkpoints))
        folds = [checkpoints / "state-00000.proof", checkpoints / "state-00001.proof", top]
        for proof in folds[:2]:
            recursive_audit = run("python3", str(HERE / "s31.py"), "audit-state-fold-next", str(package), str(proof))
            if "rejected=28" not in recursive_audit:
                raise AssertionError("recursive audit did not challenge all child proof fields")
        direct_previous = first
        for index, batched in enumerate(folds):
            direct = work / f"direct-{index}.proof"
            run("python3", str(HERE / "s31.py"),
                "state-fold-base" if index == 0 else "state-fold-next",
                str(package), str(direct_previous), str(direct))
            if direct.read_bytes() != batched.read_bytes():
                raise AssertionError(f"cached batch changed proof bytes at step {index}")
            direct_previous = direct
        resumed = work / "resumed.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
            str(folds[1]), str(resumed), "--steps", "1")
        if resumed.read_bytes() != top.read_bytes():
            raise AssertionError("checkpoint resume changed proof bytes")
        low_memory = work / "low-memory.proof"
        run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
            str(folds[1]), str(low_memory), "--steps", "1", "--low-memory")
        if low_memory.read_bytes() != top.read_bytes():
            raise AssertionError("low-memory resume changed proof bytes")
        batch_args = (str(package / "verification-key.json"),
                      str(package / "recursive-verification-key.json"),
                      str(key_path))
        run(str(prover), "state-fold-wrap-batch", str(first), f"{first}.statement.json",
            str(work / "invalid-batch.proof"), *batch_args, "1", str(work / "scratch"),
            "2", "base", accept=False)
        run(str(prover), "state-fold-wrap-batch", str(top), f"{top}.statement.json",
            str(work / "invalid-batch.proof"), *batch_args, "1", str(work / "scratch"),
            "2", "next", accept=False)
        run(str(prover), "state-fold-wrap-batch", str(first), f"{first}.statement.json",
            str(top), *batch_args, "1", str(work / "scratch"), "0", "base", accept=False)
        if top.read_bytes() != resumed.read_bytes():
            raise AssertionError("batch preflight modified an existing proof")
        last_step_claim = copy.deepcopy(statement(top))
        last_step_claim["step"] = (1 << 32) - 1
        last_step_path = work / "last-step-claim.json"
        s31.write_json(last_step_path, last_step_claim)
        overflow = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                       str(top), str(work / "overflow.proof"), "--statement", str(last_step_path),
                       "--steps", "1", accept=False)
        zero = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                   str(top), str(work / "zero.proof"), "--steps", "0", accept=False)
        if "counter would overflow" not in overflow or "at least one step" not in zero:
            raise AssertionError("state-fold advance rejected bounds for the wrong reason")
        malformed_step = copy.deepcopy(statement(top))
        malformed_step["step"] = True
        malformed_step_path = work / "malformed-step.json"
        s31.write_json(malformed_step_path, malformed_step)
        malformed = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                        str(top), str(work / "malformed.proof"), "--statement",
                        str(malformed_step_path), "--steps", "1", accept=False)
        if "invalid step counter" not in malformed:
            raise AssertionError("malformed step failed after batch preflight")
        collision_dir = work / "collision-checkpoints"
        collision = run("python3", str(HERE / "s31.py"), "state-fold-advance", str(package),
                        str(first), str(collision_dir / "state-00000.proof"),
                        "--steps", "2", "--checkpoint-dir", str(collision_dir), accept=False)
        if "batch outputs collide" not in collision or any(collision_dir.iterdir()):
            raise AssertionError("batch output collision was not rejected before proving")
        root = key["fold_preprocessed_root"]
        for i, proof in enumerate(folds):
            item = statement(proof)
            if i:
                expected = step(expected)
            if item["step"] != i or item["current_state"] != expected:
                raise AssertionError(f"incorrect state at fold step {i}")
            if item["fold_public_words"] != digest(root, i, item["base_public_words"],
                                                   item["initial_state"], expected):
                raise AssertionError("state fold public digest mismatch")
            run(str(verifier), "state-fold-verify", str(proof), f"{proof}.statement.json")

        hostile = copy.deepcopy(statement(folds[-1]))
        hostile["current_state"][0] = (hostile["current_state"][0] + 1) % P
        hostile["fold_public_words"] = digest(root, hostile["step"], hostile["base_public_words"],
                                               hostile["initial_state"], hostile["current_state"])
        hostile_path = work / "false-state-rehashed.json"
        s31.write_json(hostile_path, hostile)
        run(str(verifier), "state-fold-verify", str(folds[-1]), str(hostile_path), accept=False)

        altered = copy.deepcopy(key)
        altered["step_body"][1]["constant"] = 4
        altered_key_path = work / "false-body-key.json"
        s31.write_json(altered_key_path, altered)
        run(str(prover), "state-fold-wrap-next", str(folds[-1]), f"{folds[-1]}.statement.json",
            str(work / "invalid.proof"), str(package / "verification-key.json"),
            str(package / "recursive-verification-key.json"), str(altered_key_path), accept=False)

        for path in (leaf, first, *folds[:-1]):
            path.unlink()
            Path(f"{path}.statement.json").unlink()
        run(str(verifier), "state-fold-verify", str(folds[-1]), f"{folds[-1]}.statement.json")
        inspected = json.loads(run("python3", str(HERE / "inspect_state_fold_claim.py"),
                                   str(package), str(folds[-1])))
        if (inspected["native_top_verification"] != "accepted" or
                inspected["independent_state_replay"] != "matched" or
                inspected["source_rounds"] != 3 or inspected["step_body"] != BODY or
                inspected["expected_current_state"] != expected or
                inspected["current_state"] != expected or
                inspected["step"] != 2 or inspected["lower_proof_files_required"] is not False):
            raise AssertionError("isolated state-fold claim inspector disagreed with the source")
        bounded = json.loads(run("python3", str(HERE / "inspect_state_fold_claim.py"),
                                 str(package), str(folds[-1]), "--max-replay-steps", "1"))
        if bounded["independent_state_replay"] != "skipped_step_limit" or bounded["native_top_verification"] != "accepted":
            raise AssertionError("bounded state replay changed top proof verification")
        print("S31 general state-fold acceptance: three base rounds, square/multiply/add step, "
              "independent M31 arithmetic, byte-identical cached batch and resume, hostile claims and key, isolated top proof and source replay")


if __name__ == "__main__":
    main()
