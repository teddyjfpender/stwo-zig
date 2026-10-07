#!/usr/bin/env python3
"""A sparse-wide leaf, two wrappers, and three proofs under one fold key."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import s31

HERE = Path(__file__).resolve().parent
M31 = (1 << 31) - 1


def call(*args: str, accepted: bool = True) -> tuple[str, float]:
    started = time.perf_counter()
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    elapsed = time.perf_counter() - started
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{output}")
    return output, elapsed


def digest(key_bytes: bytes, words: list[int]) -> list[int]:
    message = hashlib.sha256(key_bytes).digest() + struct.pack("<8I", *words)
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31RCV2!").digest()))


def fold_digest(root_hex: str, step: int, words: list[int]) -> list[int]:
    message = bytes.fromhex(root_hex) + struct.pack("<I8I", step, *words)
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31FOL2!").digest()))


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoin", action="store_true", help="fold the two-header SHA256d/PoW proof")
    parser.add_argument("--fri-fold-step", type=int, choices=(1, 4), default=4)
    parser.add_argument("--package", type=Path, help="reuse a sealed sparse-wide package")
    parser.add_argument("--record", type=Path, help="write the run's measurement JSON here")
    args = parser.parse_args()
    name = "bitcoin_header_pair" if args.bitcoin else "wide_order"
    source = HERE / "examples" / f"{name}.s31"
    assignment = HERE / "examples" / f"{name}.valid.json"
    cli = (sys.executable, str(HERE / "s31.py"))
    with tempfile.TemporaryDirectory(prefix="s31-wide-fold-") as temporary:
        work = Path(temporary)
        started = time.perf_counter()
        package = args.package.resolve() if args.package else s31.build(source, work / "package", "sparse-wide-gate", args.fri_fold_step)
        manifest = s31.verify_package(package)
        build_seconds = None if args.package else time.perf_counter() - started
        if manifest["lowering"] != "sparse-wide-gate" or manifest["fri_fold_step"] != args.fri_fold_step:
            raise AssertionError("fixture received the wrong package profile")
        leaf = work / "leaf.proof"
        first = work / "first.proof"
        second = work / "second.proof"
        folds = [work / f"fold-{step}.proof" for step in range(3)]
        _, leaf_seconds = call(*cli, "prove", str(package), str(assignment), str(leaf))
        _, first_seconds = call(*cli, "wrap", str(package), str(leaf), str(first), "--low-memory")
        _, second_seconds = call(*cli, "wrap-next", str(package), str(first), str(second), "--low-memory")
        call(*cli, "verify-recursive-next", str(package), str(second))
        base_audit, _ = call(*cli, "audit-fold-base", str(package), str(second))
        if "valid=true rejected=24" not in base_audit:
            raise AssertionError(base_audit)
        _, fold0_seconds = call(*cli, "fold-base", str(package), str(second), str(folds[0]), "--low-memory")
        call(*cli, "verify-fold", str(package), str(folds[0]))
        next_audit, _ = call(*cli, "audit-fold-next", str(package), str(folds[0]))
        if "valid=true rejected=24" not in next_audit:
            raise AssertionError(next_audit)
        _, fold1_seconds = call(*cli, "fold-next", str(package), str(folds[0]), str(folds[1]), "--low-memory")
        _, fold2_seconds = call(*cli, "fold-next", str(package), str(folds[1]), str(folds[2]), "--low-memory")
        _, verify_seconds = call(*cli, "verify-fold", str(package), str(folds[2]))
        if "s31-fixed-fold-batch-v1" not in manifest.get("capabilities", []):
            raise AssertionError("package did not advertise its fixed-fold batch path")
        batch_top = work / "batch-top.proof"
        checkpoints = work / "batch-checkpoints"
        _, batch_seconds = call(*cli, "fold-advance", str(package), str(second), str(batch_top),
                                "--steps", "3", "--checkpoint-dir", str(checkpoints), "--low-memory")
        batch_paths = [checkpoints / "fold-00000.proof", checkpoints / "fold-00001.proof", batch_top]
        for step, (one, batched) in enumerate(zip(folds, batch_paths, strict=True)):
            if one.read_bytes() != batched.read_bytes() or Path(str(one) + ".statement.json").read_bytes() != Path(str(batched) + ".statement.json").read_bytes():
                raise AssertionError(f"batch fold step {step} changed proof or statement bytes")
        call(*cli, "verify-fold", str(package), str(batch_top))
        resumed = work / "resumed-top.proof"
        call(*cli, "fold-advance", str(package), str(folds[0]), str(resumed),
             "--steps", "2", "--low-memory")
        if resumed.read_bytes() != folds[2].read_bytes():
            raise AssertionError("resumed fold changed the top proof")
        call(*cli, "fold-advance", str(package), str(folds[2]), str(work / "overflow.proof"),
             "--steps", "65537", accepted=False)
        collision_dir = work / "collision-checkpoints"
        call(*cli, "fold-advance", str(package), str(second),
             str(collision_dir / "fold-00000.proof"), "--steps", "2",
             "--checkpoint-dir", str(collision_dir), accepted=False)
        if any(collision_dir.iterdir()):
            raise AssertionError("batch output collision left a proof behind")

        keys = [package / "verification-key.json", package / "recursive-verification-key.json",
                package / "recursive-verification-key-level2.json", package / "fixed-fold-verification-key.json"]
        prover = package / "bin" / f"s31-{manifest['name']}-prover"
        reproduced = work / "reproduced-fold-key.json"
        call(str(prover), "wide-fold-keygen", *(str(path) for path in keys[:3]), str(reproduced))
        if reproduced.read_bytes() != keys[3].read_bytes():
            raise AssertionError("wide fold key is not reproducible")
        geometry_output, _ = call(*cli, "inspect-fold", str(package))
        geometry = json.loads(geometry_output)
        if (geometry["schema"] != "s31-wide-fixed-fold-geometry-v1" or
                geometry["fold_preprocessed_root"] != json.loads(keys[3].read_text())["fold_preprocessed_root"]):
            raise AssertionError("inspected fold geometry does not match its sealed key")
        stages = geometry["verifier_stages"]
        if (not isinstance(stages, list) or len(stages) < 20 or
                stages[0]["name"] != "proof_witness" or
                stages[-3]["name"] != "fri_decommit" or
                stages[-2]["name"] != "fixed_fold_digest" or
                stages[-1]["name"] != "finalize" or
                stages[-1]["raw_vars"] != geometry["raw_vars"]):
            raise AssertionError("fixed-fold verifier stage capture is incomplete")
        for before, after in zip(stages, stages[1:]):
            if any(after[key] < before[key] for key in
                   ("raw_vars", "eq", "qm31_ops", "triple_xor", "m31_to_u32", "blake_g")):
                raise AssertionError("fixed-fold verifier stages are not cumulative")
        chain = json.loads(Path(str(second) + ".statement.json").read_text())
        statements = [json.loads(Path(str(proof) + ".statement.json").read_text()) for proof in folds]
        leaf_words = chain["leaf"]["child_public_words"]
        expected_base = digest(keys[1].read_bytes(), digest(keys[0].read_bytes(), leaf_words))
        root = statements[0]["fold_preprocessed_root"]
        if not any(word >= M31 for word in expected_base):
            raise AssertionError("fixture does not exercise raw high-bit recursive words")
        for step, statement in enumerate(statements):
            if (statement["schema"] != "s31-fixed-fold-statement-v4" or
                    statement["step"] != step or statement["leaf_public_words"] != leaf_words or
                    statement["base_public_words"] != expected_base or
                    statement["fold_preprocessed_root"] != root or
                    statement["fold_public_words"] != fold_digest(root, step, expected_base)):
                raise AssertionError(f"fold statement {step} does not bind the nested claim")
        if not all(Path(str(proof) + ".statement.json").exists() for proof in folds):
            raise AssertionError("fold proof is missing its public statement")

        negatives = []
        top = statements[2]
        for high_step in (65536, 0x80000000, 0xffffffff):
            high_claim = dict(top)
            high_claim["step"] = high_step
            high_claim["fold_public_words"] = fold_digest(root, high_step, expected_base)
            high_claim_path = work / f"high-step-{high_step}.statement.json"
            write(high_claim_path, high_claim)
            rejection, _ = call(*cli, "verify-fold", str(package), str(folds[2]),
                                "--statement", str(high_claim_path), accepted=False)
            if "InvalidFoldStatement" in rejection:
                raise AssertionError("rehashed high counter failed before checking the top proof")
        negatives.append("rehashed_high_u32_steps_rejected_by_top_proof")
        max_counter = dict(top)
        max_counter["step"] = 0xffffffff
        max_counter["fold_public_words"] = fold_digest(root, max_counter["step"], expected_base)
        max_counter_path = work / "max-counter.statement.json"
        write(max_counter_path, max_counter)
        overflow_target = work / "overflow-counter.proof"
        call(*cli, "fold-advance", str(package), str(folds[2]), str(overflow_target),
             "--statement", str(max_counter_path), "--steps", "1", accepted=False)
        if overflow_target.exists():
            raise AssertionError("u32 counter overflow preflight wrote a proof")
        negatives.append("u32_counter_overflow_before_output")
        rejection, _ = call(*cli, "fold-base", str(package), str(first),
                            str(work / "wrong-base-proof.proof"), "--statement",
                            str(Path(str(second) + ".statement.json")), accepted=False)
        if "VerificationFailed" not in rejection and "Invalid" not in rejection:
            raise AssertionError(f"first wrapper failed for an unexpected reason: {rejection}")
        negatives.append("first_wrapper_cannot_replace_second_wrapper_base")
        damaged_child = bytearray(folds[0].read_bytes())
        damaged_child[-1] ^= 1
        damaged_child_path = work / "damaged-fold-child.proof"
        damaged_child_path.write_bytes(damaged_child)
        call(*cli, "fold-next", str(package), str(damaged_child_path),
             str(work / "should-not-exist.proof"), "--statement",
             str(Path(str(folds[0]) + ".statement.json")), accepted=False)
        negatives.append("damaged_recursive_child_proof")
        changed = json.loads(json.dumps(top))
        changed["base_public_words"][0] ^= 1
        path = work / "wrong-base.json"
        write(path, changed)
        call(*cli, "verify-fold", str(package), str(folds[2]), "--statement", str(path), accepted=False)
        negatives.append("wrong_nested_base_digest")
        changed = json.loads(json.dumps(top))
        changed["leaf_public_words"][0] ^= 1
        changed["base_public_words"] = digest(keys[1].read_bytes(), digest(keys[0].read_bytes(), changed["leaf_public_words"]))
        changed["fold_public_words"] = fold_digest(root, 2, changed["base_public_words"])
        path = work / "repaired-wrong-leaf.json"
        write(path, changed)
        rejection, _ = call(*cli, "verify-fold", str(package), str(folds[2]), "--statement", str(path), accepted=False)
        if "InvalidFoldStatement" in rejection:
            raise AssertionError("repaired leaf claim failed before STARK verification")
        negatives.append("repaired_leaf_claim_rejected_by_top_proof")
        changed = json.loads(json.dumps(top))
        changed["step"] = 1
        changed["fold_public_words"] = fold_digest(root, 1, expected_base)
        path = work / "repaired-wrong-step.json"
        write(path, changed)
        rejection, _ = call(*cli, "verify-fold", str(package), str(folds[2]), "--statement", str(path), accepted=False)
        if "InvalidFoldStatement" in rejection:
            raise AssertionError("repaired step failed before STARK verification")
        negatives.append("repaired_step_rejected_by_top_proof")
        damaged = bytearray(folds[2].read_bytes())
        damaged[-1] ^= 1
        bad_proof = work / "damaged-top.proof"
        bad_proof.write_bytes(damaged)
        call(*cli, "verify-fold", str(package), str(bad_proof), "--statement",
             str(Path(str(folds[2]) + ".statement.json")), accepted=False)
        negatives.append("damaged_top_proof")
        wrong_second = json.loads(keys[2].read_text())
        wrong_second["outer_fri_fold_step"] = 1
        wrong_second_path = work / "wrong-second-key.json"
        write(wrong_second_path, wrong_second)
        rejection, _ = call(str(prover), "wide-fold-keygen", str(keys[0]), str(keys[1]),
                            str(wrong_second_path), str(work / "bad-fold-key.json"), accepted=False)
        if "InvalidRecursiveVerificationKey" not in rejection:
            raise AssertionError(f"wrong second-key FRI failed for another reason: {rejection}")
        negatives.append("wrong_second_key_fri_schedule")

        sizes = [path.stat().st_size for path in (leaf, first, second, *folds)]
        for proof in (leaf, first, second, folds[0], folds[1]):
            proof.unlink()
            Path(str(proof) + ".statement.json").unlink()
        call(*cli, "verify-fold", str(package), str(folds[2]))
        inspected_output, _ = call(sys.executable, str(HERE / "inspect_recursive_claim.py"),
                                   str(package), str(folds[2]))
        inspected = json.loads(inspected_output)
        if (inspected["native_top_verification"] != "accepted" or
                inspected["leaf_public_words_w0"] != leaf_words or
                inspected["first_wrapper_public_words_d1"] != digest(keys[0].read_bytes(), leaf_words) or
                inspected["base_public_words"] != expected_base or
                inspected["top_public_words"] != fold_digest(root, 2, expected_base) or
                inspected["step"] != 2 or inspected["lower_proof_files_required"] is not False):
            raise AssertionError("claim inspector did not explain the isolated top proof")
        record = {
            "schema": "s31-sparse-wide-fixed-fold-acceptance-v1",
            "source_name": name,
            "source_sha256": s31.file_hash(source),
            "compiler_sha256": manifest["compiler_sha256"],
            "child_fri_fold_step": args.fri_fold_step,
            "wrapper_and_fold_fri_fold_step": 4,
            "build_seconds": build_seconds,
            "proof_bytes_leaf_first_second_fold0_fold1_fold2": sizes,
            "wall_seconds": {"leaf": leaf_seconds, "first": first_seconds, "second": second_seconds,
                             "fold0": fold0_seconds, "fold1": fold1_seconds, "fold2": fold2_seconds,
                             "batch_three_steps": batch_seconds, "top_verify": verify_seconds},
            "batch_matches_separate_proofs_and_statements": True,
            "batch_resume_matches_separate_top": True,
            "fold_geometry": {"raw_vars": geometry["raw_vars"], "padded_rows": geometry["padded_rows"],
                              "headroom_rows": geometry["headroom_rows"]},
            "fold_steps": [0, 1, 2],
            "fold_preprocessed_root": root,
            "base_public_words_d2": expected_base,
            "fold_public_words_first_words": [fold_digest(root, step, expected_base)[0]
                                                for step in range(3)],
            "same_fold_root_for_all_steps": True,
            "fold_key_reproduced": True,
            "base_and_next_audit_rejections": [24, 24],
            "fold_verifier_stages": stages,
            "top_verified_without_lower_proofs": True,
            "inspector_verified_isolated_top": True,
            "host_negative_checks": negatives,
        }
        if args.record or not args.package:
            output = args.record.resolve() if args.record else s31.ROOT / "design" / "s31" / "measurements" / f"{('bitcoin-' if args.bitcoin else '')}sparse-wide-fold-v1-2026-10-07.json"
            s31.write_json(output, record)
            print(output)
        print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
