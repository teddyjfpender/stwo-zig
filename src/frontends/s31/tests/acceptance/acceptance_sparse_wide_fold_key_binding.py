#!/usr/bin/env python3
"""Reject a fixed-fold proof replay under another valid sparse-wide key chain."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))
sys.path.insert(0, str(S31_SOURCE_ROOT / "tools/inspect"))

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import s31
from inspect_recursive_claim import fold_digest, recursive_digest


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples" / "wide" / "wide_order.s31"
ASSIGNMENT = HERE / "examples" / "wide" / "wide_order.valid.json"


def call(*args: str, accepted: bool = True) -> str:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {' '.join(args)}\n{output}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, help="reuse a sealed fourfold wide_order package")
    parser.add_argument("--mode", choices=("source", "fri"), default="source")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    cli = (sys.executable, str(HERE / "python/s31.py"))
    with tempfile.TemporaryDirectory(prefix="s31-wide-fold-key-binding-") as temporary:
        work = Path(temporary)
        original = args.package.resolve() if args.package else s31.build(SOURCE, work / "original", "sparse-wide-gate", 4)
        original_manifest = s31.verify_package(original)
        if original_manifest["name"] != "wide_order" or original_manifest["fri_fold_step"] != 4:
            raise AssertionError("original package must be the fourfold wide_order source")
        if args.mode == "source":
            clone_source = work / "wide_order_clone.s31"
            clone_source.write_text(SOURCE.read_text().replace("circuit wide_order(", "circuit wide_order_clone("))
            clone_fri = 4
        else:
            clone_source = SOURCE
            clone_fri = 1
        clone = s31.build(clone_source, work / "clone", "sparse-wide-gate", clone_fri)
        clone_manifest = s31.verify_package(clone)
        original_key = json.loads((original / "verification-key.json").read_text())
        clone_key = json.loads((clone / "verification-key.json").read_text())
        if original_key["preprocessed_root"] != clone_key["preprocessed_root"]:
            raise AssertionError("comparison changed the leaf preprocessed AIR")
        if args.mode == "fri" and original_key["circuit_hash"] != clone_key["circuit_hash"]:
            raise AssertionError("FRI-only comparison changed the leaf circuit identity")
        original_fold = json.loads((original / "fixed-fold-verification-key.json").read_text())
        clone_fold = json.loads((clone / "fixed-fold-verification-key.json").read_text())
        if original_fold["fold_preprocessed_root"] == clone_fold["fold_preprocessed_root"]:
            raise AssertionError("different key chains produced one fold AIR root")
        leaf, first, second, top = (work / f"{name}.proof" for name in ("leaf", "first", "second", "top"))
        call(*cli, "prove", str(original), str(ASSIGNMENT), str(leaf))
        call(*cli, "wrap", str(original), str(leaf), str(first), "--low-memory")
        call(*cli, "wrap-next", str(original), str(first), str(second), "--low-memory")
        call(*cli, "fold-advance", str(original), str(second), str(top), "--steps", "2", "--low-memory")
        call(*cli, "verify-fold", str(original), str(top))
        clone_leaf = work / "clone-leaf.proof"
        call(*cli, "prove", str(clone), str(ASSIGNMENT), str(clone_leaf))
        call(*cli, "verify", str(clone), str(clone_leaf))

        original_statement = json.loads(Path(str(top) + ".statement.json").read_text())
        words = original_statement["leaf_public_words"]
        clone_d1 = recursive_digest((clone / "verification-key.json").read_bytes(), words)
        clone_d2 = recursive_digest((clone / "recursive-verification-key.json").read_bytes(), clone_d1)
        repaired = dict(original_statement)
        repaired["fold_key_sha256"] = s31.file_hash(clone / "fixed-fold-verification-key.json")
        repaired["base_public_words"] = clone_d2
        repaired["fold_preprocessed_root"] = clone_fold["fold_preprocessed_root"]
        repaired["fold_circuit_hash"] = clone_fold["fold_circuit_hash"]
        repaired["fold_public_words"] = fold_digest(clone_fold["fold_preprocessed_root"], repaired["step"], clone_d2)
        repaired_path = work / "repaired-clone-statement.json"
        s31.write_json(repaired_path, repaired)
        verifier = clone / "bin" / f"s31-{clone_manifest['name']}-native-verifier"
        rejection = call(str(verifier), "fold-verify", str(top), str(repaired_path), accepted=False)
        if "InvalidFoldStatement" in rejection or "InvalidFoldVerificationKey" in rejection:
            raise AssertionError("repaired claim failed before checking the top STARK proof")
        record = {
            "schema": "s31-sparse-wide-fold-key-binding-v1",
            "mode": args.mode,
            "original_source_sha256": original_manifest["program_sha256"],
            "clone_source_sha256": clone_manifest["program_sha256"],
            "original_compiler_sha256": original_manifest["compiler_sha256"],
            "clone_compiler_sha256": clone_manifest["compiler_sha256"],
            "same_leaf_preprocessed_air_root": True,
            "same_leaf_circuit_identity": args.mode == "fri",
            "different_fold_air_roots": True,
            "original_top_native_accepted": True,
            "clone_leaf_native_accepted": True,
            "clone_public_claim_repaired_under_exact_key_bytes": True,
            "cross_key_fold_replay_rejected_by_top_stark": True,
            "original_fold_root": original_fold["fold_preprocessed_root"],
            "clone_fold_root": clone_fold["fold_preprocessed_root"],
            "top_proof_bytes": top.stat().st_size,
        }
        if args.record:
            s31.write_json(args.record.resolve(), record)
        print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
