#!/usr/bin/env python3
"""Check that selectable FRI schedules remain key-bound and nonportable."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

import s31
from acceptance_state_fold import run


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/affine_square4.s31"
ASSIGNMENT = HERE / "examples/affine_square4.valid.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--step-one", type=Path)
    parser.add_argument("--step-four", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-fri-fold-step-") as temporary:
        work = Path(temporary)
        one = args.step_one.resolve() if args.step_one else s31.build(SOURCE, work / "step-one", fri_fold_step=1)
        four = args.step_four.resolve() if args.step_four else s31.build(SOURCE, work / "step-four", fri_fold_step=4)
        try:
            s31.build(SOURCE, work / "unsupported-profile", lowering="direct-gate", fri_fold_step=4)
        except ValueError as exc:
            if "requires gate or sparse-wide-gate lowering" not in str(exc):
                raise AssertionError("unsupported FRI setting failed for the wrong reason") from exc
        else:
            raise AssertionError("FRI fold step 4 was offered for an unsupported proof profile")
        for package, expected_step in ((one, 1), (four, 4)):
            manifest = s31.verify_package(package)
            key = json.loads((package / "verification-key.json").read_text())
            if manifest.get("fri_fold_step", 1) != expected_step or key["fri"]["fold_step"] != expected_step:
                raise AssertionError("FRI fold step is not bound in manifest and leaf key")
            if (key["fri"]["pow_bits"], key["fri"]["log_blowup_factor"], key["fri"]["queries"]) != (26, 1, 70):
                raise AssertionError("FRI schedule changed PoW, blowup, or query count")
        key_one = json.loads((one / "verification-key.json").read_text())
        key_four = json.loads((four / "verification-key.json").read_text())
        if key_one["preprocessed_root"] != key_four["preprocessed_root"] or key_one["circuit_hash"] != key_four["circuit_hash"]:
            raise AssertionError("FRI schedule unexpectedly changed the leaf AIR")
        state_one = json.loads((one / "state-fold-verification-key.json").read_text())
        state_four = json.loads((four / "state-fold-verification-key.json").read_text())
        if state_one["fold_preprocessed_root"] == state_four["fold_preprocessed_root"]:
            raise AssertionError("FRI schedule did not change the recursive AIR key")
        if state_four["padded"]["blake_g"] * 2 != state_one["padded"]["blake_g"]:
            raise AssertionError("fold-four recursive Blake geometry did not halve")

        proofs: dict[int, Path] = {}
        for step, package in ((1, one), (4, four)):
            proof = work / f"leaf-{step}.proof"
            run("python3", str(HERE / "python/s31.py"), "prove", str(package), str(ASSIGNMENT), str(proof))
            run("python3", str(HERE / "python/s31.py"), "verify", str(package), str(proof))
            proofs[step] = proof
        for package, proof in ((one, proofs[4]), (four, proofs[1])):
            run("python3", str(HERE / "python/s31.py"), "verify", str(package), str(proof), accept=False)

        forged_key = copy.deepcopy(key_four)
        forged_key["fri"]["fold_step"] = 1
        forged_key_path = work / "forged-fri-key.json"
        s31.write_json(forged_key_path, forged_key)
        run(str(four / "bin/s31-affine_square4-native-verifier"), str(proofs[4]),
            f"{proofs[4]}.statement.json", str(forged_key_path), accept=False)

        copied = work / "tampered-manifest"
        shutil.copytree(four, copied, copy_function=os.link)
        manifest_path = copied / "manifest.json"
        altered = copy.deepcopy(json.loads(manifest_path.read_text()))
        altered["fri_fold_step"] = 1
        # Break the hard link before writing so the installed package remains intact.
        manifest_path.unlink()
        s31.write_json(manifest_path, altered)
        try:
            s31.verify_package(copied)
        except ValueError as exc:
            if "recursive FRI schedule does not match the package profile" not in str(exc):
                raise AssertionError("tampered FRI schedule failed for the wrong reason") from exc
        else:
            raise AssertionError("tampered manifest selected a different FRI schedule")
        print(json.dumps({
            "schema": "s31-fri-fold-step-acceptance-v1",
            "same_leaf_air": True,
            "distinct_recursive_air": True,
            "same_pow_blowup_queries": True,
            "cross_schedule_leaf_proofs_rejected": True,
            "forged_fri_key_rejected": True,
            "manifest_schedule_tamper_rejected": True,
            "fold_four_padded_blake_rows_halved": True,
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
