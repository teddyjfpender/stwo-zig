#!/usr/bin/env python3
"""Prove one Bitcoin header with a sealed, source-bound shift SHA package."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/bitcoin/bitcoin_header_pow.s31.json"
ASSIGNMENT = HERE / "examples/bitcoin/bitcoin_header_pow.valid.json"


def command(*args: object, accepted: bool = True) -> str:
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode}: {args}\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shift-package", type=Path, help="reuse a sealed sha-shift package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-sha-shift-package-") as directory:
        root = Path(directory)
        package = args.shift_package.resolve() if args.shift_package else s31.build(SOURCE, root / "shift", "sha-shift")
        manifest = s31.verify_package(package)
        if manifest["lowering"] != "sha-shift":
            raise AssertionError("expected a sha-shift package")
        key = package / "verification-key.json"
        sealed = json.loads(key.read_text())
        report = json.loads((package / "cost-report.json").read_text())
        if (sealed["fri"] != {"pow_bits": 26, "log_blowup_factor": 1,
                               "last_layer_degree_bound": 0, "queries": 70, "fold_step": 1} or
                sealed["sha_shift"]["claimed_sums"] != 15 or
                report["sha_air_cost"]["main_columns"] != 521):
            raise AssertionError("wrong production shift profile")
        name = manifest["name"]
        prover = package / "bin" / f"s31-{name}-prover"
        verifier = package / "bin" / f"s31-{name}-native-verifier"
        assignment = json.loads(ASSIGNMENT.read_text())
        statement = {"public_inputs": assignment["public_inputs"],
                     "public_outputs": assignment["public_outputs"]}
        statement_path = root / "statement.json"
        s31.write_json(statement_path, statement)
        proof = root / "shift.proof"
        command(prover, "prove", ASSIGNMENT, proof)
        command(verifier, proof, statement_path, key)

        wrong_root = copy.deepcopy(statement)
        wrong_root["public_outputs"]["root"][0] += 1
        wrong_root_path = root / "wrong-root.json"
        s31.write_json(wrong_root_path, wrong_root)
        command(verifier, proof, wrong_root_path, key, accepted=False)

        corrupted = root / "corrupt.proof"
        bytes_ = bytearray(proof.read_bytes())
        bytes_[-1] ^= 1
        corrupted.write_bytes(bytes_)
        command(verifier, corrupted, statement_path, key, accepted=False)

        changed_key = copy.deepcopy(sealed)
        changed_key["sha_shift"]["key_digest"] = "00" * 32
        changed_key_path = root / "wrong-key.json"
        s31.write_json(changed_key_path, changed_key)
        command(verifier, proof, statement_path, changed_key_path, accepted=False)

        # The same relation, written with different source bytes, has a
        # different source digest and consequently a different sealed AIR key.
        alternate_source = root / "alternate.s31.json"
        alternate_source.write_bytes(SOURCE.read_bytes() + b"\n")
        alternate = s31.build(alternate_source, root / "alternate", "sha-shift")
        alternate_key = alternate / "verification-key.json"
        if (json.loads(alternate_key.read_text())["sha_shift"]["key_digest"] ==
                sealed["sha_shift"]["key_digest"]):
            raise AssertionError("source digest was not bound into the shift key")
        alternate_verifier = alternate / "bin" / f"s31-{name}-native-verifier"
        command(alternate_verifier, proof, statement_path, alternate_key, accepted=False)

        print(json.dumps({
            "schema": "s31-sha-shift-package-acceptance-v1",
            "source_sha256": s31.file_hash(SOURCE),
            "profile": sealed["profile"],
            "proof_bytes": proof.stat().st_size,
            "production_fri": sealed["fri"],
            "native_verifier_accepted": True,
            "negative_cases_rejected": ["wrong public root", "corrupt proof", "altered key",
                                        "different trusted source digest"],
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
