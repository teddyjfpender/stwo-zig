#!/usr/bin/env python3
"""Audit checked and wrapping UInt256 subtraction proof packages.

Run the two `s31 trial` commands in docs/wide-values.md first. The script
checks both saved proofs and the negative cases, then writes a pinned record.
"""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))
from example_paths import example_path

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import s31


ROOT = S31_SOURCE_ROOT.parents[2]
S31 = S31_SOURCE_ROOT
TRIALS = ROOT / "zig-out/s31"
RECORD = ROOT / "design/s31/measurements/language/u256-subtraction-v1-2026-10-07.json"


def run(*args: object, accept: bool) -> None:
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                            capture_output=True, text=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(
            f"unexpected exit {result.returncode} for {args!r}:\n{result.stdout}{result.stderr}"
        )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    trials = {mode: TRIALS / f"u256-sub-{mode}-trial" for mode in ("checked", "wrap")}
    for mode, path in trials.items():
        if not (path / "trial-report.json").is_file():
            raise SystemExit(f"missing {mode} trial; run the commands in docs/wide-values.md")
    reports = {mode: json.loads((path / "trial-report.json").read_text())
               for mode, path in trials.items()}
    for mode, report in reports.items():
        assert report["schema"] == "s31-trial-v1"
        assert report["native_verifier_accepted"] is True
        assert report["independent_value_oracle"]["status"] == "passed"
        assert report["changed_public_statement_rejected"] == "public_outputs.root[0]"
        assert report["lowering"] == "sparse-wide-gate"
        package = trials[mode] / "package"
        s31.verify_package(package)
        proof = trials[mode] / "proof.bin"
        statement = trials[mode] / "statement.json"
        verifier = package / "bin" / f"s31-u256_sub_{mode}-native-verifier"
        run(verifier, proof, statement, package / "verification-key.json", accept=True)
        assert report["proof_bytes"] == proof.stat().st_size
        assert report["proof_sha256"] == sha(proof)

    checked = trials["checked"]
    wrap = trials["wrap"]
    checked_pkg = checked / "package"
    wrap_pkg = wrap / "package"
    checked_verifier = checked_pkg / "bin/s31-u256_sub_checked-native-verifier"
    wrap_verifier = wrap_pkg / "bin/s31-u256_sub_wrap-native-verifier"
    run(checked_verifier, wrap / "proof.bin", wrap / "statement.json",
        checked_pkg / "verification-key.json", accept=False)
    run(wrap_verifier, checked / "proof.bin", checked / "statement.json",
        wrap_pkg / "verification-key.json", accept=False)
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        underflow_proof = temporary / "underflow.proof"
        run(checked_pkg / "bin/s31-u256_sub_checked-prover", "prove",
            S31 / "examples/wide/u256_sub_wrap.valid.json", underflow_proof, accept=False)
        same_claim_wrap_proof = temporary / "wrap-same-claim.proof"
        run(wrap_pkg / "bin/s31-u256_sub_wrap-prover", "prove",
            S31 / "examples/wide/u256_sub_checked.valid.json", same_claim_wrap_proof, accept=True)
        run(wrap_verifier, same_claim_wrap_proof, checked / "statement.json",
            wrap_pkg / "verification-key.json", accept=True)
        run(checked_verifier, same_claim_wrap_proof, checked / "statement.json",
            checked_pkg / "verification-key.json", accept=False)
        run(wrap_verifier, checked / "proof.bin", checked / "statement.json",
            wrap_pkg / "verification-key.json", accept=False)
        for mode, trial in trials.items():
            package = trial / "package"
            verifier = package / "bin" / f"s31-u256_sub_{mode}-native-verifier"
            damaged = temporary / f"{mode}.damaged.proof"
            proof = bytearray((trial / "proof.bin").read_bytes())
            proof[len(proof) // 2] ^= 1
            damaged.write_bytes(proof)
            run(verifier, damaged, trial / "statement.json",
                package / "verification-key.json", accept=False)

    sources = ("relation.zig", "canonical.zig", "relation_compiler.zig",
               "python/s31_mathlib.py", "python/s31_stdlib.py", "python/text_frontend.py", "python/oracle.py",
               "python/s31.py", "tests/acceptance/acceptance_u256_sub.py")
    record = {
        "schema": "s31-u256-subtraction-v1",
        "scope": "Two one-run local proof samples; timings do not establish a general speedup.",
        "profiles": {mode: {
            "canonical_ir_sha256": report["canonical_ir_sha256"],
            "proof_bytes": report["proof_bytes"],
            "proof_sha256": report["proof_sha256"],
            "raw": report["raw"],
            "padded": report["padded"],
            "preprocessed_cells": report["preprocessed_cells"],
            "prove_seconds": report["prove_seconds"],
            "prove_excluding_pow_seconds": report["prover_stages"]["prove_excluding_pow_seconds"],
            "verify_seconds": report["verify_seconds"],
            "key_sha256": sha(trials[mode] / "package/verification-key.json"),
        } for mode, report in reports.items()},
        "checked_underflow_rejected": True,
        "cross_key_replay_rejected": True,
        "same_claim_cross_key_replay_rejected": True,
        "damaged_proofs_rejected": True,
        "changed_public_statements_rejected": True,
        "source_sha256": {name: sha(S31 / name) for name in sources},
        "fixture_sha256": {f"{mode}.{extension}": sha(example_path(f"u256_sub_{mode}.{extension}"))
                           for mode in trials for extension in ("s31", "valid.json")},
    }
    RECORD.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"UInt256 subtraction: valid proofs accepted; checked underflow and cross-key replay rejected; record={RECORD.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
