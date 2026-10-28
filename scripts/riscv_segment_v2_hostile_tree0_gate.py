#!/usr/bin/env python3
"""Replay a re-proved hostile native Tree-0 outer candidate at leaf admission.

The test-only q193 producer writes the candidate bundle. This gate never
creates or alters a proof: it runs the ordinary standalone leaf verifier with
an independently supplied key pin, then repeats with proof.bin absent to
locate the rejection boundary before proof I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value: str) -> str:
    if len(value) != 64:
        raise argparse.ArgumentTypeError("expected a 64-digit SHA-256")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a hexadecimal SHA-256") from exc
    return value.lower()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--key-sha256", type=digest, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", type=digest, required=True)
    parser.add_argument("--native-test-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    verifier = args.verifier.resolve(strict=True)
    test_log = args.native_test_log.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be new; retain previous evidence")
    if sha256(verifier) != args.verifier_sha256:
        parser.error("standalone verifier binary pin mismatch")
    paths = {name: bundle / name for name in
             ("key.json", "claims.json", "proof.bin", "expected-wire.json",
              "hostile-native-proof.bin", "hostile-native-statement.json",
              "hostile-native-claim.json")}
    pins = {name: sha256(path) for name, path in paths.items()}
    if pins["key.json"] != args.key_sha256:
        parser.error("hostile candidate key pin mismatch")
    text = test_log.read_text()
    if ("V2_NATIVE_PROOF_SUITE suite=poseidon-q193 queries=193 pow_bits=16" not in text
            or "HOSTILE_TREE0_OUTER_CANDIDATE" not in text
            or f"key_sha256={args.key_sha256}" not in text
            or f"proof_sha256={pins['proof.bin']}" not in text
            or f"native_proof_sha256={pins['hostile-native-proof.bin']}" not in text
            or "self_pinned_outer_verified=true" not in text):
        parser.error("native test log does not bind the hostile candidate")

    output.mkdir(parents=True)
    report = {"passed": False, "script_sha256": sha256(Path(__file__)),
              "verifier_sha256": args.verifier_sha256,
              "native_test_log_sha256": sha256(test_log),
              "bundle_inputs_sha256": pins, "cases": []}
    try:
        for proof_present in (True, False):
            if proof_present:
                directory = bundle
            else:
                temporary = tempfile.TemporaryDirectory(prefix="hostile-tree0-no-proof-")
                directory = Path(temporary.name)
                shutil.copy2(paths["key.json"], directory / "key.json")
                shutil.copy2(paths["claims.json"], directory / "claims.json")
            try:
                argv = [str(verifier), str(directory), args.key_sha256,
                        str(paths["expected-wire.json"])]
                started = time.monotonic_ns()
                result = subprocess.run(argv, capture_output=True, text=True)
                elapsed = time.monotonic_ns() - started
                name = "proof-present" if proof_present else "proof-absent"
                log = output / f"{name}.log"
                log.write_text(result.stdout + result.stderr)
                case = {"name": name, "exit_code": result.returncode,
                        "elapsed_ns": elapsed, "log_sha256": sha256(log),
                        "expected_error": "InvalidNativePreprocessedCommitment"}
                report["cases"].append(case)
                if result.returncode == 0 or case["expected_error"] not in log.read_text():
                    raise RuntimeError(f"{name}: wrong rejection boundary; see {log}")
            finally:
                if not proof_present:
                    temporary.cleanup()
        report["inputs_unchanged"] = all(sha256(paths[name]) == pin
                                         for name, pin in pins.items())
        report["passed"] = report["inputs_unchanged"]
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        raise RuntimeError("hostile Tree-0 replay failed")
    print(f"hostile Tree-0 standalone rejection passed: {output / 'report.json'}")


if __name__ == "__main__":
    main()
