#!/usr/bin/env python3
"""Retain and run genuine Ethereum native-bundle admission regressions.

Each case runs the verifier in a fresh subprocess. The original directory is
read-only; generated manifests, changed proof bytes, process logs and receipts
remain in --output. This is the native full-leaf bundle endpoint, not recursion.
Requires Python 3.11+. Coordinate with other heavy proof jobs before running
(this script never builds).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import time


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: pathlib.Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def prepare(bundle: pathlib.Path, output: pathlib.Path, expected: str) -> list[dict]:
    original_bytes = (bundle / "bundle.json").read_bytes()
    if digest(original_bytes) != expected:
        raise ValueError("original bundle manifest differs from independently pinned SHA256")
    original = json.loads(original_bytes)
    leaves = original["leaves"]
    if len(leaves) < 2:
        raise ValueError("reordering and adjacency regressions require at least two real leaves")
    sources = {}
    for leaf in leaves:
        name = bytes(leaf["proof_sha256"]).hex() + ".bin"
        source = bundle / name
        if source.stat().st_size != leaf["proof_bytes"] or file_digest(source) != name[:-4]:
            raise ValueError(f"original proof identity mismatch: {source}")
        sources[name] = source
    output.mkdir(parents=True, exist_ok=False)
    cases = []
    for name in ("genuine", "missing-leaf", "reordered-leaves", "duplicate-leaf", "changed-continuation", "changed-total-coverage", "changed-proof-bytes"):
        case_dir = output / name
        case_dir.mkdir()
        manifest = copy.deepcopy(original)
        current = manifest["leaves"]
        if name == "missing-leaf":
            current.pop()
        elif name == "reordered-leaves":
            current[0], current[1] = current[1], current[0]
        elif name == "duplicate-leaf":
            current[1] = copy.deepcopy(current[0])
        elif name == "changed-continuation":
            current[1]["metadata"]["entry"]["continuation_root"] ^= 1
        elif name == "changed-total-coverage":
            current[-1]["metadata"]["global_cycle_end"] += 1
        elif name == "changed-proof-bytes":
            # Re-pin the changed bytes in this manifest: rejection must reach
            # native decoding/verification, not just the transport hash guard.
            leaf = current[0]
            old_name = bytes(leaf["proof_sha256"]).hex() + ".bin"
            changed = bytearray(sources[old_name].read_bytes())
            changed[-1] ^= 1
            changed_sha = digest(changed)
            (case_dir / (changed_sha + ".bin")).write_bytes(changed)
            leaf["proof_sha256"] = list(bytes.fromhex(changed_sha))
        for leaf in current:
            proof_name = bytes(leaf["proof_sha256"]).hex() + ".bin"
            destination = case_dir / proof_name
            if not destination.exists():
                # Artifact custody intentionally rejects symlinks. Each case
                # owns a regular-file copy, so mutations cannot reach originals.
                shutil.copyfile(sources[proof_name], destination)
        # Keep original serialization and original pin for genuine admission.
        data = original_bytes if name == "genuine" else json_bytes(manifest)
        (case_dir / "bundle.json").write_bytes(data)
        cases.append({"name": name, "directory": str(case_dir), "manifest_sha256": digest(data), "expect_accept": name == "genuine"})
    return cases


def run_case(verifier: pathlib.Path, case: dict, timeout: float) -> dict:
    directory = pathlib.Path(case["directory"])
    command = [str(verifier), str(directory), case["manifest_sha256"]]
    start = time.monotonic()
    try:
        with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
        code = completed.returncode
        stderr_text = (directory / "stderr.log").read_text(errors="replace")
        result = {**case, "command": command, "elapsed_s": time.monotonic() - start, "returncode": code, "passed": False}
        if case["expect_accept"]:
            if code == 0:
                receipt = json.loads((directory / "stdout.log").read_bytes())
                manifest = json.loads((directory / "bundle.json").read_bytes())
                result["passed"] = (receipt.get("endpoint") == "verified_native_full_leaf_bundle" and
                                    receipt.get("leaf_count") == len(manifest["leaves"]) and
                                    bytes(receipt.get("manifest_sha256", [])).hex() == case["manifest_sha256"] and
                                    receipt.get("total_proof_bytes") == sum(leaf["proof_bytes"] for leaf in manifest["leaves"]))
                result["verifier_receipt"] = receipt
        else:
            # A crash or launch failure is not evidence of semantic rejection.
            result["passed"] = code > 0 and "error: " in stderr_text and "panic:" not in stderr_text
        return result
    except (subprocess.TimeoutExpired, OSError, ValueError) as error:
        return {**case, "command": command, "elapsed_s": time.monotonic() - start, "passed": False, "error": str(error)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verifier", type=pathlib.Path)
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path, help="new retained regression directory (must not exist)")
    parser.add_argument("--timeout", type=float, default=3600, help="seconds per fresh verifier process")
    parser.add_argument("--prepare-only", action="store_true", help="retain cases and commands without running a proof verifier")
    args = parser.parse_args()
    expected = args.expected_manifest_sha256.lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        parser.error("expected manifest hash must be 64 hexadecimal characters")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    verifier = args.verifier.resolve(strict=True)
    bundle = args.bundle.resolve(strict=True)
    output = args.output.resolve()
    cases = prepare(bundle, output, expected)
    plan = {"version": 1, "endpoint": "verified_native_full_leaf_bundle", "source_bundle": str(bundle), "source_manifest_sha256": expected, "verifier": str(verifier), "verifier_sha256": file_digest(verifier), "cases": cases}
    (output / "plan.json").write_bytes(json_bytes(plan))
    if args.prepare_only:
        print(json.dumps({"prepared": len(cases), "plan": str(output / "plan.json"), "verified": False}))
        return 0
    results = []
    for case in cases:
        result = run_case(verifier, case, args.timeout)
        results.append(result)
        (pathlib.Path(case["directory"]) / "receipt.json").write_bytes(json_bytes(result))
        print(json.dumps({"case": case["name"], "passed": result["passed"], "elapsed_s": result["elapsed_s"]}), flush=True)
        # Do not treat failures of the baseline endpoint as regression evidence.
        if case["expect_accept"] and not result["passed"]:
            break
    original = json.loads((bundle / "bundle.json").read_bytes())
    unchanged = (file_digest(bundle / "bundle.json") == expected and
                 file_digest(verifier) == plan["verifier_sha256"] and
                 all(file_digest(bundle / (bytes(leaf["proof_sha256"]).hex() + ".bin")) == bytes(leaf["proof_sha256"]).hex()
                     for leaf in original["leaves"]))
    passed = unchanged and len(results) == len(cases) and all(item["passed"] for item in results)
    (output / "receipt.json").write_bytes(json_bytes({"version": 1, "passed": passed, "source_and_verifier_unchanged": unchanged, "cases": results}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
