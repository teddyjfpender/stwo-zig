#!/usr/bin/env python3
"""Verify a copied fold bundle on macOS with the original artifact store denied.

The expected key digest must come from trusted setup. This command measures one
verification request and exercises rejection; it does not admit the circuit key.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-key-sha256", required=True)
    parser.add_argument("--deny-store", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    bundle = args.bundle.resolve(strict=True)
    denied = args.deny_store.resolve(strict=True)
    expected = bytes.fromhex(args.expected_key_sha256)
    if len(expected) != 32:
        raise ValueError("expected key digest must be 32 bytes")
    if not bundle.is_relative_to(denied):
        raise ValueError("the denied store must contain the original bundle")
    if hashlib.sha256((bundle / "key.json").read_bytes()).digest() != expected:
        raise ValueError("bundle does not match the separately supplied key digest")
    # Native macOS sandbox paths use quoted Scheme strings, not shell text.
    profile = f"(version 1)(allow default)(deny file-read* (subpath {json.dumps(str(denied))}))"
    prefix = ["/usr/bin/sandbox-exec", "-p", profile]
    with tempfile.TemporaryDirectory(prefix="stwo-fold-verify-") as temporary:
        cwd = Path(temporary)
        for name in ("key.json", "inputs.json", "proof.bin"):
            shutil.copyfile(bundle / name, cwd / name)

        def run(command: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(prefix + command, cwd=cwd, capture_output=True,
                                  text=True, timeout=120, check=False)

        probe = run(["/bin/cat", str(bundle / "key.json")])
        if probe.returncode == 0 or "Operation not permitted" not in probe.stderr:
            raise RuntimeError(f"sandbox denial was not confirmed: {probe.stderr}")
        command = [str(binary), "key.json", expected.hex(), "inputs.json", "proof.bin"]
        started = time.perf_counter()
        result = run(["/usr/bin/time", "-l", *command, "shape.json"])
        elapsed = time.perf_counter() - started
        if result.returncode != 0:
            raise RuntimeError(f"fresh verifier failed: {result.stderr}")
        receipt = json.loads(result.stdout)
        if receipt.get("verified") is not True or not (cwd / "shape.json").is_file():
            raise RuntimeError("fresh verifier did not produce a verified capture")
        shape = json.loads((cwd / "shape.json").read_text())
        maximum_rss = next(int(line.split()[0]) for line in result.stderr.splitlines()
                           if "maximum resident set size" in line)
        wrong_key = command.copy()
        wrong_key[2] = bytes([expected[0] ^ 1]).hex() + expected[1:].hex()
        rejected_key = run(wrong_key)
        if rejected_key.returncode == 0 or "VerifierKeyHashMismatch" not in rejected_key.stderr:
            raise RuntimeError("wrong expected key digest was not rejected")
        proof = bytearray((cwd / "proof.bin").read_bytes())
        proof[len(proof) // 2] ^= 1
        (cwd / "proof.bin").write_bytes(proof)
        inputs = json.loads((cwd / "inputs.json").read_text())
        inputs["proof_sha256"] = list(hashlib.sha256(proof).digest())
        (cwd / "inputs.json").write_text(json.dumps(inputs))
        (cwd / "shape.json").unlink()
        rejected_proof = run([*command, "shape.json"])
        if (rejected_proof.returncode == 0 or (cwd / "shape.json").exists()
                or "error:" not in rejected_proof.stderr
                or "VerifierProofIdentityMismatch" in rejected_proof.stderr):
            raise RuntimeError(f"changed proof did not fail core verification: {rejected_proof.stderr}")
        report = {
            "format_version": 1,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "key_sha256": expected.hex(),
            "independent_key_admission": False,
            "fresh_process_verified": True,
            "original_store_read_denied": True,
            "process_wall_seconds": elapsed,
            "maximum_resident_set_size_bytes": maximum_rss,
            "receipt": receipt,
            "shape": shape,
            "wrong_key_rejected": True,
            "altered_proof_with_updated_transport_hash_rejected": True,
            "no_shape_on_verification_failure": True,
            "time_stderr": result.stderr,
            "rejected_proof_stderr": rejected_proof.stderr,
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Verified with original store denied; evidence: {args.out}")


if __name__ == "__main__":
    main()
