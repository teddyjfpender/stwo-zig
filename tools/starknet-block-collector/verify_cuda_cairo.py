"""Verify saved CUDA Cairo leaf proofs against pinned Rust proof binaries.

Run this after copying a GPU pipeline's Cairo JSON proofs to the local machine.
It keeps Rust verification outside the measured CUDA proving wall time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = (ROOT / "vectors/reports/recursive-product-20260918/"
             "cuda-resident-pipeline-h100-20261001/pinned-cairo-reference.json")
ACCEPTED = re.compile(r"RUST_CAIRO_VERIFIER=accepted binary_bytes=(\d+) binary_sha256=([0-9a-f]{64})")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(proof_dir: Path, receipt_path: Path, reference_path: Path, verifier: Path) -> dict:
    receipt = json.loads(receipt_path.read_text())
    reference = json.loads(reference_path.read_text())
    if receipt.get("schema") != "stwo-starknet-circuit-pipeline-v1":
        raise ValueError("unsupported pipeline receipt")
    if reference.get("schema") != "stwo-circuit-recursion-pinned-cairo-reference-v1":
        raise ValueError("unsupported pinned Cairo reference")
    parity = receipt.get("qualified_reference_parity", {})
    if not parity.get("rust_root_byte_equal_by_digest") or not parity.get("leaf_and_input_byte_equal_by_digest"):
        raise ValueError("pipeline receipt lacks Rust-qualified leaf/root parity")
    leaves = receipt["leaves"]
    if len(leaves) != len(reference["leaves"]):
        raise ValueError("Cairo reference leaf count differs")
    results = []
    for actual, expected in zip(leaves, reference["leaves"]):
        name = Path(actual["pie"]).stem
        if (name != expected["name"] or
                actual["adapt"].get("reused_adapted_input_sha256") != expected["adapted_input_sha256"]):
            raise ValueError(f"Cairo input differs from pinned Rust: {name}")
        proof = proof_dir / f"{name}.cairo_proof.json"
        checked = subprocess.run(
            [str(verifier), str(proof), expected["cairo_binary_sha256"]],
            capture_output=True, text=True, check=False,
        )
        if checked.returncode:
            raise ValueError(f"pinned Rust rejected {proof}: {(checked.stderr or checked.stdout)[-1000:]}")
        match = ACCEPTED.search(checked.stdout)
        if not match or int(match.group(1)) != expected["cairo_binary_bytes"] or \
                match.group(2) != expected["cairo_binary_sha256"]:
            raise ValueError(f"pinned Rust returned unexpected Cairo proof identity: {proof}")
        results.append({"name": name, "proof_json_sha256": sha256(proof),
                        "canonical_binary_bytes": int(match.group(1)),
                        "canonical_binary_sha256": match.group(2), "rust_accepted": True})
    return {"schema": "stwo-circuit-cuda-cairo-rust-verification-v1",
            "pipeline_receipt_sha256": sha256(receipt_path),
            "reference_sha256": sha256(reference_path),
            "verifier_binary_sha256": sha256(verifier), "leaves": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-dir", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--reference", default=REFERENCE, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.proof_dir.resolve(), args.receipt.resolve(),
                    args.reference.resolve(), args.verifier.resolve())
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
