#!/usr/bin/env python3
"""Verify a fixed-fold top proof and expose the exact sealed claim chain."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path

import s31


def recursive_digest(key_bytes: bytes, words: list[int]) -> list[int]:
    if len(words) != 8 or any(type(word) is not int or word < 0 or word > 0xffffffff for word in words):
        raise ValueError("a recursive digest requires eight u32 words")
    preimage = hashlib.sha256(key_bytes).digest() + struct.pack("<8I", *words)
    return list(struct.unpack("<8I", hashlib.blake2s(preimage, person=b"S31RCV2!").digest()))


def fold_digest(root: str, step: int, words: list[int]) -> list[int]:
    if type(step) is not int or not 0 <= step <= 0xffffffff:
        raise ValueError("fixed-fold step is outside the constrained u32 range")
    preimage = bytes.fromhex(root) + struct.pack("<I8I", step, *words)
    return list(struct.unpack("<8I", hashlib.blake2s(preimage, person=b"S31FOL2!").digest()))


def inspect(package: Path, proof: Path, statement_path: Path) -> dict:
    manifest = s31.verify_package(package)
    profile = manifest["lowering"]
    if profile not in {"gate", "sparse-wide-gate"}:
        raise ValueError("fixed-fold inspection requires a gate or sparse-wide package")
    statement = json.loads(statement_path.read_text())
    expected_schema = "s31-fixed-fold-statement-v4" if profile == "sparse-wide-gate" else "s31-fixed-fold-statement-v3"
    if statement.get("schema") != expected_schema:
        raise ValueError("fixed-fold statement has the wrong schema for this package")
    leaf_key = (package / "verification-key.json").read_bytes()
    first_key = (package / "recursive-verification-key.json").read_bytes()
    fold_key = (package / "fixed-fold-verification-key.json").read_bytes()
    fold = json.loads(fold_key)
    wide = profile == "sparse-wide-gate"
    second_key = (package / "recursive-verification-key-level2.json").read_bytes() if wide else None
    base_key = second_key if second_key is not None else first_key
    if fold["base_recursive_key_sha256"] != hashlib.sha256(base_key).hexdigest():
        raise ValueError("fold key does not bind the expected base verifier key")
    words = statement["leaf_public_words"]
    first_words = recursive_digest(leaf_key, words)
    base_words = recursive_digest(first_key, first_words) if wide else first_words
    step = statement["step"]
    root = fold["fold_preprocessed_root"]
    output = fold_digest(root, step, base_words)
    if (statement["base_public_words"] != base_words or
            statement["fold_public_words"] != output or
            statement["fold_preprocessed_root"] != root or
            statement["fold_circuit_hash"] != fold["fold_circuit_hash"] or
            statement["fold_key_sha256"] != hashlib.sha256(fold_key).hexdigest()):
        raise ValueError("statement does not match independently computed key and public digests")
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    checked = subprocess.run((str(verifier), "fold-verify", str(proof), str(statement_path)),
                             cwd=s31.ROOT, text=True, capture_output=True)
    if checked.returncode:
        raise ValueError(f"native top proof verification failed:\n{checked.stdout}{checked.stderr}")
    keys = {
        "leaf_k0_sha256": hashlib.sha256(leaf_key).hexdigest(),
        "first_wrapper_k1_sha256": hashlib.sha256(first_key).hexdigest(),
        "fold_kf_sha256": hashlib.sha256(fold_key).hexdigest(),
    }
    if second_key is not None:
        keys["second_wrapper_k2_sha256"] = hashlib.sha256(second_key).hexdigest()
    return {
        "schema": "s31-verified-fixed-fold-claim-v1",
        "program": manifest["name"],
        "program_sha256": manifest["program_sha256"],
        "profile": profile,
        "step": step,
        "base_proof_kind": "second_wrapper" if wide else "first_wrapper",
        "key_sha256": keys,
        "leaf_fri_fold_step": manifest["fri_fold_step"],
        "wrapper_fri_fold_step": manifest["recursive_fri_fold_step"],
        "fold_preprocessed_root": root,
        "leaf_public_words_w0": words,
        "leaf_public_abi": json.loads((package / "public-abi.json").read_text()),
        "first_wrapper_public_words_d1": first_words,
        "base_public_words": base_words,
        "previous_fold_public_words": fold_digest(root, step - 1, base_words) if step else None,
        "top_public_words": output,
        "top_proof_bytes": proof.stat().st_size,
        "top_proof_sha256": s31.file_hash(proof),
        "statement_sha256": s31.file_hash(statement_path),
        "native_top_verification": "accepted",
        "lower_proof_files_required": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("top_proof", type=Path)
    parser.add_argument("--statement", type=Path, help="defaults to TOP_PROOF.statement.json")
    parser.add_argument("--out", type=Path, help="write the verified JSON report")
    args = parser.parse_args()
    package = args.package.resolve()
    proof = args.top_proof.resolve()
    statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
    report = inspect(package, proof, statement)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        output = args.out.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
