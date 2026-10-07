#!/usr/bin/env python3
"""End-to-end two-level S31 recursion, including a private-witness leaf."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import s31


HERE = S31_SOURCE_ROOT
SOURCE = HERE / "examples/hashes/preimage4.s31"
ASSIGNMENT = HERE / "examples/hashes/preimage4.valid.json"
M31_MODULUS = (1 << 31) - 1
EXPECTED_FIRST_WORDS = [114393851, 3697851308, 811829754, 1234097880,
                        1149239534, 237789166, 2377151022, 2124025211]
EXPECTED_SECOND_WORDS = [3261532993, 4216833817, 3540888548, 444438926,
                         1344647726, 3496049993, 1965291402, 1057682655]


def run(*args: str, accept: bool = True) -> None:
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    if (result.returncode == 0) != accept:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n"
                             f"{result.stdout}{result.stderr}")


def digest(key_bytes: bytes, words: list[int]) -> list[int]:
    message = hashlib.sha256(key_bytes).digest() + struct.pack("<8I", *words)
    return list(struct.unpack("<8I", hashlib.blake2s(message, person=b"S31RCV2!").digest()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, help="reuse a preimage4 gate package")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s31-recursion-chain-") as temporary:
        work = Path(temporary)
        package = args.package.resolve() if args.package else s31.package_for(SOURCE)
        s31.verify_package(package)
        child_key = package / "verification-key.json"
        first_key = package / "recursive-verification-key.json"
        next_key = package / "recursive-verification-key-level2.json"
        prover = package / "bin/s31-preimage4-prover"
        verifier = package / "bin/s31-preimage4-native-verifier"
        reproduced_key = work / "reproduced-level2-key.json"
        run(str(prover), "recurse-keygen-next", str(child_key), str(first_key),
            str(reproduced_key))
        if json.loads(reproduced_key.read_text()) != json.loads(next_key.read_text()):
            raise AssertionError("sealed second-level key is not reproducible")
        child = work / "child.proof"
        first = work / "first.proof"
        second = work / "second.proof"
        run("python3", str(HERE / "python/s31.py"), "prove", str(package), str(ASSIGNMENT), str(child))
        run("python3", str(HERE / "python/s31.py"), "wrap", str(package), str(child), str(first))
        first_statement = json.loads(Path(f"{first}.statement.json").read_text())
        if first_statement["outer_public_words"] != EXPECTED_FIRST_WORDS:
            raise AssertionError("documented first recursive digest changed")
        if not any(word >= M31_MODULUS for word in first_statement["outer_public_words"]):
            raise AssertionError("fixture does not exercise raw u32 recursive outputs")
        run("python3", str(HERE / "python/s31.py"), "audit-recursive-next", str(package), str(first))
        run("python3", str(HERE / "python/s31.py"), "wrap-next", str(package), str(first), str(second))
        chain_path = Path(f"{second}.statement.json")
        chain = json.loads(chain_path.read_text())
        if chain["head"]["outer_public_words"] != EXPECTED_SECOND_WORDS:
            raise AssertionError("documented second recursive digest changed")
        if chain["leaf"] != first_statement:
            raise AssertionError("second wrapper changed the first public statement")
        if chain["head"]["child_public_words"] != chain["leaf"]["outer_public_words"]:
            raise AssertionError("second wrapper did not link the first digest")
        run(str(verifier), "recurse-verify-next", str(second), str(chain_path))
        low_memory = work / "second-low-memory.proof"
        run("python3", str(HERE / "python/s31.py"), "wrap-next", str(package), str(first),
            str(low_memory), "--low-memory")
        if low_memory.read_bytes() != second.read_bytes():
            raise AssertionError("second-level low-memory policy changed proof bytes")

        # Repair both public digests after altering the original leaf claim.
        # The top-level STARK must reject the otherwise self-consistent chain.
        changed = copy.deepcopy(chain)
        changed["leaf"]["child_public_words"][0] += 1
        changed["leaf"]["outer_public_words"] = digest(
            child_key.read_bytes(), changed["leaf"]["child_public_words"])
        changed["head"]["child_public_words"] = changed["leaf"]["outer_public_words"]
        changed["head"]["outer_public_words"] = digest(
            first_key.read_bytes(), changed["head"]["child_public_words"])
        changed_path = work / "changed-claim.json"
        s31.write_json(changed_path, changed)
        run(str(verifier), "recurse-verify-next", str(second), str(changed_path), accept=False)

        changed = copy.deepcopy(chain)
        changed["head"]["child_public_words"][0] ^= 1
        changed["head"]["outer_public_words"] = digest(
            first_key.read_bytes(), changed["head"]["child_public_words"])
        changed_path = work / "unlinked-chain.json"
        s31.write_json(changed_path, changed)
        run(str(verifier), "recurse-verify-next", str(second), str(changed_path), accept=False)

        corrupted_first = bytearray(first.read_bytes())
        corrupted_first[-1] ^= 1
        corrupted_first_path = work / "corrupted-first.proof"
        corrupted_first_path.write_bytes(corrupted_first)
        run(str(prover), "recurse-wrap-next", str(corrupted_first_path), f"{first}.statement.json",
            str(work / "bad-second.proof"), str(child_key), str(first_key), str(next_key), accept=False)
        corrupted_second = bytearray(second.read_bytes())
        corrupted_second[-1] ^= 1
        corrupted_second_path = work / "corrupted-second.proof"
        corrupted_second_path.write_bytes(corrupted_second)
        run(str(verifier), "recurse-verify-next", str(corrupted_second_path),
            str(chain_path), accept=False)
        bad_first_key = json.loads(first_key.read_text())
        bad_first_key["outer_preprocessed_root"] = "0" * 64
        bad_first_key_path = work / "bad-first-key.json"
        s31.write_json(bad_first_key_path, bad_first_key)
        run(str(prover), "recurse-keygen-next", str(child_key), str(bad_first_key_path),
            str(work / "bad-next-key.json"), accept=False)
        run(str(prover), "recurse-wrap-next", str(first), f"{first}.statement.json",
            str(work / "bad-first-key-wrap.proof"), str(child_key),
            str(bad_first_key_path), str(next_key), accept=False)
        bad_next_key = json.loads(next_key.read_text())
        bad_next_key["outer_preprocessed_root"] = "0" * 64
        bad_next_key_path = work / "bad-next-key.json"
        s31.write_json(bad_next_key_path, bad_next_key)
        run(str(prover), "recurse-wrap-next", str(first), f"{first}.statement.json",
            str(work / "bad-next-key-wrap.proof"), str(child_key),
            str(first_key), str(bad_next_key_path), accept=False)

        # The verifier needs only the top proof, the chain statement and
        # its embedded keys; both lower proof files can be removed.
        child.unlink()
        first.unlink()
        run("python3", str(HERE / "python/s31.py"), "verify-recursive-next",
            str(package), str(second))
        print(json.dumps({"schema": "s31-recursion-chain-acceptance-v1",
                          "level": 2,
                          "private_leaf": True,
                          "first_has_full_u32_word": True,
                          "same_padded_layout": json.loads(first_key.read_text())["outer_padded"] ==
                              json.loads(next_key.read_text())["outer_padded"],
                          "first_public_words": chain["leaf"]["outer_public_words"],
                          "second_public_words": chain["head"]["outer_public_words"],
                          "top_proof_bytes": second.stat().st_size,
                          "same_proof_under_low_memory": True,
                          "in_circuit_rejections": 7,
                          "accepted": 3,
                          "rejected": 7}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
