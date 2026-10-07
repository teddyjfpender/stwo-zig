#!/usr/bin/env python3
"""Verify a state-fold top proof and independently replay its public recurrence."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path

import s31

P = (1 << 31) - 1


def words(value: object, size: int, maximum: int, label: str) -> list[int]:
    if (not isinstance(value, list) or len(value) != size or
            any(type(word) is not int or not 0 <= word <= maximum for word in value)):
        raise ValueError(f"{label} must contain {size} canonical unsigned words")
    return value


def recurrence(values: list[int], body: list[dict]) -> list[int]:
    result = values.copy()
    for operation in body:
        name = operation["op"]
        constant = operation.get("constant")
        if name == "square" and constant is None:
            result = [value * value % P for value in result]
        elif name == "mix4" and constant is None and len(result) == 4:
            total = sum(result) % P
            result = [(value + total) % P for value in result]
        elif name in {"add_const", "mul_const"} and type(constant) is int and 0 <= constant < P:
            result = [((value + constant) if name == "add_const" else (value * constant)) % P
                      for value in result]
        else:
            raise ValueError(f"unsupported or malformed state-fold operation: {operation!r}")
    return result


def fold_digest(root: str, step: int, base: list[int], initial: list[int], current: list[int]) -> list[int]:
    root_bytes = bytes.fromhex(root)
    if len(root_bytes) != 32 or type(step) is not int or not 0 <= step <= 0xffffffff:
        raise ValueError("invalid state-fold root or u32 counter")
    preimage = root_bytes + struct.pack("<I8I4I4I", step, *base, *initial, *current)
    return list(struct.unpack("<8I", hashlib.blake2s(preimage, person=b"S31STF2!").digest()))


def inspect(package: Path, proof: Path, statement_path: Path, max_replay_steps: int) -> dict:
    if type(max_replay_steps) is not int or max_replay_steps < 1:
        raise ValueError("max_replay_steps must be positive")
    manifest = s31.verify_package(package)
    if manifest["lowering"] != "gate" or "state-fold-verification-key.json" not in manifest["artifacts"]:
        raise ValueError("state-fold inspection requires a recurrence gate package")
    key_bytes = (package / "state-fold-verification-key.json").read_bytes()
    key = json.loads(key_bytes)
    if key.get("schema") != "s31-state-fold-verification-key-v3" or key.get("counter_bits") != 32:
        raise ValueError("unsupported state-fold verification key")
    first_key = (package / "recursive-verification-key.json").read_bytes()
    leaf_key = (package / "verification-key.json").read_bytes()
    if key["base_recursive_key_sha256"] != hashlib.sha256(first_key).hexdigest():
        raise ValueError("state-fold key does not bind the first wrapper")
    statement = json.loads(statement_path.read_text())
    if statement.get("schema") != "s31-state-fold-statement-v2":
        raise ValueError("unsupported state-fold statement")
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    checked = subprocess.run((str(verifier), "state-fold-verify", str(proof), str(statement_path)),
                             cwd=s31.ROOT, text=True, capture_output=True)
    if checked.returncode:
        raise ValueError(f"native top proof verification failed:\n{checked.stdout}{checked.stderr}")

    source = json.loads((package / "source.s31.json").read_text())
    repeats = [node for node in source["nodes"] if node.get("op") == "repeat"]
    if len(repeats) != 1:
        raise ValueError("state-fold source does not contain one repeat node")
    repeated = repeats[0]
    body = key["step_body"]
    if (type(key["source_rounds"]) is not int or key["source_rounds"] < 1 or
            repeated["rounds"] != key["source_rounds"] or
            [(item["op"], item.get("constant")) for item in repeated["body"]] !=
            [(item["op"], item.get("constant")) for item in body]):
        raise ValueError("sealed state transition differs from the normalized source")
    leaf = words(statement["leaf_public_words"], 8, P - 1, "leaf public words")
    base = words(statement["base_public_words"], 8, 0xffffffff, "base public words")
    initial = words(statement["initial_state"], 4, P - 1, "initial state")
    current = words(statement["current_state"], 4, P - 1, "current state")
    step = statement["step"]
    if type(step) is not int or not 0 <= step <= 0xffffffff:
        raise ValueError("state-fold step is outside the constrained u32 range")
    base_preimage = hashlib.sha256(leaf_key).digest() + struct.pack("<8I", *leaf)
    expected_base = list(struct.unpack("<8I", hashlib.blake2s(base_preimage, person=b"S31RCV2!").digest()))
    expected_initial = leaf[:4]
    for _ in range(key["source_rounds"]):
        expected_initial = recurrence(expected_initial, body)
    root = key["fold_preprocessed_root"]
    if (initial != leaf[4:] or expected_initial != initial or base != expected_base or
            statement["state_fold_key_sha256"] != hashlib.sha256(key_bytes).hexdigest() or
            statement["fold_preprocessed_root"] != root or
            statement["fold_circuit_hash"] != key["fold_circuit_hash"] or
            statement["fold_public_words"] != fold_digest(root, step, base, initial, current)):
        raise ValueError("public state-fold claim does not match the sealed source and keys")

    replay_status = "skipped_step_limit"
    expected_current: list[int] | None = None
    previous: list[int] | None = None
    if step <= max_replay_steps:
        expected_current = initial.copy()
        for _ in range(step):
            previous = expected_current
            expected_current = recurrence(expected_current, body)
        if expected_current != current:
            raise ValueError("public current state disagrees with independent recurrence replay")
        replay_status = "matched"
    return {
        "schema": "s31-verified-state-fold-claim-v1",
        "program": manifest["name"],
        "program_sha256": manifest["program_sha256"],
        "key_sha256": {
            "leaf_k0": hashlib.sha256(leaf_key).hexdigest(),
            "first_wrapper_k1": hashlib.sha256(first_key).hexdigest(),
            "state_fold_kf": hashlib.sha256(key_bytes).hexdigest(),
        },
        "source_rounds": key["source_rounds"],
        "step_body": body,
        "step": step,
        "initial_state": initial,
        "current_state": current,
        "expected_current_state": expected_current,
        "previous_state": previous,
        "independent_state_replay": replay_status,
        "replay_limit": max_replay_steps,
        "leaf_public_words": leaf,
        "leaf_public_abi": json.loads((package / "public-abi.json").read_text()),
        "base_public_words": base,
        "top_public_words": statement["fold_public_words"],
        "fold_preprocessed_root": root,
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
    parser.add_argument("--max-replay-steps", type=int, default=100000,
                        help="bound local recurrence replay; native proof verification still runs")
    parser.add_argument("--out", type=Path, help="write the verified JSON report")
    args = parser.parse_args()
    package = args.package.resolve()
    proof = args.top_proof.resolve()
    statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
    report = inspect(package, proof, statement, args.max_replay_steps)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        output = args.out.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
