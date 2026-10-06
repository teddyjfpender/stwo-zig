#!/usr/bin/env python3
"""Expand a fixed-depth Merkle inclusion function into normalized S31 JSON."""

import argparse
import hashlib
import struct
from pathlib import Path

import s31
import poseidon2_oracle


P = (1 << 31) - 1


def digest(words: list[int], domain: bytes) -> list[int]:
    message = b"".join(struct.pack("<I", value) for value in words)
    raw = hashlib.blake2s(message, person=domain).digest()
    return [value % P for value in struct.unpack("<8I", raw)]


def generate(depth: int, seed: int, hash_kind: str = "blake2s") -> tuple[dict, dict]:
    if not 1 <= depth <= 16 or seed < 0:
        raise ValueError("depth must be 1..16 and seed must be nonnegative")
    if hash_kind not in ("blake2s", "poseidon2"):
        raise ValueError("hash_kind must be blake2s or poseidon2")
    leaf_op = "hash_poseidon2_leaf" if hash_kind == "poseidon2" else "hash_blake2s_leaf"
    pair_op = "hash_poseidon2_pair" if hash_kind == "poseidon2" else "hash_blake2s_pair"
    leaf_hash = poseidon2_oracle.leaf if hash_kind == "poseidon2" else lambda words: digest(words, b"S31LEAF1")
    pair_hash = poseidon2_oracle.pair if hash_kind == "poseidon2" else lambda left, right: digest(left + right, b"S31PAIR1")
    leaf = [((seed * 17 + i + 1) % P) for i in range(8)]
    inputs = [{"name": "leaf", "kind": "m31", "length": 8, "visibility": "private"}]
    private = {"leaf": leaf}
    nodes = [{"name": "digest", "op": leaf_op, "lhs": "leaf"}]
    current_name = "digest"
    current_value = leaf_hash(leaf)
    for level in range(depth):
        sibling_name = f"sibling_{level}"
        direction_name = f"direction_{level}"
        sibling = [((seed * 29 + level * 101 + i * 13 + 100) % P) for i in range(8)]
        direction = (seed + level) % 2
        inputs.extend([
            {"name": sibling_name, "kind": "m31", "length": 8, "visibility": "private"},
            {"name": direction_name, "kind": "m31", "length": 1, "visibility": "private"},
        ])
        private[sibling_name] = sibling
        private[direction_name] = [direction]
        left_name = f"left_{level}"
        right_name = f"right_{level}"
        next_name = f"parent_{level}"
        nodes.extend([
            {"name": left_name, "op": "select", "lhs": current_name, "rhs": sibling_name, "selector": direction_name},
            {"name": right_name, "op": "select", "lhs": sibling_name, "rhs": current_name, "selector": direction_name},
            {"name": next_name, "op": pair_op, "lhs": left_name, "rhs": right_name},
        ])
        current_value = pair_hash(current_value, sibling) if direction == 0 else pair_hash(sibling, current_value)
        current_name = next_name
    source = {
        "version": 1,
        "name": f"merkle_path{depth}" + ("_poseidon" if hash_kind == "poseidon2" else ""),
        "inputs": inputs,
        "nodes": nodes,
        "assertions": [],
        "public_outputs": [current_name],
    }
    assignment = {"public_inputs": {}, "private_inputs": private, "public_outputs": {current_name: current_value}}
    return source, assignment


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--depth", type=int, required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--hash", choices=("blake2s", "poseidon2"), default="blake2s")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source, assignment = generate(args.depth, args.seed, args.hash)
    args.out.mkdir(parents=True, exist_ok=True)
    s31.write_json(args.out / f"{source['name']}.s31.json", source)
    s31.write_json(args.out / f"{source['name']}.valid.json", assignment)
    print(args.out)


if __name__ == "__main__":
    main()
