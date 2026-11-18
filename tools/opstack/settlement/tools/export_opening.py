#!/usr/bin/env python3
"""Validate and export a compact lifted opening from native receiver diagnostics."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


def hash_node(left, right):
    return hashlib.blake2s(b"node".ljust(64, b"\0") + left + right).digest()


def hash_leaf(row):
    return hashlib.blake2s(b"leaf".ljust(64, b"\0") + row).digest()


def word(value):
    return "0x" + value.hex()


def capture(log):
    current = None
    for line in log.open():
        fields = line.split()
        if not fields:
            continue
        match fields:
            case ["SETTLEMENT_ROOT", root, depth, columns]:
                if current is not None:
                    raise ValueError("nested capture")
                current = (bytes.fromhex(root), int(depth), int(columns), [], [], [])
            case ["SETTLEMENT_ROW", position, leaf, *values]:
                _, _, columns, indices, rows, _ = current
                limbs = list(map(int, values))
                if len(limbs) != columns or any(not 0 <= n < 2**31 - 1 for n in limbs):
                    raise ValueError("invalid M31 row")
                row = struct.pack("<" + "I" * columns, *limbs)
                if hash_leaf(row) != bytes.fromhex(leaf):
                    raise ValueError("leaf digest mismatch")
                indices.append(int(position))
                rows.append(row)
            case ["SETTLEMENT_HASH", sibling]:
                current[-1].append(bytes.fromhex(sibling))
            case ["SETTLEMENT_END"]:
                yield current
                current = None
    if current is not None:
        raise ValueError("incomplete capture")


def rebuild(depth, leaves, witness):
    """Build all observed nodes and reject missing or surplus sibling hashes."""
    layers = [dict(leaves)]
    used = 0
    for _ in range(depth):
        layer = layers[-1]
        parents = {}
        for index in sorted(layer):
            if index >> 1 in parents:
                continue
            sibling_index = index ^ 1
            sibling = layer.get(sibling_index)
            if sibling is None:
                sibling = witness[used]
                used += 1
                layer[sibling_index] = sibling
            pair = (layer[index], sibling) if index % 2 == 0 else (sibling, layer[index])
            parents[index >> 1] = hash_node(*pair)
        layers.append(parents)
    if used != len(witness) or layers[-1].keys() != {0}:
        raise ValueError("malformed compressed opening")
    return layers


def compress_positions(layers, positions):
    witness = []
    for layer in layers[:-1]:
        current = set(positions)
        for index in positions:
            if index ^ 1 not in current:
                witness.append(layer[index ^ 1])
        positions = sorted({index >> 1 for index in positions})
    return witness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostics", type=Path)
    parser.add_argument("proof", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--block", type=int, required=True)
    parser.add_argument("--queries", type=int, help="optional evenly spaced subset")
    args = parser.parse_args()
    if args.queries is not None and not 1 <= args.queries <= 256:
        parser.error("--queries must be in 1..256")

    binary = args.proof.read_bytes()
    for root, depth, columns, positions, rows, witness in capture(args.diagnostics):
        offset = binary.find(root)
        witness_offset = binary.find(b"".join(witness))
        if offset < 0 or not witness or witness_offset < 0:
            continue
        count = args.queries if args.queries is not None else len(positions)
        if count > len(positions):
            continue
        if sorted(set(positions)) != positions or positions[-1] >= 1 << depth:
            raise ValueError("invalid query positions")
        layers = rebuild(depth, zip(positions, map(hash_leaf, rows)), witness)
        if layers[-1][0] != root:
            raise ValueError("root digest mismatch")
        # Use an evenly spaced subset to retain coverage across the full tree.
        selected = [i * len(positions) // count for i in range(count)]
        positions = [positions[i] for i in selected]
        args.output.write_text(
            json.dumps(
                {
                    "chainId": 10,
                    "blockNumber": args.block,
                    "worker": args.proof.name,
                    "workerSha256": hashlib.sha256(binary).hexdigest(),
                    "rootByteOffset": offset,
                    "originalWitnessByteOffset": witness_offset,
                    "root": word(root),
                    "depth": depth,
                    "rowBytes": 4 * columns,
                    "positions": positions,
                    "rows": word(b"".join(rows[i] for i in selected)),
                    "witness": [word(item) for item in compress_positions(layers, positions)],
                },
                indent=2,
            )
            + "\n"
        )
        return
    raise SystemExit("no captured opening matches this worker and query count")


if __name__ == "__main__":
    main()
