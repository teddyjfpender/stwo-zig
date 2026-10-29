"""Recover hash-authenticated pre-state nodes after trie path compression.

Deleting a branch can prepend its path to a surviving leaf/extension. A post
proof then contains the combined node, while an offline mutating trie needs the
old shorter node. Enumerate suffixes and retain only exact hashes already
referenced by a supplied node. This computes witnesses; it changes no roots.
"""
from __future__ import annotations

import rlp
from eth_hash.auto import keccak


def compact_path(raw: bytes) -> tuple[bool, list[int]]:
    if not isinstance(raw, bytes) or not raw:
        raise ValueError('invalid compact trie path')
    values = [n for b in raw for n in (b >> 4, b & 15)]
    flag = values[0]
    if flag > 3 or (flag % 2 == 0 and values[1]):
        raise ValueError('invalid compact trie flag/padding')
    return flag >= 2, values[1:] if flag % 2 else values[2:]


def encode_path(leaf: bool, path: list[int]) -> bytes:
    prefix = [2 * int(leaf) + len(path) % 2] + ([] if len(path) % 2 else [0])
    values = prefix + path
    return bytes(16 * a + b for a, b in zip(values[::2], values[1::2]))


def recover_compressed_siblings(encoded: set[str]) -> tuple[list[str], dict]:
    nodes = {keccak(bytes.fromhex(raw[2:])): raw for raw in encoded}
    wanted, compact = set(), []

    def visit(node):
        if not isinstance(node, list):
            raise ValueError('expected trie node list')
        if len(node) == 17:
            children = node[:16]
        elif len(node) == 2:
            leaf, path = compact_path(node[0])
            compact.append((leaf, path, node[1]))
            children = [] if leaf else [node[1]]
        else:
            raise ValueError('invalid trie node arity')
        for child in children:
            if isinstance(child, list):
                visit(child)
            elif isinstance(child, bytes) and len(child) == 32:
                wanted.add(child)
            elif child != b'':
                raise ValueError('invalid child reference')

    for raw in encoded:
        visit(rlp.decode(bytes.fromhex(raw[2:]), strict=True))
    wanted.difference_update(nodes)
    recovered = []
    for leaf, path, value in compact:
        for removed in range(1, len(path) + int(leaf)):
            raw = rlp.encode([encode_path(leaf, path[removed:]), value])
            if len(raw) < 32:
                continue  # An ordinary hashed child cannot be an inline node.
            key = keccak(raw)
            if key in wanted:
                nodes[key] = '0x' + raw.hex()
                wanted.remove(key)
                recovered.append('0x' + key.hex())
    return sorted(nodes.values()), dict(method='hash-matched-compact-path-suffixes-v1',
                                       supplied_nodes=len(encoded), recovered_nodes=len(recovered),
                                       recovered_node_hashes=sorted(recovered))
