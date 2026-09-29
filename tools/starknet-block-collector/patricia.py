"""Partial Starknet Patricia tries (height 251, Pedersen) built from RPC proof nodes.

A trie is parsed from ``starknet_getStorageProof`` nodes. Subtrees the proof
does not expand stay opaque (hash only). Leaves can then be set to other
values, and the root and proof paths recomputed. This is how proofs for an
older block are rebuilt from fresh proofs plus the permanent state diffs.

Node forms (tuples):
    ("E",)                    empty subtree
    ("L", value)              leaf (height 0)
    ("O", hash, prefix, h)    opaque subtree at height h, key prefix ``prefix``
    ("B", left, right)        binary node
    ("X", path, length, child) edge node

Hashes: binary H(l, r); edge H(child, path) + length; leaf = value.
"""

from __future__ import annotations

try:  # native C++ Pedersen (crypto-cpp-py), ~6x faster than cairo-lang's
    from crypto_cpp_py.cpp_bindings import cpp_hash as pedersen_hash
except ImportError:  # pragma: no cover
    from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash

P = 2**251 + 17 * 2**192 + 1
HEIGHT = 251
EMPTY = ("E",)


class NeedExpand(Exception):
    def __init__(self, prefix: int, height: int):
        super().__init__(f"opaque subtree prefix={prefix:#x} height={height}")
        self.prefix, self.height = prefix, height

    def probe_key(self) -> int:
        """Any key inside the opaque subtree; its proof expands the subtree's top."""
        return self.prefix << self.height


def mask(n: int) -> int:
    return (1 << n) - 1


class Trie:
    def __init__(self, root_hash: int, nodes: dict[int, dict], hash_fn=pedersen_hash):
        self.hash_fn = hash_fn
        self.nodes = nodes
        self.root = self._parse(root_hash, HEIGHT, 0)
        self._cache: dict[int, int] = {}

    # -- parsing -----------------------------------------------------------
    def _parse(self, hsh: int, h: int, prefix: int):
        if hsh == 0:
            return EMPTY
        if h == 0:
            return ("L", hsh)
        n = self.nodes.get(hsh)
        if n is None:
            return ("O", hsh, prefix, h)
        if "left" in n:
            return ("B", self._parse(int(n["left"], 16), h - 1, prefix << 1),
                    self._parse(int(n["right"], 16), h - 1, (prefix << 1) | 1))
        length, path = int(n["length"]), int(n["path"], 16)
        return ("X", path, length, self._parse(int(n["child"], 16), h - length, (prefix << length) | path))

    # -- hashing -----------------------------------------------------------
    def hash(self, node) -> int:
        kind = node[0]
        if kind == "E":
            return 0
        if kind == "L":
            return node[1]
        if kind == "O":
            return node[1]
        # Memoised by object identity; the cache holds the node itself so an id
        # is never reused while cached. Updates rebuild only the changed path,
        # so unchanged subtrees keep their hashes across set() calls.
        hit = self._cache.get(id(node))
        if hit is not None and hit[0] is node:
            return hit[1]
        if kind == "B":
            v = self.hash_fn(self.hash(node[1]), self.hash(node[2]))
        else:
            v = (self.hash_fn(self.hash(node[3]), node[1]) + node[2]) % P
        self._cache[id(node)] = (node, v)
        return v

    def root_hash(self) -> int:
        return self.hash(self.root)

    # -- expansion ---------------------------------------------------------
    def expand(self, prefix: int, height: int, nodes: dict[int, dict]) -> None:
        """Replace the opaque subtree at (prefix, height) using newly fetched nodes.

        The subtree must not contain keys modified since the nodes' block, so
        its structure is the same at every block the trie represents.
        """
        self.nodes.update(nodes)
        self.root = self._expand(self.root, HEIGHT, prefix, height, 0)

    def _expand(self, node, h: int, prefix: int, target_h: int, cur: int):
        kind = node[0]
        if kind == "O":
            node = self._parse(node[1], h, cur)
            if node[0] == "O":
                return node  # still unknown: nodes did not cover it
            kind = node[0]
        if h == target_h or kind in ("E", "L"):
            return node
        if kind == "B":
            bit = (prefix >> (h - 1 - target_h)) & 1
            if bit:
                return ("B", node[1], self._expand(node[2], h - 1, prefix, target_h, (cur << 1) | 1))
            return ("B", self._expand(node[1], h - 1, prefix, target_h, cur << 1), node[2])
        path, length, child = node[1], node[2], node[3]
        if h - length < target_h:
            return node  # target lies inside a compressed edge: nothing to expand
        return ("X", path, length, self._expand(child, h - length, prefix, target_h, (cur << length) | path))

    def opaque_at(self, prefix: int, height: int) -> bool:
        """Whether the subtree at (prefix, height) is still unexpanded."""
        node, h = self.root, HEIGHT
        while h > height:
            kind = node[0]
            if kind == "O":
                return True
            if kind in ("E", "L"):
                return False
            if kind == "B":
                bit = (prefix >> (h - 1 - height)) & 1
                node, h = node[2] if bit else node[1], h - 1
            else:
                path, length, child = node[1], node[2], node[3]
                if h - length < height or (prefix >> (h - length - height)) & ((1 << length) - 1) != path:
                    return False
                node, h = child, h - length
        return node[0] == "O"

    # -- updates -----------------------------------------------------------
    def set(self, key: int, value: int) -> None:
        self.root = self._set(self.root, HEIGHT, key, value, 0)

    def _edge(self, path: int, length: int, child, h: int, prefix: int):
        """Edge of ``length`` bits from height h onto ``child`` (normalised)."""
        if child[0] == "E":
            return EMPTY
        if length == 0:
            return child
        if child[0] == "X":
            return ("X", (path << child[2]) | child[1], length + child[2], child[3])
        if child[0] == "O":
            # Merging needs to know whether the opaque child is itself an edge.
            raise NeedExpand(child[2], child[3])
        return ("X", path, length, child)

    def _set(self, node, h: int, key: int, value: int, prefix: int):
        if h == 0:
            return ("L", value) if value else EMPTY
        kind = node[0]
        if kind == "E":
            return ("X", key, h, ("L", value)) if value else EMPTY
        if kind == "O":
            raise NeedExpand(node[2], node[3])
        if kind == "B":
            bit = (key >> (h - 1)) & 1
            sub = key & mask(h - 1)
            left, right = node[1], node[2]
            if bit:
                right = self._set(right, h - 1, sub, value, (prefix << 1) | 1)
            else:
                left = self._set(left, h - 1, sub, value, prefix << 1)
            if left[0] == "E" and right[0] == "E":
                return EMPTY
            if left[0] == "E":
                return self._edge(1, 1, right, h, prefix)
            if right[0] == "E":
                return self._edge(0, 1, left, h, prefix)
            return ("B", left, right)
        # edge
        path, length, child = node[1], node[2], node[3]
        top = key >> (h - length)
        if top == path:
            new_child = self._set(child, h - length, key & mask(h - length), value, (prefix << length) | path)
            return self._edge(path, length, new_child, h, prefix)
        if not value:
            return node  # key absent already
        # Split at the first differing bit.
        i = 0
        while ((path >> (length - 1 - i)) & 1) == ((key >> (h - 1 - i)) & 1):
            i += 1
        split_h = h - i  # height of the new binary node
        old_bit = (path >> (length - 1 - i)) & 1
        rem_len = length - i - 1
        # ``child`` already hung under this edge, so it is not itself an edge.
        old_side = ("X", path & mask(rem_len), rem_len, child) if rem_len else child
        new_side = self._set(EMPTY, split_h - 1, key & mask(split_h - 1), value, 0)
        binary = ("B", new_side, old_side) if old_bit else ("B", old_side, new_side)
        return self._edge(path >> (length - i), i, binary, h, prefix) if i else binary

    # -- proofs --------------------------------------------------------------
    def proof(self, key: int) -> list[dict]:
        """RPC-format nodes on the path to ``key`` (membership or non-membership)."""
        out, node, h = [], self.root, HEIGHT
        while h > 0:
            kind = node[0]
            if kind in ("E", "L"):
                break
            if kind == "O":
                raise NeedExpand(node[2], node[3])
            if kind == "B":
                out.append({"node": {"left": hex(self.hash(node[1])), "right": hex(self.hash(node[2]))},
                            "node_hash": hex(self.hash(node))})
                bit = (key >> (h - 1)) & 1
                node, h = node[2] if bit else node[1], h - 1
            else:
                path, length, child = node[1], node[2], node[3]
                out.append({"node": {"child": hex(self.hash(child)), "length": length, "path": hex(path)},
                            "node_hash": hex(self.hash(node))})
                if (key >> (h - length)) & mask(length) != path:
                    break
                node, h = child, h - length
        return out


def contract_state_hash(class_hash: int, storage_root: int, nonce: int) -> int:
    """Leaf of the contracts trie; zero for a contract that does not exist."""
    if class_hash == 0 and storage_root == 0 and nonce == 0:
        return 0
    return pedersen_hash(pedersen_hash(pedersen_hash(class_hash, storage_root), nonce), 0)
