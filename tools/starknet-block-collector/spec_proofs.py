"""Speculative Merkle-proof capture for ``starknet_getStorageProof``.

The node only serves proofs for the last ~16-24 blocks, but SNOS asks for them
only after re-executing the whole block, which over a long-haul link takes
longer than that. The proxy therefore fetches the proof for each storage key /
contract leaf *as soon as SNOS first reads it*, at both the pre-state block and
the block itself, and keeps the union of returned trie nodes per block.

A later ``getStorageProof`` request is answered from that union when every
requested contract, key and class is covered. The answer is a superset of the
nodes the node would return (extra nodes are harmless: consumers index nodes
by hash); the OS state-root check in the collector validates the result.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from pathlib import Path

LOG = logging.getLogger("spec_proofs")
MAX_KEYS_PER_REQUEST = 90


def h(x: str) -> str:
    return hex(int(x, 16))


class BlockTries:
    def __init__(self):
        self.roots: dict | None = None
        self.contract_nodes: dict[str, dict] = {}
        self.leaves: dict[str, dict] = {}
        self.storage_nodes: dict[str, dict[str, dict]] = defaultdict(dict)
        self.storage_keys: dict[str, set[str]] = defaultdict(set)
        self.class_nodes: dict[str, dict] = {}
        self.classes: set[str] = set()


class SpecProofs:
    def __init__(self, forward, max_blocks: int = 256):
        self.forward = forward  # async (method, params) -> full JSON-RPC body
        self.blocks: dict[int, BlockTries] = {}
        self.max_blocks = max_blocks
        self.pending: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.requested: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.flush_scheduled: set[int] = set()
        self.requested_classes: dict[int, set[str]] = defaultdict(set)
        self.pending_classes: dict[int, set[str]] = defaultdict(set)
        self.stats = defaultdict(int)

    def tries(self, b: int) -> BlockTries:
        if b not in self.blocks:
            self.blocks[b] = BlockTries()
            for old in sorted(self.blocks)[:-self.max_blocks]:
                del self.blocks[old]
        return self.blocks[b]

    # -- ingestion ---------------------------------------------------------
    def ingest(self, b: int, params: dict, result: dict) -> None:
        t = self.tries(b)
        t.roots = result["global_roots"]
        for n in result["contracts_proof"]["nodes"]:
            t.contract_nodes[n["node_hash"]] = n
        for c, leaf in zip(params.get("contract_addresses", []), result["contracts_proof"]["contract_leaves_data"]):
            t.leaves[h(c)] = leaf
        for entry, nodes in zip(params.get("contracts_storage_keys", []), result["contracts_storage_proofs"]):
            c = h(entry["contract_address"])
            for n in nodes:
                t.storage_nodes[c][n["node_hash"]] = n
            t.storage_keys[c].update(h(k) for k in entry["storage_keys"])
        for n in result.get("classes_proof", []):
            t.class_nodes[n["node_hash"]] = n
        t.classes.update(h(x) for x in params.get("class_hashes", []))

    # -- speculation -------------------------------------------------------
    def want(self, b: int, contract: str, key: str | None = None) -> None:
        c = h(contract)
        k = h(key) if key is not None else None
        t = self.blocks.get(b)
        if t is not None and c in t.leaves and (k is None or k in t.storage_keys[c]):
            return
        requested = self.requested[b]
        # Any request naming contract c also returns its leaf.
        if (k is None and c in requested) or (k is not None and k in requested.get(c, ())):
            return
        item = k if k is not None else "__leaf__"
        requested[c].add(item)
        self.pending[b][c].add(item)
        if b not in self.flush_scheduled:
            self.flush_scheduled.add(b)
            asyncio.get_running_loop().call_later(0.05, lambda: asyncio.ensure_future(self.flush(b)))

    def want_class(self, b: int, class_hash: str) -> None:
        ch = h(class_hash)
        t = self.blocks.get(b)
        if (t is not None and ch in t.classes) or ch in self.requested_classes[b]:
            return
        self.requested_classes[b].add(ch)
        self.pending_classes[b].add(ch)
        if b not in self.flush_scheduled:
            self.flush_scheduled.add(b)
            asyncio.get_running_loop().call_later(0.05, lambda: asyncio.ensure_future(self.flush(b)))

    async def flush(self, b: int) -> None:
        self.flush_scheduled.discard(b)
        classes = sorted(self.pending_classes.pop(b, set()))
        pending = self.pending.pop(b, {})
        chunks, cur, n = [], {}, 0
        for c, keys in pending.items():
            ks = sorted(k for k in keys if k != "__leaf__")
            if not ks:
                cur.setdefault(c, [])
                continue
            for i in range(0, len(ks), MAX_KEYS_PER_REQUEST):
                part = ks[i:i + MAX_KEYS_PER_REQUEST]
                if n + len(part) > MAX_KEYS_PER_REQUEST and cur:
                    chunks.append(cur)
                    cur, n = {}, 0
                cur.setdefault(c, []).extend(part)
                n += len(part)
        if cur:
            chunks.append(cur)
        jobs = [self.fetch(b, ch) for ch in chunks]
        jobs += [self.fetch(b, {}, classes[j:j + MAX_KEYS_PER_REQUEST]) for j in range(0, len(classes), MAX_KEYS_PER_REQUEST)]
        await asyncio.gather(*jobs)

    async def fetch(self, b: int, chunk: dict[str, list[str]], classes: list[str] = ()) -> None:
        params = {
            "block_id": {"block_number": b},
            "class_hashes": list(classes),
            "contract_addresses": sorted(chunk),
            "contracts_storage_keys": [{"contract_address": c, "storage_keys": ks} for c, ks in sorted(chunk.items()) if ks],
        }
        try:
            body = await self.forward("starknet_getStorageProof", params)
        except Exception as exc:  # noqa: BLE001
            self.stats["spec_fail"] += 1
            LOG.warning("speculative proof b=%d failed: %s", b, exc)
            return
        if "result" in body:
            self.ingest(b, params, body["result"])
            self.stats["spec_ok"] += 1
        else:
            code = body.get("error", {}).get("code")
            self.stats[f"spec_err_{code}"] += 1
            if code != 42:  # outside the window a retry cannot succeed
                for c, ks in chunk.items():
                    self.requested[b][c].difference_update(ks or ["__leaf__"])
                self.requested_classes[b].difference_update(classes)

    # -- synthesis ---------------------------------------------------------
    def synthesize(self, params: dict) -> dict | None:
        bid = params.get("block_id")
        if not (isinstance(bid, dict) and "block_number" in bid):
            return None
        t = self.blocks.get(int(bid["block_number"]))
        if t is None or t.roots is None:
            return None
        contracts = [h(c) for c in params.get("contract_addresses", [])]
        if any(c not in t.leaves for c in contracts):
            return None
        entries = params.get("contracts_storage_keys", [])
        for e in entries:
            c = h(e["contract_address"])
            if any(h(k) not in t.storage_keys[c] for k in e["storage_keys"]):
                return None
        classes = [h(x) for x in params.get("class_hashes", [])]
        if any(x not in t.classes for x in classes):
            return None
        self.stats["synthesized"] += 1
        return {
            "classes_proof": list(t.class_nodes.values()) if classes else [],
            "contracts_proof": {
                "nodes": list(t.contract_nodes.values()) if contracts else [],
                "contract_leaves_data": [t.leaves[c] for c in contracts],
            },
            "contracts_storage_proofs": [list(t.storage_nodes[h(e["contract_address"])].values()) for e in entries],
            "global_roots": t.roots,
        }

    def missing(self, params: dict) -> str:
        bid = params.get("block_id", {})
        t = self.blocks.get(int(bid.get("block_number", -1)))
        if t is None:
            return "no speculative data for block"
        miss = [c for c in params.get("contract_addresses", []) if h(c) not in t.leaves]
        keys = sum(1 for e in params.get("contracts_storage_keys", []) for k in e["storage_keys"]
                   if h(k) not in t.storage_keys[h(e["contract_address"])])
        return f"missing leaves={len(miss)} keys={keys}"
