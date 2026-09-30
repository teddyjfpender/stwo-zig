"""Rebuild ``starknet_getStorageProof`` answers for blocks older than the node's window.

Given a request at block ``b``, pick a fresh block ``L`` near the head and:

1. read the state diffs of blocks ``b+1..L`` (permanent RPC data);
2. fetch proofs at ``L`` for the requested contracts/keys plus every contract
   and key modified in ``b+1..L``;
3. set every modified leaf back to its value at ``b`` (``getStorageAt`` /
   ``getNonce`` / ``getClassHashAt`` at ``b`` are permanent), recomputing each
   storage root and then the contracts-trie root;
4. check the recomputed contracts root against the root recorded while ``b``
   was fresh, and emit proof paths at ``b``.

Where a rolled-back deletion merges a path into an unexpanded sibling, the
sibling's top is fetched at ``L`` with a probe key and the trie rebuilt.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from patricia import NeedExpand, Trie, contract_state_hash

LOG = logging.getLogger("rollback")
MAX_KEYS = 90
MAX_CONTRACTS = 90
LAG = 4  # stay this many blocks behind the head so L remains provable


def i(x) -> int:
    return int(x, 16) if isinstance(x, str) else int(x)


class WindowExpired(Exception):
    pass


class State:
    """Rollback of one block ``b`` from one fresh block ``L``."""

    def __init__(self, engine: "Rollback", b: int, L: int):
        self.e, self.b, self.L = engine, b, L
        self.mod_keys: dict[int, set[int]] = defaultdict(set)
        self.mod_contracts: set[int] = set()
        self.class_changes = False
        self.cnodes: dict[int, dict] = {}
        self.leaves_L: dict[int, dict] = {}
        self.snodes: dict[int, dict[int, dict]] = defaultdict(dict)
        self.keys_L: dict[int, set[int]] = defaultdict(set)
        self.roots_L: dict | None = None
        self.values_b: dict[tuple, int] = {}
        self.strie: dict[int, Trie] = {}
        self.ctrie: Trie | None = None
        self.lock = asyncio.Lock()

    async def init(self) -> None:
        blocks = list(range(self.b + 1, self.L + 1))
        diffs = await self.e.call_many([("starknet_getStateUpdate", {"block_id": {"block_number": n}}) for n in blocks])
        for body in diffs:
            d = body["result"]["state_diff"]
            for sd in d["storage_diffs"]:
                c = i(sd["address"])
                self.mod_contracts.add(c)
                self.mod_keys[c].update(i(e["key"]) for e in sd["storage_entries"])
            self.mod_contracts |= {i(x["contract_address"]) for x in d["nonces"]}
            self.mod_contracts |= {i(x["address"]) for x in d.get("deployed_contracts", [])}
            self.mod_contracts |= {i(x["contract_address"]) for x in d.get("replaced_classes", [])}
            if d.get("declared_classes") or d.get("deprecated_declared_classes") or d.get("migrated_compiled_classes"):
                self.class_changes = True

    # -- fetching at L --------------------------------------------------------
    async def fetch_L(self, contracts: set[int], keys: dict[int, set[int]]) -> None:
        contracts = {c for c in contracts if c not in self.leaves_L}
        keys = {c: {k for k in ks if k not in self.keys_L[c]} for c, ks in keys.items()}
        keys = {c: ks for c, ks in keys.items() if ks}
        reqs = []
        for c, ks in keys.items():
            ks = sorted(ks)
            for j in range(0, len(ks), MAX_KEYS):
                reqs.append(([c], {c: ks[j:j + MAX_KEYS]}))
            contracts.discard(c)
        cs = sorted(contracts)
        for j in range(0, len(cs), MAX_CONTRACTS):
            reqs.append((cs[j:j + MAX_CONTRACTS], {}))
        if not reqs:
            return
        calls = []
        for cs_, ks_ in reqs:
            calls.append(("starknet_getStorageProof", {
                "block_id": {"block_number": self.L}, "class_hashes": [],
                "contract_addresses": [hex(c) for c in cs_],
                "contracts_storage_keys": [{"contract_address": hex(c), "storage_keys": [hex(k) for k in v]} for c, v in ks_.items()],
            }))
        for (cs_, ks_), body in zip(reqs, await self.e.call_many(calls)):
            if "result" not in body:
                if body.get("error", {}).get("code") == 42:
                    raise WindowExpired(self.L)
                raise RuntimeError(f"proof at L={self.L} failed: {body.get('error')}")
            res = body["result"]
            self.roots_L = res["global_roots"]
            self.cnodes.update({i(n["node_hash"]): n["node"] for n in res["contracts_proof"]["nodes"]})
            for c, leaf in zip(cs_, res["contracts_proof"]["contract_leaves_data"]):
                self.leaves_L[c] = leaf
            for (c, ks), nodes in zip(ks_.items(), res["contracts_storage_proofs"]):
                self.snodes[c].update({i(n["node_hash"]): n["node"] for n in nodes})
                self.keys_L[c].update(ks)
        self.strie.clear()
        self.ctrie = None

    async def values_at_b(self, wanted: list[tuple]) -> None:
        """wanted: ("s", c, k) | ("n", c) | ("c", c) not yet known."""
        todo = [w for w in wanted if w not in self.values_b]
        calls = []
        blk = {"block_number": self.b}
        for w in todo:
            if w[0] == "s":
                calls.append(("starknet_getStorageAt", {"contract_address": hex(w[1]), "key": hex(w[2]), "block_id": blk}))
            elif w[0] == "n":
                calls.append(("starknet_getNonce", {"block_id": blk, "contract_address": hex(w[1])}))
            else:
                calls.append(("starknet_getClassHashAt", {"block_id": blk, "contract_address": hex(w[1])}))
        for w, body in zip(todo, await self.e.call_many(calls)):
            if "result" in body:
                self.values_b[w] = i(body["result"])
            elif body.get("error", {}).get("code") == 20:  # contract not found at b
                self.values_b[w] = 0
            else:
                raise RuntimeError(f"value at b failed {w}: {body.get('error')}")

    # -- tries at b -------------------------------------------------------------
    async def storage_trie(self, c: int) -> Trie:
        if c in self.strie:
            return self.strie[c]
        await self.values_at_b([("s", c, k) for k in self.mod_keys.get(c, ())])
        while True:
            t = Trie(i(self.leaves_L[c]["storage_root"]), self.snodes[c])
            try:
                for k in self.mod_keys.get(c, ()):
                    t.set(k, self.values_b[("s", c, k)])
                t.root_hash()
                break
            except NeedExpand as ne:
                await self.fetch_L(set(), {c: {ne.probe_key()}})
        self.strie[c] = t
        return t

    async def contract_trie(self) -> Trie:
        if self.ctrie is not None:
            return self.ctrie
        leaves = {}
        await self.values_at_b([(kind, c) for c in self.mod_contracts for kind in ("n", "c")])
        for c in self.mod_contracts:
            root = (await self.storage_trie(c)).root_hash() if c in self.mod_keys else i(self.leaves_L[c]["storage_root"])
            leaves[c] = contract_state_hash(self.values_b[("c", c)], root, self.values_b[("n", c)])
        while True:
            t = Trie(i(self.roots_L["contracts_tree_root"]), self.cnodes)
            try:
                for c, v in leaves.items():
                    t.set(c, v)
                t.root_hash()
                break
            except NeedExpand as ne:
                await self.fetch_L({ne.probe_key()}, {})
        self.ctrie = t
        return t

    async def answer(self, params: dict) -> dict:
        async with self.lock:
            req_contracts = {i(c) for c in params.get("contract_addresses", [])}
            req_keys = {i(e["contract_address"]): {i(k) for k in e["storage_keys"]} for e in params.get("contracts_storage_keys", [])}
            need_c = req_contracts | set(req_keys) | self.mod_contracts
            need_k = defaultdict(set)
            for c, ks in self.mod_keys.items():
                need_k[c] |= ks
            for c, ks in req_keys.items():
                need_k[c] |= ks
            await self.fetch_L(need_c, need_k)
            ctrie = await self.contract_trie()
            recorded = await self.e.recorded_roots(self.b)
            computed = hex(ctrie.root_hash())
            if recorded and i(recorded["contracts_tree_root"]) != i(computed):
                raise RuntimeError(f"rollback root mismatch at b={self.b}: {computed} != {recorded['contracts_tree_root']}")
            if self.class_changes and not recorded:
                raise RuntimeError(f"class trie changed in ({self.b},{self.L}] and no recorded roots for b")
            classes_root = recorded["classes_tree_root"] if recorded else self.roots_L["classes_tree_root"]
            block_hash = recorded["block_hash"] if recorded else await self.e.block_hash(self.b)

            await self.values_at_b([(kind, c) for c in req_contracts for kind in ("n", "c")])
            cnodes, leaves = {}, []
            for c in [i(x) for x in params.get("contract_addresses", [])]:
                for n in ctrie.proof(c):
                    cnodes[n["node_hash"]] = n
                sroot = (await self.storage_trie(c)).root_hash() if c in self.mod_keys else i(self.leaves_L[c]["storage_root"])
                leaves.append({"class_hash": hex(self.values_b[("c", c)]), "nonce": hex(self.values_b[("n", c)]),
                               "storage_root": hex(sroot)})
            sproofs = []
            for e in params.get("contracts_storage_keys", []):
                c = i(e["contract_address"])
                st = await self.storage_trie(c)
                nodes = {}
                for k in e["storage_keys"]:
                    for n in st.proof(i(k)):
                        nodes[n["node_hash"]] = n
                sproofs.append(list(nodes.values()))
            return {
                "classes_proof": [],
                "contracts_proof": {"nodes": list(cnodes.values()), "contract_leaves_data": leaves},
                "contracts_storage_proofs": sproofs,
                "global_roots": {"block_hash": block_hash, "classes_tree_root": classes_root, "contracts_tree_root": computed},
            }


class Rollback:
    def __init__(self, forward, store):
        self.forward = forward  # async (method, params) -> JSON-RPC body
        self.store = store
        self.states: dict[int, State] = {}
        self.stats = defaultdict(int)

    async def call_many(self, calls: list[tuple[str, object]]) -> list[dict]:
        out = []
        for m, p in calls:
            cached = self.store.lookup(m, p)
            out.append(cached if cached is not None else None)
        missing = [j for j, v in enumerate(out) if v is None]
        fetched = await asyncio.gather(*(self.forward(*calls[j]) for j in missing))
        for j, body in zip(missing, fetched):
            body = {k: body[k] for k in ("result", "error") if k in body}
            if "result" in body and calls[j][0] != "starknet_getStorageProof":
                self.store.record(*calls[j], body)
            out[j] = body
        return out

    async def head(self) -> int:
        return i((await self.forward("starknet_blockNumber", []))["result"])

    async def block_hash(self, b: int) -> str:
        body = (await self.call_many([("starknet_getBlockWithTxHashes", {"block_id": {"block_number": b}})]))[0]
        return body["result"]["block_hash"]

    async def recorded_roots(self, b: int) -> dict | None:
        body = self.store.lookup("starknet_getStorageProof", roots_probe(b))
        return body["result"]["global_roots"] if body and "result" in body else None

    async def serve(self, params: dict) -> dict | None:
        b = int(params["block_id"]["block_number"])
        if params.get("class_hashes"):
            return await self.serve_classes(b, params)
        for attempt in range(3):
            st = self.states.get(b)
            if st is None:
                L = await self.head() - LAG
                if L <= b:
                    return None
                st = State(self, b, L)
                await st.init()
                self.states[b] = st
                for old in sorted(self.states)[:-64]:
                    del self.states[old]
            try:
                res = await st.answer(params)
                self.stats["rollback_ok"] += 1
                return res
            except WindowExpired:
                self.stats["rollback_retry"] += 1
                self.states.pop(b, None)
            except Exception as exc:  # noqa: BLE001
                self.stats["rollback_fail"] += 1
                LOG.warning("rollback b=%d failed: %s", b, exc)
                self.states.pop(b, None)
                return None
        return None


async def _serve_classes(self, b: int, params: dict) -> dict | None:
    """Class-trie proofs at b from a fresh block L, valid when no class changed in (b, L]."""
    if params.get("contract_addresses") or params.get("contracts_storage_keys"):
        return None
    recorded = await self.recorded_roots(b)
    if not recorded:
        self.stats["rollback_class_no_roots"] += 1
        return None
    for _ in range(3):
        L = await self.head() - LAG
        if L <= b:
            return None
        st = State(self, b, L)
        await st.init()
        if st.class_changes:
            self.stats["rollback_class_changed"] += 1
            return None
        q = dict(params, block_id={"block_number": L})
        body = (await asyncio.gather(self.forward("starknet_getStorageProof", q)))[0]
        if "result" not in body:
            if body.get("error", {}).get("code") == 42:
                continue
            return None
        res = body["result"]
        if i(res["global_roots"]["classes_tree_root"]) != i(recorded["classes_tree_root"]):
            self.stats["rollback_class_root_mismatch"] += 1
            return None
        self.stats["rollback_class_ok"] += 1
        return {"classes_proof": res["classes_proof"],
                "contracts_proof": {"nodes": [], "contract_leaves_data": []},
                "contracts_storage_proofs": [], "global_roots": recorded}
    return None


Rollback.serve_classes = _serve_classes


def roots_probe(b: int) -> dict:
    """The cheap proof request the collector makes on arrival to pin block b's roots."""
    return {"block_id": {"block_number": b}, "class_hashes": [], "contract_addresses": ["0x1"], "contracts_storage_keys": []}
