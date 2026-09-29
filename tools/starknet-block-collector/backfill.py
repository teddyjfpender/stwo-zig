"""Rebuild expired storage proofs for many blocks from one fresh block.

The proxy (``--defer-proofs``) logs every proof request SNOS made for a block
that had already left the node's ~16-24 block proof window. This tool answers
all of them in one pass:

1. choose a fresh block ``L`` (head - 3) and read the state diffs of every
   block from the oldest pending block up to ``L`` (permanent RPC data);
2. fetch proofs at ``L`` for every requested contract/key plus every contract
   and key modified in between (a few hundred batched requests, well inside
   the window);
3. walk the tries backwards one block at a time, setting each modified leaf to
   its value in the previous block (``getStorageAt``/``getNonce``/
   ``getClassHashAt`` at old blocks are permanent), and at each requested block
   emit exactly the proofs SNOS asked for;
4. check each rebuilt contracts-trie root against the root recorded while that
   block was fresh (``rollback.roots_probe``), record the answers, and re-run
   the block through the collector so the OS state-root check validates it.

Class-trie proofs are served from ``L`` when no class was declared or migrated
in between (verified against the recorded class root).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout

sys.path.insert(0, str(Path(__file__).parent))
from patricia import NeedExpand, Trie, contract_state_hash  # noqa: E402
from rollback import roots_probe  # noqa: E402
from rpc_store import RpcStore  # noqa: E402

LOG = logging.getLogger("backfill")
MAX_KEYS = 90
MAX_CONTRACTS = 90
LAG = 3


def i(x) -> int:
    return int(x, 16) if isinstance(x, str) else int(x)


class Expired(Exception):
    pass


def deepest_opaque_sibling(root: int, nodes: dict[int, dict], key: int) -> int | None:
    """Probe key for the opaque sibling at the deepest binary node on ``key``'s path."""
    h, cur, prefix, last = 251, root, 0, None
    while h > 0 and cur:
        n = nodes.get(cur)
        if n is None:
            break
        if "left" in n:
            bit = (key >> (h - 1)) & 1
            sib = i(n["right"] if bit == 0 else n["left"])
            last = (sib, (prefix << 1) | (1 - bit), h - 1)
            cur, prefix, h = i(n["right"] if bit else n["left"]), (prefix << 1) | bit, h - 1
        else:
            length, path = int(n["length"]), i(n["path"])
            if (key >> (h - length)) & ((1 << length) - 1) != path:
                break
            cur, prefix, h = i(n["child"]), (prefix << length) | path, h - length
    if last is None or last[0] == 0 or last[0] in nodes or last[2] == 0:
        return None
    return last[1] << last[2]


class Backfill:
    def __init__(self, args):
        self.args = args
        self.store = RpcStore(args.data, args.network)
        self.proxy = f"http://127.0.0.1:{args.proxy_port}"
        self.session: ClientSession | None = None
        self._progress = {"s": 0}

    # -- RPC through the proxy (records reads, paces upstream) ------------------
    async def call_many(self, calls: list[tuple[str, object]], chunk: int = 400) -> list[dict]:
        out: list[dict] = []
        for j in range(0, len(calls), chunk):
            part = calls[j:j + chunk]
            payload = [{"jsonrpc": "2.0", "id": k, "method": m, "params": p} for k, (m, p) in enumerate(part)]
            async with self.session.post(f"{self.proxy}/rpc/v0_10", json=payload) as r:
                res = sorted(await r.json(), key=lambda x: x["id"])
            out.extend(res)
        return out

    async def head(self) -> int:
        async with self.session.get(f"{self.proxy}/head") as r:
            return int((await r.json())["head"])

    # -- pending work -------------------------------------------------------------
    def pending_blocks(self) -> list[int]:
        out = []
        for meta in self.store.blocks.glob("*/meta.json"):
            try:
                if json.loads(meta.read_text()).get("status") == "pending":
                    out.append(int(meta.parent.name))
            except (ValueError, OSError):
                pass
        return sorted(out)

    def requests_for(self, blocks: list[int]) -> dict[int, list[dict]]:
        by_b: dict[int, list[dict]] = defaultdict(list)
        seen = set()
        for n in blocks:
            f = self.store.block_dir(n) / "pending_proofs.jsonl"
            for line in open(f):
                p = json.loads(line)
                key = json.dumps(p, sort_keys=True)
                if key in seen or self.store.lookup("starknet_getStorageProof", p) is not None:
                    continue
                seen.add(key)
                by_b[int(p["block_id"]["block_number"])].append(p)
        return by_b

    # -- one pass -----------------------------------------------------------------
    async def run_pass(self, blocks: list[int]) -> dict[int, str]:
        needed = self.requests_for(blocks)
        if not needed:
            return {n: "ready" for n in blocks}
        A = min(needed)
        recorded = {}
        for b in needed:
            body = self.store.lookup("starknet_getStorageProof", roots_probe(b))
            recorded[b] = body["result"]["global_roots"] if body and "result" in body else None
        LOG.info("pass: %d blocks, %d proof requests at %d distinct blocks (from %d)",
                 len(blocks), sum(map(len, needed.values())), len(needed), A)

        # Diffs and old values up to a provisional head, before the time-critical fetch.
        L = await self.head() - LAG
        mods = await self.load_diffs(A, L)
        await self.load_old_values(mods, A, L)
        for attempt in range(4):
            L_new = await self.head() - LAG
            if L_new > L:
                mods.update(await self.load_diffs(L, L_new))
                await self.load_old_values(mods, L, L_new)
                L = L_new
            try:
                state = await self.fetch_at(L, needed, mods, A)
                await self.prefetch_siblings(state, mods, A, L)
                break
            except Expired:
                LOG.warning("L=%d expired during fetch; retrying", L)
        else:
            raise RuntimeError("could not fetch a consistent proof set at a fresh block")
        return await self.walk_back(state, needed, mods, recorded, A, L, blocks)

    async def load_diffs(self, lo: int, hi: int) -> dict:
        """mods[s] = {"storage": {c: {k}}, "contracts": {c}, "class_change": bool} for s in (lo, hi]."""
        blocks = list(range(lo + 1, hi + 1))
        bodies = await self.call_many([("starknet_getStateUpdate", {"block_id": {"block_number": s}}) for s in blocks])
        mods = {}
        for s, body in zip(blocks, bodies):
            d = body["result"]["state_diff"]
            st = defaultdict(set)
            for sd in d["storage_diffs"]:
                st[i(sd["address"])].update(i(e["key"]) for e in sd["storage_entries"])
            cs = set(st) | {i(x["contract_address"]) for x in d["nonces"]}
            cs |= {i(x["address"]) for x in d.get("deployed_contracts", [])}
            cs |= {i(x["contract_address"]) for x in d.get("replaced_classes", [])}
            mods[s] = {"storage": st, "contracts": cs,
                       "class_change": bool(d.get("declared_classes") or d.get("deprecated_declared_classes")
                                            or d.get("migrated_compiled_classes"))}
        return mods

    async def load_old_values(self, mods: dict, lo: int, hi: int) -> None:
        """Values at s-1 of everything block s modified, for s in (lo, hi]."""
        calls = []
        for s in range(lo + 1, hi + 1):
            prev = {"block_number": s - 1}
            for c, ks in mods[s]["storage"].items():
                calls += [("starknet_getStorageAt", {"contract_address": hex(c), "key": hex(k), "block_id": prev}) for k in ks]
            for c in mods[s]["contracts"]:
                calls.append(("starknet_getNonce", {"block_id": prev, "contract_address": hex(c)}))
                calls.append(("starknet_getClassHashAt", {"block_id": prev, "contract_address": hex(c)}))
        calls = [c for c in calls if self.store.lookup(*c) is None]
        if calls:
            LOG.info("fetching %d old values", len(calls))
            await self.call_many(calls)

    def value(self, method: str, params: dict) -> int:
        body = self.store.lookup(method, params)
        if body is None:
            raise KeyError(f"missing {method} {params}")
        if "result" in body:
            return i(body["result"])
        if body.get("error", {}).get("code") == 20:  # contract not deployed yet
            return 0
        raise RuntimeError(f"{method} error {body['error']}")

    async def fetch_at(self, L: int, needed: dict, mods: dict, A: int) -> dict:
        keys = defaultdict(set)
        contracts = set()
        classes = set()
        for reqs in needed.values():
            for p in reqs:
                contracts |= {i(c) for c in p.get("contract_addresses", [])}
                for e in p.get("contracts_storage_keys", []):
                    keys[i(e["contract_address"])] |= {i(k) for k in e["storage_keys"]}
                classes |= {i(x) for x in p.get("class_hashes", [])}
        for s in range(A + 1, L + 1):
            contracts |= mods[s]["contracts"]
            for c, ks in mods[s]["storage"].items():
                keys[c] |= ks
        contracts |= set(keys)
        blk = {"block_number": L}
        reqs = []
        for c, ks in keys.items():
            ks = sorted(ks)
            for j in range(0, len(ks), MAX_KEYS):
                reqs.append(([c], {c: ks[j:j + MAX_KEYS]}, []))
        rest = sorted(contracts - set(keys))
        for j in range(0, len(rest), MAX_CONTRACTS):
            reqs.append((rest[j:j + MAX_CONTRACTS], {}, []))
        cl = sorted(classes)
        for j in range(0, len(cl), MAX_KEYS):
            reqs.append(([], {}, cl[j:j + MAX_KEYS]))
        calls = [("starknet_getStorageProof", {
            "block_id": blk, "class_hashes": [hex(x) for x in cls],
            "contract_addresses": [hex(c) for c in cs],
            "contracts_storage_keys": [{"contract_address": hex(c), "storage_keys": [hex(k) for k in v]} for c, v in ks.items()],
        }) for cs, ks, cls in reqs]
        t0 = time.time()
        LOG.info("fetching %d proof requests at L=%d (%d contracts, %d keys, %d classes)",
                 len(calls), L, len(contracts), sum(map(len, keys.values())), len(classes))
        bodies = await self.call_many(calls, chunk=len(calls))
        bad = [(c, b) for c, b in zip(calls, bodies) if "error" in b]
        if bad:
            (m, p0), b0 = bad[0]
            LOG.warning("%d/%d proof requests failed at L=%d; first: %s (contracts=%d keys=%d classes=%d)",
                        len(bad), len(calls), L, b0["error"], len(p0["contract_addresses"]),
                        sum(len(e["storage_keys"]) for e in p0["contracts_storage_keys"]), len(p0["class_hashes"]))
            if any(b.get("error", {}).get("code") == 42 for _, b in bad):
                raise Expired()
        state = {"L": L, "cnodes": {}, "snodes": defaultdict(dict), "leaves": {}, "cls_nodes": {}, "roots": None}
        for (cs, ks, cls), body in zip(reqs, bodies):
            if "result" not in body:
                if body.get("error", {}).get("code") == 42:
                    raise Expired()
                raise RuntimeError(f"proof at L failed: {body.get('error')}")
            res = body["result"]
            state["roots"] = res["global_roots"]
            state["cnodes"].update({i(n["node_hash"]): n["node"] for n in res["contracts_proof"]["nodes"]})
            for c, leaf in zip(cs, res["contracts_proof"]["contract_leaves_data"]):
                state["leaves"][c] = leaf
            for (c, _), nodes in zip(ks.items(), res["contracts_storage_proofs"]):
                state["snodes"][c].update({i(n["node_hash"]): n["node"] for n in nodes})
            for n in res.get("classes_proof", []):
                state["cls_nodes"][n["node_hash"]] = n
        LOG.info("proofs at L fetched in %.1fs", time.time() - t0)
        return state

    async def prefetch_siblings(self, st: dict, mods: dict, A: int, L: int) -> None:
        """Fetch, at L, the unexpanded siblings that rolled-back deletions will merge with.

        A leaf that is zero at some block of the walk disappears from the trie;
        its parent collapses onto the sibling at the deepest binary node of its
        path. If that sibling is opaque its top node is needed, and it must come
        from L itself (later blocks may have changed it).
        """
        deleted_keys: dict[int, set[int]] = defaultdict(set)
        deleted_contracts: set[int] = set()
        for s in range(A + 1, L + 1):
            prev = {"block_number": s - 1}
            for c, ks in mods[s]["storage"].items():
                for k in ks:
                    if self.value("starknet_getStorageAt", {"contract_address": hex(c), "key": hex(k), "block_id": prev}) == 0:
                        deleted_keys[c].add(k)
            for c in mods[s]["contracts"]:
                if self.value("starknet_getClassHashAt", {"block_id": prev, "contract_address": hex(c)}) == 0:
                    deleted_contracts.add(c)
        probes_s: dict[int, set[int]] = defaultdict(set)
        for c, ks in deleted_keys.items():
            root = i(st["leaves"][c]["storage_root"]) if c in st["leaves"] else 0
            for k in ks:
                p = deepest_opaque_sibling(root, st["snodes"][c], k)
                if p is not None:
                    probes_s[c].add(p)
        probes_c = set()
        croot = i(st["roots"]["contracts_tree_root"])
        for c in deleted_contracts:
            p = deepest_opaque_sibling(croot, st["cnodes"], c)
            if p is not None:
                probes_c.add(p)
        blk = {"block_number": L}
        calls = []
        for c, ks in probes_s.items():
            ks = sorted(ks)
            for j in range(0, len(ks), MAX_KEYS):
                calls.append(("s", c, {"block_id": blk, "class_hashes": [], "contract_addresses": [hex(c)],
                                       "contracts_storage_keys": [{"contract_address": hex(c), "storage_keys": [hex(k) for k in ks[j:j + MAX_KEYS]]}]}))
        pc = sorted(probes_c)
        for j in range(0, len(pc), MAX_CONTRACTS):
            calls.append(("c", None, {"block_id": blk, "class_hashes": [], "contract_addresses": [hex(x) for x in pc[j:j + MAX_CONTRACTS]],
                                      "contracts_storage_keys": []}))
        if not calls:
            return
        LOG.info("prefetching %d sibling probes at L=%d (%d storage, %d contract)",
                 sum(len(v) for v in probes_s.values()) + len(probes_c), L, len(probes_s), len(probes_c))
        bodies = await self.call_many([("starknet_getStorageProof", p) for _, _, p in calls], chunk=len(calls))
        for (kind, c, _), body in zip(calls, bodies):
            if "result" not in body:
                if body.get("error", {}).get("code") == 42:
                    raise Expired()
                continue
            res = body["result"]
            st["cnodes"].update({i(n["node_hash"]): n["node"] for n in res["contracts_proof"]["nodes"]})
            if kind == "s":
                st["snodes"][c].update({i(n["node_hash"]): n["node"] for n in res["contracts_storage_proofs"][0]})

    async def probe(self, contract: int | None, key: int) -> dict[int, dict]:
        """Nodes on the path to ``key`` at a fresh block (for an unmodified subtree)."""
        L = await self.head() - LAG
        if contract is None:
            p = {"block_id": {"block_number": L}, "class_hashes": [], "contract_addresses": [hex(key)], "contracts_storage_keys": []}
        else:
            p = {"block_id": {"block_number": L}, "class_hashes": [], "contract_addresses": [hex(contract)],
                 "contracts_storage_keys": [{"contract_address": hex(contract), "storage_keys": [hex(key)]}]}
        body = (await self.call_many([("starknet_getStorageProof", p)]))[0]
        res = body["result"]
        if contract is None:
            return {i(n["node_hash"]): n["node"] for n in res["contracts_proof"]["nodes"]}
        return {i(n["node_hash"]): n["node"] for n in res["contracts_storage_proofs"][0]}

    async def set_leaf(self, trie: Trie, contract: int | None, key: int, value: int) -> None:
        for _ in range(64):
            try:
                trie.set(key, value)
                trie.root_hash()
                return
            except NeedExpand as ne:
                nodes = await self.probe(contract, ne.probe_key())
                before = trie.root
                trie.expand(ne.prefix, ne.height, nodes)
                if trie.root is before:
                    raise RuntimeError(f"sibling at prefix {ne.prefix:#x} changed after L; cannot expand")
        raise RuntimeError("expansion did not converge")

    async def proof_paths(self, trie: Trie, contract: int | None, keys) -> dict[str, dict]:
        out = {}
        for k in keys:
            for _ in range(64):
                try:
                    for n in trie.proof(k):
                        out[n["node_hash"]] = n
                    break
                except NeedExpand as ne:
                    trie.expand(ne.prefix, ne.height, await self.probe(contract, ne.probe_key()))
        return out

    async def walk_back(self, st: dict, needed: dict, mods: dict, recorded: dict, A: int, L: int,
                        blocks: list[int]) -> dict[int, str]:
        t0 = time.time()
        ctrie = Trie(i(st["roots"]["contracts_tree_root"]), st["cnodes"])
        stries: dict[int, Trie] = {}
        cur = {c: {"class_hash": i(v["class_hash"]), "nonce": i(v["nonce"]), "storage_root": i(v["storage_root"])}
               for c, v in st["leaves"].items()}

        def strie(c: int) -> Trie:
            if c not in stries:
                stries[c] = Trie(cur[c]["storage_root"], st["snodes"][c])
            return stries[c]

        class_change_after = {}  # b -> any class change in (b, L]
        flag = False
        for s in range(L, A - 1, -1):
            class_change_after[s] = flag
            flag = flag or (mods[s]["class_change"] if s in mods else False)
        bad_b: set[int] = set()
        try:
            await self._walk(ctrie, strie, cur, st, needed, mods, recorded, A, L, bad_b, class_change_after)
        except Exception as exc:  # noqa: BLE001
            LOG.error("walk stopped: %s", exc)
        LOG.info("walked back %d blocks in %.1fs; %d bad blocks", L - A, time.time() - t0, len(bad_b))
        result = {}
        for n in blocks:
            result[n] = "failed" if ({n, n - 1} & bad_b) else "ready"
        return result

    async def _walk(self, ctrie, strie, cur, st, needed, mods, recorded, A, L, bad_b, class_change_after) -> None:
        s = L
        try:
            await self._walk_steps(ctrie, strie, cur, st, needed, mods, recorded, A, L, bad_b, class_change_after, self._progress)
        except Exception:
            # Everything at or below the block being processed is unproven.
            bad_b.update(range(A, self._progress["s"] + 1))
            raise

    async def _walk_steps(self, ctrie, strie, cur, st, needed, mods, recorded, A, L, bad_b, class_change_after, progress) -> None:
        for s in range(L, A - 1, -1):
            progress["s"] = s
            if s in needed:
                root = ctrie.root_hash()
                rec = recorded.get(s)
                if rec is None or i(rec["contracts_tree_root"]) != root:
                    LOG.error("root mismatch at b=%d: rebuilt %#x recorded %s", s, root, rec and rec["contracts_tree_root"])
                    bad_b.add(s)
                else:
                    for p in needed[s]:
                        if p.get("class_hashes"):
                            if class_change_after[s] or i(rec["classes_tree_root"]) != i(st["roots"]["classes_tree_root"]):
                                bad_b.add(s)
                                continue
                            body = {"result": {"classes_proof": list(st["cls_nodes"].values()),
                                               "contracts_proof": {"nodes": [], "contract_leaves_data": []},
                                               "contracts_storage_proofs": [], "global_roots": rec}}
                        else:
                            cs = [i(c) for c in p.get("contract_addresses", [])]
                            cnodes = await self.proof_paths(ctrie, None, cs)
                            leaves = [{"class_hash": hex(cur[c]["class_hash"]), "nonce": hex(cur[c]["nonce"]),
                                       "storage_root": hex(cur[c]["storage_root"])} for c in cs]
                            sproofs = []
                            for e in p.get("contracts_storage_keys", []):
                                c = i(e["contract_address"])
                                nodes = await self.proof_paths(strie(c), c, [i(k) for k in e["storage_keys"]])
                                sproofs.append(list(nodes.values()))
                            body = {"result": {"classes_proof": [],
                                               "contracts_proof": {"nodes": list(cnodes.values()), "contract_leaves_data": leaves},
                                               "contracts_storage_proofs": sproofs, "global_roots": rec}}
                        self.store.record("starknet_getStorageProof", p, body)
            if s == A:
                break
            # Roll block s back to s-1.
            prev = {"block_number": s - 1}
            for c in mods[s]["contracts"]:
                if c not in cur:
                    continue  # never requested and absent from the fetched set: cannot happen by construction
                for k in mods[s]["storage"].get(c, ()):
                    v = self.value("starknet_getStorageAt", {"contract_address": hex(c), "key": hex(k), "block_id": prev})
                    await self.set_leaf(strie(c), c, k, v)
                if c in mods[s]["storage"]:
                    cur[c]["storage_root"] = strie(c).root_hash()
                cur[c]["nonce"] = self.value("starknet_getNonce", {"block_id": prev, "contract_address": hex(c)})
                cur[c]["class_hash"] = self.value("starknet_getClassHashAt", {"block_id": prev, "contract_address": hex(c)})
                leaf = contract_state_hash(cur[c]["class_hash"], cur[c]["storage_root"], cur[c]["nonce"])
                await self.set_leaf(ctrie, None, c, leaf)

    def rerun(self, n: int) -> None:
        subprocess.run([sys.executable, str(Path(__file__).parent / "collector.py"), "--data", str(self.args.data),
                        "--start", str(n), "--count", "1", "--replaying", "--scratch", str(self.args.data / ".scratch"),
                        "--proxy-port", str(self.args.proxy_port)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    async def main(self) -> None:
        self.session = ClientSession(timeout=ClientTimeout(total=900))
        while True:
            blocks = self.pending_blocks()[: self.args.max_blocks]
            if blocks:
                try:
                    status = await self.run_pass(blocks)
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("pass failed: %s", exc)
                    status = {}
                ready = [n for n, s in status.items() if s == "ready"]
                for n, s in status.items():
                    if s != "ready":
                        meta = self.store.block_dir(n) / "meta.json"
                        m = json.loads(meta.read_text())
                        m["status"] = "backfill_failed"
                        meta.write_text(json.dumps(m, indent=1))
                LOG.info("re-running SNOS for %d backfilled blocks", len(ready))
                loop = asyncio.get_running_loop()
                await asyncio.gather(*(loop.run_in_executor(None, self.rerun, n) for n in ready))
                for n in ready:
                    m = json.loads((self.store.block_dir(n) / "meta.json").read_text())
                    LOG.info("block %d after backfill: %s steps=%s", n, m.get("status"), m.get("n_steps"))
            if self.args.once:
                break
            await asyncio.sleep(self.args.interval)
        await self.session.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--network", default="mainnet")
    ap.add_argument("--proxy-port", type=int, default=9545)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--max-blocks", type=int, default=40)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(Backfill(args).main())


if __name__ == "__main__":
    main()
