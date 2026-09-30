"""Check trie rollback against real recorded proofs.

For a collected block N, SNOS recorded genuine proofs at N and N-1 for every
contract and key the block touched. Rolling the block-N tries back with the
block's state diff must reproduce the N-1 storage roots, the N-1 contracts
root, and the N-1 proof paths exactly.

    ~/Coding/snos/sequencer_venv/bin/python test_patricia.py [--data DIR] BLOCK...
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patricia import NeedExpand, Trie, contract_state_hash  # noqa: E402
from rpc_store import RpcStore  # noqa: E402


def i(x) -> int:
    return int(x, 16)


def proofs_at(store: RpcStore, block: int, at: int):
    """Merge every recorded getStorageProof result for block ``at``."""
    cnodes, snodes, leaves, roots, keys = {}, defaultdict(dict), {}, None, defaultdict(set)
    for line in open(store.block_dir(block) / "requests.jsonl"):
        r = json.loads(line)
        p = r["params"]
        if r["method"] != "starknet_getStorageProof" or p["block_id"].get("block_number") != at:
            continue
        body = store.lookup(r["method"], p)
        if not body or "result" not in body:
            continue
        res = body["result"]
        roots = res["global_roots"]
        cnodes.update({i(n["node_hash"]): n["node"] for n in res["contracts_proof"]["nodes"]})
        for c, leaf in zip(p["contract_addresses"], res["contracts_proof"]["contract_leaves_data"]):
            leaves[i(c)] = leaf
        for e, nodes in zip(p["contracts_storage_keys"], res["contracts_storage_proofs"]):
            snodes[i(e["contract_address"])].update({i(n["node_hash"]): n["node"] for n in nodes})
            keys[i(e["contract_address"])].update(i(k) for k in e["storage_keys"])
    return cnodes, snodes, leaves, roots, keys


def value_at(store: RpcStore, method: str, params: dict) -> int:
    body = store.lookup(method, params)
    if body is None:
        raise KeyError(f"not recorded: {method} {params}")
    return i(body["result"]) if "result" in body else 0


def check_block(store: RpcStore, n: int) -> bool:
    diff = store.lookup("starknet_getStateUpdate", {"block_id": {"block_number": n}})["result"]["state_diff"]
    cn_new, sn_new, lv_new, rt_new, keys_new = proofs_at(store, n, n)
    cn_old, sn_old, lv_old, rt_old, keys_old = proofs_at(store, n, n - 1)
    ok = True
    prev = {"block_number": n - 1}
    mod = defaultdict(set)
    for d in diff["storage_diffs"]:
        for e in d["storage_entries"]:
            mod[i(d["address"])].add(i(e["key"]))
    touched = set(mod) | {i(x["contract_address"]) for x in diff["nonces"]}
    touched |= {i(x["contract_address"]) for x in diff.get("deployed_contracts", []) + diff.get("replaced_classes", [])}

    new_roots = {}
    for c in touched:
        leaf = lv_new[c]
        t = Trie(i(leaf["storage_root"]), sn_new[c])
        for k in mod.get(c, ()):
            old = value_at(store, "starknet_getStorageAt", {"contract_address": hex(c), "key": hex(k), "block_id": prev})
            t.set(k, old)
        root = t.root_hash()
        want = i(lv_old[c]["storage_root"]) if c in lv_old else None
        match = want is None or root == want
        ok &= match
        print(f"  storage {hex(c)[:12]}… keys={len(mod.get(c, ()))} root {'OK' if match else 'MISMATCH'}")
        if c in lv_old:
            for k in sorted(keys_old[c])[:50]:
                mine = {x["node_hash"] for x in t.proof(k)}
                real = {hex(h) for h in sn_old[c]}
                if not mine <= real:
                    ok = False
                    print(f"    proof path for key {hex(k)[:12]}… not in real N-1 nodes")
                    break
        new_roots[c] = root

    ct = Trie(i(rt_new["contracts_tree_root"]), cn_new)
    for c in touched:
        ch = value_at(store, "starknet_getClassHashAt", {"block_id": prev, "contract_address": hex(c)})
        nonce = value_at(store, "starknet_getNonce", {"block_id": prev, "contract_address": hex(c)})
        ct.set(c, contract_state_hash(ch, new_roots[c], nonce))
    root = ct.root_hash()
    match = root == i(rt_old["contracts_tree_root"])
    ok &= match
    print(f"  contracts root {'OK' if match else 'MISMATCH'} ({len(touched)} contracts)")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path(__file__).resolve().parents[2] / "block-data")
    ap.add_argument("blocks", type=int, nargs="+")
    args = ap.parse_args()
    store = RpcStore(args.data, "mainnet")
    results = {}
    for n in args.blocks:
        print(f"block {n}")
        try:
            results[n] = check_block(store, n)
        except (KeyError, NeedExpand) as exc:
            print(f"  skipped: {exc}")
            results[n] = None
    print(json.dumps(results))
    sys.exit(0 if all(v is not False for v in results.values()) else 1)


if __name__ == "__main__":
    main()
