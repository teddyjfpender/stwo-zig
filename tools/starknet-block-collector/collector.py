# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9"]
# ///
"""Follow Starknet mainnet and capture everything SNOS needs per block.

For each new block N, while N-1 is still inside the node's storage-proof
window (~16-24 blocks on Cartridge), this:

1. fetches the block, its state diff and its traces through the recording
   proxy (``rpc_proxy.py``, tagged ``/b/N``);
2. prefetches, in parallel, every read the re-execution is likely to make
   (written storage keys, nonces and class hashes of touched contracts, class
   definitions) so blockifier's serial state reads hit the local store;
3. runs SNOS ``generate-pie`` for block N through the proxy, which records the
   storage proofs and every remaining read;
4. checks the single-block OS output against the chain's state roots and
   writes ``blocks/N/meta.json``.

Everything recorded is replayable later (``assemble.py``) to build multi-block
leaf PIEs of any size without the proof window.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
import zipfile
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout

sys.path.insert(0, str(Path(__file__).parent))
from pie_info import pie_summary  # noqa: E402
from rollback import roots_probe  # noqa: E402

LOG = logging.getLogger("collector")


def h(x: str) -> str:
    return hex(int(x, 16))


def walk_calls(inv: dict | None, contracts: set, classes: set) -> None:
    if not inv:
        return
    if inv.get("contract_address"):
        contracts.add(h(inv["contract_address"]))
    if inv.get("class_hash"):
        classes.add(h(inv["class_hash"]))
    for c in inv.get("calls", []):
        walk_calls(c, contracts, classes)


class Collector:
    def __init__(self, args):
        self.args = args
        self.data = args.data / args.network
        self.proxy = f"http://127.0.0.1:{args.proxy_port}"
        self.sem = asyncio.Semaphore(args.max_inflight)
        self.session: ClientSession | None = None
        self.stop = asyncio.Event()
        self.inflight: set[asyncio.Task] = set()

    async def rpc(self, block: int, calls: list[tuple[str, object]]) -> list[dict]:
        payload = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
        async with self.session.post(f"{self.proxy}/b/{block}/rpc/v0_10", json=payload) as r:
            out = await r.json()
        return sorted(out, key=lambda x: x["id"])

    async def head(self) -> int:
        async with self.session.get(f"{self.proxy}/head") as r:
            head = (await r.json())["head"]
        if head is None:
            raise RuntimeError("proxy has no head yet")
        return int(head)

    async def prefetch(self, n: int) -> dict:
        prev = {"block_number": n - 1}
        cur = {"block_number": n}
        su, traces, blk = await self.rpc(n, [
            ("starknet_getStateUpdate", {"block_id": cur}),
            ("starknet_traceBlockTransactions", {"block_id": cur}),
            ("starknet_getBlockWithTxHashes", {"block_id": cur}),
        ])
        diff = su["result"]["state_diff"]
        contracts, classes = set(), set()
        for t in traces.get("result", []):
            tr = t["trace_root"]
            for k in ("validate_invocation", "execute_invocation", "fee_transfer_invocation", "constructor_invocation", "function_invocation"):
                v = tr.get(k)
                if isinstance(v, dict):
                    walk_calls(v, contracts, classes)
        writes = [(h(d["address"]), h(e["key"])) for d in diff["storage_diffs"] for e in d["storage_entries"]]
        contracts |= {a for a, _ in writes} | {h(x["contract_address"]) for x in diff["nonces"]}
        calls: list[tuple[str, object]] = [
            ("starknet_getBlockWithTxs", {"block_id": cur, "response_flags": ["INCLUDE_PROOF_FACTS"]}),
            ("starknet_getBlockWithReceipts", {"block_id": cur}),
            ("starknet_getBlockWithTxHashes", {"block_id": prev}),
        ]
        calls += [("starknet_getStorageAt", {"contract_address": a, "key": k, "block_id": prev}) for a, k in writes]
        for a in contracts:
            calls.append(("starknet_getNonce", {"block_id": prev, "contract_address": a}))
            calls.append(("starknet_getClassHashAt", {"block_id": prev, "contract_address": a}))
        calls += [("starknet_getClass", {"block_id": prev, "class_hash": c}) for c in classes]
        # Pin both blocks' global roots while they are still provable; rollback checks against them.
        calls += [("starknet_getStorageProof", roots_probe(x)) for x in (n - 1, n)]
        # Class-trie proofs are only needed for classes declared/migrated in this block.
        new_classes = sorted(classes | {h(x["class_hash"]) for key in ("declared_classes", "migrated_compiled_classes")
                                        for x in diff.get(key, []) if "class_hash" in x})
        if new_classes:
            for b in (prev, cur):
                calls.append(("starknet_getStorageProof", {"block_id": b, "class_hashes": new_classes,
                                                            "contract_addresses": [], "contracts_storage_keys": []}))
        await self.rpc(n, calls)
        return {
            "n_txs": len(blk["result"]["transactions"]),
            "timestamp": blk["result"]["timestamp"],
            "starknet_version": blk["result"].get("starknet_version"),
            "old_root": h(su["result"]["old_root"]),
            "new_root": h(su["result"]["new_root"]),
            "n_prefetch": len(calls),
            "n_touched_contracts": len(contracts),
            "n_storage_writes": len(writes),
        }

    async def process(self, n: int, seen_at: float) -> None:
        bdir = self.data / "blocks" / str(n)
        bdir.mkdir(parents=True, exist_ok=True)
        meta = {"block": n, "seen_at": seen_at, "status": "running"}
        async with self.sem:
            meta["started_lag_s"] = round(time.time() - seen_at, 2)
            try:
                meta.update(await self.prefetch(n))
                meta["prefetch_s"] = round(time.time() - seen_at, 2)
                pie = self.args.scratch / f"{n}.zip"
                env = {**os.environ, "RUST_LOG": "info"}
                t0 = time.time()
                with open(bdir / "snos.log", "wb") as log:
                    proc = await asyncio.create_subprocess_exec(
                        str(self.args.generate_pie), "--blocks", str(n),
                        "--rpc-url", f"{self.proxy}/b/{n}", "--chain", self.args.network,
                        "--output", str(pie), stdout=log, stderr=log, env=env)
                    try:
                        rc = await asyncio.wait_for(proc.wait(), timeout=self.args.snos_timeout)
                    except asyncio.TimeoutError:
                        proc.kill()
                        rc = -9
                meta["snos_s"] = round(time.time() - t0, 2)
                meta["total_s"] = round(time.time() - seen_at, 2)
                deferred = bdir / "pending_proofs.jsonl"
                if deferred.exists() and not self.args.replaying:
                    # Some proofs were placeholders: backfill.py rebuilds them, then re-runs SNOS.
                    meta["status"] = "pending"
                    meta["n_deferred"] = sum(1 for _ in open(deferred))
                    pie.unlink(missing_ok=True)
                elif rc == 0 and pie.exists():
                    info = pie_summary(pie)
                    meta.update(info)
                    meta["roots_match"] = (info["initial_root"] == meta["old_root"] and info["final_root"] == meta["new_root"])
                    meta["status"] = "ok" if meta["roots_match"] else "root_mismatch"
                    if self.args.keep_single_pies:
                        (self.data / "pies" / "single").mkdir(parents=True, exist_ok=True)
                        pie.replace(self.data / "pies" / "single" / f"{n}.zip")
                    else:
                        pie.unlink()
                else:
                    tail = (bdir / "snos.log").read_text(errors="replace").splitlines()[-40:]
                    err = next((l for l in reversed(tail) if "ERROR" in l), tail[-1] if tail else "")
                    meta["status"] = "window" if "too far in the past" in err else "failed"
                    meta["error"] = err[-400:]
            except Exception as exc:  # noqa: BLE001
                meta["status"] = "failed"
                meta["error"] = repr(exc)[-400:]
        (bdir / "meta.json").write_text(json.dumps(meta, indent=1))
        LOG.info("block %d %s total=%.1fs steps=%s", n, meta["status"], meta.get("total_s", -1), meta.get("n_steps"))

    async def run(self) -> None:
        self.session = ClientSession(timeout=ClientTimeout(total=300))
        self.args.scratch.mkdir(parents=True, exist_ok=True)
        start = self.args.start or await self.head()
        nxt, stop_at = start, (start + self.args.count if self.args.count else None)
        LOG.info("collecting from block %d%s", start, f" to {stop_at - 1}" if stop_at else " (unbounded)")
        while not self.stop.is_set() and (stop_at is None or nxt < stop_at):
            try:
                head = await self.head()
            except Exception as exc:  # noqa: BLE001
                LOG.warning("head poll failed: %s", exc)
                await asyncio.sleep(1)
                continue
            while nxt <= head and (stop_at is None or nxt < stop_at):
                t = asyncio.create_task(self.process(nxt, time.time()))
                self.inflight.add(t)
                t.add_done_callback(self.inflight.discard)
                nxt += 1
            await asyncio.sleep(self.args.poll)
        if self.inflight:
            await asyncio.gather(*self.inflight)
        await self.session.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--network", default="mainnet")
    ap.add_argument("--upstream", default="https://api.cartridge.gg/x/starknet/mainnet/rpc/v0_10")
    ap.add_argument("--proxy-port", type=int, default=9545)
    ap.add_argument("--generate-pie", type=Path, default=Path.home() / "Coding/snos/target/release/generate-pie")
    ap.add_argument("--scratch", type=Path, default=Path("/tmp/starknet-block-collector"))
    ap.add_argument("--start", type=int, default=0, help="first block (default: current head)")
    ap.add_argument("--count", type=int, default=0, help="stop after this many blocks (default: run forever)")
    ap.add_argument("--max-inflight", type=int, default=16)
    ap.add_argument("--snos-timeout", type=float, default=5400)
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--keep-single-pies", action="store_true")
    ap.add_argument("--replaying", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    c = Collector(args)
    loop = asyncio.new_event_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, c.stop.set)
    loop.run_until_complete(c.run())


if __name__ == "__main__":
    main()
