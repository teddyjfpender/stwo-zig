# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9"]
# ///
"""Recording / replaying JSON-RPC proxy in front of a Starknet node.

Clients point at ``http://127.0.0.1:<port>/b/<block>`` (SNOS appends
``/rpc/v0_10``); the block tag attributes every request to that block's
``requests.jsonl``. Modes:

* ``record``  - serve from the store when present, otherwise forward upstream
                and record the answer (successful ``result`` bodies and
                deterministic Starknet errors; transport failures are retried).
* ``replay``  - serve only from the store; a miss is a JSON-RPC error, except
                that ``--replay-fallthrough`` forwards and records methods that
                are safe to fetch late (everything but ``starknet_getStorageProof``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, TCPConnector, web

from rpc_store import RpcStore, request_key
from rollback import Rollback, roots_probe
from spec_proofs import SpecProofs

LOG = logging.getLogger("rpc_proxy")
# Methods whose answer depends on "now" must never be cached.
UNCACHEABLE = {"starknet_blockNumber", "starknet_blockHashAndNumber", "starknet_syncing"}
LATE_UNSAFE = {"starknet_getStorageProof"}
CLASS_METHODS = {"starknet_getClass", "starknet_getCompiledCasm"}
SPEC_METHODS = {"starknet_getStorageAt", "starknet_getNonce", "starknet_getClassHashAt"}
# Starknet error codes that are deterministic answers (e.g. contract not found).
DETERMINISTIC_ERRORS = {20, 24, 28, 29, 40}


READ_METHODS_V010 = {"starknet_getStorageAt", "starknet_getNonce", "starknet_getClassHashAt", "starknet_getClass",
                     "starknet_getStateUpdate", "starknet_getBlockWithTxHashes", "starknet_getBlockWithTxs",
                     "starknet_getBlockWithReceipts", "starknet_traceBlockTransactions", "starknet_chainId"}
SIMPLE_READS = {"starknet_getStorageAt", "starknet_getNonce", "starknet_getClassHashAt"}


class Upstream:
    """One node with its own adaptive (AIMD) request rate."""

    def __init__(self, name: str, url: str, rps: float, lanes: set[str], methods: set[str] | None = None,
                 concurrency: int = 4):
        self.name, self.url, self.lanes, self.methods = name, url, lanes, methods
        self.rps = self.rps_max = rps
        self.next_slot = time.monotonic()
        self.sem = asyncio.Semaphore(concurrency)

    async def pace(self) -> None:
        now = time.monotonic()
        wait = self.next_slot - now
        self.next_slot = max(now, self.next_slot) + 1.0 / self.rps
        if wait > 0:
            await asyncio.sleep(wait)

    def ok(self) -> None:
        self.rps = min(self.rps_max, self.rps + 0.05)

    def limited(self) -> None:
        self.rps = max(1.0, self.rps / 2)
        self.next_slot = max(self.next_slot, time.monotonic() + 1.0)


class Proxy:
    def __init__(self, store: RpcStore, upstream: str, mode: str, fallthrough: bool, concurrency: int,
                 rps: float = 15.0, max_batch: int = 100, batch_window: float = 0.005, extra_upstreams=(),
                 defer_proofs: bool = False):
        self.store = store
        self.upstream = upstream.rstrip("/")
        self.mode = mode
        self.fallthrough = fallthrough
        self.sem = asyncio.Semaphore(concurrency)
        self.max_batch, self.batch_window = max_batch, batch_window
        self.upstreams = [Upstream("cartridge", upstream.rstrip("/"), rps, lanes={"read", "proof"}, concurrency=16)]
        for name, url, r, methods in extra_upstreams:
            self.upstreams.append(Upstream(name, url, r, lanes={"read"}, methods=methods, concurrency=4))
        self._head: tuple[float, int] | None = None
        self.spec = SpecProofs(self.forward)
        self.defer_proofs = defer_proofs
        self.rollback = Rollback(self.forward, store)
        self.head_seen = 0
        self.session: ClientSession | None = None
        self.stats = {"hit": 0, "upstream": 0, "miss": 0, "retries": 0}

    def load_recorded_proofs(self) -> None:
        """Replay: index every recorded proof so any covered subset can be answered."""
        n = 0
        for req_file in self.store.blocks.glob("*/requests.jsonl"):
            for line in open(req_file):
                if '"starknet_getStorageProof"' not in line:
                    continue
                r = json.loads(line)
                body = self.store.lookup(r["method"], r["params"])
                if body and "result" in body:
                    self.spec.ingest(int(r["params"]["block_id"]["block_number"]), r["params"], body["result"])
                    n += 1
        self.spec.max_blocks = 10**9
        LOG.info("indexed %d recorded proofs over %d blocks", n, len(self.spec.blocks))

    async def start(self, app: web.Application) -> None:
        if self.mode == "replay":
            self.spec.max_blocks = 10**9
            self.load_recorded_proofs()
        self.session = ClientSession(
            connector=TCPConnector(limit=0, keepalive_timeout=60),
            timeout=ClientTimeout(total=120),
        )
        # Separate lanes: a serial state read must not wait behind a slow proof batch.
        self.queues = {lane: asyncio.Queue() for lane in ("read", "proof")}
        self.dispatch_tasks = [asyncio.create_task(self.dispatcher(lane)) for lane in self.queues]

    async def stop(self, app: web.Application) -> None:
        if self.session:
            await self.session.close()

    # Cartridge rate-limits HTTP requests (~20/s), not JSON-RPC calls, so all
    # concurrent calls are coalesced into upstream batches.
    async def forward(self, method: str, params) -> dict:
        fut = asyncio.get_running_loop().create_future()
        lane = "proof" if method == "starknet_getStorageProof" else "read"
        await self.queues[lane].put((method, params, fut))
        return await fut

    async def dispatcher(self, lane: str) -> None:
        queue, limit = self.queues[lane], (self.max_batch if lane == "read" else 40)
        while True:
            items = [await queue.get()]
            await asyncio.sleep(self.batch_window)
            while not queue.empty() and len(items) < limit:
                items.append(queue.get_nowait())
            asyncio.create_task(self.send_batch(items, lane))

    def pick(self, lane: str, methods: set[str]) -> "Upstream":
        """Upstream with the earliest free slot that may serve every method in the batch."""
        ok = [u for u in self.upstreams if lane in u.lanes and (u.methods is None or methods <= u.methods)]
        # Keep the proof-serving node's budget for proofs: reads prefer the others.
        return min(ok, key=lambda u: u.next_slot + (0.5 if lane == "read" and "proof" in u.lanes and len(ok) > 1 else 0))

    async def send_batch(self, items: list, lane: str) -> None:
        payload = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p, _) in enumerate(items)]
        methods = {m for m, _, _ in items}
        delay = 0.3
        for attempt in range(40):
            up = self.pick(lane, methods)
            try:
                async with up.sem:
                    await up.pace()
                    async with self.session.post(up.url, json=payload, headers={"user-agent": "stwo-zig-collector"}) as resp:
                        text = await resp.text()
                        status = resp.status
                body = json.loads(text) if status == 200 else None
                if isinstance(body, dict):  # whole-batch error object
                    body = [body | {"id": i} for i in range(len(items))]
                if isinstance(body, list) and len(body) == len(items):
                    by_id = {o.get("id"): o for o in body}
                    for i, (_, _, fut) in enumerate(items):
                        if not fut.done():
                            fut.set_result(by_id.get(i, {"error": {"code": -32098, "message": "missing in batch"}}))
                    up.ok()
                    self.stats["batches"] = self.stats.get("batches", 0) + 1
                    return
                if status == 429:
                    up.limited()
                    self.stats["rate_limited"] = self.stats.get("rate_limited", 0) + 1
                LOG.debug("batch of %d to %s got status %s", len(items), up.name, status)
            except Exception as exc:  # transport / non-JSON body
                up.limited()
                LOG.debug("batch of %d to %s attempt %d failed: %s", len(items), up.name, attempt, exc)
            self.stats["retries"] += 1
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 5.0)
        for _, _, fut in items:
            if not fut.done():
                fut.set_exception(RuntimeError("upstream batch failed"))

    @staticmethod
    def class_query(method: str, params) -> tuple[str, int] | None:
        """(class_hash, block_number) for a by-number class fetch, else None."""
        if method not in CLASS_METHODS:
            return None
        if isinstance(params, dict):
            block_id, class_hash = params.get("block_id"), params.get("class_hash")
        elif isinstance(params, list) and len(params) == 2:
            block_id, class_hash = params
        else:
            return None
        if isinstance(block_id, dict) and "block_number" in block_id and class_hash:
            return class_hash, int(block_id["block_number"])
        return None

    async def answer(self, block: int | None, req: dict) -> dict:
        method, params, rid = req.get("method"), req.get("params", []), req.get("id")
        t0 = time.perf_counter()
        key = request_key(method, params)
        cq = self.class_query(method, params)
        if self.mode == "record" and not self.defer_proofs:
            self.speculate(method, params)
        cached = None if method in UNCACHEABLE else self.store.lookup(method, params)
        if cached is None and cq is not None:
            cached = self.store.lookup_class(method, *cq)
        synthesized = None
        if cached is None and method == "starknet_getStorageProof":
            synthesized = self.spec.synthesize(params)
        if cached is not None:
            source, body = "store", cached
            self.stats["hit"] += 1
        elif synthesized is not None:
            source, body = "synthesized", {"result": synthesized}
            self.store.record(method, params, body)
        elif (self.defer_proofs and block is not None and method == "starknet_getStorageProof"
              and int(params["block_id"]["block_number"]) < self.head_seen - 10):
            source, body = "deferred", self.defer(block, params)
        elif self.mode == "replay" and not (self.fallthrough and method not in LATE_UNSAFE | UNCACHEABLE):
            source, body = "miss", {"error": {"code": -32099, "message": f"replay miss: {method}"}}
            self.stats["miss"] += 1
            detail = self.spec.missing(params) if method == "starknet_getStorageProof" else json.dumps(params)[:200]
            LOG.warning("replay miss block=%s %s %s", block, method, detail)
        else:
            full = await self.forward(method, params)
            body = {k: full[k] for k in ("result", "error") if k in full}
            self.stats["upstream"] += 1
            source = "upstream"
            cacheable = method not in UNCACHEABLE and (
                "result" in body or body.get("error", {}).get("code") in DETERMINISTIC_ERRORS
            )
            if cacheable:
                self.store.record(method, params, body)
                if cq is not None and "result" in body:
                    self.store.record_class(method, cq[0], cq[1], body)
            if method == "starknet_getStorageProof":
                if "result" in body:
                    self.spec.ingest(int(params["block_id"]["block_number"]), params, body["result"])
                elif body.get("error", {}).get("code") == 42 and self.defer_proofs and block is not None:
                    source, body = "deferred", self.defer(block, params)
                elif body.get("error", {}).get("code") == 42 and self.mode == "record" and not self.defer_proofs:
                    rebuilt = await self.rollback.serve(params)
                    if rebuilt is not None:
                        body, source = {"result": rebuilt}, "rollback"
                        self.store.record(method, params, body)
                    else:
                        LOG.warning("proof unavailable block=%s: %s (%s)", block, body.get("error"), self.spec.missing(params))
        if block is not None:
            self.store.note_request(block, method, params, key, source, (time.perf_counter() - t0) * 1e3)
        return {"jsonrpc": "2.0", "id": rid, **body}

    async def handle(self, request: web.Request) -> web.Response:
        tag = request.match_info.get("block")
        block = int(tag) if tag and tag.isdigit() else None
        if block is not None and block > self.head_seen:
            self.head_seen = block
        payload = await request.json()
        if isinstance(payload, list):
            out = await asyncio.gather(*(self.answer(block, r) for r in payload))
        else:
            out = await self.answer(block, payload)
        return web.json_response(out)

    def defer(self, block: int | None, params: dict) -> dict:
        """Log an expired proof request for the batched backfill; answer with a placeholder.

        SNOS issues every proof request before using any, so a well-formed
        placeholder lets discovery finish. The placeholder is never recorded.
        """
        self.stats["deferred"] = self.stats.get("deferred", 0) + 1
        if block is not None:
            with open(self.store.block_dir(block) / "pending_proofs.jsonl", "a") as f:
                f.write(json.dumps(params) + "\n")
        roots = self.store.lookup("starknet_getStorageProof", roots_probe(int(params["block_id"]["block_number"])))
        zero = {"class_hash": "0x0", "nonce": "0x0", "storage_root": "0x0"}
        return {"result": {
            "classes_proof": [],
            "contracts_proof": {"nodes": [], "contract_leaves_data": [zero for _ in params.get("contract_addresses", [])]},
            "contracts_storage_proofs": [[] for _ in params.get("contracts_storage_keys", [])],
            "global_roots": (roots or {}).get("result", {}).get("global_roots")
            or {"block_hash": "0x0", "classes_tree_root": "0x0", "contracts_tree_root": "0x0"},
        }}

    def speculate(self, method: str, params) -> None:
        """Queue proofs for what SNOS reads, at the read block and the one after."""
        cq = self.class_query(method, params)
        if cq is not None and cq[1] >= self.head_seen - 14:
            for b in (cq[1], cq[1] + 1):
                self.spec.want_class(b, cq[0])
            return
        if method not in SPEC_METHODS or not isinstance(params, dict):
            return
        bid = params.get("block_id")
        if not (isinstance(bid, dict) and "block_number" in bid) or "contract_address" not in params:
            return
        m = int(bid["block_number"])
        if m < self.head_seen - 14:
            return  # outside the proof window; rollback covers it
        for b in (m, m + 1):
            self.spec.want(b, params["contract_address"], params.get("key"))

    async def head(self, request: web.Request) -> web.Response:
        """Chain head, cached for a second, so pollers share the paced upstream budget."""
        now = time.monotonic()
        if self._head is None or now - self._head[0] > 1.0:
            body = await self.forward("starknet_blockNumber", [])
            if "result" in body:
                self._head = (now, int(body["result"]))
        return web.json_response({"head": self._head[1] if self._head else None})

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"rps": {u.name: round(u.rps, 2) for u in self.upstreams}, "mode": self.mode, **self.stats, **self.spec.stats, **self.rollback.stats})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--network", default="mainnet")
    ap.add_argument("--upstream", default="https://api.cartridge.gg/x/starknet/mainnet/rpc/v0_10")
    ap.add_argument("--port", type=int, default=9545)
    ap.add_argument("--mode", choices=("record", "replay"), default="record")
    ap.add_argument("--replay-fallthrough", action="store_true")
    ap.add_argument("--concurrency", type=int, default=8, help="max upstream HTTP requests in flight")
    ap.add_argument("--rps", type=float, default=15.0, help="upstream HTTP requests per second (batches)")
    ap.add_argument("--no-extra-upstreams", action="store_true", help="send reads only to --upstream")
    ap.add_argument("--defer-proofs", action="store_true",
                    help="log expired proof requests for backfill.py instead of rolling back per request")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    extra = [] if args.no_extra_upstreams else [
        ("publicnode", "https://starknet-rpc.publicnode.com", 8.0, READ_METHODS_V010),
        ("zan", "https://api.zan.top/public/starknet-mainnet", 6.0, SIMPLE_READS),
    ]
    proxy = Proxy(RpcStore(args.data, args.network), args.upstream, args.mode, args.replay_fallthrough,
                  args.concurrency, rps=args.rps, extra_upstreams=extra, defer_proofs=args.defer_proofs)
    app = web.Application(client_max_size=512 * 1024**2)
    app.on_startup.append(proxy.start)
    app.on_cleanup.append(proxy.stop)
    app.router.add_get("/health", proxy.health)
    app.router.add_get("/head", proxy.head)
    for prefix in ("/b/{block}", ""):
        app.router.add_post(prefix + "/rpc/{version}", proxy.handle)
        app.router.add_post(prefix + "/", proxy.handle)
        app.router.add_post(prefix or "/x", proxy.handle)
    web.run_app(app, host="127.0.0.1", port=args.port, access_log=None, print=None)


if __name__ == "__main__":
    main()
