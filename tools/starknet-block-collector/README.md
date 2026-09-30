# starknet-block-collector

> **Development tool.** It builds contiguous multi-block Starknet OS leaf PIEs
> from mainnet RPC, proves them, and aggregates them. Validated so far:
>
> - 3-, 6- and 30-block mainnet leaves whose OS initial and final roots match
>   the chain;
> - two contiguous leaves aggregated with the Starknet aggregator;
> - every leaf and aggregator proof accepted by the official Rust verifier.
>
> The committed PIEs are in `vectors/starknet/mainnet/`.

It records every RPC response [SNOS](https://github.com/keep-starknet-strange/snos)
needs to build Starknet OS input, so leaf PIEs can be rebuilt offline and
byte-for-byte. See `design/starknet-proving-pipeline/README.md` for the pipeline
context.

## Recommended path: an archive node

`https://mainnet.nodes.starknet.org/rpc/v0_10` (spec 0.10.2) serves
`starknet_getStorageProof` at any depth. This was tested 100,000 blocks back, and
the returned global roots hash to the chain's `new_root` at each block checked.
It also accepts batches of 100 calls. That removes every proof-window problem:
point the recording proxy at it and run SNOS over any block range.

```sh
PY=~/Coding/snos/sequencer_venv/bin/python   # cairo-lang 0.14.3a3 venv (+ aiohttp, crypto-cpp-py)
$PY rpc_proxy.py --data block-data --port 9545 \
    --upstream https://mainnet.nodes.starknet.org/rpc/v0_10 --no-extra-upstreams --rps 15

# One 30-block leaf. SNOS must reuse connections: without pooling it opens one
# TCP connection per request and exhausts macOS ephemeral ports (EADDRNOTAVAIL).
BL=$(python3 -c "print(','.join(str(b) for b in range(15630654, 15630684)))")
SNOS_MAX_PARALLEL_BLOCKS=6 SNOS_RPC_POOL_MAX_IDLE_PER_HOST=64 \
SNOS_RPC_REQUEST_TIMEOUT_SECS=600 SNOS_RPC_CONNECT_TIMEOUT_SECS=120 \
  ~/Coding/snos/target/release/generate-pie --blocks $BL \
    --rpc-url http://127.0.0.1:9545/b/15630654 --chain mainnet --output leaf.zip

# Prove the leaves, verify them officially, aggregate, and prove the aggregator.
$PY prove_pipeline.py --data block-data --start 15627902 --blocks-per-leaf 3 --leaves 2
```

Measured from London: a 30-block leaf (13,370,386 steps) takes about 50 min
wall-clock but only about 92 s of CPU at 1.6 GB peak. The run is bound by about
0.5 s of latency per serial blockifier read, so run several leaves concurrently,
or run near the node.

## Fallback path: live capture from a pruning node

Most public nodes, Cartridge included, serve storage proofs only for the last
~16–24 blocks. Cartridge also allows ~20 HTTP requests/s, with a JSON-RPC batch
counting as one request. SNOS's re-execution can take minutes per block, which
is longer than that window. The fallback therefore captures each block's global
roots live and discovers what SNOS asks for. It then rebuilds the expired proofs
in batches from one fresh block, walking the Patricia tries backwards with the
permanent state diffs.

Status:

- The rollback reproduces node-served proofs node-for-node on every block
  compared.
- Every rebuilt root is checked against the chain:
  `Poseidon("STARKNET_STATE_V0", contracts_root, classes_root) == new_root`.
- Single blocks and short runs work.
- Long contiguous runs did not converge from London. Rate limits slow
  discovery, the rebuild gap grows past ~1–2k blocks, and the single
  fresh-block burst plus sibling cascades no longer fit the window. Use an
  archive node instead.

## Files

| File | Role |
|---|---|
| `rpc_store.py` | Content-addressed store: `objects/` (gzipped response bodies by sha256), `index/` (request key → object), and `blocks/<n>/requests.jsonl`. `getStorageProof` params are canonicalised (sorted contracts, keys and classes), and answers are permuted back to the caller's order, because SNOS emits key lists in hash-set order. |
| `rpc_proxy.py` | Recording/replaying JSON-RPC proxy (`http://127.0.0.1:<port>/b/<block>`). Coalesces concurrent calls into paced upstream batches with per-upstream AIMD rates, and keeps separate read and proof lanes. `--defer-proofs` logs expired proof requests for `backfill.py`. `--mode replay` serves only recorded data. |
| `prove_pipeline.py` | Assemble leaves, prove each with stwo-zig CPU, verify with the official Rust verifier, run the aggregator over the leaf outputs, and prove and verify the aggregator PIE. Stages run one at a time behind a swap guard. |
| `assemble.py` | Runs `generate-pie` over consecutive blocks through a proxy and checks each leaf's first `old_root` and last `new_root` against the chain. |
| `pie_info.py` | Reads the OS output header and execution resources from a PIE zip. |
| `collector.py` | Fallback: follows the head, prefetches likely reads, captures global roots live, runs SNOS per block, and checks the single-block OS roots. |
| `backfill.py` | Fallback: fetches proofs at one fresh block, walks the tries backwards (old values come from the diffs, with one read per key), emits the deferred proofs, and verifies each block's state root. |
| `patricia.py` | Partial Starknet Patricia tries (height 251, Pedersen): parse from proof nodes, set leaves, expand opaque subtrees in place, and recompute roots and proof paths. Uses `crypto-cpp-py`'s native Pedersen (about 6x faster than cairo-lang's). |
| `rollback.py`, `spec_proofs.py` | Earlier per-request rollback and speculative capture, superseded by `backfill.py`. |
| `test_patricia.py` | Rolls block N's recorded tries back with N's state diff and checks the N−1 roots and proof paths. |

## Dependencies

- SNOS `keep-starknet-strange/snos`, branch `feature/0.14.3` @ `38cabc9`, built
  with LLVM 19.
- A cairo-lang 0.14.3a3 venv with `aiohttp` and `crypto-cpp-py`.
- `tools/starknet-aggregator-rs` for the aggregator step.

Recorded data goes under `block-data/` at the repository root (gitignored).
