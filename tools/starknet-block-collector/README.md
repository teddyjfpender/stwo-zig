# starknet-block-collector

> **Development tool. Status: in progress.**
> Validated: single-block capture, and offline assembly of multi-block leaves
> (6-block leaf 15627902–15627907, OS initial/final roots match mainnet).
> `rollback.py` reproduces genuine proofs node-for-node on the blocks tested
> with `test_patricia.py`. The batched backfill pipeline (`backfill.py`) is
> still being validated.

Records everything [SNOS](https://github.com/keep-starknet-strange/snos) needs
to build Starknet OS input from mainnet RPC, so contiguous multi-block leaf
PIEs can be assembled offline, long after the node has stopped serving the
Merkle proofs for those blocks. See
`design/starknet-proving-pipeline/README.md` (section 7) for context.

## Constraints

Measured against Cartridge mainnet RPC from London:

- `starknet_getStorageProof` is served only for the last ~16–24 blocks.
- ~20 HTTP requests/s; a JSON-RPC batch counts as one request.
- ~140 ms RTT, and SNOS's blockifier re-execution does serial state reads, so
  a block with transactions takes 37–140 s to execute through the RPC — often
  longer than the proof window.

## Design

| File | Role |
|---|---|
| `rpc_store.py` | Content-addressed store: `objects/` (gzipped response bodies by sha256), `index/` (request key → object), `blocks/<n>/requests.jsonl` (per-block manifest). Request keys hash the method plus canonical params. `getStorageProof` params are canonicalised (sorted contracts/keys/classes) because SNOS emits key lists in hash-set order, so the same proof is found regardless of order. |
| `rpc_proxy.py` | Recording/replaying JSON-RPC proxy. Clients use `http://127.0.0.1:<port>/b/<block>`. Coalesces calls into paced batches across several upstreams (Cartridge for reads and proofs; PublicNode and ZAN for reads), each with its own AIMD rate. `--defer-proofs` logs expired proof requests for `backfill.py` instead of failing. |
| `spec_proofs.py` | Speculative proof capture: fetches proofs for each key/contract as soon as SNOS first reads it; the earlier design, used when the proxy runs without `--defer-proofs`. |
| `collector.py` | Follows the chain head. For each block it prefetches likely reads, captures both blocks' global roots live while they are still provable, runs SNOS `generate-pie` through the proxy, and checks the single-block OS roots against the chain. |
| `patricia.py` | Partial Starknet Patricia tries (height 251, Pedersen) built from proof nodes; set leaves and recompute roots and proof paths. |
| `rollback.py` | Rebuilds one expired `getStorageProof` answer from proofs at a fresh block plus permanent state diffs and old values. |
| `backfill.py` | Batched version: fetch proofs at one fresh block `L`, walk the tries backwards block by block using state diffs and old values, emit the deferred proofs, and verify each rebuilt contracts root against the root recorded while that block was fresh. |
| `assemble.py` | Offline replay: runs `generate-pie` over consecutive recorded blocks against a replay proxy and checks each leaf's first `old_root` and last `new_root`. |
| `pie_info.py` | Reads the OS output header and execution resources from a PIE zip. |
| `test_patricia.py` | Rolls block N's recorded tries back with N's state diff and checks the N−1 roots and proof paths match the genuine recorded ones. |

## Dependencies

- SNOS `keep-starknet-strange/snos`, branch `feature/0.14.3` @ `38cabc9`,
  built with LLVM 19 (`generate-pie` binary; default path
  `~/Coding/snos/target/release/generate-pie`).
- A cairo-lang 0.14.3a3 venv. Run every script with that venv's Python,
  because `patricia.py` uses cairo-lang's Pedersen hash.
- `aiohttp>=3.9`.

## Example

```sh
PY=~/Coding/snos/sequencer_venv/bin/python
# Recording proxy (deferring expired proof requests to the backfill)
$PY rpc_proxy.py --data block-data --port 9545 --defer-proofs
# Follow the head and capture blocks
$PY collector.py --data block-data --proxy-port 9545
# Answer deferred proof requests in batches
$PY backfill.py --data block-data --proxy-port 9545
# Assemble contiguous leaves offline
$PY assemble.py --data block-data --start 15627902 --blocks-per-leaf 6 --leaves 1
# Check trie rollback against recorded genuine proofs
$PY test_patricia.py --data block-data 15627903 15627904
```

Recorded data goes under `block-data/` at the repository root (gitignored).
