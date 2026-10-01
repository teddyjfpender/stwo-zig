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
| `circuit_pipeline.py` | Prove contiguous committed PIEs through the pinned leaf bootloader, wrap each Cairo proof as a circuit proof, and fold them into one recursive root. Validates manifest digests and root continuity, records time/RSS per stage, and optionally compares all root files byte for byte with the pinned Rust reducer. The final applicative proof binding that root to the aggregator remains a separate stage. |
| `run_cuda_resident_paired.sh` | Run the same two adapted PIEs on one NVIDIA GPU in serial, shared-runtime batch, and opt-in fixed-coefficient-image modes. One memory-sampled trial per mode precedes uninstrumented timing in ABCCBA order. Every run requires exact leaf/root digests against the Rust-qualified receipt. Set `STWO_PINNED_CAIRO_VERIFIER` to also verify the published CUDA Cairo proofs with pinned Rust after each run. |
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

## Two-leaf circuit root on M5 Max

The following run used the production circuit registry (70 FRI queries and 26
PoW bits in both Cairo and circuit proofs), two committed consecutive mainnet
PIEs, ReleaseFast Zig, and the pinned `proving@5a7c5ed` Rust adapter. The
numbers are serial wall time on 2026-09-30; process peak RSS is not additive.

| Program or stage | Blocks | Cairo steps | CPU time | Metal time | CPU / Metal peak RSS |
|---|---:|---:|---:|---:|---:|
| `leaf_simple_bootloader`, PIE 15627902–15627904: adapt, Cairo prove, circuit wrap | 15627902–904 | 1,224,007 | 47.80 s | 30.96 s | 28.49 / 17.03 GB |
| `leaf_simple_bootloader`, PIE 15627905–15627907: adapt, Cairo prove, circuit wrap | 15627905–907 | 785,807 | 49.74 s | 32.15 s | 28.10 / 17.04 GB |
| `circuit_multiverifier`, two leaves → root | 15627902–907 | — | 8.58 s | 12.87 s | 13.81 / 16.90 GB |
| **PIEs → one circuit root** | **15627902–907** | **2,009,814** | **106.13 s** | **75.98 s** | **28.49 / 17.04 GB** |

The serial totals break down as follows. Each receipt now also records these
phases in `phase_breakdown_s`; the small remainder includes process startup,
file publication, and rounding of the per-proof timers.

| Phase | CPU | Metal |
|---|---:|---:|
| Adapt the two PIEs | 0.85 s | 0.81 s |
| Load the adapted inputs | 0.44 s | 0.43 s |
| Prove the two Cairo PIEs | 70.38 s | 37.49 s |
| Wrap the two proofs as circuit leaves | 25.80 s | 24.33 s |
| Fold both leaves into one root | 8.58 s | 12.87 s |
| Process overhead | 0.07 s | 0.05 s |
| **Serial total** | **106.13 s** | **75.98 s** |

The root proof is 1,508,773 bytes. Both Metal leaf proofs, the root proof,
root outputs, and packed tree are byte-identical to CPU; the three root files
are also identical to the pinned Rust reducer. The first CPU leaf proof is
byte-identical to Rust `leaf-prover`. Rust's reducer took 9.90 s and 33.14 GB
RSS on the same inputs; Rust's first leaf took 26.78 s and 50.51 GB RSS.
The Metal run admitted 70/79 Cairo AIR composition components to the device
and 11/11 circuit components; nine Cairo components still used the declared
host path. macOS `time -l` reported a **34.75 GB peak memory footprint** for
the Metal run (28.50 GB for CPU), which includes memory not represented by
process RSS. The smaller Metal RSS is therefore not a total-memory reduction.
Neither the Rust parity comparison nor the original OS PIE generation is
included in the 106.13 s. The committed Starknet aggregator PIE for these two
leaves has 18,816 Cairo steps, but the circuit root alone does not bind that
aggregator output. The circuit applicative bootloader must do that before this
is a final aggregate Starknet proof.

To reproduce the PIE-to-root receipt (including an optional Rust comparison):

```sh
python3 tools/starknet-block-collector/circuit_pipeline.py \
  --oracle /path/to/stwo-circuit-oracle \
  --proving-root /path/to/proving-at-5a7c5ed \
  --rust-reducer /path/to/stwo_run_and_prove_recursive_tree \
  --out /tmp/starknet-circuit-root \
  15627902-15627904 15627905-15627907
```

For Metal, first build `src/integrations/circuit_metal` with
`zig build -Doptimize=ReleaseFast`, then add `--backend metal` to the command.

For the fully resident CUDA paired experiment, build
`circuit-recursion-cuda-resident`, generate the canonical preprocessing artifact,
and supply an absolute path to it. The adapted directory must contain the two
`*.prover_input.json` files and matching `*.preimage.hex.json` files. The
driver checks their hashes, the production security settings, both leaf files,
and all three root files against the committed Rust-qualified receipt:

```sh
export STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS=/absolute/path/preprocessed-canonical.bin
tools/starknet-block-collector/run_cuda_resident_paired.sh \
  /absolute/path/adapted /absolute/path/results
```

The nine trial directories retain proof JSON, logs, receipts, and sampled
memory from the first three trials. The runner reports uninstrumented
two-run medians for both subprocess time (`serial_wall_s`, comparable to the
earlier 32.308 s H100 receipt) and the driver wall from adapted-input loading
until the root file exists (`adapted_input_to_root_wall_s`). The latter includes
input copies, manifest checks, and assembly between proving commands. If the pinned Rust Cairo verifier is available
on that host, set
`STWO_PINNED_CAIRO_VERIFIER` to its absolute path; otherwise copy the output
directories to a host with the verifier and run `verify_cuda_cairo.py` there.
