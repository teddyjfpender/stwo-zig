# Starknet proving pipeline: leaves, aggregation, settlement — 2026-09-29

What it takes to prove Starknet the way StarkWare does: many Starknet OS
"leaf" proofs, recursively merged, aggregated into one Starknet state update,
and wrapped for Ethereum. The goal is a GPU cluster architecture that minimises
cost, and a list of what stwo-zig still has to prove.

Status markers: **VERIFIED** (read in code or on chain, with a reference),
**INFERRED** (reasoned from evidence, not traced end to end), **MEASURED**
(local measurement, with host).

## 1. Summary

- A leaf is **one Starknet OS run over several consecutive blocks**. Our
  SN_PIE_1–4 are genuine mainnet leaves: 7, 4, 11 and 5 blocks of Starknet
  0.14.2 (June 2026), each with `full_output=1`, `use_kzg_da=0`,
  `os_program_hash=0`. The block hashes in their output headers match mainnet
  (VERIFIED, `tools/starknet-block-collector/pie_info.py`).
- Above the leaves, StarkWare's newest pipeline (`starkware-libs/proving`
  `5a7c5ed`, "SHARP 8.0") replaces Cairo-verifier recursion with **M31 circuit
  recursion**: each leaf proof is verified by a circuit, circuits are folded
  2-to-1, and only the root is verified inside Cairo, together with the Starknet
  aggregator, by a single applicative-bootloader run (VERIFIED in code; whether
  it is live in production is INFERRED/unknown).
- Ethereum still verifies a **Stone** proof (`recursive_large_output` layout,
  Keccak channel) through the SHARP GPS verifier: ~5.6–6.0M gas per proof,
  one proof every ~1.5 h, shared with other SHARP customers (VERIFIED on chain).
- Mainnet load is small. All leaf + recursion proving is roughly **4–8 H100
  GPU-hours per day**; cluster size is set by latency, redundancy and GPU memory,
  not throughput. L1 gas (~$120k/yr at 1 gwei and an assumed $3k/ETH) exceeds
  compute (~$42k/yr).

## 2. The pipeline

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ STARKNET SEQUENCER (Apollo, Rust)          not ours; source of truth │
 │ batcher executes blocks · committer updates Patricia tries           │
 └───────────────────────────────┬──────────────────────────────────────┘
                                 │ OS input for N blocks (txs, execution
                                 │ infos, trie proofs, compiled classes)
                                 ▼
 ┌──────────── GPU NODE (H100 80GB, ~26 vCPU, ~200GB RAM) ─────────────┐
 │ [1] EXECUTE      CPU · Rust (cairo-vm + starknet_os hints)          │
 │     runs  os.cairo  ─────────────────────────────►  CairoPie (RAM)  │
 │ [2] LEAF RUN     CPU · Rust (cairo-program-runner + adapter)        │
 │     runs  leaf_simple_bootloader.cairo  (task = that PIE)           │
 │     ─────────────────────────────────►  ProverInput (~300MB, RAM)   │
 │ [3] LEAF PROVE   GPU · Stwo, Blake2s-M31 channel ► leaf Cairo proof │
 │ [4] LEAF WRAP    circuit_cairo_verifier checks [3] ► circuit proof  │
 └───────────────────────────────┬─────────────────────────────────────┘
                                 │ circuit proof + output preimage (small)
                                 ▼
          OBJECT STORE + JOB QUEUE ◄──► COORDINATOR (blocks→leaves→tree)
                                 ▼
 [5] FOLD         circuit_multiverifier: 2 children → 1, ⌈log2 N⌉ levels
                  internal folds M31 channel; root Blake2s, felt252 args
                                 ▼
 [6] AGGREGATE    circuit_applicative_bootloader.cairo
                    ├─ aggregator task: aggregator/main.cairo + N leaf outputs
                    └─ verifier task:   stwo_circuit_verifier (Cairo 1) + root
                  ► Stwo proof + DA blobs (compressed state diff, KZG)
                                 ▼
 [7] L1 WRAP      Stone prover (C++), recursive_large_output, Keccak
                                 ▼
 [8] L1 SUBMIT    GPS verifier (verifyMerkle×3, verifyFRI×7, pages,
                  verifyProofAndRegister ≈5.8M gas) → fact;
                  Starknet core updateStateKzgDA(programOutput, kzgProofs)
```

### Stage details

| # | Program proved / run | Inputs | Output | Where |
|---|---|---|---|---|
| 1 | `core/os/os.cairo` (Cairo 0), run only | OS input for N blocks: transactions and blockifier execution infos; block info; prev/new block hash; Patricia proofs for every touched storage key, contract and class, before and after each block; CASM of executed classes; chain id, fee token, committee keys; `full_output=1`, `use_kzg_da=0` | CairoPie; OS output header = roots, block range and hashes, full state diff, L1↔L2 messages | sequencer `crates/apollo_starknet_os_program`, `starknet_os` |
| 2 | `leaf_simple_bootloader.cairo` (Cairo 0) with one task: the PIE | PIE | public output = **exactly 2 cells**, the Blake2s digest of (OS program hash, OS output); full output carried as a hash preimage | `proving/crates/leaf_prover/src/prove_leaf.rs` (`N_OUTPUTS == 2`) |
| 3 | Stwo proof of [2] | `ProverInput` from `adapt()`, registry `cairo_prover_params` | leaf Cairo proof, `Blake2sM31MerkleChannel` | `prove_leaf.rs` |
| 4 | `circuit_cairo_verifier` (Rust M31 circuit, not Cairo) | leaf proof, leaf bootloader program, 2-cell output | circuit proof, uniform shape for all leaves (~3 s on a laptop per StarkWare) | `proving/crates/circuit_cairo_verifier` |
| 5 | `circuit_multiverifier` | two child circuit proofs | parent circuit proof; balanced tree, odd node carried; single leaf folds with itself; also `packed_output` preimage tree | `proving/crates/stwo_run_and_prove_recursive_tree` |
| 6 | `circuit_applicative_bootloader.cairo` (Cairo 0) | `aggregator_task` (`core/aggregator/main.cairo` + N leaf OS outputs, OS program hash, `use_kzg_da=1`, `full_output=0`, public keys), `verifier_task` (`stwo_circuit_verifier` Cairo 1 + root proof), `packed_output`, `supported_circuit_hashes` | one Stwo proof that the root verifies, the tree unpacks to exactly the aggregator's inputs, and the aggregator's combined output is correct; plus blob data | `proving/crates/cairo-program-runner-lib/src/hints/types.rs` `CircuitApplicativeBootloaderInput` |
| 7 | Stone proof of the SHARP root | Stwo proof(s) of [6], other customers' tasks (INFERRED) | Stone proof | on chain: `cairoVerifierId=7`, 11 queries, log blowup 6, 30 PoW bits |
| 8 | L1 transactions | Stone proof; program output + blobs | registered fact; new state root | SHARP proxy `0x4731…Db60`, core `0xc662…8c4` |

The aggregator ([`combine_blocks.cairo`](https://github.com/starkware-libs/sequencer/blob/39ed6782dea45f47ef5a1d49a7f9bf1030283fba/crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/aggregator/combine_blocks.cairo))
asserts that each leaf's initial root, block number and block hash equal the
previous leaf's final values. **Leaves must be contiguous**. The OS runs the same
`combine_blocks` internally over the blocks of one leaf (`os_utils.cairo`
`process_os_output`).

### Older pipeline

If SHARP 8.0 is not yet live, stages 4–5 are bootloader runs of the Cairo 1
`stwo_cairo_verifier`, ~**18.15M Cairo steps per verified proof** (stwo-cairo
CI, Blake2s inner proof, 70 queries, 26 PoW bits) and ~1 minute per node per
StarkWare. Recursion then costs more than the leaves, roughly tripling GPU time.

## 3. Hard constraint: everything is hash-pinned

The OS program, aggregator, bootloaders, circuit hashes and proof parameters
are pinned by L1 (program hashes in the core contract and fact registry, circuit
hashes in `supported_circuit_hashes`, parameters in the circuit registry). **No
Cairo program or circuit may change.** An alternative prover competes only on
how fast and cheaply it produces proofs that StarkWare's verifiers accept
bit-for-bit.

## 4. Languages and ownership

| Component | Language | Owner | Notes |
|---|---|---|---|
| Starknet OS, aggregator, leaf/applicative bootloaders | Cairo 0 | StarkWare | pinned; reuse |
| `stwo_circuit_verifier` | Cairo 1 | StarkWare | pinned |
| cairo-vm, OS hints, program runner, adapter | Rust | StarkWare / LambdaClass | reuse |
| Leaf and fold circuits | Rust | StarkWare | circuit hashes pinned; the prover may be replaced |
| **Leaf Stwo prover (GPU)** | Zig + CUDA/Metal | ours | needs Blake2s-M31 channel + registry parameters |
| **Circuit prover on GPU** | Zig/CUDA or Rust | ours, later | CPU Rust acceptable at first |
| **Worker** (execute → leaf run → prove in one process) | Rust | ours | hosts cairo-vm and runner, calls Zig over C ABI; no PIE serialization |
| **Coordinator** | Rust | ours | block→leaf→tree→batch scheduling, retries |
| Stone prover | C++ | StarkWare | reuse |
| **L1 submitter** | Rust | ours | only if settling ourselves |
| GPS verifier, core contract | Solidity | StarkWare | deployed |

## 5. Workload and cost model

MEASURED from mainnet RPC (2026-09-29) and the four SN PIEs:

| | now | June 2026 |
|---|---|---|
| blocks/day | 51k | 33k |
| txs/day | 109k | 259k |
| txs/block | 2.1 | 7.9 |
| Cairo steps/tx | 150–310k (SN PIEs) | |
| empty block | ~15k steps (collector) | |
| state update | every 1,500 blocks ≈ 160 leaves (VERIFIED on chain) | |

With the user's measurement of SN_PIE_2 (7.7M steps) in ~1.5 s on an H100
(Rust Stwo CUDA), leaf proving is ~5M steps/s/GPU. Starknet needs roughly
2–4 GPU-hours/day for leaves, 1–2 for circuit recursion (assuming the ~3 s
circuit verifier), negligible aggregation: **4–8 H100-hours/day**.

Recommended deployment: 2 × single-H100 nodes on different providers, with
execute/leaf-run on the GPU node's own CPUs (PIE/ProverInput stays in RAM; 300 MB
per leaf would otherwise be 1.5–3 TB/day of I/O), plus a 64-core CPU server for
Stone and coordination.

| Item | Assumed price | Monthly |
|---|---|---|
| 2 × H100 80GB, 1-yr reserved | ~$1.8/GPU-hr | ~$2.6k |
| 1–2 × 64-core/256GB dedicated | $300–400 each | ~$0.35–0.7k |
| storage/network (co-located) | | ~$0.1–0.3k |
| **Compute total** | | **~$3.5k (~$42k/yr)** |

L1 at SHARP's cadence: ~110M gas/day ≈ 0.11 ETH/day at 1 gwei. That's
≈$120k/yr at an assumed $3k/ETH, linear in gas price. Prices are assumptions,
not quotes.

**GPU memory is the open sizing question.** stwo-zig's CUDA plan puts SN_PIE_2
at ~58 GB device memory; Metal host footprint is 32–52 GB for SN_PIE_1–4 (M5
Max, `autoresearch/notes/2026-09-27-cairo-completion`). If 14M-step leaves do not
fit 80 GB, cap leaves at ~8M steps (cheap with circuit recursion) or use H200.

## 6. What stwo-zig can prove today

| Program / stage | Status |
|---|---|
| OS PIE under the simple bootloader (CPU, Metal) | EXISTS. Adapter runs PIEs through `simple_bootloader` (proving `5a7c5ed`), Blake2s channel, official verifier accepts |
| `leaf_simple_bootloader` + Blake2s-M31 channel | ABSENT. Channel exists in core only; Cairo products are Blake2s-only |
| Leaf wrap and folds (M31 circuits) | ABSENT. StarkWare Rust only |
| Applicative bootloader with aggregator + Cairo 1 verifier task | ABSENT. The adapter has no bootloader program-input path |
| Stone | out of scope; StarkWare C++ |

Benchmarks of each stage on real contiguous mainnet leaves: section 8.

## 7. Test data: live mainnet collection

`tools/starknet-block-collector/` records everything
[SNOS](https://github.com/keep-starknet-strange/snos) (`feature/0.14.3`,
sequencer `APOLLO-0.14.3-RC.15`) needs to build OS input, so multi-block leaves
can be assembled offline later.

Constraints found on Cartridge mainnet RPC (MEASURED, London):

- `starknet_getStorageProof` serves only the last ~16–24 blocks (~30–40 s).
- ~20 HTTP requests/s; a JSON-RPC batch of 100 calls counts as one request.
- ~140 ms RTT; SNOS's blockifier re-execution makes ~100–250 serial reads per
  block with transactions, taking 37–140 s. That's too slow to fetch proofs
  after execution.

The collector therefore:

- runs every RPC call through a recording proxy with a content-addressed store
  and per-block manifests. `getStorageProof` params are canonicalised before
  lookup, because SNOS emits key lists in hash-set order;
- coalesces calls into paced JSON-RPC batches across several upstreams
  (Cartridge for proofs and reads; PublicNode and ZAN for reads), each with an
  AIMD rate, and prefetches each block's likely reads in parallel on arrival;
- captures each block's global roots **live**, while the block is still
  provable (`starknet_getStorageProof` root probes at N−1 and N);
- runs the proxy with `--defer-proofs`. SNOS executes each block (discovery),
  and proof requests that arrive after the window has closed are logged rather
  than failed;
- answers the deferred requests with a **batched trie backfill**
  (`backfill.py`). It fetches proofs at one fresh block L, then walks the
  Patricia tries backwards one block at a time using the permanent state
  diffs and old values (`getStorageAt`/`getNonce`/`getClassHashAt` at old
  blocks). It checks each rebuilt contracts-trie root against the root
  recorded while that block was fresh;
- validates every block by running the OS on it alone and comparing the output
  roots with the chain. Multi-block leaves are assembled offline by replaying
  the store (`assemble.py`), with the same state-root checks.

Status (in progress): single-block capture and offline multi-block assembly
are validated (6-block leaf 15627902–15627907, roots match mainnet). Trie
rollback reproduces genuine proofs node-for-node on the blocks tested
(`test_patricia.py`). The batched backfill is still being validated.

Target: ~150 contiguous blocks → 3–5 contiguous leaves of ~30 blocks, which is
enough to exercise every stage (≥2 leaves for folds and aggregation, 3 to hit
the odd-leaf carry). Cost at 1,500 blocks is extrapolated from per-stage timings.

## 8. Benchmarks

MEASURED on an Apple M4 Max (36 GB, macOS 15.3), **CPU product only**. The
committed Metal composition metallib targets a newer macOS and can't load on
this host. Numbers are single runs.

| Stage | Input | Prover | Wall | Peak RSS | Notes |
|---|---|---|---|---|---|
| Leaf prove + verify | 6-block mainnet leaf 15627902–15627907, 1,580,295 steps, PIE 10 MB | stwo-zig CPU run-and-prove | 5.04 s | 5.6 GB | proof 2.07 MB (binary) |
| Leaf prove | same leaf | official Rust `stwo-run-and-prove` (simple bootloader, canonical, 70 queries, PoW 26, fold_step 3) | 20.4 s | 23.7 GB | **not like-for-like**: ran concurrently with the block collector, different proving parameters |
| Aggregator prove | aggregator PIE over that leaf, 17,325 steps | official Rust prover | 7.7 s | 13.1 GB | same caveat |
| Aggregator prove + verify | same | stwo-zig CPU (after the `memory_address_to_id` rebinding fix) | not recorded | ~1.24 GB | official Rust verifier accepts |
| circuit-params registry generation | `leaf_simple_bootloader`, trace log 25–26 | StarkWare `proving` | 18.5 s | 19.8 GB | |
| Leaf prover (Cairo proof + circuit verifier) | 6-block leaf | StarkWare `leaf_prover` | — | — | exceeded available memory (~18 GB into swap), stopped; needs a larger host |

Not yet measured: fold (`circuit_multiverifier`), aggregation under the
applicative bootloader, and the L1 wrap.
