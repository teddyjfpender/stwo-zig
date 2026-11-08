# Starknet proving pipeline: leaves, aggregation, settlement — 2026-09-29 (cost model updated 2026-09-30)

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
- Mainnet load is small. With stwo-zig CUDA leaf proofs at 0.66–1.03 s on an
  H200 (PR #203), all GPU proving is roughly **2–4 H200-hours per day**. Cluster
  size is set by GPU memory (~100 GB for 14M-step leaves), redundancy and
  latency, not throughput.
- **The time bottleneck is on the CPU side, and it is not the Cairo VM.**
  cairo-vm runs the Starknet OS at ~2.7M steps/s (5.36M steps in ~2 s,
  MEASURED), so ~5 s for a 13M-step leaf. The long poles are preparing the OS
  input (blockifier re-execution and state reads, 129 s wall / ~30 s CPU for 10
  blocks from a local recording) and PIE serialization plus cold ingress
  (~7–8 s), against ~1 s of GPU per leaf proof (§5.2). Recursion (leaf wrap plus
  fold, two fixed-shape circuit proofs per leaf) costs about as much GPU as the
  leaves themselves.
- **Estimated running cost ≈ $215/day (~$78k/yr)** at today's gas (0.10 gwei,
  ETH $2,674): about $170/day of compute and $45/day of L1. The range is
  ~$170–550/day depending on reserved vs on-demand pricing and gas (§5.4).

## 2. The pipeline

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ STARKNET SEQUENCER (Apollo, Rust)          not ours; source of truth │
 │ batcher executes blocks · committer updates Patricia tries           │
 └───────────────────────────────┬──────────────────────────────────────┘
                                 │ OS input for N blocks (txs, execution
                                 │ infos, trie proofs, compiled classes)
                                 ▼
 ┌──────────── GPU NODE (H200 141GB, ~24 vCPU, ~250GB RAM) ────────────┐
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

### 5.1 Load (MEASURED from mainnet RPC, 2026-09-29, and the SN PIEs)

| | now | June 2026 |
|---|---|---|
| blocks/day | 51k | 33k |
| txs/day | 109k | 259k |
| txs/block | 2.1 | 7.9 |
| Cairo steps/tx | 150–310k (SN PIEs) | |
| empty block | ~15k steps (collector) | |
| state update | every 1,500 blocks ≈ 160 leaves (VERIFIED on chain) | |

A ~13M-step leaf is ~30 blocks today (MEASURED: 15630654–683 = 13,370,386
steps; 15630684–713 = 10,816,445), so the chain produces **~1.7k leaves/day
now** and ~5k/day at June-2026 load. Sizing below uses the June load (5k/day) as
the design point.

### 5.2 Where the work is, per 1,500-block batch (~160 leaves)

| Stage | Jobs/batch | Per job | Where | Share of GPU time |
|---|---|---|---|---|
| OS input preparation (blockifier re-execution, state reads, trie witnesses) | 160 | 129 s wall / ~30 s CPU per 10 blocks from a local recording (MEASURED); ~0 when the sequencer supplies the OS input | CPU, latency-bound | CPU only — **largest by wall-clock today** |
| OS execution (cairo-vm + OS hints → PIE) | 160 | ~2.7M steps/s: 5.36M steps in ~2 s (MEASURED), ~5 s per 13M-step leaf | CPU, one core per leaf | CPU only |
| PIE write + leaf ingress (adapt + upload) | 160 | ~3 s zip write (MEASURED) + ~4–5 s cold ingress (MEASURED, PR #203) | CPU/PCIe | removable with in-memory handoff |
| **Leaf Cairo proof** | 160 | **0.66–1.03 s** (MEASURED, H200, PR #203) | GPU, 61–100 GB | ~45% |
| **Leaf wrap** (circuit verifies Cairo proof) | 160 | fixed circuit shape (qm31/blake_g 2²³ rows); today 50–65 s Zig CPU / ~20 s Rust CPU (MEASURED, M4 Max); ~0.5–1 s on GPU (INFERRED) | GPU (planned) | ~25–30% |
| **Fold** (2-to-1 multiverifier) | 159 | same shape as the wrap | GPU (planned) | ~25–30% |
| Aggregation (applicative bootloader: aggregator + in-Cairo root verification) | 1 | aggregator ~17k steps per leaf (MEASURED, 1–2 leaves) + circuit verifier ~5–20M steps (INFERRED); ~30–60 s cairo-vm + ~1–2 s GPU | CPU + GPU | <1% |
| Stone wrap for L1 | ~0.5 | ~2²² steps, minutes | CPU | CPU only |

Consequences:

1. **Recursion costs about as much as the leaves.** Each leaf needs one wrap and
   about one fold, two circuit proofs of the same fixed shape. At the CPU speeds
   measured today, recursion would be ~40× the leaf cost. The ≥10× fold
   optimisation loop and a CUDA circuit prover are therefore the highest-value
   GPU work.
2. **Aggregation is negligible in throughput.** It is one proof per 1,500 blocks
   and matters only for latency.
3. **The CPU side dominates wall-clock, but not because of the VM.** Measured
   on a 10-block leaf (15630654–663, 5,358,099 steps) replayed from local
   recordings: input preparation 129 s, cairo-vm OS run ~2 s, PIE validate and
   write ~3 s. Levers, in order:
   - **Feed OS input from the sequencer.** It already holds execution infos and
     trie witnesses, so re-execution disappears. Otherwise run SNOS against a
     co-located node database (Pathfinder or Juno) with blocks processed in
     parallel: about 10–20 s CPU.
   - **Hand the trace over in memory.** Run OS, adapter and GPU prover in one
     process: no PIE zip (~3 s) and no re-adaptation (~4–5 s). Stream the
     adapter into pinned device buffers.
   - **Tune the VM last** (hint dispatch, memory layout; ~1.5–2× on ~5 s).

   Target: CPU work per leaf of ~5–8 s, comparable to GPU proving.
4. **Latency path at batch close:** the last leaf's input preparation and OS run
   (~5–8 s after the levers above), its proof (~1 s), its wrap, **8 sequential
   folds**, aggregation (cairo-vm + proof), then Stone (minutes).

### 5.3 Deployment (H200)

- **GPU:** 2 × single-H200 nodes (141 GB) on different providers, for
  redundancy.
  - Each node runs leaves, wraps and folds.
  - 14M-step leaves need ~100 GB of device memory (SN_PIE_1/3), so they do not
    fit an H100. Using H100s means capping leaves at ~7–8M steps (SN_PIE_2:
    61 GB). That roughly doubles leaves, and with them recursion.
  - Per-leaf GPU time is ~2–3 s (leaf ~1 s + wrap and fold ~1–2 s, ingress
    overlapped). At 5k leaves/day that is ~3–4 H200-hours/day, **~10–15% of one
    H200**, so one node carries ~7–15× today's load.
- **CPU:** a ~32-core pool co-located with the GPUs, for OS input preparation,
  OS execution, adaptation and aggregation. At 5k leaves × ~10–40 CPU-s that is
  ~1–2.5 cores on average; the pool is sized for burst latency and parallel
  per-block input preparation, not throughput. One 64-core box runs Stone.
- **Data:** PIEs and prover inputs stay in RAM on the GPU node and never cross
  the network.

### 5.4 Daily cost estimate (2026-09-30)

Market inputs, queried 2026-09-30: Ethereum base fee median 0.101 gwei over the
last ~1,024 blocks (p90 0.159), blob base fee ~6 Mwei, ETH $2,674. Hardware
prices are assumptions, not quotes.

| Item | Basis | $/day (reserved / dedicated) | $/day (on-demand cloud) |
|---|---|---:|---:|
| 2 × H200 | $3.00 / $4.25 per GPU-hr | 144 | 204 |
| CPU pool, 32 cores (OS execution, aggregation) | dedicated ~$300/mo; cloud ~$1.2/hr | 10 | 29 |
| Stone box, 64 cores | dedicated ~$350/mo; cloud ~$2.5/hr | 12 | 60 |
| Storage, network, coordination | co-located | 5 | 10 |
| **Compute** | | **~171** | **~303** |
| L1 execution gas | ~110M gas/day (16 SHARP-style proofs × 5.8M + 39 `updateStateKzgDA` × ~450k) at 0.15 gwei effective | 44 | 44 |
| L1 blob gas | 39 updates × ~5 blobs × 131,072 blob gas at ~6 Mwei | <1 | <1 |
| **Total** | | **≈ $215/day (~$78k/yr)** | **≈ $348/day (~$127k/yr)** |

Sensitivity and unit costs:

- **Gas:** at 1 gwei, L1 rises to ~$294/day and becomes the largest line again
  (total ~$465–600/day). L1 cost is linear in gas price. Settling less often (2–3
  state updates per proof, as SHARP does) is the main lever.
- **GPU is mostly idle standby.** GPU time actually used is ~3–4 H200-hours/day
  ≈ $10–17/day. A single H200 plus a cheaper standby (or on-demand failover)
  roughly halves the GPU line.
- **Per transaction:** ~$0.002/tx at today's 109k tx/day, ~$0.0008/tx at June
  load.

**INFERRED inputs to measure:**

- current circuit-proof time on a GPU (the CUDA circuit prover now exists; this
  earlier cost model has not been recalibrated from its campaign receipts);
- the adapter and ingress cost with an in-memory handoff, and input
  preparation against a co-located node database;
- the circuit verifier's step count in Cairo, and aggregation cost at 160
  leaves.

## 6. Current implementation

| Program / stage | Status |
|---|---|
| OS PIE under the pinned `leaf_simple_bootloader` | Qualified on CPU, Metal, and CUDA with adapted input and the production Blake2s-M31 registry; each leaf program runs exactly one PIE task |
| Leaf wrap and binary circuit folds | Qualified on CPU, Metal, and CUDA; the 128- and 512-PIE H200 campaigns reached independently verified circuit roots |
| Circuit-applicative Cairo 0 program | Implemented in `src/frontends/cairo/applicative`; it runs the Starknet aggregator and Cairo 1 circuit verifier tasks, reconstructs the tree, and proves their ordered-output equality. Two-leaf CPU/Metal proofs match pinned Rust proof bytes; 128 and 512 final proofs are independently Rust verified |
| Stone | out of scope; StarkWare C++ |

The exact compiled StarkWare circuit-applicative program is not public at the
pinned revision. Our compiled program implements its public Rust input/hint
interface, with its own pinned program identity. The shared SHARP on-chain tree
is a later proof stage and is not implemented here. See the
[applicative qualification](../../src/frontends/cairo/applicative/README.md)
and [service receipts](https://github.com/teddyjfpender/proving-service/tree/main/data/h200-api-128-512).

The experiments in section 8 are a historical M4 Max snapshot, before the
current circuit and applicative products were completed.

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

Folds and aggregation have since been measured in the 128/512-PIE campaign
receipts linked in section 6. The L1/shared on-chain-tree wrap has not been
measured in this repository.
