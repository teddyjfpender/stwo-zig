# Cost per committed cell: RV64 Ethereum prefix prover (PR #308 head e6d2ffeac)

Read-only analysis of real stage telemetry. No block or prefix proofs were run. One cheap
micro-benchmark was run (std Blake2s vs Blake3, memguard 2 GB). Scripts:
`~/Coding/ge-ops/explore/cost_per_cell_phases.py <dir>...` and `cost_per_cell_groups.py <dir>`.

## Method

- Sources: `~/Coding/ge-cache/{fused2/m4, fusedfix/prefix4, keccak2/prefix4m, prefix4q, prefix4r}`.
  Each has `cost.json` (exact native cells per tree), `report.json`, and `physical-NNNN.stages.json`.
  The `physical-*` files map in order to `cost.cpu[0..3]` then `cost.truth[*]`. File count and the
  Keccak 2^21 sizes confirm the mapping. `secp/prefix4` has no stage files, so it is excluded.
- "Cell" means a native M31 cell (pre/main/interaction). One QM31 interaction column counts as 4 cells.
  Blowup is 2x (log_blowup 1), so each native cell is 2 committed leaf values (8 bytes hashed).
- Time is **core-seconds**: the sum of `lane_user_seconds` over leaf stages. Whole-process
  `user_seconds` double-counts when two lanes overlap, and wall time differs a lot between runs
  (30–46 s) because of memory stalls. Core-seconds are stable across the 5 runs: 200–224 core-s.
- Protocol (from `gkr_main.zig:113`, `retained_main_merkle.zig`): log_blowup 1, 70 queries,
  PoW 26 bits, fold_step 1, prefixed Blake2s lifted Merkle. Nominal conjectured security is 96 bits.

## 1. Phase breakdown: fused2/m4 (best run, prove 30.45 s, 16.78M steps, 3.18 G cells)

Cells: preprocessed 168M, main 1,954M, interaction 1,062M (33% of the total). That is 190 cells per step
for this 4-packet prefix, Keccak truth included.

| Phase | core-s | % | core-ns / all cells | core-ns / own cell |
|---|---:|---:|---:|---:|
| Witness fill (`source_construction`) | 12.3 | 5.7 | 3.9 | 6.3 per main cell |
| Main LDE (streaming interpolate+extend) | 15.4 | 7.2 | 4.8 | 7.9 per main cell |
| Main Merkle (leaf hash + layers) | 17.1 | 8.0 | 5.4 | 8.8 per main cell |
| Interaction (LogUp) generation | 13.1 | 6.1 | 4.1 | 12.3 per inter cell |
| Interaction LDE | 8.3 | 3.9 | 2.6 | 7.8 per inter cell |
| Interaction Merkle | 10.9 | 5.1 | 3.4 | 10.3 per inter cell |
| **Composition evaluation** | **77.6** | **36.1** | **24.4** | |
| Composition interp+split / commit | 0.6 / 4.9 | 0.3 / 2.3 | 0.2 / 1.5 | |
| OODS sampled values | 3.2 | 1.5 | 1.0 | |
| DEEP quotient + FRI (build+commit+decommit) | 24.1 | 11.2 | 7.6 | |
| Proof of work (26 bits, per proof) | 19.5 | 9.1 | 6.1 | 0.03–1.25 s wall each |
| Trace decommit | 7.3 | 3.4 | 2.3 | ~200 core-µs per column (large proofs) |
| Retained-MAIN spill | 0.2 | 0.1 | — | **2.7 s wall** (13.4 s in fusedfix), ~0 CPU |
| **Total** | **214.7** | | **67.4** | 4.8 wall-ns/cell at 14 cores |

The other runs agree within ±10% per phase. The full-run averages range from 59.8 to 69.5 core-ns/cell.
PoW moves the most (1.7–7.0 core-ns/cell) because it depends on the nonce search.

There is no separate serialization stage; it is under 0.01 s. Preprocessed trees are committed once
in setup (`setup_ns` 1.8 s, `fixed_native_cache` 638 hits). Per proof, preprocessed cells cost only
their share of DEEP, OODS and decommit.

### Cost by proof group (fused2/m4, core-ns per cell)

| Group | cells | witness | LDE m+i | hash m+i | inter gen | comp eval | FRI | PoW | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 CPU segments (2^22) | 2,282M | 2.4 | 7.8 | 9.7 | 3.1 | **13.1** | 6.4 | 5.7 | **53** |
| 2 Keccak truths (2^21) | 892M | 7.3 | 6.6 | 6.7 | 6.6 | **53.1** | 10.7 | 2.3 | **99** |
| 5 small truths | 10M | 27 | 8 | 6 | 19 | 35 | 1 | **452** | 556 |

- Keccak is 28% of the cells but 41% of the core time. Its composition alone costs 47 core-s, 22% of
  the whole prefix. Per the Keccak README, the permutation is degree 4 on a 4n quotient domain. The
  CPU and bridges are degree 3 on 2n.
- The small truth proofs are pure fixed cost: 5.4 core-s for 10M cells, 82% of it PoW.

### Cost per column type (commit-side, core-ns per M31 cell; downstream phases come on top)

- **Base MAIN cell:** witness 6.3 + LDE 7.9 + hash 8.8 ≈ **23**.
- **Interaction cell (one QM31 coordinate):** generation 12.3 + LDE 7.8 + hash 10.3 ≈ **30**.
  So one QM31 interaction value costs about **122 core-ns, 5.3x a base cell**, before its share of
  composition, DEEP, OODS and decommit. Prefix/accumulator columns also add a shifted opening mask.
- **Preprocessed:** committed at setup and cached. Per proof it costs about 11 core-ns per cell in
  DEEP, OODS and decommit, roughly 1.8 core-s.
- **Downstream phases** (composition, DEEP/FRI, OODS, decommit) average about 35 core-ns per cell.
  This number is set by constraint density and domain size, not by commitment.

### Measured hash rate vs scalar

Leaf hashing runs at 8.8 core-ns per main cell for 8 bytes, about **1.1 ns per byte per core**. The
micro-benchmark of std scalar Blake2s on this machine gave 1.09–1.14 ns/B; std Blake3 gave
1.23 ns/B on 64 B messages and 0.93 ns/B on 256 B. So production leaf hashing runs at roughly scalar
Blake2s speed. Either the 4-way `blake2_stream4` path is not active on these leaves, or the stage is
limited by memory traffic from state expansion.

## 2. Levers that cut cost per cell (not the number of cells), ranked

Effects are against the 214.7 core-s of fused2 unless stated.

1. **Keccak permutation on degree 3 / 2n, or making its 4n evaluation cheaper.** Keccak composition
   costs 53 core-ns per cell against 13 for the CPU segments. Halving its domain saves about
   20–24 core-s (about -10%) and removes the extra 4n LDE. This needs an AIR change and a soundness
   rewrite. The docs note the degree-5 quartet is worse; any degree-3 split adds columns. This is the
   biggest measured lever on CPU, and it carries over to GPU because composition is compute-bound.
2. **Composition kernel efficiency** (36% of all time). Accumulate base-field constraint values with
   lazy (u64) reduction. Multiply by QM31 powers as M31×QM31 (4 mults), not QM31×QM31. Fuse the row
   reads of main and interaction. I have not checked whether `riscv_composition.zig` already does
   each of these. A 1.3–2x gain on composition would mean -8% to -18% overall. This is the first
   thing to profile.
3. **SIMD or Blake3 leaf hashing on CPU.** Main and interaction Merkle cost 28 core-s (13%). A
   4-way NEON path, or Blake3's 7 rounds against Blake2s's 10 (1.43x fewer operations per
   compression; 1.22x measured with std at 256 B), would save 5–7%. Remove the per-height 96 B
   state-expansion copies (see GPU section). Poseidon2 costs about 5x Blake2s per hashed cell on
   both CPU and GPU, so use it only where a recursive verifier has to hash.
4. **PoW: a fixed 26-bit grind in every proof.** It costs 9% (fused2) or 2.8–10% across runs, and
   the variance shows up directly in wall time. Fewer, larger proofs help: merge the small truths
   (lever 5) and use 2^23 segments (rv64-segment-size-analysis). A SIMD/multi-lane grinder helps the
   rest. On GPU, 2^26 Blake2s takes milliseconds, so this lever is CPU-only.
5. **Batch the small truth components into the CPU-segment PCS** (one commitment tree, one FRI, one
   PoW). That saves about 5 core-s (2.5%) here. On GPU it removes 5–6 launch-bound proofs, each with
   22 FRI layers and its own transcript round trips.
6. **Fix the spill/memory stall.** `retained_main_spill` costs 2.7 s wall in fused2 and 13.4 s in
   fusedfix with about 0 CPU. In fusedfix, composition wall also inflates to 2.1x its core time.
   This is wall loss from memory pressure, not compute. It goes away on a resident GPU when the
   proof fits in VRAM.
7. **Interaction in QM31 = 5.3x a base cell; GKR moves it out of commitment.** Interaction
   generation, LDE and hash cost 32 core-s (15%), plus about a third of DEEP/decommit and the LogUp
   share of composition. But the matched OM31 CPU0 control (rv64-gkr-same-field-performance.md)
   cut cells by 39.7% and still ran +6% slower (8.46 s vs 7.95 s), because local GKR plus binding
   took 2.17 s against 0.76 s for classic interactions. GKR is not a CPU win today.

   The cheaper cell-neutral steps are a single LogUp accumulator per component (review item 1,
   about 0.7x interaction cells) and fewer batch inversions in generation (12.3 core-ns per cell).
   On GPU, GKR layers are streaming, bandwidth-friendly reductions, so they may win there. Measure
   it on a device first, and count the Eq/binding columns honestly.
8. **Blowup and queries vs security.** For prover cost, keep log_blowup 1 (2x). Its LDE, hash, DEEP
   and composition domains are already minimal. Reaching about 128-bit *conjectured* security means
   102 queries plus 26 PoW bits. That raises only decommit (+46% of 3.4% ≈ +1.6%), proof size and
   recursive-verifier cost. log_blowup 2 with 51 queries would roughly double LDE, hash and DEEP
   (+35–40% prover time) to buy a smaller recursion leaf.

   Keep the accounting honest. 70 queries plus 26 bits is 96 bits under the ethSTARK conjecture.
   Under proven (Johnson-regime) bounds it is far lower, roughly 35 + 26. LogUp and GKR soundness
   terms are not yet in any ledger (`om31_security_candidate.zig` refuses promotion). Raising PoW to
   28–30 bits is cheap on GPU and expensive on CPU.
9. **FRI fold step 4:** less than 2% prover effect, because FRI layer hashing is small next to
   24 GB of trace hashing. It matters for proof size and recursion only.
10. **Per-component padding: small.** Padding rows are 4.9% of CPU-segment main and interaction
    cells (106M of 2,155M). The lifted, mixed-height commitment already avoids padding columns to the
    maximum height. Hashing is charged at native heights.
11. **Reusing preprocessed/fixed commitments:** already done. The fixed cache hits 638 times and
    keeps 106 MB. What is left is cell reduction (shared U16/U8/AND/SHIFT trees per block), which is
    out of scope here.
12. **Streaming LDE without materializing:** CPU already streams in 64-column batches (67 main
    batches per segment). On GPU, keep the evaluations resident. A CPU segment needs about 5.3 GB of
    extended main+interaction, which fits in 80–141 GB. Recompute only when VRAM forces it: LDE is
    used three times (commit, composition, DEEP).

## 3. GPU: which costs matter for 2 s per block

- **Target throughput.** The block is about 3.18 G / 0.62 ≈ **5.1 G cells**. The M4 Max sustains
  0.104 Gcell/s (3.18 G in 30.45 s). Two seconds per block needs 2.6 Gcell/s cluster-wide, about
  25x the M4 Max.
- **Required GPU cost.** With 8 GPUs, each needs ≤ 3.1 ns per cell including everything; with 4 GPUs,
  ≤ 1.6 ns.
- **Roofline estimate (H100, unmeasured):**
  - LDE: about 34 butterflies per native cell, about 20–30 ps.
  - Blake2s: about 17 int ops per byte, 8 B per cell, about 8–10 ps (Poseidon2 about 50 ps).
  - DEEP: about 5 ps.
  - Composition at CPU-segment density: about 10–20 ps.

  The floor is about 50–100 ps per cell. Even at 10–30% efficiency (0.2–0.5 ns per cell), cost per
  cell **is not the binding constraint**. The H200 Cairo receipt points the same way: two resident
  Cairo proof executions take about 0.8 s, inside a 12.5 s pipeline dominated by ingress, static
  assets and fold setup.
- **The binding items on GPU** (in order):
  1. Witness and execution on device. Capture alone is 1.98 s on CPU for this prefix. Main cells
     are about 20 GB at 4 B each, which over PCIe5 at ~50 GB/s is about 0.4 s; this argues for
     generating the witness on the GPU.
  2. Recursion/aggregation latency. The H200 fold is 1.3–2.9 s today.
  3. The critical-path proof. Keccak truth0 is 698M cells, the largest single proof: 14 s on CPU,
     2x a CPU segment. It cannot be split across GPUs, so lever 1 or splitting Keccak shards matters
     for latency.
  4. Fixed per-proof latency: transcript round trips, 22 FRI layers, PoW, small proofs (levers 4–5).
  5. Within kernels: composition first (36% of work, compute-bound), then lifted-Merkle state
     expansion. Use one fused leaf kernel that reads smaller columns at index `>> shift` instead of
     materializing 96 B per-leaf states at each height. That saves about 50% of hash memory traffic
     on a 2^23-leaf tree. Then LDE fused with hashing (no write-back of what the hasher consumes),
     then DEEP.
  6. Hash choice: Blake2s or Blake3 for the base layer (≈5x cheaper than Poseidon2 per cell on GPU),
     Poseidon2 only in recursion layers.

## Caveats

- Core-seconds come from per-lane rusage. When lanes overlap, wall and core time are not additive
  across proofs.
- Downstream phases are spread by cell count, which is a crude allocation.
- The GPU figures are rooflines, not measurements. I found no RV64 GPU cells/s receipt in the repo.
- The micro-benchmark used Zig std hashers, not the repo's batched implementations.
