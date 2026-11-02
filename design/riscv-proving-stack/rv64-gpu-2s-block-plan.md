# Plan: an average basket Ethereum block in < 2 s on a GPU group (RV64 Word16, Circle-STARK)

Date: 2026-11-02. Synthesis of `cost-per-cell.md`, `megakernel-gpu-research.md`,
`cuda-backend-audit.md` and `remaining-score-wins.md`, plus a recheck of the PR state
(`gh pr list`, `git show` on `classic-full-cost.json` and `basket.json`). Read-only; nothing committed.

PR state at writing:
- #308 `codex/rv64-guest-efficiency` `271ee1a42`
- #309 `88f89752d`
- #310 `codex/rv64-pr308-integration-review`: head is now `593d4ced3`; the receipts used here are
  unchanged.
- #311 `codex/rv64-cuda-resident-gkr` `771334a93`. This is still the newest GPU PR. Nothing newer
  touches `src/backends/cuda`. #299 is recursion-only.

---

## Decisions (2026-11-02, from the project owner)

1. **Security target: 128-bit conjectured** (ethSTARK-style accounting is acceptable). Go to 128
   bits from the start; do not build product features on a 96-bit QM31 pipeline. The existing QM31
   CUDA kernels are used only for a few days of 1-GPU calibration (a real ns/cell number).
   - QM31 (|F| ~ 2^124) cannot reach 128 bits even conjectured, because the algebraic
     (Schwartz-Zippel / LogUp pole / OODS) terms are bounded by the extension-field size. 128 bits
     therefore means the **OM31 extension (degree 8, ~2^248)**: the #310/#311 route.
   - FRI: about 102 queries at blowup 2 plus 26-bit PoW, or ~51 queries at blowup 4. Blowup 4 costs
     ~2x LDE/commit work on the base proofs but halves query decommitment and recursion-verifier
     work; evaluate it against recursion latency (track C4/G8).
   - OM31 makes every committed extension column 8 base cells instead of 4, so interaction columns
     must leave the commitment: LogUp-GKR (#310) is main line, not optional (track G10 becomes
     core). Consequence for #308: v3 services, layouts and truths must be admitted on the OM31/GKR
     route instead of failing closed (`gkr_local/v2_scope.zig`).
2. **Hardware target: 4x RTX 5090** for an average basket block (29.7 M gas, ~97 M instructions,
   ~27 G CPU-segment-equivalent cells) in < 2 s. 16x is the conservative sizing at 200 ps/cell;
   block 24,628,607 (7.4 M gas) is about a quarter of the average and fits on 2-4 GPUs much more
   easily.

## Per-GPU efficiency ladder: what moves a GPU from ~1 ns to 200, 100 and 60-80 ps per cell

Cost is per CPU-segment-equivalent committed cell, end to end on one GPU (witness, interaction,
LDE, commit, composition, OODS/DEEP/FRI, PoW), at the 128-bit OM31 route. The plan's per-GPU
roofline is ~40 ps/cell (HBM traffic plus M31 multiply throughput on an RTX 5090). On the 14-core
M4 Max CPU today the figure is 60-70 core-ns per cell, so even the first rung is ~300x a CPU core.

GPU count needed for a mean block in < 2 s (base proving plus recursion, ~0.5 s of serial work):

| ps per cell | % of roofline | 16x 5090 | 8x 5090 | 4x 5090 | 2x 5090 |
|---|---:|---|---|---|---|
| ~1,000 (naive port) | 4% | no | no | no | no |
| **200** | 20% | yes (~1.0-1.2 s) | with -30% cells | no | no |
| **100-120** | 33-40% | yes | yes | **yes with -30% cells** | no |
| **60-80** | 50-65% | yes | yes | yes | **stretch, needs -50% cells and cheap recursion** |

The table covers mean-block latency. Pipelining across blocks helps throughput, not latency.

**Rung 0 -> 200 ps/cell (~20% of roofline): make it resident and stop paying fixed costs.**
- Reuse the resident PCS kernels (circle LDE, Blake2s lifted Merkle, DEEP/FRI fold, PoW grind)
  and keep every proof's data on the device from witness to proof bytes. No host round trips
  between phases; only compact records in, proof bytes out.
- A generic RV64 composition kernel driven by an exported constraint IR (track C5) instead of
  per-component host evaluation. Composition is **36% of prove time**
  (`gpu-2s/cost-per-cell.md`), the largest single phase.
- Lifted-Merkle native-height absorb (G1): avoids ~45x hash amplification on small components.
- CUDA graphs per proof shape plus programmatic dependent launch, so the hundreds of small
  component kernels do not each pay launch and sync latency.
- Persistent per-GPU sessions across blocks: setup, fixed/preprocessed columns and tables
  (e.g. the Keccak 2^21 tables) built once and reused.

**200 -> 100-120 ps/cell (33-40%): cut HBM traffic and specialize the hot phases.**
- **Generated composition code per component** (constant-folded constraints, shared
  subexpressions, lazy M31 reduction, M31xOM31 products kept in registers, fused quotient /
  vanishing division) inside a **persistent stream-K composition kernel**. This is the biggest
  single GPU-side lever because composition is the largest phase.
- GPU witness expansion from compact per-step records (C2/G4): removes ~12 GB of MAIN upload per
  mean block and makes witness generation a few ms per segment.
- Fused LDE -> leaf hash -> shared-memory/thread-block-cluster Merkle (G9): about -50% of
  commitment HBM traffic.
- LogUp interaction out of the commitment via GKR on the device (#311's resident sumcheck with
  device-side Fiat-Shamir feedback): interaction was 33% of committed cells.
- Dedicated Keccak and secp truth kernels (G5): truths are ~45% of block time on the CPU.

**100 -> 60-80 ps/cell (50-65%): one persistent megakernel per GPU, no bubbles.**
- **Megakernel patterns** (Flapping Airplanes has published no technical details; the public
  patterns come from Hazy Research's low-latency/throughput megakernels, CMU's Mirage Persistent
  Kernel and ParallelKittens; see `gpu-2s/megakernel-gpu-research.md`):
  - an **on-GPU interpreter over a per-SM schedule precomputed on the CPU**, executing coarse
    instructions (LDE tile, hash tile, composition tile, FRI fold, sumcheck round);
  - **global-counter dependencies between stages** instead of kernel boundaries, so the next
    stage starts on finished tiles while the previous one drains;
  - shared-memory page recycling across instructions;
  - **peer-to-peer stores across GPUs from inside the kernel** for recursion inputs and
    cross-GPU reductions.
  These fit our workload: many small per-proof stages (dozens of components per segment, OODS,
  DEEP, FRI tail, PoW) and the recursion tree, where idle time between launches, not arithmetic,
  dominates.
- Co-schedule several proofs per GPU (32 GB fits 2-3 segments) so no SM idles during a proof's
  narrow tail (FRI/OODS) or a recursion node.
- Tile-level kernels in the ThunderKittens style (register/SMEM-resident tiles, warp
  specialization with async copies) for LDE butterflies and Merkle layers.
- Arithmetic: packed M31 with lazy reduction, IMAD-friendly reduction, OM31 multiply via
  Karatsuba on M31 limbs kept in registers.

**What pushes the number up:** OM31 doubles the cost of every extension-field element against
QM31; 128-bit queries add decommitment and recursion work; per-proof fixed costs dominate for small
components unless they are batched (merge small truths into one PCS, track C3).

**Cells per block (score levers) multiply with ps/cell.** -30% cells (Keccak degree 3, fused
LS+CPU row, compact decode, state hints, Zbb, client work) is what lets 4 GPUs work at 100-120 ps.

## 0. Headline

- **Correction to the earlier notes: block 24,628,607 is a *small* block.** It is 7.37 M gas. The
  basket mean is 29.7 M gas (median 22.3 M, max 58.9 M). The "5.1–5.4 G cells per block" figure
  used in the earlier notes is that small block.
  - An average basket block is about **97 M instructions, ~23 CPU segments of 2^22, ~5.4 G Keccak
    cells and ~20–22 G committed cells**. That is about 27 G "CPU-segment-equivalent" cells once
    Keccak's 1.9× cost per cell is counted.
  - It would take about **150 s on the 14-core M4 Max**, so the goal needs ~75× the CPU prover,
    not 19×.
- **The math still closes, with margin, on 16× RTX 5090** (primary configuration), at an assumed
  **~200 ps per CPU-segment cell per GPU**. That is ~20% of a per-GPU roofline of ~40 ps/cell.
  Under that assumption:

  | Block | Critical-path wall | Base proving, busy time per GPU |
  |---|---:|---:|
  | Mean (29.7 M gas) | ≈ 1.0–1.2 s | 0.32 s |
  | Max (58.9 M gas) | ≈ 1.6–1.9 s | 0.62 s |

  **8× 5090 meets the 2 s average in throughput terms** (capture and recursion pipelined across
  blocks), **but not in latency terms**.
- **GPU compute is not what makes this hard.** The four gaps are, in order:
  1. **Execution.** The executor runs at ~11 MHz, so a mean block takes ~9 s just to execute. The
     target is a ≥ 500 MHz first pass plus parallel traced re-execution.
  2. **Recursion.** CUDA wrap+fold for Cairo today takes 1.3–4 s on H200. The target is ~60 ms per
     level.
  3. **No RV64 GPU prover exists.** This includes composition codegen and the 45× lifted-Merkle
     hazard.
  4. **Fixed per-proof costs:** ingress, static setup, launches and host syncs.

  None of the score/cell levers is *required* at 16 GPUs. They are what makes 8 GPUs or p99 < 2 s
  reachable.
- **Route: the classic QM31 route** (q70 / PoW 26 / blowup 2 / fold 1, Blake2s-prefixed lifted
  Merkle).
  - The existing resident CUDA PCS matches this route exactly, and it is the only route that proves
    v3 today (#310 receipt: 37.71 s, 5.41 G cells).
  - The OM31/GKR route (#310/#311) is a later lever: −15 to −25% GPU time. It is gated on v3
    admission and an OM31 PCS that does not exist yet.
- **#311 is the right shape for one sub-stage but has never run on a GPU.**
  - Its gencode includes **sm_120 (RTX 5090)**, the primary GPU of this plan. The first action is
    therefore cheap: rent a 5090 and run #311's hardware gates together with the existing QM31
    kernels, to get the first real ns/cell receipt.

---

## 1. Workload sizing

Sources:
- Per-proof cells: `classic-full-cost.json` (#310 receipt `rv64-pr308-v3-capture-20261102`).
- Gas: `autoresearch/guest_efficiency/basket.json`.
- Cost per cell: `cost-per-cell.md` (CPU segment 53 core-ns/cell, Keccak 99, secp ~70).

Scaling is linear in gas, at 734 cells/gas (measured on block 607). Block 607 is dispatch-heavy
(3.65 instr/gas against a basket mean of 3.28), so the scaled figures are 0–10% high.

| Block | gas | instructions (3.283/gas) | CPU segments (2^22) | committed cells (MAIN+INTER) | Keccak cells | CPU-seg-equivalent cells | M4 Max (scaled) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 24,628,607 (measured) | 7.37 M | 26.9 M (actual) | 7 (6×2^22 + 2^21) | 5.41 G | 1.35 G (2 × 2^21) | 6.7 G | 37.7 s |
| **Basket mean** | **29.7 M** | **97.5 M** | **~23** | **~20–22 G** | **~5.4 G** | **~27 G** | ~152 s |
| Basket max (24,628,611) | 58.9 M | 193 M | ~46 | ~43 G | ~10.8 G | ~54 G | ~301 s |

Per-proof inventory on block 607 (M cells, MAIN+INTER):

| Proof | Cells (M) |
|---|---:|
| CPU 0–5 | 660, 525, 530, 536, 526, 552 |
| CPU 6 (2^21) | 364 |
| Keccak 0 / 1 (2^21) | 674 / 674 |
| secp (2^18) | 239 |
| secp (2^17) | 100 |
| arith/SHA (2^12) | 30 |
| tiny (2^9) | 0.5 |

**Per-proof GPU working set, CPU segment:**
- Main 380 M cells and interaction 281 M cells, ×2 extended: about 5.3 GB.
- Trees, composition and DEEP buffers: about 1 GB.
- Total: **≈ 7–8 GB**.

The proof fits a 32 GB RTX 5090 with room to double-buffer 2–3 proofs. A Keccak 2^21 shard is
similar, plus a 4n QM31 composition buffer of ~134 MB. The Cairo arenas of 51–100 GB are not
representative: they are max-log-23 with different static assets.

## 2. Hardware choice and per-GPU throughput

**Primary: 16× RTX 5090** (sm_120, 32 GB GDDR7, 1.79 TB/s, 170 SMs). Packaging is 2 nodes of
8 GPUs on PCIe 5, plus host CPUs with ≥ 64 cores each for execution.
- Why the 5090: M31 work is integer-bound. A 5090 issues INT32 on all 128 lanes per SM (about
  52 T int-ops/s), while an H100 issues it on 64 lanes per SM (about 17 T).
- **The 5090 is about 3× an H100 on our math, at about a tenth of the price.**
- It is the GPU used by ZisK (4× and 24×), SP1 (16×), Pico and OpenVM, so comparisons are direct.
- #311 already compiles for sm_120.

**Alternative: 8× B200 (HGX, NVLink).**
- HBM at 8 TB/s helps LDE and hashing. NVLink helps only recursion, where P2P carries KBs to MBs.
- It costs roughly 10× per GPU for roughly equal integer throughput.
- It busts the EF CAPEX guideline of ≤ $100k.
- Choose it only if 5090 VRAM or PCIe proves binding.

**Stretch: 8× RTX 5090.** This needs the cell levers in §6 (−30%) and 2^23 segments.

### Roofline per CPU-segment native cell (blowup 2, degree-3 composition on 2n)

| Work | int-ops / cell | Note |
|---|---:|---|
| LDE (interpolate n + evaluate 2n) | ~340 | ~34 butterflies × ~10 ops (M31 mul ≈ 6 ops) |
| Blake2s leaf hash | ~140 | 8 B per cell × ~17.5 ops/B |
| Interaction generation (amortized over all cells) | ~15 | Batch inverse plus prefix sums |
| Composition | ~100–200 | Keccak is ~4× this |
| OODS (barycentric M31×QM31) | ~30 | |
| DEEP quotient | ~60 | 2 points per cell |
| FRI, PoW, decommit | ~5 | PoW 26 bits ≈ 74 G ops per proof ≈ 3 ms on a 5090 |
| **Total** | **~700–800** | **5090 ≈ 29 ps compute and ≈ 27 ps bandwidth (~40 B/cell) → ~40 ps roofline; H100 ≈ 90 ps** |

### Required throughput against measured and published numbers

| Quantity | Value | Source |
|---|---:|---|
| **Required, 16× 5090, mean block, latency ≤ 2 s** | **≈ 5 G cells/s per GPU (≈ 200 ps/cell)**, for ≈ 0.32 s of base proving per GPU | This plan |
| Required, 8× 5090 | ≈ 10 G cells/s (100 ps/cell, 40% of roofline), or 5 G cells/s after −30% cells and pipelined capture | This plan |
| 5090 roofline (estimate) | ~25 G cells/s (40 ps) | §2 table |
| M4 Max CPU, measured | 0.144 G cells/s (5.41 G in 37.7 s) | #310 receipt |
| Airbender v1, H100, Jun 2025 (published) | 21.8 MHz RISC-V base proof. At our ~200 cells/instr that is ≈ 4.4 G cells/s-equivalent (different arithmetization; anchor only) | zksync.io/airbender |
| Cairo SN PIE on H200 (our repo) | 0.66–1.03 s per proof execution. No cell counts, so no ns/cell figure | suite-v18.json |
| RV64 on any GPU | **No receipt exists** | — |

**The required per-GPU rate is about what Airbender measured on an H100 in 2025, on a GPU with
~3× the integer throughput.** It is ambitious for a first port but not heroic. The rest of the
budget goes to latency.

## 3. Per-stage critical-path budget (mean block, 16× 5090)

**Timing boundary.** Use the Ethproofs boundary: start when the block and its witness are
available, end at the final aggregated proof (≤ 300 KiB). Witness generation and recursion are
included; RPC fetch is excluded.

**Pipeline shape.** A fast execution pass emits segment checkpoints. Traced re-execution of each
segment runs in parallel on host cores. Each finished segment is shipped to a GPU, and recursion
starts as soon as each base proof lands.

| # | Stage | Where | Work (mean block) | Per-proof budget (CPU segment) | On critical path | Today |
|---|---|---|---|---:|---:|---|
| 0 | Input decode, state/witness load | CPU | ~MBs | — | 20 ms | not measured separately |
| 1 | **Capture: fast first pass** (AOT/JIT RV64 → host ISA, no trace, checkpoint every 2^22 instr) | CPU (1 core) | 97.5 M instr at ≥ 500 MHz | — | **~200 ms** (streamed: segment k is ready at ~8 ms × k) | **~9 s** (11 MHz; v3 capture 2.46 s for 26.9 M instr) |
| 2 | **Traced re-execution per segment**, emitting compact per-step records (pc, rd, mem addr/val/prev-ts, service calls) | CPU (~1 core per segment, 23 in parallel) | 4.2 M instr at ≥ 50 MHz per thread | 85 ms | 85 ms (last segment only) | none |
| 3 | H2D transfer of records | PCIe 5 ×16 | ~32 B/instr ≈ 134 MB per segment | 3 ms | 3 ms | Cairo cold ingress 4.7 s (static + source) |
| 4 | Witness expansion (MAIN) | GPU | 380 M cells per segment | 20 ms | yes | CPU only |
| 5 | Main LDE + Blake2s commit (fused, native-height absorb) | GPU | 0.38 G cells | 25 ms | yes | CPU only. **The CUDA lifted absorb would hash ~30 G lifted cells (45×), i.e. +300 ms** |
| 6 | Interaction (LogUp gen) + LDE + commit | GPU | 0.28 G cells | 25 ms | yes | CPU only |
| 7 | Composition, fused with quotient accumulation | GPU | 0.66 G cells on 2n | 40 ms (Keccak 2^20 shard: 60 ms) | yes | CPU only; 36% of CPU core time |
| 8 | OODS + DEEP quotient | GPU | 0.66 G cells | 15 ms | yes | CPU only |
| 9 | FRI (23 layers, fold 1) + last layer | GPU | latency-bound | 10 ms | yes | CPU only |
| 10 | PoW 26 bits (device grind) | GPU | 6.7e7 Blake2s | 5 ms | yes | 0.03–1.25 s per proof on CPU |
| 11 | Decommit + proof assembly + D2H | GPU | 70 queries | 5 ms | yes | — |
| | **Base proof total** | | | **≈ 150 ms** (~225 ps/cell, ~18% of roofline) | | |
| 12 | GPU queueing: 23 CPU + ~8–16 Keccak + ~3 secp/other ≈ 36–42 proofs, LPT over 16 GPUs | GPU | ≈ 27 G equiv cells × 200 ps / 16 | — | **0.32–0.40 s** of busy time per GPU, overlapped with stages 1–2 | — |
| 13 | Recursion: leaf wrap per base proof (~100 M-cell verifier circuit; dominated by Blake2s decommit hashing of ~7.3k columns × 70 queries) | GPU, split stream | ~40 wraps | 60 ms | 60 ms (last leaf) | wrap 2–3 s each (Cairo, H100/H200) |
| 14 | Aggregation, 4-ary tree (40 → 10 → 3 → 1) | GPU | 14 nodes | 60 ms per level | **180 ms** (3 levels) | fold 1.3–2.9 s (H200) |
| 15 | Final compression to ≤ 300 KiB (larger blowup, fewer queries) | GPU | 1 proof | — | 150 ms | root GPU proof ~0.25 s (H200 compact root) |
| 16 | Cross-GPU transfer (wrap proofs ~1–5 MB; P2P or host; 100 GbE between nodes) | PCIe/NIC | ~100 MB total | — | ~5 ms | n/a |
| | **Critical path, mean block** | | | | **≈ 20 + max(200 + 85 + 150, 20 + 400) + 60 + 180 + 150 + 5 ≈ 1.0–1.1 s** | |

**Max block (58.9 M gas):**
- Execution ~400 ms, base proving busy time ~0.65–0.8 s per GPU, recursion +1 level.
- Total ≈ 1.6–1.9 s.
- **p99 < 2 s is tight on 16 GPUs. The cell levers or 24 GPUs give the margin.**

**Throughput view ("on average" with cross-block pipelining):**
- GPU-seconds per mean block ≈ 5.4 base + ~2.5 recursion (40 wraps plus aggregation, including
  fixed cost) ≈ 8 GPU-s.
- At 75% utilization: 16 GPUs give ≈ 0.7 s per block, and **8 GPUs give ≈ 1.3 s per block**.

## 4. Parallelization scheme

1. **Shard by proof, never inside a proof.**
   - Each GPU owns whole proofs: CPU segments, Keccak/secp shards and recursion nodes.
   - Cross-GPU traffic is limited to roots, claims and wrap proofs (KB to MB).
   - Do not split a sumcheck or an FFT across GPUs. The measured 8× H100 sumcheck scaled only 4×
     because of the all-reduce in every round.
   - #311's 2/4-GPU credit scheduler is correctly proof-granular. Keep it that way.
2. **Inventory planner (CPU).** From the first pass's checkpoints and service-call counts:
   - Size CPU segments at 2^22, or 2^23 when fewer GPUs are available: fewer proofs means fewer
     recursion leaves and less fixed cost.
   - **Stream Keccak shards at 2^20 (~340 M cells, ≈ 0.6 G equivalent)** as permutations
     accumulate, so no Keccak proof is larger than a CPU segment. Today Keccak truth 0 is the
     largest single proof (674 M cells at 1.9× cost) and would set the latency floor.
   - Merge the small truths (2^9 / 2^12 / secp 2^17) into one PCS, or attach them to a CPU segment
     proof. That is lever 5 in cost-per-cell: 82% of their cost is PoW and fixed latency.
   - Assign proofs with LPT (longest processing time first) over a per-AIR cost model (cells ×
     coefficient: CPU 1.0, Keccak 1.9, secp 1.3).
3. **Pipelining per GPU.** Prefetch the next proof's records while the current proof runs; this is
   the ZisK v1.3 pattern. Co-schedule:
   - memory-bound LDE and hash of proof k+1
   - compute-bound composition of proof k.

   Run recursion on a split stream from the first finished base proof.
4. **Recursion tree.**
   - Leaf wrap: verify one classic base proof (Blake2s Merkle, q70) and emit a Poseidon2/M31-friendly
     proof.
   - Then 4-ary aggregation, depth ⌈log4(L)⌉ (3 for ~40 leaves, 4 for ~80), then one final
     compression.
   - Only the last leaf, the aggregation levels and the final compression are on the critical path.
     The rest hide under base proving.
   - **The cost of wrapping a base proof is dominated by decommit hashing:** 70 queries × ~7.3k
     opened columns × 2 trees. That argues for:
     - fewer, wider segments;
     - **fewer committed columns per CPU proof** (the fused LS+CPU row and GKR both help here);
     - q70 instead of q102 at the base. 128-bit raises wrap cost by about 45%.
5. **Host side:**
   - Two 64-core hosts, one per 8 GPUs.
   - One host thread runs the fast first pass for the block.
   - 23–46 threads run traced re-execution.
   - Per-GPU worker threads feed completion rings, with no per-proof host sync.
   - Blocks overlap: block b+1 executes while block b's tail recurses.

## 5. Per-segment proof engine: persistent kernel and megakernel design

**Goal: about 1 host interaction per proof (enqueue and final D2H) and no idle SMs between stages.**
The existing Cairo stack already reaches 1 sync and 1 D2H per proof, but with ~3,600 direct
launches (≈ 10 ms per proof at ~3 µs each). That is acceptable for 150 ms base proofs, but not for
the ~60 ms recursion nodes or the FRI/OODS tail.

Build it in three steps; each step stands on its own.

1. **Persistent session + CUDA graphs + PDL** (low effort; do this first).
   - One `Session` per GPU, alive across blocks. It holds:
     - static images: preprocessed commitments, twiddles, compiled per-AIR kernels;
     - an arena sized for 2–3 concurrent proofs (≤ 24 GB on a 5090).
   - Per proof geometry (component set plus segment height; a handful of distinct shapes), capture
     the whole launch DAG once as a CUDA graph with programmatic-dependent-launch edges, then
     replay it.
   - Hazy measured launch cost dropping from 2.1 µs to 1.3 µs with graphs, and PDL overlaps the
     prologue of the next kernel with the tail of the previous one.
   - The device transcript, PoW and query draws already run on device in the Cairo stack. Extend
     this to the RV64 controller, so the whole proof makes zero host round trips.
2. **Persistent stream-K composition kernel** (the largest single kernel win; high effort).
   - Generate **one CUDA device function per RV64 component** at build time. Use a *recording
     external lane* (`rv64/air/lane.zig` already defines zero/one/fromU32/add/mul/inv) that traces
     each component's `evaluate` into `secure_polynomial_program_v1` and on to CUDA through
     `secure_polynomial_codegen_v1.zig`.
   - Run all components of a proof in one persistent kernel that pulls `(component, row-tile)`
     work items from a global counter.
     - Producer warps stage trace tiles (main, interaction, preprocessed, with shifted masks) into
       SMEM via TMA/cp.async.
     - Consumer warps evaluate constraints with lazy u64 accumulation and M31×QM31 random-coefficient
       multiplies, and write straight into the quotient accumulator.
   - This removes the tail effect (hundreds of components of very different heights) and the
     re-reads.
   - The Keccak permutation gets its own specialized kernel: degree 4 on 4n is 4× the CPU density.
3. **Interpreter megakernel for the latency-bound tail and for recursion proofs** (high effort; do
   only after 1 and 2 are measured).
   - A CPU-compiled per-SM instruction list per proof shape, after Hazy and Mirage MPK, built from
     coarse instructions of ≥ 20–50 µs each:
     - `LDE_HASH(col-batch, tile)`
     - `MERKLE_UP(levels)`
     - `INTERACTION(relation, tile)`
     - `COMPOSE(component, tile)`
     - `DRAW(transcript-op)`
     - `OODS(batch)`
     - `DEEP(batch, tile)`
     - `FRI_FOLD_COMMIT(layer)`
     - `POW`
     - `DECOMMIT`
   - Dependencies are global counters per `(stage, tile)`. SMEM pages are recycled across
     instructions.
   - The payoff is in:
     - the 23-layer FRI plus OODS/DEEP tail of each proof (~60 tiny dependent kernels);
     - recursion nodes, where fixed cost is most of the work (circuit R7 shows ~50–60 ms of device
       time inside 0.56 s);
     - overlapping proof k+1's memory-bound commit with proof k's compute-bound composition.
   - A ~1 µs handoff × ~1,000 instructions ≈ 1 ms per proof.
   - **Fused LDE → leaf hash → SMEM/cluster Merkle levels:**
     - It absorbs columns at their native heights. This is the CUDA counterpart of CPU state
       expansion and the fix for the 45× lifted hazard.
     - It finishes the lower ~16 levels in the SMEM of a 16-CTA cluster on sm_90/sm_100. On sm_120,
       use plain CTA SMEM, since cluster limits differ (to verify).
     - Expected saving: about half of commit HBM traffic.

## 6. Score and cell levers: which ones the math needs

At 16× 5090 and 200 ps/cell, **none of them is required for the mean block.** They buy:
- (a) p99 under 2 s;
- (b) 8 GPUs instead of 16;
- (c) slack if achieved efficiency lands at 400 ps rather than 200.

Each −10% in equivalent cells takes about −35 ms off the mean-block critical path at 16 GPUs, or
−70 ms at 8, and also cuts recursion leaf cost.

| Lever (from remaining-score-wins / cost-per-cell) | Δ equivalent cells or GPU time | Matters for |
|---|---|---|
| Keccak degree 3 on 2n, or a cheaper 4n evaluator | −8 to −12% overall; −27% on Keccak shards, the critical path | p99; Keccak shard balance |
| Fused LS+CPU row (aligned LD/SD) | −10 to −11%; fewer columns per CPU proof means cheaper leaf wraps | 8 GPUs; recursion |
| State/trie host hints, U256 LS row, interpreter second pass, memory functions | −10 to −18% combined (instructions → also faster execution, stage 1) | 8 GPUs; capture critical path |
| Merge small truths into one PCS; 2^23 segments | −2 to −3% of cells, but removes ~5 launch-bound proofs and ~half the recursion leaves | recursion latency |
| GKR for global relations on v3 (#310 route + #311 engine) | GPU −15 to −25%, but needs an OM31 PCS (ρ=1/4 and q256 cost ≥ 2× per committed cell) | only if 128-bit with smaller proofs is required |
| Composition kernel efficiency (lazy reduction, M31×QM31) | write the GPU kernels this way from the start | GPU efficiency target |
| Lifted-Merkle expand kernel | prevents +300 ms per CPU segment | **mandatory** |

## 7. How this builds on PR #310 and #311

**#310 (integration and receipts).**
- Supplies the **v3 classic full-block reference**: 7 CPU + 6 truth proofs, per-proof cells and
  columns, statement, and a fresh native receiver.
- This is the byte-for-byte oracle for every GPU milestone.
- GPU proofs must match CPU proofs exactly, including the PoW nonce. The Zig grinder returns the
  **lowest** nonce, so the device grind must search in nonce-ordered batches and min-reduce within
  the first batch that contains a hit.
- #310's OM31/GKR route stays the CPU-side home of the GKR lever. Its open v3 gates (v3 CPU roles,
  OM31 truth adapters, binding, the v3 security budget) are prerequisites for the GKR GPU option
  only, not for this plan's main line.

**#311 (resident OM31 GKR engine).**
- Keep it as a library. Its patterns are exactly what the whole proof needs:
  - device-resident Fiat–Shamir, with Blake2s on device;
  - no sync, allocation or transfer inside the loop;
  - deterministic reductions;
  - generation-tagged arenas;
  - a proof-granular multi-GPU ledger.
- **Action now:** run its hardware gates on one rented 5090. sm_120 is already in its gencode.
  This gives:
  - the first device parity and a sanitizer pass;
  - an Nsight trace showing launch gaps, the 128-register kernels and the 192 B stack in round
    control;
  - in the same session, a timing of the existing QM31 LDE, Blake2s and FRI kernels on sm_120,
    which have only been qualified on sm_90.
- Before integration it needs:
  - mixed-instance batching across all of a proof's relations (one GKR instance, layer-batched);
  - the round loop as a CUDA graph or megakernel instructions (≈ 2,000 launches per instance
    today ≈ 6–10 ms);
  - device tuple emitters per v3 family;
  - an OM31 PCS.
- **Do not split its sumcheck across GPUs.**

## 8. Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| Achieved GPU efficiency far below 20% | No RV64 GPU receipt exists. At 400 ps/cell the mean block still fits on 16 GPUs (~1.4 s), but the max block does not | Measure with a single-segment milestone first (G3). Keep levers in reserve |
| **Execution speed (50–90× gap)** | 9 s of 11 MHz execution sits on the critical path | Track C1 is first priority; parallel traced re-execution |
| **Recursion latency (20–50× gap)** | Current wraps and folds take seconds. Most of that is host circuit build and ingress, not device time | Persistent recursion sessions, precompiled verifier circuits per proof shape, megakernel. Budget 60 ms per level |
| Keccak critical path | A 2^21 Keccak proof costs about 1.9× a CPU segment | Stream 2^20 shards; Keccak degree-3 lever |
| 5090 VRAM (32 GB) and PCIe-only P2P | Two or three proofs per GPU; recursion traffic goes over PCIe | Working set ≈ 8 GB per proof fits. Wrap proofs are MBs |
| Lifted-Merkle 45× | +300 ms per segment if ported naively | Expand kernel (G1) before any timing |
| Security level | We are at 96-bit conjectured. EF wants ≥ 128-bit; competitors claim 100–128 | 128-bit classic (q≈102 + P26, or q≈90 + P30): ≈ +2% base, ≈ +45% leaf-wrap hashing. LogUp terms go in the ledger |
| Comparability | Competitors quote p99 on Ethproofs-boundary timings; "average < 2 s" is a weaker statement | Report the mean and p99 over the 15-block basket plus holdouts, at the Ethproofs boundary |
| Power and CAPEX | 16 × 575 W ≈ 9.2 kW for GPUs alone, plus hosts, exceeds 10 kW. ~$50k in GPUs plus hosts is close to $100k | Power-cap the 5090s (~450 W costs about −10% performance), or use 12 GPUs with the levers |
| Transcript and PoW parity | Byte-identical proofs require deterministic reductions and the lowest-nonce PoW rule | Parity harness against #310 receipts (C8) |
| Soundness of new pieces | New verifier circuit, merged-truth PCS layout, Keccak AIR split, fused LS row | Each is gated by a fresh receiver and the soundness ledger |

## 9. Ordered tracks

Effect is measured against the mean-block critical path on 16× 5090.

### CPU-side prerequisites

| # | Track | Expected effect | Effort | Soundness risk |
|---|---|---|---|---|
| C1 | **Fast execution.** An AOT/JIT RV64 → host first pass (≥ 500 MHz) emits segment checkpoints and service-call counts. Then parallel traced re-execution (≥ 50 MHz per thread) emits compact per-step records (≈ 32 B/instr) with RAM prev-timestamps | 9 s → ~0.3 s on the critical path. **No plan works without this** | 4–8 weeks | none (the prover input is checked by the proof); completeness only |
| C2 | **Record format and GPU witness spec.** Define exactly what the CPU ships per segment and per Keccak/secp shard, plus a CPU reference expander for parity | Enables G4; makes H2D ≈ 3 ms per segment | 1–2 weeks | none |
| C3 | **Inventory planner.** 2^22/2^23 segments, streamed 2^20 Keccak shards, small truths merged into one PCS, LPT cost model | Removes the Keccak critical path; −5 launch-bound proofs; about half the recursion leaves at 2^23 | 1–2 weeks (+ AIR/PCS layout work for merging) | low/medium (statement layout changes; fresh receiver) |
| C4 | **RV64 recursion design.** Classic-proof verifier circuit (Blake2s decommit), 4-ary aggregation, final compression to ≤ 300 KiB, precompiled per proof shape | Makes ~60 ms per level possible | 4–8 weeks | **high** (new verifier circuit) |
| C5 | **Composition IR export.** Recording external lane → `secure_polynomial_program_v1` for every v3 component and both routes | Prerequisite of G2 | 2–3 weeks | none (parity-checked) |
| C6 | **Parity and receipt harness.** Per-proof byte-equality against #310 classic receipts; lowest-nonce PoW rule; Ethproofs-boundary timer | Prerequisite for every claim | 1 week | none |
| C7 | **128-bit classic profile and LogUp ledger terms** | Needed for an "ahead of ZisK" claim; ≈ +2% base, +45% wrap | 1–2 weeks | medium (parameter accounting) |
| C8 | **Cell levers:** Keccak degree 3 on 2n, fused LS+CPU row, state/trie hints, U256 LS row, interpreter pass | −30 to −35% equivalent cells → 8 GPUs or p99 < 2 s | 1–3 weeks each (some in progress) | Keccak medium; LS row **high**; client hints low |

### GPU kernel work

| # | Track | Expected effect | Effort | Soundness risk |
|---|---|---|---|---|
| G0 | **Rent one RTX 5090.** Run #311's hardware gates; time the existing QM31 LDE/Blake2s/FRI/PoW kernels on sm_120; take an Nsight trace | First real numbers; validates sm_120 | days | none |
| G1 | **Lifted-Merkle expand / native-height absorb kernel** in `commitment/progressive.cu` | Avoids +300 ms per segment (45× hash amplification) | days–1 week | none (same digest; parity) |
| G2 | **RV64 composition codegen + persistent stream-K composition kernel** (lazy reduction, M31×QM31 multiplies, fused quotient); dedicated Keccak 4n kernel | Composition is 36% of work. Target ≤ 40 ms per segment | 4–6 weeks | none (parity against CPU quotient) |
| G3 | **RV64 classic integration package** (arena plan, controller, transcript binding, `proof_wire` assembly), reusing the existing LDE/commit/OODS/DEEP/FRI/PoW/decommit kernels. Milestone: **one CPU segment byte-identical on 1× 5090, ≤ 150 ms, with an ns/cell receipt** | First RV64 GPU proof; calibrates the whole plan | 3–4 weeks | low (fresh native receiver) |
| G4 | **GPU witness expansion** from C2 records (MAIN for CPU/LS/ALU/bridges) + RV64 LogUp interaction kernels (reuse the `relation/*` ragged kernels) | Removes ~12 GB of MAIN upload per block; witness ≤ 20 ms per segment | 4–6 weeks | low (parity) |
| G5 | **Truth kernels** (Keccak, secp, SHA, arith256: witness + composition) | Truths are ~45% of block time on CPU | 3–5 weeks | low |
| G6 | **Multi-GPU scheduler:** persistent per-GPU sessions, prefetch, completion rings, LPT, recursion on split streams, two-node fan-out | Near-linear scaling across 16 GPUs | 2–3 weeks | none |
| G7 | **Launch elimination:** CUDA graphs + PDL per proof shape (step 1). Then the interpreter megakernel for the FRI/OODS tail and recursion nodes (step 3) | ~10 ms per base proof; most of the fixed cost of recursion nodes | 1–2 weeks / 6–10 weeks | none |
| G8 | **GPU recursion** for RV64: leaf wrap + aggregation + final compression, pipelined | Recursion 1.3–4 s → ~0.4 s on the critical path. **The second gating item after C1** | 6–10 weeks (with C4) | high (via C4) |
| G9 | **Fused LDE → leaf hash → SMEM/cluster Merkle** | About −50% of commit HBM traffic; −10–15% of base time | 2–3 weeks | low (layout must match lifted Merkle) |
| G10 | *(Optional)* **GKR route on GPU:** #311 + batched multi-instance + OM31 PCS + v3 tuple emitters | −15 to −25% of GPU base time at 128-bit | 8+ weeks after #310's v3 gates | **high** |

### Recommended sequencing and gates

1. **Weeks 0–1 (in parallel):** G0, C6, G1. Exit gate: device numbers for #311 and the QM31
   kernels on sm_120.
2. **Weeks 1–6:** C5 → G2 and G3 in parallel, with C1 started. Exit gate: **one byte-identical
   RV64 CPU segment on 1× 5090 in ≤ 150 ms**, plus a measured ns/cell. Re-plan the GPU count from
   this number.
3. **Weeks 4–12:** C1, C2 → G4, G5, C3, G6. Exit gate: **block 24,628,607 base proofs on 4× 5090
   in ≤ 0.6 s**, with execution ≤ 0.1 s.
4. **Weeks 8–18:** C4 → G8, plus G7. Exit gate: **mean basket block ≤ 2 s on 16× 5090** at the
   Ethproofs boundary, recursion included, with the final proof ≤ 300 KiB.
5. **Then:** C7 (128-bit), C8 cell levers and G9 for p99 and 8 GPUs. G10 only if 128-bit with
   smaller proofs demands it.

## Caveats

- **Every GPU timing in this plan is a budget or a roofline, not a measurement.** No RV64 GPU
  receipt exists. The 200 ps/cell assumption is ~20% of an estimated 5090 roofline. It is
  cross-checked only against Airbender v1's published H100 rate translated to our cell count, which
  is a different arithmetization.
- Mean-block sizing scales block 607's cells per gas linearly. Block 607 is dispatch-heavy, so
  cells may be over-estimated by up to ~10%. The basket blocks other than 607 and 900 have not been
  proved under v3.
- The 5090 integer-throughput figures come from public SM specs. INT32 issue rates on sm_120
  should be confirmed by microbenchmark in G0.
- Recursion budgets (60 ms per level, a ~100 M-cell leaf wrap) are design targets; no RV64
  recursion circuit exists to size them against.

---

## Critic notes (2026-11-02, independent review)

I reread this plan against `cost-per-cell.md`, `cuda-backend-audit.md`, `megakernel-gpu-research.md`
and `remaining-score-wins.md`. I also rechecked live PR state with `gh pr list` and read the PR #306
body. Ordered by how much each one changes the plan.

### K1. Security: the "128-bit classic" profile does not exist, and the repo's own gate says so

- This plan's C7 / Risk row ("128-bit classic: q≈102 + P26, +2% base, +45% wrap") counts **conjectured**
  (ethSTARK) bits. PR #306's `security_policy` already **refuses QM31-only 128-bit claims**:
  `requireSingleDrawAlgebraicBudget` fails QM31 (|F| = 2^124) at 128 bits for even a degree-1
  single draw. `whole_protocol_128` is unavailable. The *only* candidate that passes the
  field-size inequality is degree 8 (OM31), which is the #310/#311 route.
- Proven (Johnson-regime) accounting at ρ = 1/2 gives about 0.5 bit per query. q70 + P26 is therefore
  about **61 proven bits** (cost-per-cell §2 lever 8), not 96. Even 100 proven bits needs about 148
  queries at P26. That is about +110% leaf-wrap hashing, not +45%, and the field-size ceiling
  still applies at 128.
- The comparison set is also measured in proven bits: OpenVM 2.0 claims **100-bit provable**
  (megakernel table). ZisK claims 128. EF's real-time criteria ask for ≥ 128-bit, and (to verify)
  EF's later zkEVM-security milestones move to *provable* bits by end of 2026, which is now.
- **Correction:** move the security decision from step 5 to **week 0**. It decides the field (QM31
  vs OM31), ρ, query count, wrap cost and therefore the route itself. If the target is ≥ 100 proven
  bits, the classic route's q70 numbers are a nominal control (the #306 body's words). Then the
  OM31/GKR PCS (G10) is **main line, not optional**, and §6's "−15 to −25%" becomes "+≥2× PCS cost
  per committed cell, partly offset by not committing interaction". Either way, do not tune
  recursion around q70 (§4.4 "q70 instead of q102 at the base").

### K2. "Throughput terms" do not apply to real-time proving

- Ethereum produces one block per 12 s slot. There is no queue of blocks to pipeline across, so
  "8× 5090 meets the 2 s average in throughput terms" (§0, §3 throughput view) and the audit's
  TL;DR #6 ("< 2 s on average is a throughput target") do not describe real-time proving. Every
  block's latency is its own critical path. Pipelining helps only on a historical backlog.
- **Correction:** delete the throughput view as evidence for the goal, or label it "backfill only".
  The 8-GPU stretch must be argued in latency terms. Measured against the Ethproofs boundary,
  "average" is weaker than p99, and §8 already says so.

### K3. Critical-path arithmetic

- The §3 formula as written sums to **≈ 0.85 s**, not 1.0–1.1:
  20 + max(200+85+150, 20+400) + 60 + 180 + 150 + 5 = 20 + 435 + 395 + 5 = 855 ms. The stated range
  is closer to a corrected figure, but for the wrong reasons.
- Missing from the max():
  - (a) **Leaf wraps compete for the same GPUs.** 40 wraps × 60 ms = 2.4 GPU-s, about 0.15 s per
    GPU at 16 GPUs. Base plus wraps is about 0.49 s per GPU, not 0.32–0.40.
  - (b) **Proofs cannot start before they exist.** The first segment is ready at ≈ 8 + 85 ms, and
    Keccak shards fill only as permutations accumulate, so the last ones land after execution ends.
  - (c) **Granularity.** 42 proofs of 100–150 ms on 16 GPUs means the makespan is ≥ 3 proofs, about
    450 ms per GPU even under perfect LPT.
- Corrected mean-block estimate at the plan's own assumptions (200 ps/cell, 60 ms per level):
  **≈ 20 + ~600 + 60 + 180 + 150 + 5 ≈ 1.0 s**.
- The recursion arithmetic is also short. "~2.5 GPU-s recursion" is really 40 × 60 + 14 × 60 ≈
  **3.2 GPU-s**, so the total is 8.6 GPU-s, not 8.
- Sensitivity, which the plan should state:
  - At 150 ms per recursion level (see K4), the mean block is ≈ 1.4 s and the max block ≈ 2.0–2.1 s.
    **p99 < 2 s then fails on 16 GPUs without the levers.**
  - At 400 ps/cell together with 150 ms per level, the mean block is ≈ 1.8 s.
  - The "none of the levers is required" claim (§0, §6) depends on both unmeasured numbers at once.
    Restate it as "not required *if* G3 lands ≤ 225 ps/cell *and* the leaf wrap lands ≤ 60 ms".

### K4. The leaf-wrap size (~100 M cells, 60 ms) looks 2–6× low

- The wrap is dominated by in-circuit Blake2s over openings. At ~7.3k opened columns × 4 B × 70
  queries × 2 trees, that is ≈ 4 MB, or about 64k Blake2s compressions, before Merkle paths
  (≈ 70 × 22 × 2 hashes). A Blake2s compression in an M31 AIR costs thousands of cells once
  xor/rotate lookups and interaction are counted.
- That puts the wrap at about **200–600 M cells**. The wrap then commits with Poseidon2, which is
  about 5× Blake2s per cell on GPU (cost-per-cell §3). The leaf wrap is then plausibly 100–200 ms,
  not 60 ms.
- PR #306 also states that **in-circuit native Word16 proof verification does not exist** and that
  cross-segment global RAM is not yet a protocol. Batch-local RAM is still required. C4's 4–8 weeks
  should be read as a lower bound.
- **Correction:** add a paper sizing task in week 0, "C4a: count leaf-wrap cells from the real v3
  column inventory and the Blake2s AIR row cost". If it comes out > 150 M cells, it changes:
  - segment size, toward 2^23 or 2^24;
  - the column-reduction priority (fused LS+CPU row);
  - possibly the base-layer hash (Blake2s at the base vs a Poseidon2 top tree).

### K5. Throughput assumptions vs evidence

- **"5090 ≈ 3× H100 on our math" is overstated.**
  - The 128-lane INT32 figure counts add/logic issue. 32-bit IMAD / mul-hi runs at about 64 lanes
    per SM per clock on recent NVIDIA parts. Check the CUDA guide throughput table for cc 12.0 in G0.
  - An M31 multiply needs a 64-bit product, so LDE and composition (multiply-heavy, about 60% of the
    roofline ops) see roughly **1.5×** an H100 per clock-SM (170 × 2.4 GHz vs 132 × 1.98 GHz), not
    3×.
  - Blake2s (add/xor/rotate) may see about 2× if funnel shifts are full rate.
  - The per-GPU roofline is therefore more like 50–60 ps/cell than 40. The 200 ps target becomes
    about 30–40% of roofline, not 20%. That is still plausible, but less margin than stated.
- **sm_120 is not sm_90.**
  - Consumer Blackwell has about 128 KB of L1/SMEM per SM (about 99 KB per block) against 228 KB on
    H100, and no confirmed large DSMEM clusters.
  - The Hazy 213 KB / 13-page paging scheme and the "16-CTA cluster finishes ~16 Merkle levels"
    design (§5.3, G9) were sized for H100/B200. Re-size them or drop them for sm_120.
  - Every existing QM31 kernel is qualified only on sm_90, so G0 must check correctness, not just
    timing.
- **The only anchor is weak, and a cheaper one exists.**
  - Airbender v1 at 21.8 MHz × "our 200 cells/instr" mixes arithmetizations. It is not a
    calibration point.
  - The repo already has resident QM31 Cairo proofs on H200, at 0.66–1.03 s per proof, with no cell
    counts. Extracting their per-tree column log-sizes from the proof wire or the commitment config
    gives a **real ns/cell for the exact kernels this plan reuses**, at zero rental cost. Make it G0's
    first step. The H200 → 5090 delta then comes from the G0 microbenchmarks.
- **Records are 32 B/instr.** An RV64 step with 64-bit rd, rs1 and rs2 values, an address, a value
  and the register and RAM prev-timestamps is more like 48–80 B. Stage 3 is then 6–10 ms, not 3.
  That is harmless, but fix C2's spec.
- **G4's rationale is wrong in magnitude.** About 12 GB of MAIN upload spread over 16 GPUs is
  ~0.75 GB, or ~15 ms, per GPU. The real cost of CPU-side MAIN is host **compute**. Witness fill
  runs at 6.3 core-ns per main cell over about 13 G main cells, ≈ 80 core-s per block, or ≈ 0.6 s on
  128 host cores, and those cores also run the traced re-execution. Keep G4 high, but for that
  reason.

### K6. Missing stages and capacities

1. **Cross-segment memory consistency.** Stage 2 assumes each segment's traced re-execution can
   emit RAM prev-timestamps in parallel. That needs either segment-local memory with
   boundary/continuation tables, or last-access timestamps carried in the checkpoint. The latter
   makes the "no trace, ≥ 500 MHz" first pass a memory-tracking pass. #306 shows global RAM is
   still diagnostic and batch-local RAM is required. Specify which one C1/C2 targets, and add the
   global-memory/boundary proof and its recursion node to the inventory.
2. **Second node's inputs.** One host runs the first pass, but node 2's 8 GPUs need either about
   1 GB of records over 100 GbE (≈ 85 ms, on the critical path) or checkpoint memory images.
   Simplest fix: run the deterministic first pass redundantly on both hosts, and add it to §3.
3. **No P2P on GeForce.** 5090s do not expose PCIe P2P, so all cross-GPU traffic goes through
   pinned host memory. That is fine at MB sizes, but strike the "in-kernel P2P / ParallelKittens"
   carry-over for this SKU.
4. **PCIe lanes.** 8 × x16 Gen5 GPUs plus a 100 GbE NIC exceed one 64-core socket's 128 lanes. The
   chassis needs PCIe switches or 2 sockets. Budget and price that.
5. **VRAM with co-resident recursion.** §1's "2–3 proofs at ~8 GB" leaves no room for a split-stream
   leaf wrap, sized in K4 at 200–600 M cells with Poseidon2 trees and its own arena, plus the static
   images.
   - At 2^23 segments (the 8-GPU stretch), one proof is ~15 GB.
   - Re-plan as "1 base proof plus 1 recursion arena plus a prefetch buffer", or evaluate the
     **RTX PRO 6000 Blackwell**: same sm_120, 96 GB, datacenter-licensed. It is what Airbender
     Prime uses on a single GPU.
6. **PoW tail.** 26-bit grinding is geometric. p99 is about 4.6 × 2^26 hashes, ≈ 14 ms rather than
   3–5 ms, and it hits ~42 proofs plus the recursion proofs. Count it in p99, not in the mean.

### K7. Track ordering: where the leverage is

- Proposed week-0 set, all cheap, that de-risks the plan more than G1:
  1. **K1 security decision** (C7 moved up): pick the proven-bits target and with it the route.
  2. **C4a leaf-wrap sizing on paper** (K4).
  3. **G0, starting from H200 Cairo ns/cell extraction** (K5), then the 5090 rental with IMAD/SMEM
     microbenchmarks.
  4. **The memory-model decision for parallel re-execution** (K6.1). It sets C1's design.
- **G2 (composition codegen) is gated on K1.** If the route becomes OM31, the composition IR and
  the kernels change field. C5's recording lane is field-generic and safe to start. G2's kernel
  tuning is not.
- **C1 (4–8 weeks for a ≥ 500 MHz AOT/JIT plus parallel traced re-execution) is optimistic.** Set a
  floor target of ≥ 250 MHz first pass (≈ 0.4 s, still inside budget), plus a stretch, so the plan
  does not hinge on a JIT milestone.
- **Leave G9 and the interpreter megakernel (G7 step 3) late, as planned.** Their sm_120 premises
  need re-sizing first (K5).
- **PR state is still accurate.** As of this review, `gh pr list` shows #311 (updated 11:18Z) is
  still the newest PR touching `backends/cuda` or `*_cuda/`, and #299 is the only other one. #306 is
  not a GPU PR, but it is directly relevant to K1, K4 and K6.1, and this plan should cite it.

