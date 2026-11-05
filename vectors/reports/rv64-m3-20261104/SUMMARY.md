# RV64 M3 campaign summary (2026-11-04)

Branch `codex/rv64-m3-integrate`, merged into `codex/rv64-cuda-ethereum` (PR #314). Hardware: 2x RTX 5090 on a
shared pod.

**Labels:**
- **[M]** measured: a single observation with its receipt in this directory.
- **[E]** estimated.

No timing here is a median. Several large-block runs overlapped with a CPU-only receiver for the previous
block (nice 10, 8 workers).

## Headline
- **All 15 basket blocks are proven on the 2-GPU path [M].**
  - Each root was accepted by a fresh, separate, CPU-only receiver built from this tree. The receiver ran
    with the setup cache unset, CUDA disabled and the fold class cache disabled.
  - The native proofs verify, and the output matches the pin.
  - This includes **26235159**, the largest block, which had never completed on 2 GPUs before.
  - The scale-up ran one block at a time in increasing instruction count. Two blocks failed first and
    were fixed, then proven once (see below).
- **Sum of the 15 request walls: 1,843 s, against 9,209 s for the v7 1-GPU baseline, i.e. 5.0x [M].**
  Per-block speedup ranges from 4.4x to 5.5x.
- **24628607: 98.9 s became 52.4 s cold, 41.1 s warm, and 37.4 s warm with narrow runs [M].** The M3 target
  of ~10 s is **not met**: the best run is 3.7x away from it.

## 24628607 on 2 GPUs [M] (integrate/24628607.json)
| run | request | capture | setup | native prove | native verify on path | recursion | receiver |
|---|---:|---:|---:|---:|---:|---:|---|
| accepted v7 (before) | 98.92 | 6.17 | 13.06 | 10.33 | 5.54 | 63.62 | accepted |
| integrate cold | 52.44 | 3.25 | 12.68 | 6.33 | 0 (1.9 s side thread) | 29.97 | accepted |
| integrate warm (disk-seeded SetupCache) | 41.11 | 3.39 | 0.77 | 6.51 | 0 | 30.21 | accepted |
| integrate warm + narrow runs | **37.44** | 3.24 | 0.72 | 6.25 | 0 | 27.04 | accepted |
| scale-up config (cold, narrow, CPU_REPLAY, CORE_SINGLE_STREAM) | 51.11 | 3.28 | 12.55 | 7.83 | 0 | 27.28 | accepted |

- **Native and leaf proofs:** native bins, bundle and all 17 leaf proofs are byte-identical to accepted v7.
- **Folds and root:** the 16 folds, the root and the tree differ by design, because of fold message v2.
- **Across these runs:** the cold, warm and narrow-run recursive proofs are byte-identical to each other.

## Per-block scale-up [M] (summary.json; receipts in integrate/scale/)
| block | instr (M) | CPU+truth | request s | capture | setup | native prove | recursion | v7 1-GPU s | speedup | receiver |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 26235156 | 15.3 | 4+7 | 34.28 | 2.54 | 8.33 | 5.16 | 18.07 | 152.9 | 4.46x | accepted |
| 24647140 | 24.6 | 6+9 | 48.18 | 3.25 | 12.80 | 7.47 | 24.44 | 211.5 | 4.39x | accepted |
| 24628607 | 26.9 | 7+10 | 51.11 | 3.28 | 12.55 | 7.83 | 27.28 | 236.8 | 4.63x | accepted |
| 25229957 | 27.1 | 7+10 | 53.77 | 3.59 | 13.59 | 7.89 | 28.47 | 242.3 | 4.51x | accepted |
| 24628608 | 38.6 | 10+10 | 60.32 | 4.09 | 15.95 | 9.51 | 30.54 | 286.9 | 4.76x | accepted |
| 24626900 | 49.1 | 12+8 | 68.27 | 5.00 | 19.40 | 11.77 | 31.82 | 301.0 | 4.41x | accepted |
| 24697070 | 57.8 | 14+17 | 86.37 | 5.74 | 23.35 | 14.40 | 42.54 | 430.0 | 4.98x | accepted |
| 24697073 | 60.4 | 15+13 | 84.60 | 5.24 | 24.40 | 14.83 | 39.86 | 401.8 | 4.75x | accepted |
| 26235168 | 113.4 | 28+21 | 145.36 | 9.23 | 45.22 | 25.13 | 65.35 | 788.7 | 5.43x | accepted |
| 25229955 | 122.5 | 30+19 | 147.66 | 9.14 | 46.80 | 26.45 | 64.73 | 774.7 | 5.25x | accepted |
| 24628590 | 157.6 | 38+18 | 185.96 | 11.62 | 66.29 | 34.71 | 72.60 | 891.4 | 4.79x | accepted |
| 25229951 | 165.9 | 40+18 | 179.03 | 11.26 | 62.26 | 32.74 | 72.02 | 892.0 | 4.98x | accepted |
| 24628595 | 172.8 | 42+24 | 213.30 | 13.10 | 74.54 | 38.21 | 86.60 | 1165.6 | 5.46x | accepted |
| 24628611 | 187.7 | 45+22 | 234.33 | 18.09 | 83.70 | 42.41 | 89.19 | 1168.8 | 4.99x | accepted |
| 26235159 | 204.8 | 49+26 | 250.46 | 16.51 | 93.05 | 43.66 | 96.41 | 1265.0 | 5.05x | accepted |

- **Native verify** runs on a side thread joined before publication; the join waits are at the µs level.
  Its side-thread time is in summary.json.
- **Comparison with the 98.9 s 2-GPU run** is possible only for 24628607 (98.92 → 51.11 s, 1.94x). No other
  block had been proven on the earlier 2-GPU path, and 26235159 had failed there.
- **Byte parity:** native bins and bundle are byte-identical to accepted v7 on all 15 blocks. Fold and root
  bytes differ by design (fold v2).
- **Run environment:** every scale-up block ran with:
  - `STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1`;
  - `STWO_RV64_GPU_CPU_REPLAY=1` and `STWO_RV64_CORE_SINGLE_STREAM=1`. These are the accepted v7 basket
    environment; compact replay is required for 49 segments.
  - From 25229951 onward, also `STWO_RV64_PCS_IDLE_CACHE_BYTES=0`.
- **Binaries:**
  - Blocks 1-10: driver 91ce6642 and library 7de22322 (catalogues-v2).
  - Blocks 11-15: driver b28544a1 and library fe8a3e10 (catalogues-v3). This driver differs from the first
    only by failure-only diagnostic prints.

## Scale-up failures and fixes
1. **24628590 (38 CPU segments): CudaGlobalWitnessFailed in native stage two.**
   - **Cause:** the public-boundary (core initial/terminal) global projection reached log 23. The frozen
     rebuild-package global catalogue still guarded `log>22` and returned cudaErrorInvalidValue. The Zig
     policy (`MAX_PUBLIC_BOUNDARY_LOG`) and the generator (`global_aot.zig`, bb61cca24) both admit log 23.
   - **Ruled out:** the accepted d5766d83 driver plus the accepted library proved this block on 2 GPUs [M].
     Infra's pre-mem library failed identically, so no stream caused this.
   - **Fix:** regenerated the global catalogue with `rv64-global-fixtures --catalog`. 27/29 files are
     byte-equal; the 2 boundary kernels differ only in the guard. The result is catalogues-v3, now the
     harness default.
2. **25229951 (40 CPU segments): CudaResidentCompositionFailed, native_status=2 (OOM).**
   - **Where:** at the first truth composition. The pool held 29.0 GB used against a 30.06 GB cap, but live
     leases were only 23.1 GB.
   - **Ruled out:** `STWO_RV64_COMPOSITION_DIRECT=0` failed identically [M].
   - **Fix:** `STWO_RV64_PCS_IDLE_CACHE_BYTES=0` (release idle upper-PCS cache; proof-neutral) proved the
     block [M]. It was kept for the remaining blocks.
   - **Proper fix:** composition admission should evict idle PCS cache, as mem's physical admission does
     for PCS, or the bound should become a default.

## What landed per stream
- **infra:** from-source driver, receiver and CUDA image; a content-addressed object store (incremental
  CUDA image ~130 s); a one-command harness; an nsys timeline.
- **host [M]:**
  - a lock-free budget with an smp child (capture 6.2 → 3.3 s, native prove 10.3 → 6.3 s);
  - native verify overlapped with recursion (5.5 s → 0 on the path);
  - one capturing verify per CPU leaf;
  - a warm SetupCache (setup 12.7 → 0.7 s, disk-seeded).
- **pipe [M]:** three-stage nodes and a pipelined executor (recursion 63.6 → 27-30 s on 24628607). In
  integration, the topo plan-class hint is now set on pipelined prep threads.
- **mem:** streaming LDE→Merkle, direct composition and PCS streaming, plus lifetime pools. 26235159 now
  fits. The ≥40-segment blocks also needed the idle-cache bound.
- **topo:**
  - fold message v2 (**proof-changing**; argument in design/riscv-proving-stack/rv64-m3-topo-binding.md;
    adversarial substitutions rejected);
  - producer plan/PP class caches and a receiver class cache. The receiver double-free found by the check
    was fixed in 7afb20e2b.
  - Narrow-run assignment is qualified byte-identical on both dev blocks [M].
- **recsize: NOT merged.**
  - Its m3 outer profile and k-ary folds are proof-changing, off by default, and were never run on a GPU or
    a real block.
  - They conflict semantically with fold v2 (`classKey([2]Child)`, message words) and with pipe's executor
    (`Node.left/right`).
  - The branch codex/rv64-m3-recsize at 5d68d0f01 is intact for a follow-up.

## What remains for M3 (~10 s on 24628607)
Best measured is 37.4 s warm, of which recursion is ~27 s. The savings below are [E] from the review plan
and stream estimates; none is measured.
1. **Cut per-node recursion cost by 3-4x.**
   - Merge recsize after generalizing fold v2 to N children: 0.34x fold work, depth 5 → 3 (derived in
     recsize).
   - A fused Blake2s gadget [E -6..-12 s]: leaves are most of the circuit work, and Blake is ~74% of a leaf.
   - Outer LogUp-GKR [E -8..-15 s].
2. **Canonical native segment geometry**, so leaves collapse into plan/PP-cacheable classes as folds did
   [E -3..-8 s cold].
3. **Native prove at ~5 s (now 6.3) and capture at ≤1 s (now 3.3).** Sharding the ledger is estimated at
   -1.5..-2 s [E].
4. **Stream native proofs into the recursion ready-queue** [E -2..-3 s].
5. **Large blocks:**
   - Cold setup dominates (93 s on 26235159). The warm resident service with a persisted setup cache
     addresses this, but was not used in the scale-up.
   - Make the idle-PCS-cache policy a default.
   - Recursion is 65-96 s on these blocks.
6. **Check the remaining frozen catalogues** (projection, truth, rational, outer) against the current
   generator, as was done here for global.

## Soundness
- **Scheduling-only changes** (host, pipe, mem, narrow runs, setup cache, catalogue guard, idle-cache bound):
  native and bundle bytes are identical to v7 on all 15 blocks, and leaf bytes are identical on the dev
  blocks.
- **Fold v2:** binding argument plus adversarial checks (topo). Acceptance relies on a fresh receiver built
  from this tree with the class cache disabled.
- **Profiles:** the native profile stays conjectured128_b2_q108_p20_fold4, and the outer PCS profile is
  unchanged.
