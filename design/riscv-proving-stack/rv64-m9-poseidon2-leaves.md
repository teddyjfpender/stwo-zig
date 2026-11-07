# RV64 M9 prep: Poseidon2-M31 Merkle leaves (proof-format lever)

Stream `m9-poseidon2-leaves`, branch `codex/rv64-m9-poseidon2-leaves` from `codex/rv64-m7-integrate` @ `95e3d7e15`.
Flag: `STWO_RV64_M9_POSEIDON2_LEAVES` (default off; no production call site reads it yet).
Receipts: `vectors/reports/rv64-m9-prep/m9-poseidon2-leaves/` (`receipt.json` holds every source and binary hash).
Labels: [M] measured, [D] derived from code or accepted census logs, [E] estimate.

This implements the leaf part of stage S1 in `rv64-4gpu-realtime.md` §7.4 (design branch `codex/rv64-4gpu-realtime-design`), with the same layout contract as today's Blake2s leaf path. It also prices the lever end to end, which §7.2 had only sketched.

## 1. Result

| question | answer |
|---|---|
| Same-contract CPU reference + CUDA kernel | Built (new files only). GPU = Zig reference on **336/336 runs** (review re-run): 168 cases × 2 permutation variants, 344,064 digest rows, 3,984 prefix states, **2,688 GPU parent nodes and 46 full Merkle roots** (the builder's gate never compared the GPU parent layer), widths 1–200, sizes 2^10–2^24, mixed heights, seeded chains including three splits on an exact rate boundary, and the real CPU0 FIXED-tree geometry [M] |
| P2 vs Blake2s `mixed_leaf_kernel`, same shapes, 5090 | Leaves are **×7.1–11.1 slower** at log ≥ 20 for widths ≥ 16, and ×5.1–8.3 at widths 1–8. Leaves plus full tree ×8.4–11.1. P2 runs at **2.93–3.11 G permutations/s**; Blake runs at 1.3–1.45 TB/s (HBM bound) at wide shapes [M] |
| All 68 native trees of 24628607 (real geometry, prefix-bank chain) | Warm Blake 59.9 ms → P2 596 ms per request: **+0.536 GPU-s** (×9.95) [M]. With a 1-permutation 2-to-1 node: +0.452 GPU-s [E] |
| In-circuit cost per decommitment | **×15–22 cheaper** with the sponge node and ×23–29 with a 2-to-1 node: 741 cells per permutation against ~22.7k per Blake2s compression [D] |
| Whole recursion leaf | ×0.19 cells (accepted census) to ×0.21–0.31 (model at 85–74% hash share; central ×0.243) [M/D] |
| Serial device transcript (`channel_mix<<<1,1>>>`) | P2 sponge **×23.9 slower** than Blake2s per mix: 12.9 µs per permutation against 0.72 µs per compression on one thread (`serial-mix.jsonl`) [M] |
| Projected net kernel GPU-s per request [E], **after review** | **A net loss as built.** p50 (29.1 M gas): **+8.7 GPU-s** (sponge node), +5.6 (2-to-1), ≈0 (2-to-1 + P2 kernels ×0.6). Positive only once the serial transcript is also re-engineered: −6.2 GPU-s at p50 and −11.4 at p95 (20% of kernel GPU-s) in the `engineered_target` row, which is a target and not measured. 24628607 as built: +2.2 GPU-s and up to +2.3 s request wall. The builder's original −4.4 / −8.0 GPU-s rows are kept in `model.json` as `builder_original_central` |

**The finding that changes the plan (builder).** Recursion provers commit with P2 too, because every recursion tree is verified in-circuit by the next layer. Their Merkle kernels therefore get ~10× slower per committed cell, which eats part of the cell cut.
- Recursion GPU-s after the switch ≈ R · c · ((1−m) + m·k), where:
  - c is the cell ratio, 0.19–0.31;
  - m is the Merkle share of recursion kernel time;
  - k is the P2/Blake tree cost, 9.95 [M].
- The §7.2 estimate ("recursion ≈ 1.6–2.0× native") left this term out.

**Review corrections (adversarial review, 2026-11-07).** Three inputs to the builder's projection were wrong or missing. Together they turn every sponge-node and 2-to-1 row into a loss.
1. **m was too low.**
   - The builder used m = 0.18, scaled from the request-wide Merkle share.
   - The request's Merkle kernels are 1.520 GPU-s of 8.478 (`ab8-kernels.json` fullstack: `mixed_leaf_kernel` 1.250, `child_layer_kernel` 0.180, `layer` 0.080, `fri_leaf_kernel` 0.010) [M].
   - Native hashing is only ~0.12 GPU-s of that [E]. Nearly all Merkle time is therefore recursion's own.
   - So m = 1.40 / (0.573 × 8.478) = **0.29**, and 0.28–0.33 across recursion shares 0.60–0.50 [D].
   - Break-even k drops from the builder's 15–18 to **11.8** (central c), and the measured k = 9.95 sits just below it. The recursion cut alone shrinks from 6.4 to 2.3 GPU-s at p50.
2. **The native delta used the wrong geometry.**
   - The chain replay is M6 geometry at log blowup 1. The production default is the frozen D2 native profile `d2_native_b4_q54_p20_fold4`, at log blowup 2 (`om31_security_candidate.zig:438`; the opt-combined gates are byte-identical to the D2 golden).
   - The central rows now use 2× the measured native hashing [E]. Only the `optimistic_b2_retune` row keeps 1×.
3. **The serial transcript was missing.**
   - The device channel (`native/rv64/channel.cu` `channel_mix`, launched `<<<1,1>>>`) hashes digest ‖ words on one thread, on every proof's Fiat–Shamir critical path. Today it costs 0.0775 GPU-s over 363 calls [M, ab8].
   - The same mix as a one-thread P2 sponge is ×23.9 slower [M, `m9_p2_serial_mix.cu`, 8–4,096 words]. That adds **+1.78 GPU-s** on 24628607 and +6.8 at p50 [E], all of it serial.
   - The channel cannot stay on Blake2s: the pure-P2 census counts a P2 channel in-circuit, and a Blake channel in-circuit would cost ~22.7k cells per compression on every mix.
   - §8 step 5 therefore needs a real design: a warp-cooperative permutation (pil2 `poseidon2PermuteWarpReg`) or chunked/tree absorption of large mixes, which is a protocol change.
- Smaller fixes: the 2-to-1 node saves 14% of native P2 permutations, not 28% (nodes are 28% of permutations and halve) [D]. PoW at p20 adds ~0.01 GPU-s [E] and is negligible.
- The lever stays open but **conditional**. Before integration, build and measure in this order: the P2 kernel at ≥ ×1.7 throughput, the 2-to-1 node (needs an S0 note), and a parallel transcript at ≤ ×3 Blake. The `engineered_target` row is what the three together would buy.

## 2. What was built

| file | role |
|---|---|
| `src/core/vcs_lifted/poseidon2_m31_mixed_leaf.zig` | CPU reference with the mixed-segment layout contract: segments, lifted index, seeded prefix states, refusal of non-canonical words. `enabled()` reads the flag. Its tests compare against an independent model of the expansion algorithm in `prover/vcs_lifted/leaves.zig` and the existing `Poseidon2M31MerkleHasher` |
| `src/core/m9_poseidon2_leaves_test_root.zig` | Focused test root: `zig test src/core/m9_poseidon2_leaves_test_root.zig`, 90/90 pass after review (a rate-boundary chaining test was added, and the self-comparing "pinned fingerprint" assertion was replaced by real pinned values) [M] |
| `src/core/m9_poseidon2_leaves_vectors.zig` | Golden-vector emitter (168 cases with parent `N` and root `T` records; 18.3 MB, kept out of git; sha256 in the receipt) |
| `tests/cuda/rv64/m9_poseidon2/m9_p2_serial_mix.cu` | Review addition: one-thread transcript-mix microbench, Blake2s `hash_digest_and_words` (exactly `channel_mix`) against a one-thread P2 sponge over the same words |
| `tests/cuda/rv64/m9_poseidon2/poseidon2_mixed_leaf.cu` | It is staged here on purpose: the CUDA and CuMetal product builds compile every `.cu` under `native/` (`scripts/cuda_build_lib/native_closure.py`), so it moves to `native/commitment/` only at integration (§8 step 3). It provides `stwo_p2m31_mixed_seeded_on` (leaf digests, or prefix banks) and `stwo_p2m31_parent_layer_on` |
| `tests/cuda/rv64/m9_poseidon2/m9_poseidon2_leaves.cu` | Standalone gate with three modes: `parity`, `bench` (single call against `stwo_blake2s_mixed_leaf_on` + `stwo_blake2s_layer_on`) and `chain` (per-height prefix-bank chain against `stwo_blake2s_mixed_seeded_eager_on`, the production default in `pcs_pipeline.cuh:765`) |
| `scripts/rv64_m9/poseidon2_leaves_model.py` | Lever model; writes `model.json` |
| `src/core/vcs_lifted/mod.zig` | One additive line exporting the reference |

### 2.1 Layout contract (identical to `mixed_leaf_kernel`, progressive.cu)

What the kernel shares with the Blake path:
- It uses the `MixedSegment` ABI unchanged (`mixed_layout.h`: columns, stride_words, capacity_words, source_size; ≤ 96 segments).
- Sizes are powers of two, and leaf row r reads source row `((r >> (ratio+1)) << 1) | (r & 1)`.
- Words are absorbed in segment then column order.
- Host validation is the same as `stwo_blake2s_mixed_seeded_eager_compact_on`: exact slabs, no overlap with outputs, explicit word capacities.

What the hash forces to differ:
- **Digest:** 9 canonical M31 words (36 B), row-major. This matches the proof-wire `ForHasher` 36-byte family and `Poseidon2M31MerkleHasher` bytes.
- **Prefix bank:** the 24-word sponge state, stored word-major (SoA). The absorb position is `absorbed % 12`, owned by the caller.
  - There are no pending words: full rate blocks are permuted eagerly. This is the natural "eager" convention, so the seeded chain needs no deferred final block.
  - A bank costs 96 B per row, against 32–92 B for Blake eager/compact.
- **Canonicity:** inputs must be canonical (< p). A violation sets `status` bit 0, and the row is left unwritten. Blake hashes raw words, so this check is new; it costs one compare per word.
- **Framing:** the experimental M7 sponge (`crypto/poseidon2_m31_sponge.zig`).
  - Rate 12, capacity 12.
  - state[22] = version 1, state[23] = domain (1 for a leaf, 2 for a node).
  - Additive absorption, a mandatory 1-marker (an extra block at exact rate boundaries), and a 9-limb output.
  - The node hashes 18 limbs, which costs 2 permutations.

### 2.2 Kernel

The kernel uses one thread per leaf row, with the 24-limb state in registers.
- Words are absorbed at a runtime position through a static-index select, so there is no local-memory indexing.
- Full rate blocks load straight into registers.
- Variant 1 reuses the M7 `p2m31_register::permute`: common M31 mul/add, and the internal diagonal as a 31-bit rotation. Leaves use 42 registers and parents 40, with no spills (`-Xptxas -v`, sm_120).
- Variant 2 is a fully unrolled form with u64 lane sums. It is **×0.98–1.16 of v1's time, so not faster**: a negative result, kept for reference [M].

## 3. Parity [M]

Run: `parity.log`. The builder's run used binary `d5372221…` (165 cases, 330/330). The review re-run used binary `526aad18…` with vectors `2f3567a3…` (168 cases): **336/336 pass, including 2,688 parent nodes and 46 roots** checked against the Zig `hashParent`. The run's GPU was idle at entry. The benches used the earlier binary `1dc4e0c4…`, whose device code is the same; a re-check on the final binary agrees within 2% and gives identical roots.

| coverage | detail |
|---|---|
| single height | widths {1,2,3,11,12,13,23,24,25,36,47,64,100,128,199,200} × logs {10,12,14,16,18,20,22,24} |
| wide shapes at log ≥ 20 | split into aliased 8-column segments, which also exercises misaligned absorb positions |
| mixed heights | 24 random shapes with 2–12 segments, heights 2^1..2^20 and total width ≤ 200 |
| real geometry | CPU0 FIXED tree of 24628607 (12 heights, 203 columns, 2^23), and composition 16 × 2^23 |
| seeded chain | 14 cases, prefix bank at the split height then the seeded final call; prefix states checked limb for limb. Three cases (`chain-rate-boundary-{12,24,36}`) split at absorbed % 12 == 0 |
| parents and roots (review) | GPU `stwo_p2m31_parent_layer_on` over leaf rows 0..15 of every case (8 parents each), and the full root of every case whose rows are all listed (log ≤ 10) |
| sampled rows | all rows up to 2^10; at larger sizes 1,024 rows: first 16, last 16 and random |
| contract | refuses bad geometry, and flags non-canonical input with status = 1 |

The `chain` bench also checks GPU chained leaves against the GPU flat call on 4,096 rows of every one of the 68 real trees.

## 4. Microbenchmarks [M]

Setup: CUDA events, medians of 7 (single shapes) or 3 (trees), after one warm-up. RTX 5090, driver 570.195.03, nvcc 12.8, `-O3 -arch=sm_120`. GPU util 0–24% at entry and ~0% at exit (`bench-gpu-state.txt`). Full rows are in `bench-single.jsonl`.

| shape (log:width) | Blake leaf ms | P2 leaf ms | leaf × | leaf+tree × | P2 G perm/s | Blake TB/s |
|---|---:|---:|---:|---:|---:|---:|
| 18:200 | 0.161 | 1.658 | 10.3 | 9.5 | 2.69 | 1.30 |
| 20:16 | 0.100 | 0.707 | 7.1 | 9.0 | 2.97 | 0.67 |
| 20:64 | 0.201 | 2.104 | 10.5 | 10.3 | 2.99 | 1.34 |
| 20:200 | 0.579 | 6.026 | 10.4 | 10.4 | 2.96 | 1.45 |
| 22:64 | 0.755 | 8.249 | 10.9 | 11.1 | 3.05 | 1.42 |
| 23:16 (composition) | 0.671 | 5.469 | 8.1 | 9.5 | 3.07 | 0.80 |
| 24:16 | 1.332 | 11.126 | 8.4 | 9.5 | 3.02 | 0.81 |
| CPU0 FIXED, flat single call | 4.192 | 46.610 | 11.1 | 11.1 | 3.06 | — |

**Real trees, prefix-bank chain** (`chain-24628607-trees.jsonl`; 17 proofs × 4 trees, M6 geometry at log blowup 1, max LDE 2^23):

| | Blake ms | P2 ms | × | operations |
|---|---:|---:|---:|---|
| cold (68 trees) | 70.5 | 685.6 | 9.73 | — |
| warm (51 trees, FIXED omitted) | 59.9 | 596.0 | 9.95 | 1.431 G permutations against 0.943 G compressions, the same counts as the M7 hash-budget model [D] |

The numbers line up with M7: `gpu-commit-common-rotate` measured 11.7–13.4× for flat full trees, and its native scenario was 0.52–1.53 GPU-s. This stream measures the low end, 0.536.

## 5. In-circuit cost per decommitment [D]

**Costs from code:**
- **P2:** 476 MAIN + 73 FIXED + 192 classic INTER = **741 cells per permutation**, or 565 with GKR interaction (`integrations/riscv_cpu/poseidon2_outer/layout.zig`). Padded inside the accepted census it is 792.
- **Blake2s:** ~22.7k committed cells per compression (`rv64-4gpu-realtime.md` §7.1).
  - Cross-check: the accepted all-Blake CPU-leaf census has 1,339,680 G-gates, i.e. 16,746 compressions (80 G-gates each).
  - Its total is 554.8 M cells, of which 82.05 M are the non-hash part measured in the pure-P2 census.
  - That leaves **28.2k cells per compression** once padding, XOR tables and `m31_to_u32` are attributed.

**Per query, per tree** (width w, depth d):
- Blake: (⌈w/16⌉ + d) compressions.
- P2: (⌊w/12⌋ + 1 + 2d) permutations, or + d with a 2-to-1 node.

| tree (24628607 CPU proof) | w | d | Blake cells | P2 cells | × | × with 2-to-1 |
|---|---:|---:|---:|---:|---:|---:|
| FIXED | 203 | 23 | 817 k | 46.7 k | 17.5 | 27.6 |
| MAIN | 3606 | 23 | 5.65 M | 257 k | 22.0 | 23.5 |
| INTER | 2008 | 23 | 3.38 M | 159 k | 21.3 | 23.9 |
| composition | 16 | 23 | 545 k | 35.6 k | 15.3 | 29.4 |
| recursion-like | 300 | 21 | 908 k | 50.4 k | 18.0 | 26.1 |

**Whole leaf:**
- The accepted census, at the same source geometry (b4 q54 P20 fold4), goes 554.8 M → 106.3 M cells: ×0.192 [M/D] (`vectors/reports/rv64-m7-20261105/poseidon2/`).
- The model gives ×0.206–0.308 for a 74–85% hash share (§2.1 of the 4-GPU doc), with a central ×0.243, or ×0.231 with 2-to-1 nodes.

## 6. Projection per request [E] (`model.json`, schema v2-reviewed)

Inputs:
- kernel GPU-s = 1.8 + 0.28 · Minstr (bench15-1 fit, `codex/rv64-m8-gpu`);
- Minstr = gas × 3.55 instructions/gas (basket range 2.71–3.89);
- recursion share 0.573 of kernel GPU-s: recursion-node kernels 5.99 of 10.45 GPU-s in `rv64-m8-20261106/p3p5/NATIVE-REGRESSION-AUDIT.md` [M];
- **m, the Merkle share of recursion kernel time, = 0.29** (0.28–0.33), from `opt-combined/ab8-kernels.json` (§1, review correction 1) [D];
- the native delta: the measured 24628607 tree replay × **2 for the production D2 b4 LDE** (correction 2), scaled by Minstr;
- the transcript delta: `channel_mix` 0.0775 GPU-s [M] × (×23.9 − 1) measured in `serial-mix.jsonl` (correction 3), scaled by Minstr;
- gas percentiles from 2,901 mainnet blocks (Sep–Oct 2026): p50 29.11 M and p95 55.82 M gas (re-checked against `gas_sample.json`).

Signs: **positive = more GPU-s (a loss)**, negative = a cut.

| block | scenario | recursion GPU-s | recursion cut | native + | transcript + | **net Δ GPU-s** | % of kernel |
|---|---|---:|---:|---:|---:|---:|---:|
| p50, 103 Minstr, 30.7 kernel GPU-s | as measured, sponge node (c 0.243, m 0.29, k 9.96, native ×2, mix ×23.9) | 17.6 | 2.3 | 4.1 | 6.8 | **+8.7** | +28% |
|  | 2-to-1 node (c 0.231, m 0.29, k 8.55, native ×2, mix ×23.9) | 17.6 | 4.7 | 3.5 | 6.8 | **+5.6** | +18% |
|  | 2-to-1 + P2 kernels ×0.6 (c 0.231, m 0.29, k 5.13, native ×2, mix ×23.9) | 17.6 | 8.7 | 1.9 | 6.8 | **+0.0** | +0% |
|  | **engineered target**: 2-to-1 + ×0.6 + transcript ×3 (c 0.231, m 0.29, k 5.13, native ×2, mix ×3.0) | 17.6 | 8.7 | 1.9 | 0.6 | **-6.2** | -20% |
|  | pessimistic (c 0.308, m 0.33, k 11.10, native ×2, mix ×23.9) | 15.4 | -5.2 | 4.1 | 6.8 | **+16.1** | +52% |
|  | optimistic: census c, native back to b2 (c 0.192, m 0.28, k 5.13, native ×1, mix ×23.9) | 18.4 | 10.9 | 0.9 | 6.8 | **-3.1** | -10% |
|  | builder's original central (m 0.18, b1, no transcript) (c 0.243, m 0.18, k 9.96, native ×1, no mix) | 17.6 | 6.4 | 2.1 | 0.0 | **-4.4** | -14% |
| p95, 198 Minstr, 57.3 kernel GPU-s | as measured, sponge node (c 0.243, m 0.29, k 9.96, native ×2, mix ×23.9) | 32.8 | 4.2 | 7.9 | 13.1 | **+16.8** | +29% |
|  | 2-to-1 node (c 0.231, m 0.29, k 8.55, native ×2, mix ×23.9) | 32.8 | 8.7 | 6.7 | 13.1 | **+11.0** | +19% |
|  | 2-to-1 + P2 kernels ×0.6 (c 0.231, m 0.29, k 5.13, native ×2, mix ×23.9) | 32.8 | 16.2 | 3.6 | 13.1 | **+0.5** | +1% |
|  | **engineered target**: 2-to-1 + ×0.6 + transcript ×3 (c 0.231, m 0.29, k 5.13, native ×2, mix ×3.0) | 32.8 | 16.2 | 3.6 | 1.1 | **-11.4** | -20% |
|  | pessimistic (c 0.308, m 0.33, k 11.10, native ×2, mix ×23.9) | 28.6 | -9.7 | 7.9 | 13.1 | **+30.7** | +54% |
|  | optimistic: census c, native back to b2 (c 0.192, m 0.28, k 5.13, native ×1, mix ×23.9) | 34.4 | 20.3 | 1.8 | 13.1 | **-5.4** | -9% |
|  | builder's original central (m 0.18, b1, no transcript) (c 0.243, m 0.18, k 9.96, native ×1, no mix) | 32.8 | 12.0 | 4.0 | 0.0 | **-8.0** | -14% |
| 24628607, 26.9 Minstr, 9.3 kernel GPU-s (fit) | as measured, sponge node (c 0.243, m 0.29, k 9.96, native ×2, mix ×23.9) | 5.3 | 0.7 | 1.1 | 1.8 | **+2.2** | +23% |
|  | 2-to-1 node (c 0.231, m 0.29, k 8.55, native ×2, mix ×23.9) | 5.3 | 1.4 | 0.9 | 1.8 | **+1.3** | +14% |
|  | 2-to-1 + P2 kernels ×0.6 (c 0.231, m 0.29, k 5.13, native ×2, mix ×23.9) | 5.3 | 2.6 | 0.5 | 1.8 | **-0.4** | -4% |
|  | **engineered target**: 2-to-1 + ×0.6 + transcript ×3 (c 0.231, m 0.29, k 5.13, native ×2, mix ×3.0) | 5.3 | 2.6 | 0.5 | 0.2 | **-2.0** | -21% |
|  | pessimistic (c 0.308, m 0.33, k 11.10, native ×2, mix ×23.9) | 4.7 | -1.6 | 1.1 | 1.8 | **+4.4** | +47% |
|  | optimistic: census c, native back to b2 (c 0.192, m 0.28, k 5.13, native ×1, mix ×23.9) | 5.6 | 3.3 | 0.2 | 1.8 | **-1.3** | -14% |
|  | builder's original central (m 0.18, b1, no transcript) (c 0.243, m 0.18, k 9.96, native ×1, no mix) | 5.3 | 1.9 | 0.5 | 0.0 | **-1.4** | -15% |

Break-even k (the recursion term alone, no native or transcript cost) is 11.8 at the central c and m, 12.6 with 2-to-1 nodes, and 7.8 in the pessimistic corner [D].

**Critical path, 24628607 only** (`wall_24628607_E`). Each phase wall (native 3.82 s, recursion 5.44 s [M]) is scaled by that phase's own GPU-s change at constant busy. This is an upper bound on the recursion gain, because busy usually falls as work shrinks; it is not a measurement.

| scenario | native wall Δ s | recursion wall Δ s | **request wall Δ s** |
|---|---:|---:|---:|
| as measured, sponge node | +1.93 | +0.34 | **+2.27** |
| 2-to-1 node | +1.75 | -0.41 | **+1.35** |
| 2-to-1 + P2 kernels ×0.6 | +1.32 | -1.65 | **-0.33** |
| **engineered target**: 2-to-1 + ×0.6 + transcript ×3 | +0.59 | -2.59 | **-2.00** |
| pessimistic | +1.93 | +3.02 | **+4.95** |
| optimistic: census c, native back to b2 | +1.07 | -2.23 | **-1.16** |
| builder's original central (m 0.18, b1, no transcript) | +0.57 | -1.98 | **-1.41** |

Caveats:
- Recursion GPU-s are assumed proportional to committed cells.
- k is the standalone ratio. If in-request Blake runs below its HBM roofline, the effective k is lower and the lever is larger; that is unmeasured.
- The b2 retune row ignores the extra queries that b2 needs; they raise c.
- This does not stack with outer GKR's ×0.57 (§7.2.4): the two overlap.

## 7. Security parameters and sources

**Permutation:** Poseidon2 over M31, width 24, x^5 S-box, RF = 8, RP = 22, Plonky3 `MDSMat4` external matrix, internal diagonal [−2, 1, 2, 4, …, 2^22].
- Pinned to Plonky3 `0d803737b681774186cd283b1fd2d8e493655c82`, files `mersenne-31/src/poseidon2.rs` and `poseidon2/src/external.rs` (`third_party/poseidon2_plonky3/PINNED.json`).
- Constants are in `src/core/crypto/poseidon2_m31_w24_constants.zig`, checked by the Plonky3 KAT and three independent dense-matrix vectors. Parameter identity: `d2571a7f…293e`.
- Round numbers follow the Poseidon2 paper (Grassi–Khovratovich–Schofnegger, [ePrint 2023/323](https://eprint.iacr.org/2023/323)) for 128-bit security; Plonky3 uses (8, 22) for this width, degree and field.
- x^5 is a permutation of M31 because gcd(5, p−1) = 1, with p − 1 = 2·3²·7·11·31·151·331.

**Sponge:**
- Capacity 12 limbs ≈ 372 bits.
- Output 9 limbs ≈ 279 bits, so the generic collision bound is ≈ 139.5 bits.
- Width 16's 8-limb digest would be ~124-bit, which is why width 24 is used (§7.2.3).

**Cryptanalysis status:** see §7.1 of the 4-GPU doc. Full rounds are unbroken; published attacks hit only reduced rounds ([2025/954](https://eprint.iacr.org/2025/954), [2026/306](https://eprint.iacr.org/2026/306), [2026/150](https://eprint.iacr.org/2026/150)); the Poseidon Initiative bounty runs to 31 Dec 2026; there is no parameter change. A named RP = 30 "hardened" variant (about +3% cells) remains the S0 insurance option.

**Open S0 obligations** (`vectors/reports/rv64-m7-20261105/native-layout/POSEIDON2-REVIEW.md`):
- the work/ROM ledger must charge Q(Q−1)/(2p^9) collisions and Q/p^9 preimages, not the raw-Blake256 budget;
- the canonical low-bit query-draw bias is 2^(31−k)/p;
- **the 2-to-1 one-permutation node needs its own security note** before §6's 2-to-1 rows can count. It is a truncated-permutation compression of 18 limbs in a width-24 state, with 6 limbs of padding/capacity. The frontier precedent is pil2-proofman, where one permutation per level works because the sponge width equals arity × digest (`setup/pil2-stark/src/verifier_hashes.rs` `merkle_path_permutations`).

## 8. Integration path (after GPU-native lands)

Nothing below should be done while the gn-* streams own `rv64/jobs/`. Every step keeps M6/M7/D2 bytes identical while the flag is off.

1. **S0 sign-off.** Choose the sponge node or the 2-to-1 node (and RP 22 or 30), and write the profile name into `poseidon2_profile.zig` (`Om31V2`). This is a gate on everything else.
2. **Native profile (S2).**
   - Add a sibling of `integrations/riscv_cpu/word16_execution/om31_security_candidate.zig` whose `Channel` is `core.channel.poseidon2_m31.ForFieldV2(OM31)` and `Hasher` is `Poseidon2M31MerkleHasherV2` (today lines 8–10 hard-wire raw-mod Blake), under a new `ID_DOMAIN` (`rv64-om31-p2m31-native-localgkr-128-CANDIDATE/v1`).
   - Re-derive the ledger's collision term (lines 48–60), which today assumes raw256.
   - The wire family is `interop/proof_wire/family.zig` `ForHasher(OM31, Poseidon2M31MerkleHasherV2)`, with 36-byte digests and canonical-limb checks.
3. **GPU PCS commit call sites.** First move `tests/cuda/rv64/m9_poseidon2/poseidon2_mixed_leaf.cu` into `native/commitment/` (includes become same-directory), add it to the CUDA source manifests, and check that it compiles under CuMetal. Then switch on `STWO_RV64_M9_POSEIDON2_LEAVES=1` **and** the profile, never on the env alone.
   - `rv64/pcs_pipeline.cuh:757–776`, and its jobs copy `rv64/jobs/pcs_enqueue.cu:844–857`:
     - the `stwo_blake2s_mixed_seeded_eager[_compact]_on` chain becomes `stwo_p2m31_mixed_seeded_on`, with banks of `size × 24` words and the position `absorbed % 12`;
     - `stwo_blake2s_layer_on` becomes `stwo_p2m31_parent_layer_on`;
     - `tree_words` becomes 9 words per node;
     - root copies (line 777) move 9 words.
   - `rv64/trace.cu:147,221` (trace commit) and `rv64/fri.cu:95` (FRI layer trees).
   - `backends/cuda/runtime/stages/commitment.zig:68,297` (generic stage) and `abi/stages/commitment*.zig`: a 36-byte hash ABI family next to the 32-byte one.
   - Bank sizing in the planner: P2 banks are 96 B per row, against Blake compact 32 + 4·(absorbed % 16) B.
4. **Decommit and openings.** In `native/decommit/{merkle_walk.cuh,trace.cu,fri.cu,sparse_parents.cu}` and `stwo_rv64_trace_open_paths_on`, path hashes become 9 words and the parent recompute uses the P2 node. Query planning is unchanged.
5. **Transcript and PoW.**
   - `native/transcript/*`: the device channel moves to the v2 Poseidon2 channel. Numerical reference: `p2m31::transcript` in `rv64/poseidon2_m31.cuh`. It must use the v2 u32 draw counter, not v1's u64 callback (POSEIDON2-REVIEW).
   - mixRoot absorbs 9 limbs.
   - `native/pow/*`: a P2 PoW over the low bits of a canonical M31 word, with difficulty ≤ 30 bits.
   - The native GKR channel switches to the same channel.
   - **Review: the one-thread `channel_mix<<<1,1>>>` pattern cannot be ported as is.** A one-thread P2 sponge is ×23.9 slower per mix [M] (+1.78 GPU-s on 24628607, all serial). Design the device P2 channel as a warp-cooperative permutation, or absorb large mixes through a parallel P2 tree whose root is mixed (a protocol change, mirrored in-circuit), and gate it at ≤ ×3 Blake per mix.
6. **In-circuit verifier (S3) and outer/fold/root (S4).**
   - Point `channel`, `merkle`, `raw_mod_channel` and `fri` at the `poseidon2_outer` component, and drop the Blake components from the roster (`frontends/circuit/{native_verifier,stark_verifier}`, `builder/blake.zig`, `fused_blake/*`).
   - Then `rv64_recursion/vk_table.zig` (the T_nat tree), the `om31_native/{canon_hash,frame,fri,proof,leaf_graph,fold_tape,node_summary_v3,…}` files, `root_{verify,derive}.zig` and `fold_root.zig`.
   - Recursion provers must use this same kernel for their own trees (§1 finding).
7. **Golden regeneration.**
   - M6/M7/D2 goldens stay frozen and must still match with the flag off.
   - The new profile gets new goldens: per-tree roots from the Zig reference (`poseidon2_m31_mixed_leaf.zig` + `hashParent`); fresh native proofs for both dev blocks (26235156, 24628607); fresh CPU receivers; and a tamper corpus covering a foreign suite, non-canonical limbs, a 32-byte digest under the P2 ID and a wrong absorb position.
   - Re-emit `m9_poseidon2_leaves_vectors.zig` if the framing changes.
8. **Gates, in order.**
   - the parity gate in this stream (`m9p2 parity`, plus memcheck);
   - native-only A/B on the dev blocks, where the native-hash GPU-s must stay within +1.07 (the +0.54 measured here × 2 for D2 b4; +0.90 with 2-to-1);
   - the serial-mix microbench (`m9_p2_serial_mix.cu`) at ≤ ×3 Blake for the chosen transcript design;
   - the exact padded full-leaf census, which must stay at or below ×0.25 cells (go/no-go);
   - net kernel GPU-s per request below today, on the composed tree;
   - then request time.

## 9. Kernel work that decides the lever's size

- The scenario k is linear in P2 throughput: the recursion provers' own trees pay it. At ×0.6 (≈ 5 G permutations/s) the p50 net cut rises from 4.4 to 9.6 GPU-s.
- The fused-rounds register kernel sits at ~3 G permutations/s, about 13k–17k SASS instructions per permutation for a ~52 T int-op/s part [E].
- Frontier patterns worth trying, from pil2-proofman `goldilocks/src/poseidon2_goldilocks.cuh`:
  - a **warp-register** permutation (`poseidon2PermuteWarpReg`: one lane per state element, shuffles for the MDS), suited to parents and small-width leaves where one thread per row leaves ILP idle;
  - a **shared-memory** variant;
  - tiled sponge loads (`spongeLoadTiled`).
- Also: lazy reduction in partial rounds (v2's u64 sums alone did not help), two rows per thread for small widths, and fusing the bottom node layer into the leaf kernel.
- The 2-to-1 node is the cheapest single win: −14% of P2 native permutations [D] (nodes are 28% of permutations and halve; review correction), and fewer path cells in-circuit.
- **The serial transcript is now the largest single cost** (review correction 3): a one-thread P2 permutation takes 12.9 µs against 0.72 µs per Blake2s compression [M]. A warp-cooperative permutation (24 lanes, MDS by shuffles) or chunked parallel absorption of large mixes is a precondition, not an option.
