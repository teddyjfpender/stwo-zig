# RV64 M9: segment size and tree shape (fewer, bigger segments)

Status: 2026-11-07. Branch `codex/rv64-m9-segment-shape`, cut from `codex/rv64-m7-integrate`. CPU-side M9 prep, run
alongside the GPU-native landing. No GPU was used: neither dev pod had `/workspace/m3/READY-DEV`, and the main
2x5090 belongs to GPU-native. Labels: **[M]** measured, **[D]** derived from measured, **[E]** estimate.

- Model: `scripts/rv64_m9/segment_shape_model.py`. Tests: `scripts/tests/test_rv64_m9_segment_shape_model.py` (7/7).
- Plan-model variant: levers `SEG23` / `SEG24` in `scripts/rv64_m9/plan_model.py`. The rev-4 search is unchanged
  unless `SEARCH_EXTRA` is set, and the rev-4 tests still pass (16/16).
- Receipt: `vectors/reports/rv64-m9-prep/m9-segment-shape/model.json` (114 KB).
- Reused, not copied:
  - the padding-aware recursion cell model from `codex/rv64-m9-fewer-leaves` (`scripts/rv64_m9_leaf_fanin_model.py`, unchanged);
  - the request model from `codex/rv64-m9-plan` (`plan_model.py`, plus the two levers).

## 1. Result

**About half of a 2^22 segment's GPU-s does not scale with its rows [D].** A full segment carries 0.95 GPU-s:
- native, 0.50 GPU-s, of which about 0.05 is a per-job fixed cost;
- its recursion leaf, 0.29 GPU-s;
- its share of the folds above it, 0.16 GPU-s.

The leaf verifies the segment's proof. That cost is set by columns and queries, not by rows, so it is the same for any
segment size. Doubling the segment therefore halves the CPU leaves and folds, and the native side changes only through
the FFT log factor and the CPU AIR geometry.

**2^23 CPU segments (`SEG23`) are a work-reduction lever worth ×0.855 on all remaining kernel GPU-s after the rev-4
best set [E, central].** Range: ×0.93 pessimistic, ×0.82 optimistic.

| post-M8 model, 2x5090, central [E] | p50 (29.1 M gas, 93 Minstr) | p95 (55.8 M gas, 179 Minstr) | 15-block basket |
|---|---:|---:|---:|
| post-M8 baseline | 19.66 s, 24.5 GPU-s | 32.85 s, 43.5 GPU-s | 293.6 s |
| `SEG23` alone | 17.00 s (−14%), 20.3 GPU-s | 27.95 s (−15%), 36.3 GPU-s | 252.8 s (−14%) |
| rev-4 best set (#1–#9) | 11.04 s (−44%), 16.1 GPU-s | 18.84 s (−43%), 29.0 GPU-s | 166.6 s (−43%) |
| **rev-4 best + `SEG23`** | **9.59 s (−51%), 13.8 GPU-s** | **16.37 s (−50%), 24.9 GPU-s** | **145.3 s (−51%)** |
| rev-4 best − `LEAVES` + `SEG23` | 10.81 s (−45%) | 18.20 s (−45%) | 160.7 s (−45%) |
| rev-4 best + `SEG24` (memory-infeasible, §5) | 9.38 s (−52%), 13.2 GPU-s | 15.68 s (−52%) | 142.6 s (−51%) |

- **Scenarios** (`model.json` `plan`):
  - pessimistic: rev-4 + `SEG23` gives −43%, against −39% for rev-4 alone;
  - optimistic: −63% / −62% / −62%, against −56%. This is the first optimistic set over 60% on 2 GPUs. Three such sets
    exist, all with `SEG23` + P2 + D2REV.
- **The x0.67 target is not reached.** Central `SEG23` takes p50 from 16.1 to 13.8 GPU-s; the target is 10.8. A
  further ×0.78 is still missing, against the ×0.67 needed before.
- **Production** (a new block each request, so every class misses): rev-4 + `SEG23` gives −54% at p50, against −43%.
  Fewer leaves also means fewer class misses.
- **`SEG23` and k-leaf fan-in (`LEAVES`) stack.** A 2^23 leaf verifies one proof. A 2^22 CPU-pair leaf verifies two
  proofs, at 2.11 G cells against 1.10 G.
  - Fan-in on top of `SEG23` still pairs 2^23 CPU proofs and groups truths.
  - Recursion cells at p50: ×0.684 for `SEG23` alone, ×0.772 for fan-in alone, ×0.513 for both.
- **Recommendation:** adopt `SEG23` as M9 lever #10, after the P1 memory items it depends on (§5). Do not adopt 2^24 in M9.
  Its native cost rises (×1.10 central: LDE log 26, CPU24 padding), its GKR workspace (31 GB) and PCS (47–52 GB) do not
  fit, and it needs a new clock AIR plus an LS ladder at log 23. Its extra gain over `SEG23` is only ×0.95.

## 2. Fixed vs proportional GPU-s per segment [M → D]

| fit | result | basis |
|---|---|---|
| native job GPU ms per CPU segment vs segment cells | **35.6 ms + 1.093 ms/M cells** (R² 0.87, n = 11): fixed ≈ 10% of a 310 M-cell segment | M8 job-path CUDA events per job (Stage1 + composition + OODS/PCS), `native-finish-p3/*-parity-{24628607,26235156}.json` on `codex/rv64-m8-gpu` [M] |
| stage pieces | Stage1 33.2 + 0.489/M cells (R² 0.60); composition −1.9 + 0.172 (0.93); PCS 4.4 + 0.431 (0.75) | same |
| kernel GPU-s, 6 bench15 blocks | 1.45 + 0.284·Minstr (R² 0.980); **0.155·Minstr + 0.253·nodes** (R² 0.993) | bench15-1 `summary.json` [M]; nodes = Nsight launches / launches_per_node [D] |
| same, 3 parameters | −1.14 + 0.091·Minstr + 0.395·nodes (R² 0.996) | Minstr and nodes are collinear on 6 points; coefficients unstable |
| recursion-after-native wall, 15 blocks | **0.49 s + 0.278 s/node** (R² 0.997) | bench15-1 (6, qualified) + p-truth-split `1088a894d` (9, single unqualified walls) [M] |
| native window wall, 15 blocks | −0.61 + 0.191 s/Minstr (R² 0.991) | same |

**Per full 2^22 segment, post-M8 model [D]:**
- native 0.500 GPU-s (plan `N_PER_MI` × 4.194 Minstr), of which 0.047 is fixed;
- leaf 0.287 GPU-s (1.097 G padded cells × 0.262 ns/cell, fan-in calibration);
- fold share 0.163 GPU-s (a 4-child fold's padded cells / 4, plus 1/3 for the levels above);
- total **0.95 GPU-s, of which 52% is not row-proportional.**

The tree grows by about 1.33 nodes per segment. The truth leaves (12 at p50) are block-content-bound, not
segment-bound.

What else is per-segment and why it is small:
- FIXED/preprocessed commits are class-cached in GPU-native (§3.1 ClassCache).
- GKR setup is in the Stage-1 intercept: about 2,000–2,300 launches per job [M], which graphs collapse.
- Openings and FRI decommit are about 0.01 s/proof (segment-size-analysis §3).
- The native fixed part is ≤ 10%, so **the per-segment fixed cost that matters is the leaf plus its fold share.**

## 3. Shapes: bigger segments, truth batching, mixed last segments [D/E]

- **Segment rule [M]:** a segment holds up to 2^k − 1 steps, and the last proof uses a minimal `cpu_log`. With k = 22
  this reproduces every M3 segment count (test).
- **CPU leaf at log 23/24 [D]:** native verification rows grow by one Merkle level per tree path and one FRI layer per
  doubling, using the measured fold-child increment 22→23: +78 k blake rows, +76 k qm31 rows.
  - The base is the max of the 10 measured full-CPU leaf row vectors.
  - The row growth is 2.3% per doubling (pessimistic: ×2, plus 5% more columns). It stays inside the 2^22 leaf's padded
    rungs: blake 3.45 M < 4.19 M, qm31 5.61 M < 8.39 M.
  - So **a 2^23 or 2^24 CPU leaf costs the same 1.097 G padded cells as a 2^22 leaf**, in every scenario (test).

| block | 2^22 today: segments, leaves/folds | 2^22 + truth fan-in | 2^22 + fan-in (`LEAVES`) | **2^23** | 2^23 + truth fan-in | 2^23 + fan-in | 2^24 | 2^24 + fan-in |
|---|---|---|---|---|---|---|---|---|
| p50 (93 Minstr, 16 truths) | 23 seg, 36/12 | ×0.901 (30/11) | ×0.772 (19/7) | **×0.684** (12 seg, 25/9) | ×0.584 (19/7) | ×0.513 (14/5) | ×0.517 (6 seg, 19/7) | ×0.381 (10/4) |
| p95 (179 Minstr, 24 truths) | 43 seg, 64/21 | ×0.903 | ×0.762 (32/11) | **×0.675** (22 seg, 43/15) | ×0.561 | ×0.501 (22/9) | ×0.482 (11 seg) | ×0.345 (16/5) |
| 24628607 | 7 seg, 14/5 | ×0.922 | ×0.822 (9/3) | ×0.801 (4 seg, 11/4) | ×0.682 | ×0.638 (8/3) | ×0.637 | ×0.518 |
| 26235159 | 49 seg, 72/25 | ×0.901 | ×0.758 | ×0.655 (25 seg, 48/16) | ×0.556 | ×0.486 (24/9) | ×0.482 | ×0.349 |

- Ratios are recursion padded cells against today's 2^22 one-native-per-leaf tree on the same block. Cells are independent
  of the scenario.
- The 2^22 + fan-in column reproduces the fewer-leaves receipt (`plan_model.FANIN_SAME`) to within 0.002 on 14 of the
  15 blocks. 24647140 is off by 0.044: its last segment holds 3.63 M instructions, so it is a full log-22 class, while
  the receipt took it as a tail.
- **Small blocks gain least.** On 24628607, the 4 truth families × 3 t_a dominate once the CPU leaves halve (×0.80).

**Truth batching.**
- One proof per family is memory- and cell-negative (§5; native-layout README: +23.7% / +8.8% own-height MAIN on the dev
  blocks, and a 19.5 GB Keccak GKR workspace). So truth batching here means **leaf-level** fan-in: t_a triples and the
  same-class policy.
- Alone it gives ×0.90. After `SEG23` it gives a further ×0.85, because truths become about half of the leaves.
- The `LEAVES` lever in the plan already includes it. On top of `SEG23` it is worth ×0.513 / ×0.684 = ×0.75 more
  recursion cells.

**Mixed last segments.**
- A near-empty final segment (< 10% full) occurs on **9.3%** of the 2,900 mainnet blocks at 2^22, 9.7% at 2^23 and
  10.4% at 2^24 [D, `gas_sample.json` × 3.198 instr/gas].
- It costs about 0.30 GPU-s: native 0.04, tail leaf 0.16 (log-21 rows, conservative), and verification in its parent
  fold 0.10.
- Absorbing it into the previous proof as one 2^(k+1)-row proof doubles the CPU AIR plane. That plane is 37 of 80.5 MAIN
  cells/row, so the extra is +0.23 GPU-s [D/E].
- Net: about −0.07 GPU-s on 9% of blocks, which is < 0.1% of mean kernel GPU-s, at the price of a second CPU class per
  block. **Not worth it; keep the minimal-log tail.**
- The mixed sizes that do pay are already in the rule: k-sized segments, then a tail at its own minimal log.

## 4. Native GPU-s factor per doubling [D/E]

f = cells × (1 + FFT share × (FFT growth − 1)) − (fewer segments × fixed).

| term | pess | central | opt | basis |
|---|---:|---:|---:|---|
| cells, 2^23 (exact source census) | ×1.050 (CPU23 wide47, the only CPU23 class that exists) | ×1.000 | ×0.967 (compact37 extension) | `rv64-m7-20261105/native-layout/model.json`: compact ×0.989 / ×0.967, wide47 ×1.050 / ×1.017 on 24628607 / 26235156 [D] |
| cells, 2^24 | ×1.150 | ×1.050 | ×0.979 | same; CPU24 pads 26.9 Minstr to 2 × 2^24 [D] |
| FFT growth per doubling | ×1.285 (log-25 LDE falls back to 3 passes) | ×1.085 (wide kernel extended to log 25/26) | ×1.044 | T4 bench [M]: b2n 22→23 +8.2%, n2b +5.7%, LDE 23→24 +9.7%; the wide n2b/LDE stops at log 24 (`kWideHighBits` 11 + 13, `STWO_B2N_WIDE_MAX_LOG` 24); old 3-pass / 2-pass = ×1.5 [M ratio] |
| FFT share of native | 0.405 | 0.405 | 0.405 | FFT 2.975 / (8.333 − chain 0.996) GPU-s, 24628607 census [D] |
| fixed per removed segment | 0 | 0.018 GPU-s | 0.036 GPU-s | §2 intercept; half survives graphs [E] |
| **native factor, 2^23** | **×1.157** | **×1.017** | **×0.946** | |
| native factor, 2^24 | ×1.33 | ×1.10 | ×0.955 | |

Merkle and GKR are bandwidth-linear in cells, so their per-element cost does not change [D]. The sumcheck gains one
round per doubling, which is negligible. The capture head grows by one extra 2^22 segment of capture before Stage 1:
+0.087 s at 2^23 and +0.26 s at 2^24 (`CAP_B`). The plan model's last-segment Stage-1 term already scales with segment
size.

**Red flag (measured on CPU, not GPU).** The 2^23 prototype `codex/rv64-ge-seg23` (segment-size-analysis §7) was 27–29%
slower end to end on the CPU prover, with 2 CPU proofs on 2 lanes, plus 7–9 GB of memory. That was lane-tail- and
cache-bound CPU proving. The GPU per-element FFT growth is measured at ≤ 10% per log up to log 24. **Still, the native
factor must be measured on GPU before `SEG23` lands** (§7, step 3).

## 5. Memory on a 32 GB RTX 5090 [M/D/E]

Budget per GPU (gpu-native §3.7): class cache 3.1 + graphs 0.25 + reserve 1.0 + slab, plus `main_resident`. The
`main_resident` region holds about 1.05 GB per 2^22 segment of MAIN [M: 4.15 + 3.23 GB for 7 segments on 24628607], and
the total is **independent of segment size**.

| | 2^22 | 2^23 | 2^24 |
|---|---:|---:|---:|
| native Stage-1 job peak | 13.2–18.6 GB [M] | 21.9–30.9 GB [D] | 35–50 GB [D] |
| native OODS+PCS job peak | 11.7–12.9 GB [M] | 23.5–25.9 GB [D] | 47–52 GB [D] |
| GKR workspace, exact consumed-Eq plan | 10.2 GB [D] | 15.3 GB | 31.4 GB |
| Stage-1 lower bound with same-GPU MAIN | 16.0 GB | 26.6 GB | 42.7 GB |
| post-P1 Stage-1 (GKR chunk ≤ 2 GB + MAIN coeffs + one LDE bank/tree) | 4.3 GB [E] | 6.6 GB [E] | 11.2 GB [E] |
| arena left: 24628607 / p50 / p95 | 23.9 / 15.5 / 5.0 GB | same | same |
| fits today? | 607 yes; p50 Stage-1 no (18.6 > 15.5) | **no** | no |
| fits post-P1? | yes / yes / yes | yes / yes / no at p95 | yes / yes / no |

- **`SEG23` needs, in order:**
  - P1 chunk-bounded GKR workspace (engineering scope P1: "the 15 GB modelled GKR workspace has to become a bounded
    constant");
  - PCS plane retirement (memory-plan README: the peak is the last PCS allocation, 3.2 GB at 2^22);
  - streamed commit with partial trees (stream-commit review: a memory lever, 1 GiB → 1 MiB per log-24 tree, about
    0 GPU-s).
- **At p95, GPU-native's `main_resident` alone is 22.6 GB per GPU**, at any segment size. Large blocks need MAIN
  spill/recompute regardless of this stream, and `SEG23` adds nothing to that total.
- Recursion leaves and folds do not change class with segment size: leaf peak 3.1–18.2 GB, fold 21.8 GB [M]. The
  fan-in pair leaf memory gate (fewer-leaves §3) is unchanged.
- 2^24 also needs the 2^24 LDE (log 26) FFT schedule, and its jobs exceed a card even after P1 once `main_resident` is
  counted at p95.

## 6. Soundness at the D2 target, and what changes the proof

- **Per-proof security is unchanged.** The D2 profile is `d2_native_b4_q54_p20_fold4`: conjectured 54 × 2 + 20 = 128
  bits. That depends on the rate (b4), the queries and the PoW, not on the domain size. The domain-size terms are
  negligible at LDE 2^25 over QM31 (|F| = 2^124):
  - DEEP/OODS ~deg/|F|;
  - GKR/sumcheck rounds × degree / |F|;
  - LogUp fractions/|F|.
- **The union bound improves.** Fewer verified proofs: p50 CPU proofs 23 → 12, recursion nodes 48 → 34 (`SEG23`) or
  19 (with fan-in).
- **Clock.** `SEG23` uses the existing wide-clock CPU encoding: REG gaps are bounded by U16(128·gap8), so gap < 2^26 ≪ p,
  checked exhaustively in `rv64_word16_execution_wide_clock_test.zig`; the OWNER/RAM tick is `row + 1` < 2^24, and every
  RAM-side AIR is unchanged (segment-size-analysis §7, CPU23-WIDENING.md).
  - The compact37 extension needs its own authenticated source mode, with the three gap terms moved to range16 mass.
  - The LogUp mass bounds bind only near 2^27 rows.
- **What changes the proof:**
  - a new CPU class (the `wideClockIdentity` transcript domain, a new FIXED root and VK);
  - new native-GKR scope, GPU codegen projection, typed CPU policy and class caps (all capped at 22 today);
  - new log-23 CPU leaf verifier classes in `vk_table`/T_rec;
  - the topology fingerprint (fewer leaves).
- **No byte identity with the D2 golden.** The gates are fresh CPU receivers, the 43-byte output, semantic equality of
  final PC/registers/RAM, and negatives: gap high limb 511/512, gap ≥ 2^25, a forged cross-window predecessor.
- **2^24 also needs** a scale64 U16 gap check (10-bit limb), an LS ladder at log 23 and a new geometry `MAX_LOG`. It
  is source-invalid today.

## 7. Integration after GPU-native lands

1. **Land the model.** Merge `scripts/rv64_m9/plan_model.py` (default rev-4 search unchanged; `SEG23`/`SEG24` and
   `SEARCH_EXTRA`) and `segment_shape_model.py`. `rv64_m9_leaf_fanin_model.py` is identical to `codex/rv64-m9-fewer-leaves`.
2. **Prerequisites, in order (P1).** Chunk-bounded native GKR workspace, PCS plane retirement and streamed commit with
   partial trees. Gate: a 2^22 native job peak of ≤ 7 GB on 24628607.
3. **GPU check of the native factor** (dev pod a once READY-DEV exists, [M dev-5090], then the 2x5090):
   - `fft_passes_bench bench 256 9 22 23 24 25`, after extending the wide n2b/LDE to log 25 (`kWideHighBits` 12);
   - a standalone native 2^23 segment job from a recorded capture of 24628607 segments 0+1;
   - Gate: native job GPU-s per Minstr ≤ ×1.05 the 2^22 pair, and Stage-1/PCS peaks against the post-P1 plan.
4. **CPU23 class, default off (`STWO_RV64_M9_SEG23=1` → `batch_steps` 2^23 − 1).**
   - Work: the compact37 wide-clock source mode, native-GKR scope > 22, GPU codegen projection, typed CPU policy, a FIXED
     root, VKs, and log-23 CPU leaf classes.
   - Receivers derive the segment count from the public inventory. Old classes stay frozen.
5. **Gates:**
   - fresh receivers plus the negative corpus on 26235156, 24628607 and one ≥ 28-segment block;
   - recursion cells against this model (exact census: ×0.80 on 24628607, ×0.68 on 26235168);
   - the 2x5090 3+3 on 24628607 and bench15.
6. **Then stack `LEAVES`** (fan-in over 2^23 CPU pairs and truth triples). The pair-leaf memory gate is unchanged.
7. Keep 2^24 for M10 (4 GPUs). It needs a streamed GKR and the CPU24 AIR.
