# RV64 M9 plan: gas-weighted targets and the >60% cut budget (2×RTX 5090, then 4×)

Status: plan of record draft, 2026-11-07. Written **in parallel with** the GPU-native landing (workflow round 3, `codex/rv64-m8-gpu`, `codex/rv64-m8-gn-*`); it touches no code those streams own.
Branch `codex/rv64-m9-plan` from `codex/rv64-m7-integrate @ 95e3d7e15`.

Labels:
- **[M]** measured, with a receipt;
- **[D]** arithmetic on measured numbers;
- **[E]** estimate.

Model: `scripts/rv64_m9/plan_model.py`. Run it with `python3 -I scripts/rv64_m9/plan_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/m9-plan/model.json`. Without `--gas-sample` it uses the embedded percentiles. The receipt is `vectors/reports/rv64-m9-prep/m9-plan/model.json`. The raw gas sample stays out of git (see the receipt README).

Inputs:
- the 4-GPU lever map `rv64-4gpu-realtime.md` (§1, §6, §7, §8) and `scripts/rv64_4gpu/levers.py`, both on `codex/rv64-4gpu-realtime-design`;
- the frontier delta `rv64-frontier-gpu-delta.md` §4;
- `rv64-m8-engineering-scope.md` §2 (P2–P5);
- `rv64-m8-gpu-native.md` and bench15-1, both on `codex/rv64-m8-gpu`;
- `rv64-m9-io-streaming.md` on `codex/rv64-m9-io-design`.

---

## 0. Summary

1. **The headline block is wrong for M9.**
   - 24628607 (7.37 M gas) is in the smallest **4%** of mainnet blocks. The mainnet median is **29.1 M gas** and p95 is **55.8 M** [M, 2,897-block sample].
   - The basket is bimodal: 8 of 15 blocks sit at or below p21, 6 sit at or above p79, and only 26235168 is near the median [D].
   - Weighted by mainnet, three middle blocks (24697073, **26235168**, 25229955) carry **72%** of the weight. All three are refused today by the D2 coalesced-truth profile (`OneTruthPerFamilySourceCapacity`) [M, bench15-1].
2. **New targets** (2×5090, warm request, Ethproofs proving boundary). Each is a ≥60% cut from the post-M8 GPU-native baseline [E]:
   - p50 block: **≤ 8.4 s**, from about 21 s;
   - p95 block: **≤ 14.9 s**, from about 37 s;
   - 15-block basket total: **≤ 128 s**, from about 320 s;
   - mainnet-weighted mean: **≤ 8.7 s**, from about 21.7 s.
   - M10 on 4×5090: p50 ≤ 5 s, p95 ≤ 9 s (the <10 s p99 class).
3. **Baseline.** bench15-1 [M] fits kernel GPU-s = **1.46 + 0.284·Minstr** (R² 0.98, n = 6) and warm proving = **2.38 + 0.385·Minstr**. Under the post-M8 GPU-native model [E, central], the request costs:
   - p50: 26.5 GPU-s, 20.9 s;
   - p95: 49.5 GPU-s, 37.2 s;
   - 26235159: 56.6 GPU-s, 42.5 s.
4. **Budget.** No single lever gets close to 60%; the best one alone gives −31% at p50 (leaves). The central case needs **six or seven levers combined** to reach 60% on 2 GPUs.
   - **M9 alone just reaches it** (central): streaming commit, occupancy, fewer/bigger leaves, native GKR v2, Poseidon2 leaves, outer GKR, and then **reverting D2 to b2 native** once recursion is cheap. That gives p50 −60%, p95 −62%, basket −60%. The levers stay in that order.
   - Adding M10's **GPU capture replay** brings it to −68 / −67 / −68%.
   - The pessimistic case reaches 60% only with GPU capture: {streaming, occupancy, leaves, native GKR, outer GKR, GPU capture} gives −61%.

   What each lever is worth alone (p50/p95):
   - Recursion cuts are the bulk: leaves −6.5/−11.3 s and P2 −6.1/−10.0 s.
   - Proof-neutral GPU work is next: streaming commit −2.6/−5.1 s, occupancy −2.3/−4.7 s, and witness without the DAG −1.8/−3.2 s.
   - IO and D2D are small: together −0.6/−1.1 s.
   - **After the cuts, capture becomes the critical path on large blocks.** The pre-seal stage is 5.2 of 13.8 s at p95.
5. **Production reality.** In production every request is a new block, so leaf classes miss.
   - Without canonical leaf classes (L4) the miss adds about **7 s at p50 and 13 s at p95** [E], and GPU-native fails closed on a miss (`GpuNativeClassNotWarmed`).
   - **Canonical leaf classes are the lever that makes the bench number the production number.** They save zero on the warm-repeat bench.
6. **Order.** Every lever sits behind the GPU-native landing (job/slab contract, `ClassCache`, device transcript):
   - wave 1, proof-neutral: IO, D2D, streaming commit, witness, occupancy;
   - wave 2, named profiles: leaves, canonical classes, native GKR;
   - wave 3, the hash backbone: Poseidon2 S2–S4 / outer GKR, then the D2 revert;
   - M10: GPU capture and 4-GPU placement.

   Kernels, microbenchmarks and the profile design can all start now (§4).

---

## 1. Targets: gas-weighted, not 24628607

### 1.1 Mainnet gas distribution [M]

Source: `gas_sample.json`, rows `[number, gasUsed, gasLimit, txs, ts]`.
- 2,901 rows, of which 2,897 are distinct blocks, between blocks 26,019,159 and 26,236,159.
- Dated 2026-09-20 to 2026-10-20; the gas limit is about 60 M.
- 72% of the rows are from the 26.2 M range, so the sample leans towards recent blocks.

| p5 | p10 | p25 | **p50** | p75 | p90 | **p95** | p99 | mean | gas-weighted median |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8.3 M | 15.8 M | 23.4 M | **29.1 M** | 37.2 M | 47.1 M | **55.8 M** | 60.0 M | 30.4 M | 33.3 M |

- Blocks above 40 M gas: **19.0%** of blocks and 30.9% of gas. Blocks at or above 39 M: 20.8%.
- 24628607 (7.37 M) sits at **p4**. 26235159 (57.7 M) sits at **p96**.

### 1.2 What the basket over-weights [D]

| | basket (15) | mainnet |
|---|---:|---:|
| blocks > 40 M gas | 5 (33%); 6 (40%) at ≥ 39 M | 19% (21% at ≥ 39 M) |
| gas in blocks > 40 M | **62%** | 31% |
| blocks < 13 M gas (≤ p8) | 5 (33%) | ~8% |
| blocks between p21 and p79 | **1** (26235168) | 58% |

Mainnet percentile of each basket block:

| block | 26235156 | 24628607 | 24647140 | 25229957 | 24628608 | 24626900 | 24697070 | 24697073 | **26235168** | **25229955** | 24628590 | 24628595 | 26235159 | 25229951 | 24628611 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| percentile | p2 | p4 | p4 | p6 | p8 | p10 | p11 | p21 | **p50** | **p79** | p92 | p94 | p96 | p96 | p96 |

**Mainnet weight of each basket block.** Each sampled block is assigned to the basket block nearest in gas.
- 26235168: **0.33**;
- 24697073: 0.20;
- 25229955: 0.19;
- 24628590: 0.06;
- all others: ≤ 0.04 each.

So the **15-block total is dominated by the 6 large blocks** (they hold 62% of basket gas), while mainnet is dominated by the middle.

### 1.3 Metrics and targets

The primary metric is warm **proving time** in the Ethproofs boundary: from input bytes through capture, native and recursion to the root. Request (job) time is proving time plus about 0.01 s on the spool [M, bench15-1].

| metric | definition | post-M8 baseline [E, central (pess–opt)] | **M9 target, 2×5090** | M10 target, 4×5090 |
|---|---|---:|---:|---:|
| **p50 block** | model at 29.1 M gas (93 M instr; 23 seg) | 20.9 s (25.7–18.4) | **≤ 8.4 s** (−60%) | ≤ 5 s |
| p50, measured proxy | **26235168** (29.1 M gas, 113 M instr, 28 seg) | 24.6 s (30.6–21.7) | **≤ 9.9 s** | ≤ 5.5 s |
| **p95 block** | model at 55.8 M gas (178 M instr; 43 seg) | 37.2 s (46.6–32.3) | **≤ 14.9 s** | ≤ 9 s |
| p95, measured proxy | **26235159** (57.7 M gas, 205 M instr, 49 seg) | 42.5 s (53.2–36.8) | **≤ 17 s** | ≤ 9.5 s |
| **15-block basket total** | sum of warm proving | 320 s (395–280) | **≤ 128 s** | ≤ 75 s |
| mainnet-weighted mean | model over the 2,897 sampled blocks | 21.7 s (26.8–19.1) | **≤ 8.7 s** | ≤ 5 s |
| production p50 | new block each request (class misses) | 28.2 s (39.7–21.3) [E] | **≤ 9.2 s** (bench p50 + 10%; needs L4) | ≤ 5.5 s |
| 24628607 (continuity only) | dev block | 8.3 s (9.8–7.4) | ≤ 3.3 s | ≤ 2.0 s |

The model's own composed estimates [E, central], for comparison:

| lever set | p50 | p95 | 26235168 | 26235159 | basket | mainnet mean |
|---|---:|---:|---:|---:|---:|---:|
| every M9 lever (no GPU capture) | 8.1 s | 13.8 s | 9.3 s | 15.4 s | 125 s | — |
| + GPU capture (all 2-GPU levers) | 6.7 s | 12.1 s | 7.8 s | 13.6 s | 104 s | 7.0 s |
| + 4-GPU placement | 4.2 s | 7.3 s | — | — | 66 s | 4.4 s |

The targets sit at about −60%; the M9-only composition reaches them with roughly 0–3% headroom. The model is calibrated on blocks ≤ 58 M instructions (§2), so treat the p95 figures as extrapolated.

### 1.4 Canonical benchmark set (proposal)

- **3+3 set: 24628607 (continuity) + 26235168 (mainnet p50).** 26235168 is the only basket block between p21 and p79, and it alone carries 33% of the mainnet weight.
  - Cost: a warm request of about 21–25 s post-M8 [E]. A 3+3 is about 6 services × (cold + warm), roughly 10 GPU-minutes [E].
- **Second median block, for scale probes and the weekly run: 25229955** (p79, 39.1 M gas, 30 seg). Together with 26235168 it covers 52% of the weight. Use 24697073 (p21, 0.20 weight) when a cheaper probe is needed.
- **Prerequisite:** 26235168, 25229955 and 24697073 are all refused today by `OneTruthPerFamilySourceCapacity` (bench15-1 [M]). The round-3 p-truth-split fix must land before either can be a gate block.
- **Owner-rule change:** `rv64_m4_resident.py` and the canonical runner refuse non-dev blocks (`opt-combined/README.md`). Allow 26235168 in the 3+3 runner once it proves.
- **Reporting:**
  - bench15 keeps the full basket total;
  - every bench also reports a **mainnet-weighted basket mean**, Σ wᵢ·tᵢ with the weights of §1.2, stored as a fixed table in the bench script.

---

## 2. Baseline

### 2.1 bench15-1, default arm, 2×5090 [M]

Source: `codex/rv64-m8-gpu`, `vectors/reports/rv64-m8-20261106/bench15/SUMMARY.md`, opt-combined image. It proves 6/15 blocks; GPU-native fails at install on 0/6.

| block | gas | Minstr | seg | warm proving | capture | native window | recursion after native | kernel GPU-s | busy (kernel) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 26235156 | 5.4 M | 15.3 | 4 | 9.55 | 1.73 | 2.84 | 4.84 | 6.56 | 34% |
| 24647140 | 7.7 M | 24.6 | 6 | 11.46 | 1.99 | 3.83 | 5.38 | 8.47 | 37% |
| 24628607 | 7.4 M | 26.9 | 7 | 11.77 | 2.10 | 3.81 | 5.69 | 8.43 | 36% |
| 25229957 | 9.8 M | 27.1 | 7 | 12.51 | 2.14 | 4.05 | 6.18 | 9.12 | 37% |
| 24628608 | 12.9 M | 38.6 | 10 | 17.03 | 2.88 | 6.87 | 7.27 | 11.72 | 34% |
| 24697070 | 17.4 M | 57.8 | 14 | 25.14 | 3.74 | 11.19 | 10.06 | 18.39 | 36% |

Fits on these six rows [D]:
- **kernel GPU-s = 1.46 + 0.284·Minstr** (R² 0.980);
- warm proving = 2.38 + 0.385·Minstr (R² 0.981).

Extrapolated today-path proving [E]: p50 38 s, 26235168 46 s, p95 71 s, 26235159 81 s. That is about 584 s over 15 blocks (M3: 1,843 s [M]).

Limits:
- The extrapolation assumes today's default profile also proves the large blocks. It does not: 9/15 are refused.
- It assumes 34–37% busy holds at scale.

### 2.2 Per-block GPU-seconds model [D/E]

Inputs:
- **Basket instructions per gas:** gas-weighted 3.20 [D]. Per block it ranges 2.71–3.89; 26235168 is 3.90 and 26235159 is 3.55.
- **Segments** = ⌈instr / 2²²⌉. This matches all 15 M3 receipts.
- **Truth proofs** ≈ 7.6 + 0.37·seg [D, M3 rows]; coalesced truth leaves ≈ 0.7 × truths.
- **Leaves** = seg + truth leaves, aggregated 4-ary.

Splits:
- **Native vs recursion.** On 24628607 the M7 exact cells (native 5.454 G at 0.72 ns/cell; recursion 21.7 G at 0.29 ns/cell) give 3.93 + 6.29 GPU-s. That is 10.22 GPU-s against 10.58 measured [D], so native is 38.5% of kernel GPU-s.
  - At opt-combined (8.48 GPU-s [M]) that means native **0.121 GPU-s per M instr** and recursion = the rest.
  - On large blocks recursion is **about 58%** of kernel GPU-s.
- **Kernel families, 24628607 opt-combined [M]** (`opt-combined/ab8-kernels.json`):
  - FFT/LDE (n2b/b2n): 2.98 GPU-s (35%);
  - Merkle leaf + layers: 1.43 (17%);
  - recursion witness DAG (`chain_run`): 1.00 (12%);
  - GKR folds/sums: about 0.36;
  - DEEP/sample: about 0.39.

| block | Minstr | seg / leaves / folds | kernel GPU-s [E] | native | recursion |
|---|---:|---|---:|---:|---:|
| 24628607 | 26.9 | 7 / 14 / 5 | 8.6 | 3.1 | 5.5 |
| p50 (29.1 M gas) | 93 | 23 / 35 / 13 | 26.5 | 10.7 | 15.7 |
| 26235168 | 113 | 28 / 43 / 15 | 31.9 | 13.1 | 18.9 |
| p95 (55.8 M gas) | 178 | 43 / 60 / 20 | 49.5 | 20.6 | 28.9 |
| 26235159 | 205 | 49 / 68 / 25 | 56.6 | 23.6 | 33.0 |

(Post-M8 includes ×0.95 for setup and replay moved to warm/install [E].)

### 2.3 Post-M8 GPU-native request model [E]

`plan_model.model()` follows the M8 request flow (`rv64-m8-gpu-native.md` §1).
- **Capture and Stage 1 overlap.** **The seal barrier waits for both.**
  - Stage 2, every leaf and every fold come after the seal.
  - Stage 1 is 37% of native job GPU-s [M, M8 §5: 1.04 of 2.82 GPU-s on 24628607].
- The request is assembled as:
  - wall = fixed + max(head + S1/(G·busy), capture) + (S2 + R − tail)/(G·busy) + IO + D2D + tail;
  - tail = (last leaf + one node per fold level)/busy_tail.

Central parameters [E]:

| parameter | central | range | basis |
|---|---|---|---|
| busy after the seal | 0.72 | 0.60–0.80 | — |
| head | 0.4 s | — | M8 §5 |
| fixed | 0.3 s | — | bench15 setup 0.11–0.21 + tail 0.03–0.07 [M] |
| capture | 1.51 + 0.0207·Minstr | — | T1 [M] two-point: 2.07 s / 5.76 s |
| IO | 0.30 s/GPU × leaves/14 × 50% exposed | — | IO doc §1.6 |

Calibration:
- On 24628607 the model gives **8.3 s (7.4–9.8)**. M8 §5 expects about 6–7 s, and bench15-1 / integrate measured 11.77 / 11.64 s [M]. The model is deliberately more conservative than M8 §5: it charges the seal barrier with the full capture.
- **The model must be recalibrated on the landed GPU-native bench15** (§6 step 2) before any lever is judged.

**Structural consequence.** On large blocks the pre-seal stage (capture or Stage 1) is 6.4 s of 42.5 s on 26235159 today [E]. After the M9 cuts it is **more than a third of the request**: 5.8 of 15.4 s, central. So capture and Stage 1 throughput become first-order on p95 blocks only after the kernel and recursion cuts.

### 2.4 Production vs bench: class misses [E]

- bench15 and every 3+3 replay the same block, so all 19 recursion classes hit [M, IO doc §0].
- On a new block, leaf classes miss:
  - a cold-class request spent 13.2 CPU-s in plan builds plus 2.72 CPU-s in PP packing [M Σ, IO doc L4];
  - that is about 0.84 CPU-s per node, and about 4-way parallel [E].
- GPU-native turns a miss into `GpuNativeClassNotWarmed`, so production needs either a miss path or canonical leaves.

| | 24628607 | p50 | p95 | 26235159 |
|---|---:|---:|---:|---:|
| bench baseline | 8.3 | 20.9 | 37.2 | 42.5 |
| production baseline (miss path) | 11.3 | 28.2 | 49.8 | 56.8 |

---

## 3. The >60% budget (2×5090)

Each lever's factor comes from a receipt or a stated estimate (`SC` in `plan_model.py`). "Alone" means applied to the post-M8 baseline. "Cumulative" applies the levers in the landing order of §4. The central case is shown, with (pessimistic … optimistic) ranges.

### 3.1 Lever table: p50 (29.1 M gas) and p95 (55.8 M gas) [E]

| # | lever (flag) | basis for the factor | p50 ΔGPU-s alone | p50 Δwall alone | p50 cumulative wall (cut) | p95 ΔGPU-s alone | p95 Δwall alone | p95 cumulative wall (cut) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| — | **post-M8 baseline** | §2.3 | 26.5 GPU-s | 20.9 s | 20.9 (25.7…18.4) | 49.5 GPU-s | 37.2 s | 37.2 (46.6…32.3) |
| 1 | packed class ingress + copy stream (`STWO_RV64_M9_CLASS_PACKED_INGRESS`, `_H2D_STREAM`; IO L1a + L3) | leaf statics 0.455 vs 15.8 GB [M]; residual ×0.1 | 0 | −0.3 | 20.5 (2%) | 0 | −0.6 | 36.7 (2%) |
| 2 | in-place coset / D2D + partial Merkle trees (`_D2D_INPLACE`, `_PARTIAL_MERKLE`; IO L5, delta §4 item 4) | D2D ≤ 0.11 s/GPU on 607 [D], 70% removed | 0 | −0.3 | 20.3 (3%) | 0 | −0.5 | 36.1 (3%) |
| 3 | **FFT/LDE cuts: streaming commit** (fused LDE → leaf hash, never write the LDE back unhashed), leafless/partial trees, column-batched NTT (`_STREAM_COMMIT`; delta §4 item 4) | FFT + Merkle = 52% of GPU-s [M]; ×0.70 on that share (−40% HBM traffic, 4-GPU §5) | −4.1 | −2.6 | 17.7 (15%) | −7.7 | −5.1 | 31.0 (17%) |
| 4 | **recursion witness without the task DAG** (`_WITNESS_ROWPAR`; delta §4 item 7, ZisK compact witness + GPU gate-interior expansion) | `chain_run` 1.0 GPU-s = 18% of recursion [M]; ×0.2 residual | −2.4 | −1.8 | 16.2 (22%) | −4.4 | −3.2 | 28.3 (24%) |
| 5 | **occupancy**: per-class graphs, 2 jobs/GPU once a node fits ≤ 11 GB (`_CLASS_GRAPHS`; scope P1, delta §4 items 2/5) | busy 0.72 → 0.85 | 0 | −2.3 (−5.2…−1.4) | 14.5 (31%) | 0 | −4.7 (−10.5…−2.7) | 25.1 (33%) |
| 6 | **fewer/bigger leaves**: truth early + late batches at b16 q27 p20, 2²³ CPU rungs (`_TRUTH_BATCHES`, `_CPU23_RUNGS`; 4-GPU §6.2 c/b1, scope P4) | CPU leaves ÷2, truth leaves → 2, per-leaf ×1.10; nodes 48 → 26 (p50) | **−8.9** | **−6.5** | 10.6 (49%) | **−15.8** | **−11.3** | 18.5 (50%) |
| 7 | **canonical leaf classes** (`_CANON_LEAF`; IO L4, `rv64-m6-enqueue.md:97`) | bench: 0. Production: removes the 7.4 / 12.6 s miss (§2.4) | 0 | 0 (prod −7.4) | 10.6 (49%) | 0 | 0 (prod −12.6) | 18.5 (50%) |
| 8 | native GKR v2-gkr in production, 128-oracle cap (`_NATIVE_GKR_V2`) | native ×0.826, leaf ×0.936 [D, levers.py/model.json] | −2.9 | −1.6 | 9.8 (53%) | −5.4 | −3.4 | 16.9 (54%) |
| 9 | **Poseidon2-M31-W24 leaves**, S2–S4 (`_P2_LEAVES`; 4-GPU §7, scope P2) | leaf cells ×0.19 [M]; recursion GPU-s ×0.30 (0.40…0.22) because GPU hashing is 11.7–13.4× slower per element [M]; native +0.037 GPU-s/Minstr (GO-NOGO 0.52–1.53 on 607 [D]) | −7.6 | −6.1 (−4.4…−7.1) | 8.8 (58%) | −13.6 | −10.0 (−7.4…−12.2) | 15.1 (60%) |
| 10 | outer GKR (DW-R1) in nodes (`_OUTER_GKR`) | ×0.57 alone, ×0.80 after P2 (overlap) [E] | −6.8 | −5.0 | 8.6 (59%) | −12.4 | −9.0 | 14.7 (61%) |
| 11 | **revert D2: native b4 → b2** once recursion is cheap (new named profile; levers.py `d2_nat`/`d2_leaf`) | native ÷1.4, leaves ÷0.55 [E] | +9.8 | **+8.2 alone** | **8.1 (61%)** | +17.8 | **+14.1 alone** | **13.8 (63%)** |
| 12 | **GPU capture replay** (M10; `_GPU_REPLAY`, `_GPU_GROUP`; IO L9 §5.9) | fast pass 168 MIPS [M] + GPU replay at 160 MIPS aggregate [E] | 0 | −0.3 alone (it only bites late) | **6.7 (68%)** | 0 | 0 alone | **12.1 (67%)** |
| 13 | 4-GPU placement (M10) | 4 GPUs at 92% scaling efficiency [E] | 0 | −6.7 | 4.2 (80%) | 0 | −13.3 | 7.3 (80%) |

Kernel GPU-s after levers 1–11 [E]: p50 26.5 → 9.6 (−64%) and p95 49.5 → 18.4 (−63%). So **the wall cut is cut work, not overlap**.

**D2 flips sign.** Reverting D2 alone is a large loss (+8 / +14 s). After leaves, P2 and outer GKR it is a gain (−0.4 s at p50, −0.9 s at p95), and the gain is −2.0 to −3.8 GPU-s of kernel time [D]. The reason is that recursion has dropped to 1.2–2.3 GPU-s, so cheaper native work outweighs the dearer leaves. This is the 4-GPU doc's finding that "D2 hurts once recursion is cheap", quantified.

### 3.2 15-block basket total and the measured proxies [E]

| step (cumulative, 2 GPUs unless noted) | basket total, central (pess…opt) | cut | 26235168 | 26235159 |
|---|---:|---:|---:|---:|
| post-M8 baseline | 320 s (395…280) | — | 24.6 | 42.5 |
| + IO, D2D | 311 | 3% | 23.9 | 41.3 |
| + streaming commit | 269 | 16% | 20.9 | 35.3 |
| + witness without DAG | 247 | 23% | 19.1 | 32.2 |
| + occupancy | 220 | 31% | 17.0 | 28.5 |
| + fewer/bigger leaves (+ canonical classes) | 165 | 48% | 12.1 | 20.5 |
| + native GKR v2 | 152 | 52% | 11.1 | 18.8 |
| + Poseidon2 leaves | 134 | 58% | 10.1 | 16.9 |
| + outer GKR | 131 | 59% | 9.9 | 16.5 |
| + revert D2 (b2 native) | **125 (170…97)** | **61%** | **9.3** | **15.4** |
| + GPU capture replay (M10) | 104 (163…66) | 68% | 7.8 | 13.6 |
| + 4 GPUs (M10) | 66 (109…41) | 79% | 4.8 | 8.1 |

Reference points: today-path extrapolation 584 s [E]; M3 1,843 s [M].

### 3.3 Which combinations reach >60% on p50, p95 and the basket at once [E]

Found by exhaustive search in `plan_model.py`, with IO and D2D always on. These are minimal sets, and none includes 4 GPUs:

- **central, M9 only (no GPU capture):** {streaming, occupancy, leaves, native GKR, P2, outer GKR, revert D2}: −60 / −62 / −60%.
- **central, with GPU capture** (examples):
  - {streaming, occupancy, leaves, native GKR, outer GKR, GPU capture}: **−65 / −64 / −64%**;
  - {streaming, occupancy, leaves, native GKR, P2, GPU capture}: −61 / −60 / −61%;
  - {streaming, witness, occupancy, leaves, outer GKR, GPU capture}: −61 / −60 / −61%;
  - {streaming, occupancy, leaves, P2, revert D2, GPU capture}: −61 / −61 / −61%.
- **pessimistic:** only {streaming, occupancy, leaves, native GKR, outer GKR, GPU capture}: −61 / −61 / −61%.
- **optimistic:** four- and five-lever sets suffice, for example:
  - {streaming, native GKR, P2, GPU capture};
  - {streaming, occupancy, leaves, native GKR, P2}.

What the search says:
1. **Fewer/bigger leaves is in every central and pessimistic set, and streaming commit is in all but one.** They are the two non-negotiables, and the prep for both can start now.
2. **One recursion-cell lever is needed, not two,** whenever GPU capture is in the set. Poseidon2 and outer GKR overlap: after leaves, P2 adds −1.0 s at p50 and outer GKR adds −0.2 s on top.
   - In the **pessimistic** case P2 after leaves is **net negative** on p95 (+0.3 s): its native hashing cost exceeds the recursion it saves once recursion is small.
   - So gate S1 (Poseidon2 GPU throughput) decides between them. P2 stays the 4-GPU backbone (4-GPU doc §7), because it shrinks node memory and cuts the hash cells outer GKR does not touch.
   - Without GPU capture, M9 needs both cell levers plus the D2 revert.
3. **Capture (or Stage 1 throughput) is the next critical path.** After the M9 cuts the pre-seal stage is 3.4 of 8.1 s at p50 and 5.2 of 13.8 s at p95 (central). GPU capture, or any capture or Stage 1 speed-up that frees the seal earlier, is the cheapest margin above 60%, and it is required in the pessimistic case.
4. **Revert D2 only after the hash backbone** (§3.1). Before it, the revert loses at every scale.
5. **IO and D2D are below 2% each at p50.** Do them for host relief (−3.7 CPU-s unpack, −25 GB memcpy [M/D]) and because they matter on p95 if M8 leaves more leaf statics than assumed (IO doc: ≤ 2.2–3.0 s/GPU on 26235159 before M8 [D]). They are not the cut.

### 3.4 Risk to the budget

- **The baseline is [E].**
  - In the pessimistic scenario (busy 0.60, weaker levers) every 2-GPU lever together gives −59% on the basket.
  - If GPU-native lands nearer M8 §5 (6–7 s on 24628607), the fixed costs weigh more and the levers' share falls.
  - **Recalibrate before committing to a combination** (§6).
- **The leaves lever** carries the largest single wall cut. Its factors (×1.10 per-leaf growth at 2²³, truth leaves → 2) need:
  - the 2²³ device peak to fit (it must stay ≤ 28 GB; 2²⁴ does not fit at b4);
  - truth batching to pass GPU qualification (scope P4).

  The `fewer-leaves` prep stream owns this measurement.
- **Occupancy** has the widest range (−1.4 … −5.2 s at p50), because it depends on per-node memory reaching ≤ 11 GB (scope P1).
- **The D2 revert** relies on the levers.py D2 factors (native ×1.4, leaf ×0.55), which have no direct receipt at b2 vs b4 on the GPU path. Measure it with a paired A/B after wave 3.
- **The p95 numbers extrapolate** the kernel fit beyond 58 M instructions. 26235159 has no kernel receipt.

---

## 4. Ordering and dependencies on GPU-native

All flags are new, default-off `STWO_RV64_M9_*` flags. Rules:
- every wave-1 item is byte-identical to the frozen D2 golden (32/32, 39/39);
- every wave-2 and wave-3 item ships as a named profile with fresh receivers and corpora.

| wave | lever | depends on (GPU-native piece) | prep possible now (no request-level GPU) | parallel stream |
|---|---|---|---|---|
| 0, inside M8 (not M9) | L0 compact `TraceChunk` v2; leaf class-miss rule; p-truth-split so all 15 blocks prove | — | — | round 3 (gn-*) |
| 1 | IO L1a + L3 | `ClassCache`, `MemoryPlan` per-node region, M8 streams | device decoder for `cache_pack.zig` blocks + parity microbench | `packed-ingress` |
| 1 | D2D in place / partial trees | M8 MAIN-resident (H5/H12), PCS job | kernels + byte-parity vs CPU on single trees | — |
| 1 | streaming commit (fused LDE → leaf hash) | native Stage 1/2 jobs on device; PCS enqueue-only | standalone kernel: iNTT → LDE → Blake2s leaf in one pass, CUDA-event timing vs today's n2b + `mixed_leaf_kernel` | — |
| 1 | witness without the DAG | recursion jobs (R1–R6), outer node plans in `ClassCache` | compact witness format + gate-interior expansion kernel; dump one real node (`STWO_RV64_M8_ASSIGNMENT_DUMP`) | — |
| 1 | occupancy (graphs, 2 jobs/GPU) | **all of GPU-native** (enqueue-only `prove()`, device FS), plus P1 ≤ 11 GB/node | graph-capture feasibility per class; memory sweep tool (delta §4 item 3) | — |
| 2 | fewer/bigger leaves | GPU-native truth job; `RequestLayout` slab sized by leaves | truth-batch geometry, 2²³ peak model (`rv64_m7_layout_model.py`), soundness note | `fewer-leaves` |
| 2 | canonical leaf classes | `ClassCache` keying; resolves `GpuNativeClassNotWarmed` | shape catalog + statement change + soundness review | `canon-leaf` |
| 2 | native GKR v2-gkr | native Stage 1 device channel | 128-oracle CUDA cap (WIP `codex/rv64-m7-native-gkr`) | — |
| 3 | Poseidon2 leaves S2–S4 | the device transcript in GPU-native must take a 36-byte hash family; slab encoding | **S1 now**: W24 PCS / transcript / PoW kernels, 5090 throughput vs Blake2s (go/no-go) | `poseidon2-leaves` |
| 3 | outer GKR | recursion jobs | DW-R1 constrained eq column; census | — |
| 3 | revert D2 (b2 native profile) | P2 or outer GKR landed; named profile + fresh receivers | none needed before wave 3; then a paired b2/b4 A/B on the 3+3 set | — |
| M10 | GPU capture replay, 4-GPU placement | GPU-native capture feed (`Feed`), peer exchange | `_GPU_GROUP` sort/reduce-by-key microbench (CPU-side T10 numbers [M]) | — |

**Why this order.**
- Wave 1 changes no proof bytes. It can be gated with the existing D2 golden as soon as GPU-native is the default, and it delivers about 31% (central).
- Wave 2 delivers the next 21–22 points (to 53–54%), and wave 3 the last 7–9 (to 61–63%). Wave 2 needs profile and soundness work that is pure CPU and design today.
- Wave 3's go/no-go (S1) is a standalone-kernel measurement. It decides whether wave 3 is Poseidon2 or outer GKR.
- Nothing in waves 1–3 may land on `codex/rv64-m7-integrate` before GPU-native is the default, because every lever modifies a GPU-native component.

---

## 5. M10+ roadmap

| milestone | content | exit [E targets] |
|---|---|---|
| **M10: 4×5090 and the last mile** | 4-GPU placement (key affinity, root-critical-chain priority, comb aggregation with capacity-fit arity, 4-GPU §6.2 g / §9); GPU capture replay (fast pass with checkpoints → GPU replay, ledger as GPU sort); native GPU witness for all columns; kernel fusion (constraint eval + quotient + first FRI fold; GKR layer + next round, delta §4 item 1 windowed sumcheck); megakernel scheduler only if busy < 85% (4-GPU §8.4) | p50 ≤ 5 s, p95 ≤ 9 s, basket ≤ 75 s, every basket block ≤ 10 s on 4×5090 |
| M10 | precompile delegations ranked by instruction attribution (BN254, KZG/BLS first, 4-GPU §4.1); compress S5 (Poseidon C1, Keccak C2, ≤ 120 KB) | −20–35% instructions on blocks that use them; root ≤ 120 KB |
| M11 | protocol parameters: query grinding 26, Merkle caps, per-layer FRI schedule (4-GPU §10); hand-designed verifier AIR (4-GPU §6.2 a) for witness depth O(10) | −5–15% recursion; tail ≤ 1 s |
| M11 | production service: canonical classes for every shape, install-time `ClassCache` for the whole shape catalog, Prometheus per stage, identity table (delta §4 item 8); mainnet-replay soak at p50/p95 | production p50 = bench p50 ± 5% |
| watch | multilinear/WHIR recursion (4-GPU §6.2 e), hash-based accumulation (f) | only if recursion > 0.3 G cells per verified proof after M9 |

Kill and pivot points:
- If S1 shows Poseidon2 native hashing > 3 GPU-s on the p95 block, use outer GKR or GKR-proven Blake2s (h1) as the cell lever.
- If 2²³ rungs exceed 28 GB peak, keep 2²² and take truth batching only. Leaves then give about −4.3 GPU-s, roughly −3 s, at p50 instead of −6.5 s (nodes 48 → 35) [E].
- If GPU-native lands at < 0.65 busy, prioritise occupancy (P1 memory) ahead of wave 2.

---

## 6. Steps to integrate after GPU-native lands

1. Rebase `codex/rv64-m9-plan` onto `codex/rv64-m7-integrate` once GPU-native is the default. It adds only a doc, a script, a test and a receipt, so it is conflict-free.
2. Run bench15 on the landed default, with all 15 blocks proving after p-truth-split, and record:
   - per stage: pre-seal, post-seal, tail, IO;
   - kernel GPU-s split native/recursion by NVTX;
   - busy;
   - class hits.

   Then refit `plan_model.py` (`KFIT`, `k_m8`, `busy`, `head`, `STAGE1_FRAC`, `IO_LINK_607_POST_M8`) and regenerate `model.json` and the §3 tables. The **[E] baseline becomes [M]**.
3. Adopt the canonical set:
   - add 26235168 to the 3+3 runner and the owner-rule allowlist;
   - add 25229955 as the scale probe;
   - add the mainnet-weighted basket mean (weights §1.2) to `rv64_m8_bench15.py` output.
4. Run IO E8 (different-blocks warm) to measure the production class-miss cost. It decides how urgent `_CANON_LEAF` is.
5. Land wave 1 one flag at a time: an A/B 3+3 on 24628607 and 26235168, byte-identical to the frozen golden, fresh receivers. Promote each flag to default when Δ ≥ noise and nothing regresses.
6. Wave 2: named profiles with soundness notes, fresh receivers and corpora; bench15 after each.
7. Wave 3: decide P2 vs outer GKR on the S1 receipt, then stages S2–S4.
8. Re-score the >60% claim on the measured bench15 after each wave. Stop and re-plan if the cumulative cut trails §3.2 by more than 5 points.

---

## 7. Sources

- Gas sample: `gas_sample.json` (raw, out of git; percentiles and weights in `vectors/reports/rv64-m9-prep/m9-plan/model.json`).
- Basket: `vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json` (gas, instructions), `vectors/reports/rv64-m3-20261104/summary.json` (segments, truths, M3 times).
- bench15-1: `codex/rv64-m8-gpu:vectors/reports/rv64-m8-20261106/bench15/{SUMMARY.md,summary.json,estimate.json}`.
- Kernel census: `vectors/reports/rv64-m8-20261106/opt-combined/{README.md,ab8-kernels.json}`; capture T1: `vectors/reports/rv64-m8-20261106/opt-T1-capture-parallel/README.md`.
- Poseidon2 GPU budget: `vectors/reports/rv64-m7-20261105/poseidon2/GO-NOGO.md`.
- `rv64-4gpu-realtime.md`, `rv64-frontier-gpu-delta.md`, `scripts/rv64_4gpu/levers.py` (`codex/rv64-4gpu-realtime-design`); `rv64-m8-gpu-native.md` (`codex/rv64-m8-gpu`); `rv64-m9-io-streaming.md` (`codex/rv64-m9-io-design`); `rv64-m8-engineering-scope.md` (integrate).
