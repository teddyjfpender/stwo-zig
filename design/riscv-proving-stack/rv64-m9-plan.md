# RV64 M9 plan: gas-weighted targets and the >60% cut budget (2×RTX 5090, then 4×)

Status: plan of record, revision 3, 2026-11-07. It folds in the four reviewed M9 prep streams (§3) and re-runs the budget; every number is regenerated from `scripts/rv64_m9/plan_model.py`. Written **in parallel with** the GPU-native landing (workflow round 3, `codex/rv64-m8-gpu`, `codex/rv64-m8-gn-*`); it touches no code those streams own.
Branch `codex/rv64-m9-plan`, cut from `codex/rv64-m7-integrate @ 95e3d7e15` (integrate has since moved to 786429aca; this branch only adds files).

Labels: **[M]** measured, with a receipt; **[D]** arithmetic on measured numbers; **[E]** estimate.

Model: `python3 -I scripts/rv64_m9/plan_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/m9-plan/model.json` (tests: `python3 -I scripts/tests/test_rv64_m9_plan_model.py`, 12/12). Receipt: `vectors/reports/rv64-m9-prep/m9-plan/model.json`. The raw gas sample stays out of git (sha256 in the receipt README).

---

## 0. TL;DR

1. **Targets are gas-weighted, not 24628607.** Mainnet p50 = 29.1 M gas, p95 = 55.8 M [M, 2,897 blocks]; 24628607 is p4. Targets on 2×5090, ≥ 60% below the post-M8 baseline [E]: **p50 ≤ 7.9 s** (from 19.7), **p95 ≤ 13.2 s** (from 32.9), **15-block basket ≤ 118 s** (from 294). M10 on 4×5090: p50 ≤ 5 s, p95 ≤ 8 s.
2. **The streams shrank two of the three big recursion levers.**
   - k-leaf fan-in (fewer-leaves) gives recursion cells ×0.76–0.86 [D], so −2.3 s at p50, not the −5.4 s the truth-batch/2²³ estimate gave.
   - Poseidon2 leaves (reviewed) are a **net loss as built** (+8.7 GPU-s at p50 [E]). Even at the engineered target they lose once outer GKR and fan-in have cut recursion (+0.5 to +2.0 s at p50).
   - Canonical leaf classes (catalog R=4) carry a **held-out native padding tax of ×1.55** [D] and leave 79% of fold classes missing on a new block [D/E]. That makes them a bench loss (+3.4 s at p50) and only a small production gain.
   - Packed ingress works (4.48 ms decode per 1.03 GB node [M]) but is worth only about 1% of wall [E].
3. **No 2-GPU combination reaches 60% in the central case; the best gets to −58%.** The best set is {IO, D2D, streaming commit, witness without the DAG, occupancy, k-leaf fan-in, native GKR v2, outer GKR, GPU capture replay}: **p50 8.0 s (−59%), p95 13.8 s (−58%), basket 121 s (−59%)** [E]. Poseidon2 and the D2 revert are both *worse* on top of that set.
   - The 60% bar is reached on all three metrics only if **one** unmeasured lever beats its central factor by a notch [E]: occupancy busy 0.90 (instead of 0.85), streaming commit ×0.60 (instead of ×0.70), or outer GKR ×0.50 (instead of ×0.57; this one misses p95 by 0.2 points).
   - The optimistic case has 3 minimal sets (−61 to −63%). The pessimistic case peaks at −53%.
   - **4×5090 (M10) on the same set: p50 5.1 s (−74%), p95 8.3 s (−75%), basket 78 s (−73%)** [E].
4. **Order after GPU-native and the post-M8 cleanup:**
   - wave 1, byte-identical: IO, D2D, streaming commit, witness, occupancy (needs P1 ≤ 11–13 GB per node);
   - wave 2, new profiles: k-leaf fan-in (needs P1 too), native GKR v2;
   - wave 3: **outer GKR, not Poseidon2**, plus **GPU capture replay (pulled from M10; worth 8 points)**;
   - M10: 4 GPUs, then Poseidon2 only as a node-memory/compression lever.
   - Shelved for M9: the D2 revert and canonical leaves as built.
5. **Production is the real gap.** Every production request is a new block. Charging the class-build miss serially (an upper bound), the best 2-GPU set gives p50 **13.6 s** (11.7 s with canonical leaves) against a bench 8.0 s [E]. GPU-native fails closed on a miss (`GpuNativeClassNotWarmed`). M9 needs a miss path that overlaps capture, or class-stable outer shapes. E8 has to measure it.

---

## 1. Targets

### 1.1 Mainnet gas and the basket [M/D]

Source: `gas_sample.json` (2,897 distinct blocks, 26,019,159–26,236,159, 2026-09-20 to 10-20, about 60 M limit).

| p5 | p10 | p25 | **p50** | p75 | p90 | **p95** | p99 | mean |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8.3 M | 15.8 M | 23.4 M | **29.1 M** | 37.2 M | 47.1 M | **55.8 M** | 60.0 M | 30.4 M |

- The basket over-weights big blocks: 5 of 15 blocks are above 40 M and hold 62% of basket gas; on mainnet those are 19% of blocks and 31% of gas.
- It also over-weights tiny ones: 5 of 15 are at or below p8. Only 26235168 (p50) lies between p21 and p79.
- Mainnet weights by nearest gas: 26235168 0.33, 24697073 0.20, 25229955 0.19, 24628590 0.06, all others ≤ 0.04 [D].
- Percentiles: 24628607 p4, 25229955 p79, 26235159 p96.

### 1.2 Targets (warm proving, Ethproofs boundary; request = proving + about 0.01 s [M])

| metric | post-M8 baseline [E, central (pess–opt)] | **M9, 2×5090** | best 2-GPU set [E] | M10, 4×5090 |
|---|---:|---:|---:|---:|
| **p50** (29.1 M gas, 93 M instr, 23 seg) | 19.7 s (23.8–17.4) | **≤ 7.9 s** | 8.0 s | ≤ 5 s (5.1) |
| p50 proxy **26235168** (113 M instr, 28 seg) | 23.3 s | ≤ 9.3 s | 9.5 s | ≤ 5.5 s (5.9) |
| **p95** (55.8 M gas, 178 M instr, 43 seg) | 32.9 s (41.1–28.9) | **≤ 13.2 s** | 13.8 s | ≤ 8 s (8.3) |
| p95 proxy 26235159 (205 M instr, 49 seg) | 37.9 s | ≤ 15.2 s | 15.7 s | ≤ 9 s (9.4) |
| **15-block total** | 294 s (361–259) | **≤ 118 s** | 121 s | ≤ 70 s (78) |
| mainnet-weighted mean | 20.1 s | ≤ 8.0 s | 8.2 s | ≤ 5 s (5.3) |
| production p50 (new block per request) | 29.7 s | ≤ 8.7 s | 13.6 s (11.7 with canonical leaves) | ≤ 5.5 s |
| 24628607 (continuity) | 8.5 s | ≤ 3.4 s | 3.4 s | ≤ 2.4 s (2.7) |

### 1.3 Benchmark set

- **3+3: 24628607 (continuity) + 26235168 (mainnet p50).** Scale probe: 25229955 (p79). Cheaper probe: 24697073 (p21).
- **Prerequisite:** all three middle blocks are refused today by `OneTruthPerFamilySourceCapacity` [M, bench15-1]. Round-3 p-truth-split has to land first, and it changes the truth roster, so recalibrate the shapes afterwards.
- Allow 26235168 in the 3+3 runner and the owner-rule allowlist.
- Every bench also reports the mainnet-weighted basket mean Σ wᵢ·tᵢ (weights from §1.1).

---

## 2. Baseline (unchanged by the streams; still [E] until GPU-native bench15)

- **bench15-1 fits [D]** (6 proved blocks, `codex/rv64-m8-gpu:vectors/reports/rv64-m8-20261106/bench15/`):
  - kernel GPU-s = 1.46 + 0.284·Minstr (R² 0.980);
  - native = 0.119 GPU-s/Minstr (K607 = 8.333, T2 off);
  - **recursion = 0.046 + 0.306·nodes** (R² 0.954).
  - The fewer-leaves cell model reproduces this independently: node wall 0.455 ns/cell, kernel 0.262 ns/cell + 0.118 GPU-s/Minstr native [D].
- **Kernel families on 24628607 [M]** (`opt-combined/ab8-kernels.json`): FFT 2.98 GPU-s (35%), Merkle 1.52 (18%: mixed_leaf 1.250, child_layer 0.180, layer 0.080, fri_leaf 0.010), `chain_run` 1.00 (12%), `channel_mix` 0.078 over 363 calls.
- **Request model (`plan_model.model`)**:
  - wall = fixed + max(head + S1/(G·busy), capture + S1/seg/busy) + (K − S1 − tail)/(G·busy) + IO + D2D + tail;
  - Stage 1 is 37% of native work [M, M8 §5];
  - central busy is 0.72, the capture fit uses T1 (default-off: promoting it is a cleanup prerequisite);
  - D2 and native-GKR factors apply to leaves only.
- Post-M8 central kernel GPU-s: p50 24.5 (native 10.5, recursion 14.0); p95 43.5 (20.2 / 23.3).
- **Production miss [E]:** on a new block, every leaf class misses and so do 97% of fold classes (exact outer shape, 204/210 [D/E, canon-leaf review]). The host builds classes at 0.84 CPU-s each, 4-way parallel.
  - The model charges this serially (an upper bound): +10.0 s at p50 and +16.7 s at p95 on the baseline.
  - The earlier revision charged leaves only (7.4 / 12.6 s).

---

## 3. What the prep streams changed

| lever | revision 2 assumption | stream result (reviewed) | now in the model | branch @ head |
|---|---|---|---|---|
| packed ingress (L1a) | residual IO ×0.10, IO 0.30 s/GPU × 50% exposed | decoder parity on real leaf data, 2 GPUs; **4.48 ms per 1.03 GB node** [M]; 2.85 ms per 0.34 GB; 0.455 vs 15.86 GB per request [D]; link 24.6 GB/s in-request, 46% exposed [D]; wall about 0.10 s on 607, 0.42 s at p50 [E] | link 0.31 s/GPU × 0.46 exposed, residual ×0.03 [D], +0.004 GPU-s decode per leaf [M/E] | `codex/rv64-m9-packed-ingress` @ 805d1a105 |
| fewer/bigger leaves | truth batches b16 + 2²³ CPU rungs: CPU leaves ÷2, truth leaves → 2, truth native ×1.5 | **k-leaf fan-in** (2–4 same-family natives per leaf; blake_g ≤ 2²³, ≤ 2.2 G cells). Recursion cells: 607 ×0.822, 26235168 ×0.761, 26235159 ×0.757 [D/E, cell model exact on 607]; nodes 19→12 / 62→33 / 97→48. Truth batching inside the envelope is only about 2%; 8-ary folds don't fit (36–43 GB). Pair leaf about 30.7 GB against the 30.06 GB gate today: **no fit until P1** (12.4–13.4 GB) [E]. Natives unchanged | per-block receipt ratios and tree shapes; synthetic p50/p95 ×0.76; pess ×0.80 (k2), opt ×0.73 (any family) | `codex/rv64-m9-fewer-leaves` @ a056cee67 |
| canonical leaf classes (L4) | bench padding tax ×1.04; production removes the leaf miss | catalog R=4: 72 classes, 0 in-sample misses [M]. **Held-out CPU cells tax +61%**, truth rows +2.5% [D]; per block 607 +22%, 26235168 +107%. 1 of 15 held-out blocks refused (26235159, bn254_g1_add). Folds still 79% new [D/E]. Net per new 607-like block about 0 to +8 s [E] | native ×1.55 (pess ×2.07, opt ×1.22); leaf miss removed, fold miss ×0.79 | `codex/rv64-m9-canon-leaf` @ 64a2cb991 |
| Poseidon2-M31 leaves | recursion ×0.30 (0.55–0.22), native +0.037 GPU-s/Minstr | kernel parity 336/336 incl. 46 roots [M]; **P2/Blake GPU cost ×9.95** [M] against break-even ×11.8 [D]; recursion Merkle share 0.29 [D]; **serial transcript ×23.9** [M]. Net GPU-s at p50: **as built +8.7**, 2-to-1 + kernels ×0.6 about 0, engineered target (plus a parallel transcript, which is a protocol change) −6.2 [E] | pess = as built (rec ×0.87, native +0.040/Minstr, transcript +0.066/Minstr); central = 2-to-1 + ×0.6 (rec ×0.51, +0.018, +0.066); opt = engineered (transcript +0.006). Transcript is half hidden with 2 jobs per GPU [E] | `codex/rv64-m9-poseidon2-leaves` @ 37e581cfc |

Not touched by any stream and still [E]: streaming commit, witness without the DAG, occupancy, native GKR v2, outer GKR, D2 revert, GPU capture, 4 GPUs.

---

## 4. The budget (2×5090)

"Alone" means applied to the post-M8 baseline. "Cumulative" applies the levers in the §5 landing order. Central values, with (pess…opt) ranges.

### 4.1 Lever table: p50 (29.1 M gas) and p95 (55.8 M gas) [E]

| # | lever (flag) | basis | p50 ΔGPU-s alone | p50 Δwall alone | p50 cumulative (cut) | p95 ΔGPU-s alone | p95 Δwall alone | p95 cumulative (cut) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| — | **post-M8 baseline** | §2 | 24.5 GPU-s | 19.7 s | 19.7 (23.8…17.4) | 43.5 GPU-s | 32.9 s | 32.9 (41.1…28.9) |
| 1 | packed class ingress + copy stream (`STWO_RV64_M9_CLASS_PACKED_INGRESS`) | 4.48 ms/node decode [M]; 0.455/15.86 GB [D]; 46% exposed [D] | +0.1 | −0.2 | 19.4 (1%) | +0.2 | −0.4 | 32.4 (1%) |
| 2 | in-place coset / D2D (`_D2D_INPLACE`) | ≤ 0.11 s/GPU on 607 [D], 70% removed [E] | 0 | −0.3 | 19.1 (3%) | 0 | −0.5 | 31.9 (3%) |
| 3 | **streaming commit** (fused LDE → leaf hash) (`_STREAM_COMMIT`) | FFT + Merkle 53% of GPU-s [M]; ×0.70 on it [E] | −3.9 | −2.4 | 16.7 (15%) | −6.9 | −4.2 | 27.7 (16%) |
| 4 | **witness without the DAG** (`_WITNESS_ROWPAR`) | `chain_run` 19% of recursion [D]; ×0.2 residual [E] | −2.2 | −1.6 | 15.4 (22%) | −3.6 | −2.6 | 25.5 (22%) |
| 5 | **occupancy**: class graphs, 2 jobs/GPU (`_CLASS_GRAPHS`; needs P1) | busy 0.72 → 0.85 [E] | 0 | −2.1 (−4.5…−1.3) | 13.8 (30%) | 0 | −3.9 (−9.3…−2.3) | 22.6 (31%) |
| 6 | **k-leaf fan-in** (`STWO_RV64_M9_LEAF_FANIN=4`, `_POLICY=same`; needs P1) | recursion cells ×0.76–0.86 [D, fewer-leaves receipt] | −3.4 | −2.3 | 12.5 (36%) | −5.6 | −3.8 | 20.5 (38%) |
| 7 | native GKR v2-gkr (`_NATIVE_GKR_V2`) | native ×0.826, leaf ×0.936 [D] | −2.5 | −1.3 | 11.7 (40%) | −4.7 | −2.5 | 19.0 (42%) |
| 8 | **outer GKR** (DW-R1) in nodes (`_OUTER_GKR`) | recursion ×0.57 [E] | −6.0 | −4.4 | 9.6 (51%) | −10.0 | −7.2 | 15.7 (52%) |
| 9 | **GPU capture replay** (M10 → M9; `_GPU_REPLAY`) | fast pass 168 MIPS [M], replay 160 MIPS [E] | 0 | −0.6 (bites late) | **8.0 (59%)** (11.1…6.0) | 0 | 0 (bites late) | **13.8 (58%)** (19.0…10.4) |
| 10 | 4-GPU placement (M10) | 92% scaling [E] | 0 | −6.2 | 5.1 (74%) | 0 | −11.2 | 8.3 (75%) |
| — | *off the order:* Poseidon2 leaves (`_POSEIDON2_LEAVES`) | §3 | +1.0 (as built +8.7) | 0.0 (pess +6.6, opt −3.3) | **+2.0 on top of #9** | +3.6 | +2.2 | **+4.1 on top of #9** |
| — | *off the order:* revert D2 (b4 → b2 native) | native ÷1.4, leaf ÷0.55 [E] | +5.6 | +4.7 | +0.25 on top of #9 | +8.9 | +7.6 | +0.05 on top of #9 |
| — | *off the order:* canonical leaves R=4 (`_CANON_LEAF`) | held-out tax ×1.55 [D] | +5.8 | +3.4 | +2.4 on top of #9 (prod −1.9) | +11.1 | +7.7 | +4.5 on top of #9 (prod −2.4) |

After #1–#9, kernel GPU-s falls 24.5 → 11.5 at p50 (−53%) and 43.5 → 21.0 at p95 (−52%). At p95 the wall of 13.8 s splits into 3.5 s pre-seal, 9.1 s post-seal, 0.9 s tail and 0.3 s fixed [E].

### 4.2 Basket total and proxies [E]

| step (cumulative, 2 GPUs) | 15-block total, central (pess…opt) | cut | 26235168 | 26235159 | 24628607 |
|---|---:|---:|---:|---:|---:|
| post-M8 baseline | 294 (361…259) | — | 23.3 | 37.9 | 8.5 |
| + IO, D2D | 286 | 3% | 22.6 | 36.8 | 8.3 |
| + streaming commit | 250 | 15% | 19.8 | 31.7 | 7.4 |
| + witness | 230 | 22% | 18.1 | 29.2 | 6.8 |
| + occupancy | 206 | 30% | 16.2 | 25.9 | 6.3 |
| + k-leaf fan-in | 189 | 36% | 14.7 | 23.3 | 6.0 |
| + native GKR v2 | 176 | 40% | 13.7 | 21.6 | 5.7 |
| + outer GKR | 145 | 51% | 11.2 | 17.7 | 4.7 |
| + GPU capture replay | **121 (168…91)** | **59%** | **9.5** | **15.7** | **3.4** |
| + 4 GPUs (M10) | 78 (114…56) | 73% | 5.9 | 9.4 | 2.7 |

### 4.3 Which combination reaches >60% [E]

Exhaustive search over {streaming, witness, occupancy, k-leaf, native GKR, outer GKR, GPU capture, Poseidon2, D2 revert}, with IO and D2D always on, requiring ≥ 60% on the p50 block, the p95 block **and** the basket at once:

| case | sets that reach 60% on all three | best set (min of p50 / p95 / basket) |
|---|---|---|
| **central** | **none** | all of #1–#9: p50 −59.4%, p95 −58.1%, basket −58.8% |
| pessimistic | none | the same set, −53% |
| optimistic | {streaming, occupancy, k-leaf, native GKR, outer GKR, GPU capture}: −63/−62/−62%; {streaming, witness, occupancy, native GKR, outer GKR, GPU capture}: −62/−61/−62%; {streaming, witness, k-leaf, native GKR, outer GKR, GPU capture, D2 revert}: −62/−61/−61% | — |
| 4×5090, central | all of #1–#10 | −74 / −75 / −73% |

Per metric, central: **the p50 block reaches −59.4%** (8.0 s against the 7.9 s target), **the p95 block −58.1%** (13.8 against 13.2), **the basket −58.8%** (121 against 118). All three miss by 0.6–1.9 points.

**What closes the gap, with one lever beating its central factor** (cuts for p50 / p95 / basket):
- occupancy busy 0.90: −61.2 / −60.2 / −60.6%;
- streaming commit ×0.60: −61.6 / −60.6 / −61.0%;
- outer GKR ×0.50: −61.1 / −59.8 / −60.5%, which still misses p95;
- k-leaf with the any-family policy: −59.9 / −58.7 / −59.3%, which is not enough.

So the plan of record is the #1–#9 set, with streaming commit and occupancy as the levers to push. A 2-GPU M9 exit at −58% is the honest central expectation.

What the search says:
1. **Every 60% set has streaming, native GKR, outer GKR and GPU capture.** GPU capture is worth 8 points at the end (−51% → −59%): after the cuts, capture is the pre-seal critical path on large blocks.
2. **Outer GKR is the recursion-cell lever, not Poseidon2.** P2's transcript (one thread, ×23.9) and native hashing (×9.95 per cell) are fixed costs. The recursion it saves is already small after fan-in and outer GKR. Even at the engineered target P2 adds +0.5 s at p50 on top of #9.
3. **The D2 revert no longer flips sign** (+0.25 s at p50, +0.05 s at p95 on top of #9): revision 2's gain needed P2's recursion cut. Shelve it until recursion is about 2× cheaper again.
4. **Canonical leaves as built are not an M9 lever.** The padding tax is too high; the envelope design is the real lever (canon-leaf review §9).

---

## 5. Ordering after GPU-native lands and the cleanup pass

Rules:
- Nothing lands on `codex/rv64-m7-integrate` before GPU-native is the default and the post-M8 cleanup (productionisation, repeatable benchmark set) is done.
- Every flag is new, default-off `STWO_RV64_M9_*`.
- Wave 1 is byte-identical to the frozen D2 golden (32/32, 39/39).
- Waves 2–3 are named profiles with fresh receivers and corpora.

| step | content | depends on | gate |
|---|---|---|---|
| 0 (cleanup) | promote T1 capture to default; p-truth-split so all 15 blocks prove; landed-default bench15 → refit `plan_model.py` (baseline [E] → [M]); 3+3 = 607 + 26235168; **E8 different-blocks warm run** (production miss) | GPU-native default | refit within 5 points of §4.2 or re-plan |
| 1a | packed ingress (prototype ready) → D2D in place | `ClassCache`, `MemoryPlan`, M8 streams | byte identity; host-to-device bytes −14 GB on 607 |
| 1b | **streaming commit** | native Stage 1/2 on device, PCS enqueue-only | standalone fused kernel against n2b + `mixed_leaf_kernel`, then A/B |
| 1c | witness without the DAG | recursion jobs, node plans in `ClassCache` | node dump parity |
| 1d | **P1 node memory ≤ 11–13 GB → occupancy** (2 jobs/GPU, class graphs) | all of GPU-native | busy ≥ 0.85 measured |
| 2a | **k-leaf fan-in** (planner prototype ready) → k-leaf circuit, receiver, VK registration | P1 (pair leaf does not fit today) | standalone memory probe ≤ 28 GiB / ≤ 13 GB post-P1; −18% cells on 607 exactly |
| 2b | native GKR v2 in production | native Stage 1 device channel | fresh receivers |
| 2c | **production miss path**: overlap leaf class builds with capture; class-stable outer shapes (set-v2 / uniform-v1) | E8 number | production p50 ≤ bench p50 + 10% |
| 3a | **outer GKR** (DW-R1) | recursion jobs | soundness note, census |
| 3b | **GPU capture replay** | GPU-native `Feed`, T1 promoted | pre-seal ≤ 2 s at p50 |
| M10 | 4-GPU placement; Poseidon2 for node memory / compression only if S0 + parallel transcript land; canonical-leaf envelope redesign; D2 revert re-check | — | p50 ≤ 5 s, p95 ≤ 8 s |

Waves 1–2 are where the levers that close the gap live (streaming, occupancy). Their prep is CPU or standalone-kernel work and can run now, in parallel with the GPU-native landing.

---

## 6. Branches holding each prototype

| prototype | branch @ head | key files (new) | state |
|---|---|---|---|
| plan + model | `codex/rv64-m9-plan` | `design/riscv-proving-stack/rv64-m9-plan.md`, `scripts/rv64_m9/plan_model.py`, `scripts/tests/test_rv64_m9_plan_model.py` | 12/12 tests |
| packed ingress | `codex/rv64-m9-packed-ingress` @ 805d1a105 | `src/backends/cuda/native/rv64/m9_class_unpack.{h,cu}`, `src/integrations/riscv_cuda/rv64/m9_class_packed_ingress.zig`, `tools/rv64-m9-packed-ingress/{corpus.zig,bench.cu}`; doc `rv64-m9-packed-ingress.md` | parity on dev0/dev1, memcheck/racecheck clean [M]; not linked into the native lib |
| k-leaf fan-in | `codex/rv64-m9-fewer-leaves` @ a056cee67 | `om31_native/leaf_fanin.zig`, `scripts/rv64_m9_leaf_fanin_model.py`; doc `rv64-m9-fewer-leaves.md` | planner only (flag off is identity on 15 shapes); k-leaf circuit not built |
| canonical leaf catalog | `codex/rv64-m9-canon-leaf` @ 64a2cb991 | `rv64_recursion/canon_leaf{,_catalog,_test,_bounds_test}.zig`, `scripts/rv64_m9_canon_leaf_{catalog,fold_classes}.py`; doc `rv64-m9-canon-leaf.md` | 10 tests; nothing reads the flag |
| Poseidon2 leaves | `codex/rv64-m9-poseidon2-leaves` @ 37e581cfc | `src/core/vcs_lifted/poseidon2_m31_mixed_leaf.zig`, `tests/cuda/rv64/m9_poseidon2/*.cu`, `scripts/rv64_m9/poseidon2_leaves_model.py`; doc `rv64-m9-poseidon2-leaves.md` | 336/336 GPU parity, 90/90 Zig; staged outside `native/`; conditional no-go for M9 |
| IO streaming design | `codex/rv64-m9-io-design` | `rv64-m9-io-streaming.md` | design (E8 defined there) |

Not prototyped yet (the levers that decide 60%): streaming commit, witness without the DAG, occupancy/P1, outer GKR, GPU capture replay.

---

## 7. Open risks

1. **The baseline is [E].** Every cut is relative to a modelled post-M8 baseline calibrated on 6 small blocks (≤ 58 M instr). p95 extrapolates. If GPU-native lands near M8 §5's 6–7 s on 607, fixed costs weigh more and the percentages fall.
2. **The 60% levers are the unmeasured ones.** Streaming commit (×0.70), occupancy (0.85), outer GKR (×0.57) and GPU capture (160 MIPS) are all [E] with no prototype. The measured streams all came in below their revision-2 estimates, and the remaining ones may do the same.
3. **P1 memory gates two levers.** Occupancy and k-leaf both need nodes ≤ 11–13 GB. A pair leaf is about 30.7 GB against the 30.06 GB gate today [E].
4. **Production miss.** The serial upper bound costs +5.6 s at p50 even after fan-in. GPU-native refuses on a miss. Fold classes miss too under the exact outer shape. Without E8 and a miss path, the production p50 target (≤ 8.7 s) is not reachable: 13.6 s [E].
5. **k-leaf VK set is per request** under exact native shapes (11 distinct CPU leaf row vectors in 11 segments [M]). A bounded VK set needs canonical native shapes, and canonical shapes as built cost ×1.55.
6. **Soundness work per profile.** k-leaf (per-native Fiat–Shamir; union bound shrinks), native GKR v2, outer GKR and GPU capture all need conjectured-128 notes, fresh receivers and tamper corpora. Canonical leaves cost up to 1.53 bits of lookup slack [M].
7. **Model simplifications.** The Poseidon2 transcript is treated as GPU capacity (fully exposed at 1 job/GPU, half hidden at 2), which is between the latency-only bound and the upper bound. The leaf/fold split after fan-in uses 26235168's 0.72 leaf share for every block. Truth jobs do not fill the seal barrier.
8. **Packed ingress has no checksum.** A bit flip that leaves the LZ4 stream valid decodes to wrong words with status 0. The host path behaves the same; a wrong word only makes the proof fail.

---

## 8. Integration steps after GPU-native lands

1. Rebase `codex/rv64-m9-plan` on integrate (adds files only).
2. Cleanup step 0 (§5): T1 default, p-truth-split, landed bench15 on all 15 blocks. Refit `RFIT`, `KFIT`, `k_m8`, `busy`, `head`, `STAGE1_FRAC`, `IO_LINK_607_POST_M8` and `FANIN_SAME` (re-run `rv64_m9_leaf_fanin_model.py` on the D2 shapes after p-truth-split); regenerate `model.json` and §4.
3. Run E8; set `fold_miss`, `miss_par`, and choose between the overlap miss path and class-stable outer shapes.
4. Land waves 1–3 one flag at a time. Run an A/B 3+3 on 607 + 26235168 and bench15 after each wave. Re-score §4.3 on measured numbers and re-plan if the cumulative cut trails §4.2 by more than 5 points.

---

## 9. Sources

- Gas sample `gas_sample.json` (out of git); basket `vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json`, `vectors/reports/rv64-m3-20261104/summary.json`.
- bench15-1 and kernel census: `codex/rv64-m8-gpu:vectors/reports/rv64-m8-20261106/{bench15,opt-combined}/`.
- Stream receipts: `vectors/reports/rv64-m9-prep/{packed-ingress,m9-fewer-leaves,canon-leaf,m9-poseidon2-leaves}/` on their branches (§6).
- `rv64-4gpu-realtime.md`, `rv64-frontier-gpu-delta.md`, `scripts/rv64_4gpu/levers.py` (`codex/rv64-4gpu-realtime-design`); `rv64-m8-gpu-native.md` (`codex/rv64-m8-gpu`); `rv64-m9-io-streaming.md` (`codex/rv64-m9-io-design`); `rv64-m8-engineering-scope.md` (integrate).

## 10. Revision history

- **r1** (06ec8ec25, 6064251e6): first budget; claimed M9 levers reach −61%.
- **r2** (fba033dfe, adversarial review): recursion fit on nodes, D2 and native-GKR factors on leaves only, K607 with T2 off, seal waits for the last Stage 1, and integration costs added. Result: M9 alone −56%; GPU capture needed for −62 to −64%.
- **r3** (this revision, stream results): fan-in ×0.76–0.86 replaces the truth-batch/2²³ lever. Poseidon2 is a loss on top of outer GKR. Canonical leaves carry a held-out tax of ×1.55 and fold classes still miss. Packed ingress is measured. The production miss now includes folds. Result: **best central 2-GPU set −58/−59%, no set reaches 60%; 4 GPUs −73 to −75%.**
